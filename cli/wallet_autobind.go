package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// autoBindWalletBestEffort attempts to bind each auto-generated wallet via the
// operator-level challenge/verify flow. This gives the operator verified
// ownership of the wallet addresses, which is required for loan eligibility.
//
// Best-effort: failures produce warnings but never fail init.
func autoBindWalletBestEffort(agentID string) []string {
	cfg, err := loadCLIConfig()
	if err != nil {
		return []string{"wallet-bind: failed to load config: " + err.Error()}
	}
	// Use the explicit agentID for key lookup, falling back to active agent.
	keys := cfg.walletKeysForAgent(agentID)
	if keys == nil {
		keys = cfg.activeWalletKeys()
	}
	if keys == nil {
		return []string{"wallet-bind: no wallet keys found for agent " + agentID}
	}

	var warnings []string

	// EVM binding
	if keys.EVMAddress != "" && keys.EVMPrivateKey != "" {
		if w := bindWalletForRail("evm", keys.EVMAddress, keys.EVMPrivateKey); w != "" {
			warnings = append(warnings, w)
		}
	}

	// BTC binding (BIP-137 signed message using same secp256k1 key as EVM)
	if keys.BTCAddress != "" && keys.BTCPrivateKey != "" {
		if w := bindWalletForRail("btc", keys.BTCAddress, keys.BTCPrivateKey); w != "" {
			warnings = append(warnings, w)
		}
	}

	// Solana binding
	if keys.SOLAddress != "" && keys.SOLPrivateKey != "" {
		if w := bindWalletForRail("solana", keys.SOLAddress, keys.SOLPrivateKey); w != "" {
			warnings = append(warnings, w)
		}
	}

	return warnings
}

// bindWalletForRail performs the challenge/verify flow for a single rail.
func bindWalletForRail(rail, address, privKeyHex string) string {
	// Step 1: Request challenge
	challengeResp, err := apiPost(
		fmt.Sprintf("/operators/me/wallet-bindings/%s/challenge", url.PathEscape(rail)),
		map[string]any{"address": address},
	)
	if err != nil {
		// 409 means already bound — not an error
		if strings.Contains(err.Error(), "409") {
			return ""
		}
		return fmt.Sprintf("%s: wallet bind challenge failed: %s", rail, err.Error())
	}

	// Parse challenge response
	var challenge struct {
		ChallengeID string `json:"challenge_id"`
		Message     string `json:"message"`
	}
	if err := json.Unmarshal(challengeResp, &challenge); err != nil {
		return fmt.Sprintf("%s: failed to parse challenge response: %s", rail, err.Error())
	}
	if challenge.ChallengeID == "" || challenge.Message == "" {
		return fmt.Sprintf("%s: empty challenge_id or message in response", rail)
	}

	// Step 2: Sign the challenge message
	sig, err := signChallengeMessage(rail, challenge.Message, privKeyHex)
	if err != nil {
		return fmt.Sprintf("%s: signing failed: %s", rail, err.Error())
	}

	// Step 3: Verify
	_, err = apiPost(
		fmt.Sprintf("/operators/me/wallet-bindings/%s/verify", url.PathEscape(rail)),
		map[string]any{
			"challenge_id": challenge.ChallengeID,
			"address":      address,
			"signature":    sig,
		},
	)
	if err != nil {
		return fmt.Sprintf("%s: wallet bind verify failed: %s", rail, err.Error())
	}

	return "" // success
}

// signChallengeMessage signs the challenge message with the appropriate algorithm
// for the given rail, returning a hex-encoded signature string.
func signChallengeMessage(rail, message, privKeyHex string) (string, error) {
	switch rail {
	case "evm":
		return signEVMChallenge(message, privKeyHex)
	case "btc":
		return signBTCChallenge(message, privKeyHex)
	case "solana":
		return signSolanaChallenge(message, privKeyHex)
	default:
		return "", fmt.Errorf("unsupported rail for auto-signing: %s", rail)
	}
}

// signEVMChallenge signs a message using EIP-191 personal_sign.
// The message is prefixed with "\x19Ethereum Signed Message:\n<len>" then
// keccak256-hashed and signed with secp256k1.
func signEVMChallenge(message, privKeyHex string) (string, error) {
	privKeyBytes, err := hex.DecodeString(strings.TrimPrefix(privKeyHex, "0x"))
	if err != nil {
		return "", fmt.Errorf("decode private key: %w", err)
	}
	ecKey, err := ethcrypto.ToECDSA(privKeyBytes)
	if err != nil {
		return "", fmt.Errorf("parse ECDSA key: %w", err)
	}

	// EIP-191 prefix
	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(message))
	hash := ethcrypto.Keccak256(append([]byte(prefix), []byte(message)...))

	sig, err := ethcrypto.Sign(hash, ecKey)
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	if err := normalizeEthereumRecoveryID(sig); err != nil {
		return "", err
	}

	return "0x" + hex.EncodeToString(sig), nil
}

func normalizeEthereumRecoveryID(sig []byte) error {
	if len(sig) != 65 {
		return fmt.Errorf("signature must be 65 bytes")
	}
	// go-ethereum returns [R || S || V] where V is 0 or 1.
	// External verifiers in this codebase expect the canonical 27/28 form.
	if sig[64] < 27 {
		sig[64] += 27
	}
	if sig[64] != 27 && sig[64] != 28 {
		return fmt.Errorf("unexpected recovery ID %d after normalization", sig[64])
	}
	return nil
}

// signBTCChallenge signs a message using BIP-137 Bitcoin Signed Message format.
// Hash: SHA256(SHA256("Bitcoin Signed Message:\n" + varint(len(message)) + message))
// The result is base64-encoded with the recovery flag byte first: [V+27 || R || S].
func signBTCChallenge(message, privKeyHex string) (string, error) {
	privKeyBytes, err := hex.DecodeString(strings.TrimPrefix(privKeyHex, "0x"))
	if err != nil {
		return "", fmt.Errorf("decode private key: %w", err)
	}
	ecKey, err := ethcrypto.ToECDSA(privKeyBytes)
	if err != nil {
		return "", fmt.Errorf("parse ECDSA key: %w", err)
	}

	// Build the Bitcoin Signed Message payload:
	// "Bitcoin Signed Message:\n" + varint(len(message)) + message
	var buf []byte
	prefix := "Bitcoin Signed Message:\n"
	buf = append(buf, bitcoinVarint(len(prefix))...)
	buf = append(buf, []byte(prefix)...)
	buf = append(buf, bitcoinVarint(len(message))...)
	buf = append(buf, []byte(message)...)

	// Double SHA256
	first := sha256.Sum256(buf)
	hash := sha256.Sum256(first[:])

	// Sign with secp256k1 — returns [R(32) || S(32) || V(1)]
	sig, err := ethcrypto.Sign(hash[:], ecKey)
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	if len(sig) != 65 {
		return "", fmt.Errorf("unexpected signature length: %d", len(sig))
	}

	// Rearrange from [R || S || V] to BIP-137 format [V+27 || R || S]
	v := sig[64] + 27 // recovery flag: 27 or 28 for uncompressed, +4 for compressed
	// Use compressed key flag (31 or 32) for P2PKH compressed
	v += 4 // compressed public key
	var bip137Sig [65]byte
	bip137Sig[0] = v
	copy(bip137Sig[1:33], sig[0:32])   // R
	copy(bip137Sig[33:65], sig[32:64]) // S

	return base64.StdEncoding.EncodeToString(bip137Sig[:]), nil
}

// bitcoinVarint encodes an integer as a Bitcoin-style variable-length integer.
func bitcoinVarint(n int) []byte {
	if n < 253 {
		return []byte{byte(n)}
	}
	if n <= 65535 {
		return []byte{0xfd, byte(n & 0xff), byte((n >> 8) & 0xff)}
	}
	// Unlikely for message lengths, but handle 4-byte case
	return []byte{0xfe, byte(n & 0xff), byte((n >> 8) & 0xff), byte((n >> 16) & 0xff), byte((n >> 24) & 0xff)}
}

// signSolanaChallenge signs the raw message bytes with Ed25519.
// The private key is a 64-byte hex-encoded Ed25519 secret key.
func signSolanaChallenge(message, privKeyHex string) (string, error) {
	privKeyBytes, err := hex.DecodeString(strings.TrimPrefix(privKeyHex, "0x"))
	if err != nil {
		return "", fmt.Errorf("decode private key: %w", err)
	}
	if len(privKeyBytes) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid Ed25519 key length: got %d, want %d", len(privKeyBytes), ed25519.PrivateKeySize)
	}

	privKey := ed25519.PrivateKey(privKeyBytes)
	sig := ed25519.Sign(privKey, []byte(message))

	return "0x" + hex.EncodeToString(sig), nil
}
