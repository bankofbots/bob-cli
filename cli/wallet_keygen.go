package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/ripemd160"
)

// walletKeys holds generated keys for all supported chains.
type walletKeys struct {
	// EVM (Ethereum + Base) — secp256k1
	EVMPrivateKey string // hex-encoded
	EVMAddress    string // 0x-prefixed checksum address

	// Bitcoin — secp256k1, bech32 segwit address (bc1q...)
	BTCPrivateKey string // hex-encoded (same key material as EVM for simplicity)
	BTCAddress    string // bech32 segwit address

	// Solana — Ed25519
	SOLPrivateKey string // hex-encoded 64-byte secret key
	SOLAddress    string // base58-encoded public key
}

// generateWalletKeys creates keypairs for all four chains.
// EVM and BTC share the same secp256k1 key (different address derivation).
// Solana uses a separate Ed25519 key.
// btcHRP controls the bech32 prefix: "bc" (mainnet), "tb" (testnet), "bcrt" (regtest).
func generateWalletKeys(btcHRP string) (*walletKeys, error) {
	// secp256k1 key for EVM + BTC
	ecKey, err := ethcrypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generate secp256k1 key: %w", err)
	}
	evmAddr := ethcrypto.PubkeyToAddress(ecKey.PublicKey).Hex()
	evmPrivHex := hex.EncodeToString(ethcrypto.FromECDSA(ecKey))

	// BTC bech32 address from same public key
	btcAddr, err := pubkeyToBech32(&ecKey.PublicKey, btcHRP)
	if err != nil {
		return nil, fmt.Errorf("derive btc address: %w", err)
	}

	// Ed25519 key for Solana
	solPub, solPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}

	return &walletKeys{
		EVMPrivateKey: evmPrivHex,
		EVMAddress:    evmAddr,
		BTCPrivateKey: evmPrivHex, // same key, different address derivation
		BTCAddress:    btcAddr,
		SOLPrivateKey: hex.EncodeToString(solPriv),
		SOLAddress:    base58Encode(solPub),
	}, nil
}

// rederiveBTCAddress regenerates a BTC bech32 address from a hex-encoded secp256k1
// private key (the same key used for EVM). Returns the new address or an error.
func rederiveBTCAddress(privKeyHex, hrp string) (string, error) {
	privBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return "", fmt.Errorf("decode private key hex: %w", err)
	}
	ecKey, err := ethcrypto.ToECDSA(privBytes)
	if err != nil {
		return "", fmt.Errorf("parse secp256k1 key: %w", err)
	}
	return pubkeyToBech32(&ecKey.PublicKey, hrp)
}

// pubkeyToBech32 derives a BTC bech32 P2WPKH address from a secp256k1 public key.
// hrp is the human-readable part: "bc" for mainnet, "tb" for testnet, "bcrt" for regtest.
func pubkeyToBech32(pub *ecdsa.PublicKey, hrp string) (string, error) {
	if hrp == "" {
		hrp = "bc"
	}
	// Compressed public key (33 bytes)
	compressed := ethcrypto.CompressPubkey(pub)

	// Hash160 = RIPEMD160(SHA256(compressed_pubkey))
	sha := sha256.Sum256(compressed)
	//nolint:staticcheck // RIPEMD-160 is required by the Bitcoin spec
	h := ripemd160.New()
	h.Write(sha[:])
	hash160 := h.Sum(nil) // 20 bytes

	// Bech32 encode with witness version 0
	addr, err := bech32Encode(hrp, 0, hash160)
	if err != nil {
		return "", err
	}
	return addr, nil
}

// bech32Encode encodes a witness program as a bech32 address.
func bech32Encode(hrp string, version byte, program []byte) (string, error) {
	// Convert 8-bit to 5-bit groups
	data := []byte{version}
	conv, err := convertBits(program, 8, 5, true)
	if err != nil {
		return "", err
	}
	data = append(data, conv...)

	// Compute checksum
	polymod := bech32Polymod(expandHRP(hrp), data)
	for i := 0; i < 6; i++ {
		data = append(data, byte((polymod>>uint(5*(5-i)))&31))
	}

	// Encode
	charset := "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	result := hrp + "1"
	for _, d := range data {
		result += string(charset[d])
	}
	return result, nil
}

func expandHRP(hrp string) []byte {
	result := make([]byte, len(hrp)*2+1)
	for i, c := range hrp {
		result[i] = byte(c >> 5)
		result[i+len(hrp)+1] = byte(c & 31)
	}
	result[len(hrp)] = 0
	return result
}

func bech32Polymod(hrp, data []byte) uint32 {
	gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	values := append(hrp, data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk ^ 1
}

func convertBits(data []byte, fromBits, toBits uint, pad bool) ([]byte, error) {
	acc := uint(0)
	bits := uint(0)
	var result []byte
	maxV := uint((1 << toBits) - 1)
	for _, val := range data {
		acc = (acc << fromBits) | uint(val)
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			result = append(result, byte((acc>>bits)&maxV))
		}
	}
	if pad {
		if bits > 0 {
			result = append(result, byte((acc<<(toBits-bits))&maxV))
		}
	}
	return result, nil
}

// base58Encode encodes bytes as base58 (Bitcoin/Solana style).
func base58Encode(input []byte) string {
	alphabet := "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	x := new(big.Int).SetBytes(input)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)
	var result []byte
	for x.Cmp(zero) > 0 {
		x.DivMod(x, base, mod)
		result = append([]byte{alphabet[mod.Int64()]}, result...)
	}
	// Leading zeros
	for _, b := range input {
		if b != 0 {
			break
		}
		result = append([]byte{alphabet[0]}, result...)
	}
	return string(result)
}
