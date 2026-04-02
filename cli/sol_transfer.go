package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"filippo.io/edwards25519"
	"github.com/spf13/cobra"
)

// Solana program addresses (mainnet).
var (
	solTokenProgramID = mustBase58Decode("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
	solATAProgramID   = mustBase58Decode("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
	solSystemProgram  = mustBase58Decode("11111111111111111111111111111111")
	solUSDCMint       = mustBase58Decode("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
)

const defaultSolanaRPC = "https://api.mainnet-beta.solana.com"

func solanaRPCURL() string {
	if env := os.Getenv("BOB_SOL_RPC_URL"); env != "" {
		return env
	}
	return defaultSolanaRPC
}

// solTransferUSDC sends USDC on Solana from the agent's wallet to a recipient.
// Creates the recipient's associated token account if it doesn't exist.
// Returns the transaction signature.
func solTransferUSDC(ctx context.Context, privKeyHex string, to string, amount uint64) (string, error) {
	rpcURL := solanaRPCURL()

	privKeyBytes, err := hex.DecodeString(strings.TrimPrefix(privKeyHex, "0x"))
	if err != nil {
		return "", fmt.Errorf("decode private key: %w", err)
	}

	// Support both 32-byte seed and 64-byte full keypair.
	var privKey ed25519.PrivateKey
	switch len(privKeyBytes) {
	case ed25519.SeedSize: // 32 bytes — derive full keypair from seed
		privKey = ed25519.NewKeyFromSeed(privKeyBytes)
	case ed25519.PrivateKeySize: // 64 bytes — already a full keypair
		privKey = ed25519.PrivateKey(privKeyBytes)
	default:
		return "", fmt.Errorf("invalid Ed25519 key length: got %d, want 32 (seed) or 64 (keypair)", len(privKeyBytes))
	}
	pubKey := privKey.Public().(ed25519.PublicKey)

	toBytes := base58Decode(to)
	if len(toBytes) != 32 {
		return "", fmt.Errorf("invalid recipient address: %s", to)
	}

	fromPK := toArr32(pubKey)
	toPK := toArr32(toBytes)
	mint := toArr32(solUSDCMint)

	fromATA := deriveATA(fromPK, mint)
	toATA := deriveATA(toPK, mint)

	// Check if recipient ATA exists.
	recipientATAExists, err := solAccountExists(ctx, rpcURL, toATA[:])
	if err != nil {
		return "", fmt.Errorf("check recipient token account: %w", err)
	}

	blockhash, err := solGetRecentBlockhash(ctx, rpcURL)
	if err != nil {
		return "", fmt.Errorf("get recent blockhash: %w", err)
	}

	var instructions []solInstruction

	if !recipientATAExists {
		instructions = append(instructions, buildCreateATAIx(fromPK, toPK, mint, toATA))
	}

	instructions = append(instructions, buildTransferCheckedIx(fromATA, mint, toATA, fromPK, amount, 6))

	message := serializeSolMessage(blockhash, fromPK, instructions)
	sig := ed25519.Sign(privKey, message)

	signedTx := encodeSolSignedTx(sig, message)

	fmt.Fprintf(os.Stderr, "broadcasting SOL tx...\n")

	txSig, err := solSendTransaction(ctx, rpcURL, signedTx)
	if err != nil {
		return "", fmt.Errorf("send transaction: %w", err)
	}

	fmt.Fprintf(os.Stderr, "tx signature: %s\n", txSig)

	if err := solConfirmTransaction(ctx, rpcURL, txSig); err != nil {
		return "", fmt.Errorf("transaction sent but confirmation failed (sig: %s) — check Solana explorer: %w", txSig, err)
	}

	fmt.Fprintf(os.Stderr, "confirmed\n")
	return txSig, nil
}

// ---------------------------------------------------------------------------
// Instructions
// ---------------------------------------------------------------------------

type solInstruction struct {
	programID [32]byte
	accounts  []solAccountMeta
	data      []byte
}

type solAccountMeta struct {
	pubkey     [32]byte
	isSigner   bool
	isWritable bool
}

// CreateAssociatedTokenAccountIdempotent (instruction index 1).
func buildCreateATAIx(payer, owner, mint, ata [32]byte) solInstruction {
	return solInstruction{
		programID: toArr32(solATAProgramID),
		accounts: []solAccountMeta{
			{pubkey: payer, isSigner: true, isWritable: true},
			{pubkey: ata, isSigner: false, isWritable: true},
			{pubkey: owner, isSigner: false, isWritable: false},
			{pubkey: mint, isSigner: false, isWritable: false},
			{pubkey: toArr32(solSystemProgram), isSigner: false, isWritable: false},
			{pubkey: toArr32(solTokenProgramID), isSigner: false, isWritable: false},
		},
		data: []byte{1}, // CreateIdempotent
	}
}

// SPL Token transferChecked.
func buildTransferCheckedIx(source, mint, dest, authority [32]byte, amount uint64, decimals byte) solInstruction {
	data := make([]byte, 10)
	data[0] = 12 // TransferChecked instruction index
	binary.LittleEndian.PutUint64(data[1:9], amount)
	data[9] = decimals

	return solInstruction{
		programID: toArr32(solTokenProgramID),
		accounts: []solAccountMeta{
			{pubkey: source, isSigner: false, isWritable: true},
			{pubkey: mint, isSigner: false, isWritable: false},
			{pubkey: dest, isSigner: false, isWritable: true},
			{pubkey: authority, isSigner: true, isWritable: false},
		},
		data: data,
	}
}

// ---------------------------------------------------------------------------
// Transaction serialization (legacy format)
// ---------------------------------------------------------------------------

func serializeSolMessage(blockhash, feePayer [32]byte, instructions []solInstruction) []byte {
	// Collect unique accounts with proper flags.
	type acctInfo struct {
		signer   bool
		writable bool
	}
	seen := map[[32]byte]*acctInfo{}
	var order [][32]byte

	add := func(pk [32]byte, signer, writable bool) {
		if a, ok := seen[pk]; ok {
			a.signer = a.signer || signer
			a.writable = a.writable || writable
		} else {
			seen[pk] = &acctInfo{signer: signer, writable: writable}
			order = append(order, pk)
		}
	}

	add(feePayer, true, true)
	for _, ix := range instructions {
		for _, acc := range ix.accounts {
			add(acc.pubkey, acc.isSigner, acc.isWritable)
		}
		add(ix.programID, false, false)
	}

	// Partition: signer+writable, signer+readonly, non-signer+writable, non-signer+readonly.
	var sw, sr, nw, nr [][32]byte
	for _, pk := range order {
		a := seen[pk]
		switch {
		case a.signer && a.writable:
			sw = append(sw, pk)
		case a.signer:
			sr = append(sr, pk)
		case a.writable:
			nw = append(nw, pk)
		default:
			nr = append(nr, pk)
		}
	}

	accounts := append(sw, sr...)
	accounts = append(accounts, nw...)
	accounts = append(accounts, nr...)

	idx := map[[32]byte]byte{}
	for i, pk := range accounts {
		idx[pk] = byte(i)
	}

	var msg bytes.Buffer

	// Header.
	msg.WriteByte(byte(len(sw) + len(sr))) // num required signatures
	msg.WriteByte(byte(len(sr)))           // num readonly signers
	msg.WriteByte(byte(len(nr)))           // num readonly non-signers

	// Account keys.
	solWriteCompactU16(&msg, len(accounts))
	for _, pk := range accounts {
		msg.Write(pk[:])
	}

	// Recent blockhash.
	msg.Write(blockhash[:])

	// Instructions.
	solWriteCompactU16(&msg, len(instructions))
	for _, ix := range instructions {
		msg.WriteByte(idx[ix.programID])
		solWriteCompactU16(&msg, len(ix.accounts))
		for _, acc := range ix.accounts {
			msg.WriteByte(idx[acc.pubkey])
		}
		solWriteCompactU16(&msg, len(ix.data))
		msg.Write(ix.data)
	}

	return msg.Bytes()
}

func encodeSolSignedTx(sig []byte, message []byte) []byte {
	var buf bytes.Buffer
	solWriteCompactU16(&buf, 1) // 1 signature
	buf.Write(sig)
	buf.Write(message)
	return buf.Bytes()
}

func solWriteCompactU16(buf *bytes.Buffer, val int) {
	v := uint16(val)
	for {
		b := byte(v & 0x7F)
		v >>= 7
		if v > 0 {
			b |= 0x80
		}
		buf.WriteByte(b)
		if v == 0 {
			break
		}
	}
}

// ---------------------------------------------------------------------------
// PDA / ATA derivation
// ---------------------------------------------------------------------------

// deriveATA derives the associated token account for (owner, mint).
func deriveATA(owner, mint [32]byte) [32]byte {
	seeds := [][]byte{owner[:], solTokenProgramID, mint[:]}
	addr, _ := findProgramAddress(seeds, toArr32(solATAProgramID))
	return addr
}

// findProgramAddress finds a valid PDA by trying bump seeds 255..0.
func findProgramAddress(seeds [][]byte, programID [32]byte) ([32]byte, byte) {
	for bump := byte(255); ; bump-- {
		addr, ok := createProgramAddress(append(seeds, []byte{bump}), programID)
		if ok {
			return addr, bump
		}
		if bump == 0 {
			break
		}
	}
	return [32]byte{}, 0
}

// createProgramAddress hashes seeds + programID + "ProgramDerivedAddress"
// and rejects the result if it lies on the Ed25519 curve (valid PDAs must NOT
// be valid public keys).
//
// Matches Solana's native behavior: the hash is treated as a compressed
// Edwards Y coordinate. If it can be decompressed to a valid curve point,
// the candidate is rejected and the next bump is tried.
func createProgramAddress(seeds [][]byte, programID [32]byte) ([32]byte, bool) {
	h := sha256.New()
	for _, s := range seeds {
		h.Write(s)
	}
	h.Write(programID[:])
	h.Write([]byte("ProgramDerivedAddress"))
	hash := h.Sum(nil)

	var candidate [32]byte
	copy(candidate[:], hash[:32])

	// Reject if on the Ed25519 curve. We check by attempting to decompress
	// the 32 bytes as a compressed Edwards Y point. The top bit of byte 31
	// is the sign bit — we must try BOTH sign variants, because Solana's
	// check considers ANY valid decompression as on-curve.
	//
	// edwards25519.Point.SetBytes interprets the top bit of byte[31] as the
	// sign, so we need to check the hash as-is. If SetBytes succeeds, the
	// point is on the curve → reject.
	if _, err := new(edwards25519.Point).SetBytes(candidate[:]); err == nil {
		return [32]byte{}, false
	}
	// Also check with the sign bit flipped — Solana checks if the Y coordinate
	// (ignoring sign) is on the curve.
	flipped := candidate
	flipped[31] ^= 0x80
	if _, err := new(edwards25519.Point).SetBytes(flipped[:]); err == nil {
		return [32]byte{}, false
	}

	return candidate, true
}

// ---------------------------------------------------------------------------
// Base58
// ---------------------------------------------------------------------------

func base58Decode(s string) []byte {
	alphabet := "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	result := big.NewInt(0)
	base := big.NewInt(58)
	for _, c := range s {
		idx := strings.IndexRune(alphabet, c)
		if idx < 0 {
			return nil
		}
		result.Mul(result, base)
		result.Add(result, big.NewInt(int64(idx)))
	}
	// Preserve leading 1s (zero bytes).
	var leading int
	for _, c := range s {
		if c != '1' {
			break
		}
		leading++
	}
	b := result.Bytes()
	out := make([]byte, leading+len(b))
	copy(out[leading:], b)
	return out
}

func mustBase58Decode(s string) []byte {
	b := base58Decode(s)
	if b == nil {
		panic("invalid base58: " + s)
	}
	return b
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func toArr32(b []byte) [32]byte {
	var arr [32]byte
	copy(arr[:], b)
	return arr
}

// ---------------------------------------------------------------------------
// Solana JSON-RPC
// ---------------------------------------------------------------------------

var solHTTPClient = &http.Client{Timeout: 30 * time.Second}

func solRPCCall(ctx context.Context, rpcURL, method string, params []any) (json.RawMessage, error) {
	body := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  params,
	}
	data, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(ctx, "POST", rpcURL, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := solHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	var rpcResp struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return nil, fmt.Errorf("parse RPC response: %w", err)
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}
	return rpcResp.Result, nil
}

func solGetRecentBlockhash(ctx context.Context, rpcURL string) ([32]byte, error) {
	result, err := solRPCCall(ctx, rpcURL, "getLatestBlockhash", []any{
		map[string]string{"commitment": "confirmed"},
	})
	if err != nil {
		return [32]byte{}, err
	}
	var parsed struct {
		Value struct {
			Blockhash string `json:"blockhash"`
		} `json:"value"`
	}
	if err := json.Unmarshal(result, &parsed); err != nil {
		return [32]byte{}, err
	}
	decoded := base58Decode(parsed.Value.Blockhash)
	if len(decoded) != 32 {
		return [32]byte{}, fmt.Errorf("invalid blockhash length: %d", len(decoded))
	}
	return toArr32(decoded), nil
}

func solAccountExists(ctx context.Context, rpcURL string, pubkey []byte) (bool, error) {
	addr := base58Encode(pubkey)
	result, err := solRPCCall(ctx, rpcURL, "getAccountInfo", []any{
		addr,
		map[string]any{"encoding": "base64", "commitment": "confirmed"},
	})
	if err != nil {
		return false, err
	}
	var parsed struct {
		Value *json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(result, &parsed); err != nil {
		return false, err
	}
	return parsed.Value != nil && string(*parsed.Value) != "null", nil
}

func solSendTransaction(ctx context.Context, rpcURL string, signedTx []byte) (string, error) {
	encoded := base64.StdEncoding.EncodeToString(signedTx)
	result, err := solRPCCall(ctx, rpcURL, "sendTransaction", []any{
		encoded,
		map[string]any{"encoding": "base64", "preflightCommitment": "confirmed"},
	})
	if err != nil {
		return "", err
	}
	var sig string
	if err := json.Unmarshal(result, &sig); err != nil {
		return "", fmt.Errorf("parse tx signature: %w", err)
	}
	return sig, nil
}

// solTransferNative sends native SOL from the agent's wallet to a recipient.
func solTransferNative(ctx context.Context, privKeyHex string, to string, lamports uint64) (string, error) {
	rpcURL := solanaRPCURL()

	privKeyBytes, err := hex.DecodeString(strings.TrimPrefix(privKeyHex, "0x"))
	if err != nil {
		return "", fmt.Errorf("decode private key: %w", err)
	}

	var privKey ed25519.PrivateKey
	switch len(privKeyBytes) {
	case ed25519.SeedSize:
		privKey = ed25519.NewKeyFromSeed(privKeyBytes)
	case ed25519.PrivateKeySize:
		privKey = ed25519.PrivateKey(privKeyBytes)
	default:
		return "", fmt.Errorf("invalid Ed25519 key length: got %d, want 32 or 64", len(privKeyBytes))
	}
	pubKey := privKey.Public().(ed25519.PublicKey)

	toBytes := base58Decode(to)
	if len(toBytes) != 32 {
		return "", fmt.Errorf("invalid recipient address: %s", to)
	}

	fromPK := toArr32(pubKey)
	toPK := toArr32(toBytes)

	blockhash, err := solGetRecentBlockhash(ctx, rpcURL)
	if err != nil {
		return "", fmt.Errorf("get recent blockhash: %w", err)
	}

	// System program transfer instruction (index 2).
	data := make([]byte, 12)
	binary.LittleEndian.PutUint32(data[0:4], 2) // Transfer instruction index
	binary.LittleEndian.PutUint64(data[4:12], lamports)

	ix := solInstruction{
		programID: toArr32(solSystemProgram),
		accounts: []solAccountMeta{
			{pubkey: fromPK, isSigner: true, isWritable: true},
			{pubkey: toPK, isSigner: false, isWritable: true},
		},
		data: data,
	}

	message := serializeSolMessage(blockhash, fromPK, []solInstruction{ix})
	sig := ed25519.Sign(privKey, message)
	signedTx := encodeSolSignedTx(sig, message)

	fmt.Fprintf(os.Stderr, "broadcasting SOL native transfer...\n")

	txSig, err := solSendTransaction(ctx, rpcURL, signedTx)
	if err != nil {
		return "", fmt.Errorf("send transaction: %w", err)
	}

	fmt.Fprintf(os.Stderr, "tx signature: %s\n", txSig)

	if err := solConfirmTransaction(ctx, rpcURL, txSig); err != nil {
		return "", fmt.Errorf("transaction sent but confirmation failed (sig: %s) — check Solana explorer: %w", txSig, err)
	}

	fmt.Fprintf(os.Stderr, "confirmed\n")
	return txSig, nil
}

// runSendSOL handles `bob send sol --to <addr> --amount <atomic> [--token usdc|native]`.
func runSendSOL(cmd *cobra.Command, args []string) error {
	to, _ := cmd.Flags().GetString("to")
	amountStr, _ := cmd.Flags().GetString("amount")
	token, _ := cmd.Flags().GetString("token")

	amount, ok := new(big.Int).SetString(amountStr, 10)
	if !ok || amount.Sign() <= 0 {
		emitError("bob send sol", fmt.Errorf("amount must be a positive integer (got %q)", amountStr))
		return nil
	}
	if !amount.IsUint64() {
		emitError("bob send sol", fmt.Errorf("amount %s exceeds uint64 range", amountStr))
		return nil
	}

	cfg, err := loadCLIConfig()
	if err != nil {
		emitError("bob send sol", fmt.Errorf("load config: %w", err))
		return nil
	}
	keys := cfg.activeWalletKeys()
	if keys == nil || keys.SOLPrivateKey == "" {
		emitErrorWithActions("bob send sol", fmt.Errorf("no Solana wallet key found"), []NextAction{
			{Command: "bob init", Description: "Initialize wallet keys"},
		})
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	var (
		txSig     string
		sendErr   error
		tokenName string
	)

	switch strings.ToLower(token) {
	case "native", "sol":
		txSig, sendErr = solTransferNative(ctx, keys.SOLPrivateKey, to, amount.Uint64())
		tokenName = "SOL"
	case "usdc", "":
		txSig, sendErr = solTransferUSDC(ctx, keys.SOLPrivateKey, to, amount.Uint64())
		tokenName = "USDC"
	default:
		emitError("bob send sol", fmt.Errorf("unsupported token %q — use usdc or native", token))
		return nil
	}

	if sendErr != nil {
		emitError("bob send sol", sendErr)
		return nil
	}

	emit(Envelope{
		OK:      true,
		Command: "bob send sol",
		Data: map[string]any{
			"signature": txSig,
			"to":        to,
			"amount":    amount.String(),
			"token":     tokenName,
			"explorer":  "https://solscan.io/tx/" + txSig,
		},
		NextActions: []NextAction{
			{Command: "bob wallet balance", Description: "Check wallet balances"},
		},
	})
	return nil
}

func solConfirmTransaction(ctx context.Context, rpcURL string, sig string) error {
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		result, err := solRPCCall(ctx, rpcURL, "getSignatureStatuses", []any{
			[]string{sig},
			map[string]any{"searchTransactionHistory": false},
		})
		if err == nil {
			var parsed struct {
				Value []struct {
					ConfirmationStatus string `json:"confirmationStatus"`
					Err                any    `json:"err"`
				} `json:"value"`
			}
			if err := json.Unmarshal(result, &parsed); err == nil && len(parsed.Value) > 0 {
				status := parsed.Value[0]
				if status.Err != nil {
					return fmt.Errorf("transaction failed: %v", status.Err)
				}
				if status.ConfirmationStatus == "confirmed" || status.ConfirmationStatus == "finalized" {
					return nil
				}
			}
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("not confirmed within 60s")
}
