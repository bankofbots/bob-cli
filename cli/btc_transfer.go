package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ripemd160"
)

// ---------------------------------------------------------------------------
// Mempool API configuration
// ---------------------------------------------------------------------------

const defaultMempoolBase = "https://mempool.space"

func mempoolBaseURL() string {
	if env := os.Getenv("BOB_BTC_MEMPOOL_URL"); env != "" {
		trimmed := strings.TrimRight(env, "/")
		// Allow http only for localhost/127.0.0.1 (testing). Reject plain HTTP otherwise.
		if strings.HasPrefix(trimmed, "http://") &&
			!strings.Contains(trimmed, "localhost") &&
			!strings.Contains(trimmed, "127.0.0.1") {
			fmt.Fprintf(os.Stderr, "⚠ BOB_BTC_MEMPOOL_URL uses HTTP — rejecting for security. Use HTTPS or localhost.\n")
			// Fall through to default
		} else {
			return trimmed
		}
	}
	// Derive from apiBase: testnet → testnet mempool, localhost → signet.
	lowered := strings.ToLower(apiBase)
	if strings.Contains(lowered, "testnet") {
		return "https://mempool.space/testnet4"
	}
	if strings.Contains(lowered, "localhost") || strings.Contains(lowered, "127.0.0.1") {
		return "https://mempool.space/signet"
	}
	return defaultMempoolBase
}

// ---------------------------------------------------------------------------
// Mempool API types and helpers
// ---------------------------------------------------------------------------

type btcUTXO struct {
	TxID  string `json:"txid"`
	Vout  int    `json:"vout"`
	Value int64  `json:"value"`
	Status struct {
		Confirmed bool `json:"confirmed"`
	} `json:"status"`
}

var btcHTTPClient = &http.Client{Timeout: 30 * time.Second}

// fetchUTXOs returns all UTXOs for a given address via mempool.space.
func fetchUTXOs(address string) ([]btcUTXO, error) {
	url := mempoolBaseURL() + "/api/address/" + address + "/utxo"
	resp, err := btcHTTPClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch UTXOs: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("fetch UTXOs: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var utxos []btcUTXO
	if err := json.Unmarshal(body, &utxos); err != nil {
		return nil, fmt.Errorf("parse UTXOs: %w", err)
	}
	return utxos, nil
}

// fetchFeeRate returns the recommended fee rate (sat/vB) from mempool.space.
// Uses the "halfHourFee" by default.
func fetchFeeRate() (int64, error) {
	url := mempoolBaseURL() + "/api/v1/fees/recommended"
	resp, err := btcHTTPClient.Get(url)
	if err != nil {
		return 0, fmt.Errorf("fetch fee rate: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("fetch fee rate: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var fees struct {
		FastestFee  int64 `json:"fastestFee"`
		HalfHourFee int64 `json:"halfHourFee"`
		HourFee     int64 `json:"hourFee"`
		MinimumFee  int64 `json:"minimumFee"`
	}
	if err := json.Unmarshal(body, &fees); err != nil {
		return 0, fmt.Errorf("parse fee rate: %w", err)
	}
	if fees.HalfHourFee <= 0 {
		return 1, nil // absolute minimum
	}
	return fees.HalfHourFee, nil
}

// broadcastTx submits a raw transaction hex to mempool.space and returns the txid.
func broadcastTx(rawHex string) (string, error) {
	url := mempoolBaseURL() + "/api/tx"
	resp, err := btcHTTPClient.Post(url, "text/plain", strings.NewReader(rawHex))
	if err != nil {
		return "", fmt.Errorf("broadcast tx: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("broadcast tx: HTTP %d: %s", resp.StatusCode, string(body))
	}
	return strings.TrimSpace(string(body)), nil
}

// checkTxConfirmed checks whether a txid is confirmed on-chain.
func checkTxConfirmed(txid string) (bool, error) {
	url := mempoolBaseURL() + "/api/tx/" + txid + "/status"
	resp, err := btcHTTPClient.Get(url)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return false, nil
	}

	var status struct {
		Confirmed bool `json:"confirmed"`
	}
	if err := json.Unmarshal(body, &status); err != nil {
		return false, nil
	}
	return status.Confirmed, nil
}

// ---------------------------------------------------------------------------
// BTC send: build, sign, broadcast a P2WPKH transaction
// ---------------------------------------------------------------------------

const btcDustLimit int64 = 546

// btcSend builds and broadcasts a Bitcoin transaction sending amountSats to
// toAddress. The private key is hex-encoded secp256k1. Returns the txid.
//
// NOTE: The BTC private key is the same secp256k1 key as EVM (shared from wallet
// keyring). Compromising one chain's key compromises both. For production use,
// consider separate key derivation paths (BIP-44 m/44'/0'/0' for BTC vs m/44'/60'/0'
// for ETH). Current design prioritizes simplicity for the beta.
func btcSend(ctx context.Context, privKeyHex, toAddress string, amountSats int64, feeRateOverride int64) (string, error) {
	if amountSats < btcDustLimit {
		return "", fmt.Errorf("amount %d sats is below dust limit (%d)", amountSats, btcDustLimit)
	}

	// 1. Load private key, derive sender address.
	privKeyBytes, err := hex.DecodeString(strings.TrimPrefix(privKeyHex, "0x"))
	if err != nil {
		return "", fmt.Errorf("decode private key: %w", err)
	}
	ecKey, err := ethcrypto.ToECDSA(privKeyBytes)
	if err != nil {
		return "", fmt.Errorf("parse private key: %w", err)
	}

	senderPubCompressed := compressPublicKey(&ecKey.PublicKey)
	senderPubKeyHash := hash160(senderPubCompressed)

	// Derive sender bech32 address for UTXO lookup.
	hrp := btcHRPFromNetwork()
	senderAddr, err := bech32Encode(hrp, 0, senderPubKeyHash)
	if err != nil {
		return "", fmt.Errorf("derive sender address: %w", err)
	}

	// 2. Fetch UTXOs.
	utxos, err := fetchUTXOs(senderAddr)
	if err != nil {
		return "", err
	}

	// Filter confirmed only.
	var confirmed []btcUTXO
	for _, u := range utxos {
		if u.Status.Confirmed {
			confirmed = append(confirmed, u)
		}
	}
	if len(confirmed) == 0 {
		return "", fmt.Errorf("no confirmed UTXOs for %s", senderAddr)
	}

	// 3. Fee rate.
	feeRate := feeRateOverride
	if feeRate <= 0 {
		feeRate, err = fetchFeeRate()
		if err != nil {
			return "", err
		}
	}

	// 4. Select UTXOs: sort descending by value, accumulate.
	sort.Slice(confirmed, func(i, j int) bool {
		return confirmed[i].Value > confirmed[j].Value
	})

	var selected []btcUTXO
	var totalIn int64

	// Estimate with 2 outputs (recipient + change) initially.
	for _, u := range confirmed {
		selected = append(selected, u)
		totalIn += u.Value
		fee := estimateFee(len(selected), 2, feeRate)
		if totalIn >= amountSats+fee {
			break
		}
	}

	// Final fee calculation.
	numOutputs := 2
	change := totalIn - amountSats - estimateFee(len(selected), 2, feeRate)
	if change < btcDustLimit {
		// No change output (dust or exact); recalc fee with 1 output.
		numOutputs = 1
		fee := estimateFee(len(selected), 1, feeRate)
		if totalIn < amountSats+fee {
			return "", fmt.Errorf("insufficient funds: have %d sats, need %d + %d fee", totalIn, amountSats, fee)
		}
		change = 0
	}

	fee := estimateFee(len(selected), numOutputs, feeRate)
	if totalIn < amountSats+fee {
		return "", fmt.Errorf("insufficient funds: have %d sats, need %d + %d fee", totalIn, amountSats, fee)
	}
	if change > 0 {
		change = totalIn - amountSats - fee
	}

	// 5. Validate destination address and build output scripts.
	recipientScript, err := addressToOutputScript(toAddress)
	if err != nil {
		return "", fmt.Errorf("invalid recipient address: %w", err)
	}

	// Change script: P2WPKH back to sender.
	changeScript := buildP2WPKHScript(senderPubKeyHash)

	// 6. Build transaction.
	txRaw, err := buildSignedTx(ecKey, senderPubCompressed, senderPubKeyHash, selected, recipientScript, amountSats, changeScript, change)
	if err != nil {
		return "", fmt.Errorf("build transaction: %w", err)
	}

	rawHex := hex.EncodeToString(txRaw)

	// 7. Broadcast.
	fmt.Fprintf(os.Stderr, "broadcasting BTC tx (%d sats to %s, fee %d sats)...\n", amountSats, toAddress, fee)
	txid, err := broadcastTx(rawHex)
	if err != nil {
		return "", err
	}
	fmt.Fprintf(os.Stderr, "broadcast txid: %s\n", txid)

	// 8. Poll for confirmation (up to 120s).
	deadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return txid, fmt.Errorf("context cancelled while waiting for confirmation (txid: %s) — do NOT retry, check block explorer", txid)
		default:
		}

		confirmed, err := checkTxConfirmed(txid)
		if err == nil && confirmed {
			fmt.Fprintf(os.Stderr, "confirmed: %s\n", txid)
			return txid, nil
		}
		time.Sleep(3 * time.Second)
	}

	// Broadcast succeeded but not yet confirmed — not an error for BTC.
	fmt.Fprintf(os.Stderr, "broadcast succeeded, awaiting confirmation (txid: %s) — check mempool.space\n", txid)
	return txid, nil
}

// ---------------------------------------------------------------------------
// Fee estimation
// ---------------------------------------------------------------------------

// estimateFee returns the estimated fee in satoshis for a segwit transaction.
// Formula: (10 + 148*numInputs + 31*numOutputs + 11) * feeRate
// The +11 accounts for segwit overhead (marker, flag, witness counts).
func estimateFee(numInputs, numOutputs int, feeRate int64) int64 {
	// Virtual size estimate for P2WPKH:
	// - Base: 10 (version 4 + locktime 4 + varint counts ~2)
	// - Per input (non-witness): ~41 bytes (outpoint 36 + scriptSig length 1 + sequence 4)
	// - Per output: ~31 bytes
	// - Witness per input: ~107 bytes (at 1/4 weight discount ≈ 27 vbytes)
	// - Segwit overhead: 2 bytes (marker + flag) at 1/4 discount ≈ 0.5 vbytes
	// Simplified: vsize ≈ 10 + 68*numInputs + 31*numOutputs + 11
	vsize := int64(10 + 68*numInputs + 31*numOutputs + 11)
	return vsize * feeRate
}

// ---------------------------------------------------------------------------
// Transaction building
// ---------------------------------------------------------------------------

// buildSignedTx constructs a fully signed segwit transaction.
func buildSignedTx(
	privKey *ecdsa.PrivateKey,
	pubKeyCompressed []byte,
	pubKeyHash []byte,
	inputs []btcUTXO,
	recipientScript []byte,
	amount int64,
	changeScript []byte,
	changeAmount int64,
) ([]byte, error) {
	// Precompute BIP-143 hash components.
	var prevoutsBuf bytes.Buffer
	var sequencesBuf bytes.Buffer
	inputValues := make([]int64, len(inputs))

	for i, inp := range inputs {
		txidBytes, err := reversedTxID(inp.TxID)
		if err != nil {
			return nil, fmt.Errorf("input %d: invalid txid: %w", i, err)
		}
		prevoutsBuf.Write(txidBytes)
		binary.Write(&prevoutsBuf, binary.LittleEndian, uint32(inp.Vout))

		binary.Write(&sequencesBuf, binary.LittleEndian, uint32(0xffffffff))
		inputValues[i] = inp.Value
	}

	hashPrevouts := doubleSHA256(prevoutsBuf.Bytes())
	hashSequence := doubleSHA256(sequencesBuf.Bytes())

	// Build outputs.
	var outputsBuf bytes.Buffer
	binary.Write(&outputsBuf, binary.LittleEndian, amount)
	writeVarBytes(&outputsBuf, recipientScript)
	if changeAmount > 0 {
		binary.Write(&outputsBuf, binary.LittleEndian, changeAmount)
		writeVarBytes(&outputsBuf, changeScript)
	}

	hashOutputs := doubleSHA256(outputsBuf.Bytes())

	// ScriptCode for P2WPKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
	scriptCode := make([]byte, 0, 25)
	scriptCode = append(scriptCode, 0x76, 0xa9, 0x14)
	scriptCode = append(scriptCode, pubKeyHash...)
	scriptCode = append(scriptCode, 0x88, 0xac)

	// Sign each input using BIP-143.
	witnesses := make([][]byte, len(inputs))
	for i, inp := range inputs {
		txidBytes, _ := reversedTxID(inp.TxID)

		var preimage bytes.Buffer
		// nVersion
		binary.Write(&preimage, binary.LittleEndian, uint32(2))
		// hashPrevouts
		preimage.Write(hashPrevouts)
		// hashSequence
		preimage.Write(hashSequence)
		// outpoint (txid + vout)
		preimage.Write(txidBytes)
		binary.Write(&preimage, binary.LittleEndian, uint32(inp.Vout))
		// scriptCode (varint + script)
		writeVarBytes(&preimage, scriptCode)
		// value
		binary.Write(&preimage, binary.LittleEndian, inputValues[i])
		// nSequence
		binary.Write(&preimage, binary.LittleEndian, uint32(0xffffffff))
		// hashOutputs
		preimage.Write(hashOutputs)
		// nLocktime
		binary.Write(&preimage, binary.LittleEndian, uint32(0))
		// sighash type (SIGHASH_ALL = 1)
		binary.Write(&preimage, binary.LittleEndian, uint32(1))

		sigHash := doubleSHA256(preimage.Bytes())

		// Sign with go-ethereum's secp256k1 (produces 65-byte [R || S || V]).
		sigRaw, err := ethcrypto.Sign(sigHash, privKey)
		if err != nil {
			return nil, fmt.Errorf("sign input %d: %w", i, err)
		}

		// sigRaw is [R(32) || S(32) || V(1)]. Extract R and S for DER encoding.
		r := sigRaw[:32]
		s := sigRaw[32:64]
		derSig := encodeDERSignature(r, s)
		// Append SIGHASH_ALL byte.
		derSig = append(derSig, 0x01)

		// Witness: <sig> <pubkey>
		var witBuf bytes.Buffer
		witBuf.WriteByte(0x02) // 2 witness items
		writeVarBytes(&witBuf, derSig)
		writeVarBytes(&witBuf, pubKeyCompressed)
		witnesses[i] = witBuf.Bytes()
	}

	// Serialize full transaction.
	var tx bytes.Buffer
	// Version
	binary.Write(&tx, binary.LittleEndian, uint32(2))
	// Segwit marker + flag
	tx.Write([]byte{0x00, 0x01})
	// Input count
	writeVarInt(&tx, uint64(len(inputs)))
	// Inputs
	for _, inp := range inputs {
		txidBytes, _ := reversedTxID(inp.TxID)
		tx.Write(txidBytes)
		binary.Write(&tx, binary.LittleEndian, uint32(inp.Vout))
		tx.WriteByte(0x00) // empty scriptSig for segwit
		binary.Write(&tx, binary.LittleEndian, uint32(0xffffffff))
	}
	// Output count
	numOutputs := 1
	if changeAmount > 0 {
		numOutputs = 2
	}
	writeVarInt(&tx, uint64(numOutputs))
	// Outputs
	binary.Write(&tx, binary.LittleEndian, amount)
	writeVarBytes(&tx, recipientScript)
	if changeAmount > 0 {
		binary.Write(&tx, binary.LittleEndian, changeAmount)
		writeVarBytes(&tx, changeScript)
	}
	// Witness data
	for _, w := range witnesses {
		tx.Write(w)
	}
	// Locktime
	binary.Write(&tx, binary.LittleEndian, uint32(0))

	return tx.Bytes(), nil
}

// ---------------------------------------------------------------------------
// Address encoding / decoding
// ---------------------------------------------------------------------------

// addressToOutputScript converts a Bitcoin address to its output script.
// Supports P2WPKH (bc1q...) and P2PKH (1...).
func addressToOutputScript(addr string) ([]byte, error) {
	if strings.HasPrefix(addr, "bc1q") || strings.HasPrefix(addr, "tb1q") || strings.HasPrefix(addr, "bcrt1q") {
		prog, err := decodeBech32Address(addr)
		if err != nil {
			return nil, err
		}
		if len(prog) != 20 {
			return nil, fmt.Errorf("bech32 witness program must be 20 bytes, got %d", len(prog))
		}
		return buildP2WPKHScript(prog), nil
	}
	if strings.HasPrefix(addr, "1") || strings.HasPrefix(addr, "m") || strings.HasPrefix(addr, "n") {
		hash, err := decodeBase58CheckAddress(addr)
		if err != nil {
			return nil, err
		}
		return buildP2PKHScript(hash), nil
	}
	return nil, fmt.Errorf("unsupported address format: %s (only P2WPKH and P2PKH are supported)", addr)
}

// buildP2WPKHScript builds OP_0 <20-byte witness program>.
func buildP2WPKHScript(hash160Bytes []byte) []byte {
	script := make([]byte, 0, 22)
	script = append(script, 0x00, 0x14) // OP_0, PUSH 20 bytes
	script = append(script, hash160Bytes...)
	return script
}

// buildP2PKHScript builds OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG.
func buildP2PKHScript(hash160Bytes []byte) []byte {
	script := make([]byte, 0, 25)
	script = append(script, 0x76, 0xa9, 0x14) // OP_DUP OP_HASH160 PUSH20
	script = append(script, hash160Bytes...)
	script = append(script, 0x88, 0xac) // OP_EQUALVERIFY OP_CHECKSIG
	return script
}

// decodeBech32Address extracts the witness program from a bech32 address.
func decodeBech32Address(addr string) ([]byte, error) {
	// Find separator (last '1').
	pos := strings.LastIndex(addr, "1")
	if pos < 1 {
		return nil, fmt.Errorf("invalid bech32: no separator")
	}
	dataPart := strings.ToLower(addr[pos+1:])

	charset := "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	var data5bit []byte
	for _, c := range dataPart {
		idx := strings.IndexRune(charset, c)
		if idx < 0 {
			return nil, fmt.Errorf("invalid bech32 character: %c", c)
		}
		data5bit = append(data5bit, byte(idx))
	}

	// Remove 6-byte checksum.
	if len(data5bit) < 7 {
		return nil, fmt.Errorf("bech32 data too short")
	}
	data5bit = data5bit[:len(data5bit)-6]

	// First byte is witness version (must be 0 for P2WPKH).
	if data5bit[0] != 0 {
		return nil, fmt.Errorf("unsupported witness version: %d", data5bit[0])
	}

	// Convert remaining 5-bit groups to 8-bit.
	program, err := convertBits(data5bit[1:], 5, 8, false)
	if err != nil {
		return nil, fmt.Errorf("convert bech32 bits: %w", err)
	}

	return program, nil
}

// decodeBase58CheckAddress decodes a Base58Check-encoded Bitcoin address
// and returns the 20-byte pubkey hash (stripping version + checksum).
func decodeBase58CheckAddress(addr string) ([]byte, error) {
	decoded := base58Decode(addr)
	if len(decoded) != 25 {
		return nil, fmt.Errorf("invalid base58check address length: %d", len(decoded))
	}
	// Verify checksum: first 21 bytes → double SHA256, first 4 bytes must match last 4.
	payload := decoded[:21]
	checksum := decoded[21:]
	hash := doubleSHA256(payload)
	if !bytes.Equal(hash[:4], checksum) {
		return nil, fmt.Errorf("base58check checksum mismatch")
	}
	return payload[1:], nil // skip version byte, return 20-byte hash
}

// ---------------------------------------------------------------------------
// Cryptographic helpers
// ---------------------------------------------------------------------------

// compressPublicKey returns the 33-byte compressed form of a secp256k1 public key.
func compressPublicKey(pub *ecdsa.PublicKey) []byte {
	return ethcrypto.CompressPubkey(pub)
}

// hash160 computes RIPEMD160(SHA256(data)).
func hash160(data []byte) []byte {
	sha := sha256.Sum256(data)
	//nolint:staticcheck // RIPEMD-160 is required by Bitcoin
	h := ripemd160.New()
	h.Write(sha[:])
	return h.Sum(nil)
}

// doubleSHA256 computes SHA256(SHA256(data)).
func doubleSHA256(data []byte) []byte {
	h1 := sha256.Sum256(data)
	h2 := sha256.Sum256(h1[:])
	return h2[:]
}

// encodeDERSignature DER-encodes an ECDSA signature from raw R, S byte slices.
func encodeDERSignature(r, s []byte) []byte {
	// Strip leading zero bytes but ensure high bit isn't set (add 0x00 pad if needed).
	rEnc := derIntBytes(r)
	sEnc := derIntBytes(s)

	// DER sequence: 0x30 <total-len> 0x02 <r-len> <r> 0x02 <s-len> <s>
	totalLen := 2 + len(rEnc) + 2 + len(sEnc)
	der := make([]byte, 0, 2+totalLen)
	der = append(der, 0x30, byte(totalLen))
	der = append(der, 0x02, byte(len(rEnc)))
	der = append(der, rEnc...)
	der = append(der, 0x02, byte(len(sEnc)))
	der = append(der, sEnc...)
	return der
}

// derIntBytes prepares a big-endian integer for DER encoding.
func derIntBytes(b []byte) []byte {
	// Strip leading zeros.
	for len(b) > 1 && b[0] == 0 {
		b = b[1:]
	}
	// If high bit is set, prepend 0x00.
	if len(b) > 0 && b[0]&0x80 != 0 {
		return append([]byte{0x00}, b...)
	}
	return b
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

// reversedTxID converts a hex txid string to bytes in internal byte order (reversed).
func reversedTxID(txid string) ([]byte, error) {
	b, err := hex.DecodeString(txid)
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("txid must be 32 bytes, got %d", len(b))
	}
	// Reverse.
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b, nil
}

// writeVarInt writes a Bitcoin compact-size unsigned integer.
func writeVarInt(w *bytes.Buffer, v uint64) {
	switch {
	case v < 0xfd:
		w.WriteByte(byte(v))
	case v <= 0xffff:
		w.WriteByte(0xfd)
		binary.Write(w, binary.LittleEndian, uint16(v))
	case v <= 0xffffffff:
		w.WriteByte(0xfe)
		binary.Write(w, binary.LittleEndian, uint32(v))
	default:
		w.WriteByte(0xff)
		binary.Write(w, binary.LittleEndian, v)
	}
}

// writeVarBytes writes a varint-prefixed byte slice.
func writeVarBytes(w *bytes.Buffer, data []byte) {
	writeVarInt(w, uint64(len(data)))
	w.Write(data)
}

// btcHRPFromNetwork returns the bech32 HRP based on the current API base.
func btcHRPFromNetwork() string {
	lowered := strings.ToLower(apiBase)
	if strings.Contains(lowered, "localhost") || strings.Contains(lowered, "127.0.0.1") {
		return "bcrt"
	}
	if strings.Contains(lowered, "testnet") {
		return "tb"
	}
	return "bc"
}

// ---------------------------------------------------------------------------
// Cobra command: bob send btc
// ---------------------------------------------------------------------------

func sendCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "send",
		Short: "Send cryptocurrency",
		RunE: func(cmd *cobra.Command, args []string) error {
			emit(Envelope{
				OK:      true,
				Command: "bob send",
				Data: map[string]any{
					"subcommands": []string{"btc"},
				},
				NextActions: []NextAction{
					{Command: "bob send btc --to <address> --amount <sats>", Description: "Send BTC to an address"},
				},
			})
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	btcCmd := &cobra.Command{
		Use:   "btc",
		Short: "Send BTC to an address",
		RunE:  runSendBTC,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	btcCmd.Flags().String("to", "", "Recipient Bitcoin address (P2WPKH or P2PKH)")
	btcCmd.Flags().Int64("amount", 0, "Amount to send in satoshis")
	btcCmd.Flags().Int64("fee-rate", 0, "Fee rate in sat/vB (default: mempool.space halfHourFee)")
	_ = btcCmd.MarkFlagRequired("to")
	_ = btcCmd.MarkFlagRequired("amount")

	cmd.AddCommand(btcCmd)
	return cmd
}

func runSendBTC(cmd *cobra.Command, args []string) error {
	to, _ := cmd.Flags().GetString("to")
	amount, _ := cmd.Flags().GetInt64("amount")
	feeRate, _ := cmd.Flags().GetInt64("fee-rate")

	if amount < btcDustLimit {
		emitError("bob send btc", fmt.Errorf("amount %d sats is below dust limit (%d)", amount, btcDustLimit))
		return nil
	}

	// Load BTC private key from wallet keyring.
	cfg, err := loadCLIConfig()
	if err != nil {
		emitError("bob send btc", fmt.Errorf("load config: %w", err))
		return nil
	}
	keys := cfg.activeWalletKeys()
	if keys == nil || keys.BTCPrivateKey == "" {
		emitErrorWithActions("bob send btc", fmt.Errorf("no BTC wallet key found"), []NextAction{
			{Command: "bob init", Description: "Initialize wallet keys"},
		})
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()

	txid, err := btcSend(ctx, keys.BTCPrivateKey, to, amount, feeRate)
	if err != nil {
		emitError("bob send btc", err)
		return nil
	}

	explorerBase := mempoolBaseURL()
	emit(Envelope{
		OK:      true,
		Command: "bob send btc",
		Data: map[string]any{
			"txid":     txid,
			"to":       to,
			"amount":   amount,
			"explorer": explorerBase + "/tx/" + txid,
		},
		NextActions: []NextAction{
			{Command: "bob wallet show", Description: "Check wallet balances"},
		},
	})
	return nil
}

// btcAddressValidate checks if a string looks like a valid Bitcoin address.
// Returns nil if valid, error otherwise.
func btcAddressValidate(addr string) error {
	if addr == "" {
		return fmt.Errorf("empty address")
	}
	_, err := addressToOutputScript(addr)
	return err
}
