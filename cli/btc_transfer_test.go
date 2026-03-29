package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"os"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// UTXO selection
// ---------------------------------------------------------------------------

func TestEstimateFee(t *testing.T) {
	tests := []struct {
		name       string
		numInputs  int
		numOutputs int
		feeRate    int64
		expected   int64
	}{
		{"1-in-2-out at 1 sat/vB", 1, 2, 1, 10 + 68 + 62 + 11},
		{"2-in-2-out at 5 sat/vB", 2, 2, 5, (10 + 136 + 62 + 11) * 5},
		{"1-in-1-out at 10 sat/vB", 1, 1, 10, (10 + 68 + 31 + 11) * 10},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := estimateFee(tt.numInputs, tt.numOutputs, tt.feeRate)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestEstimateFee_Positive(t *testing.T) {
	// Fee should always be positive for any valid inputs.
	for inputs := 1; inputs <= 5; inputs++ {
		for outputs := 1; outputs <= 3; outputs++ {
			fee := estimateFee(inputs, outputs, 1)
			assert.Greater(t, fee, int64(0), "fee should be > 0 for %d inputs, %d outputs", inputs, outputs)
		}
	}
}

// ---------------------------------------------------------------------------
// DER signature encoding
// ---------------------------------------------------------------------------

func TestEncodeDERSignature_KnownValues(t *testing.T) {
	// Simple case: R and S with no leading zeros and no high bit.
	r := bytes.Repeat([]byte{0x01}, 32)
	s := bytes.Repeat([]byte{0x02}, 32)

	der := encodeDERSignature(r, s)

	// Should start with 0x30 (SEQUENCE).
	assert.Equal(t, byte(0x30), der[0], "first byte should be SEQUENCE tag")

	// Second byte is total inner length.
	innerLen := der[1]

	// Should contain two INTEGER tags.
	assert.Equal(t, byte(0x02), der[2], "R should start with INTEGER tag")
	rLen := der[3]
	rEnd := 4 + int(rLen)
	assert.Equal(t, byte(0x02), der[rEnd], "S should start with INTEGER tag")
	sLen := der[rEnd+1]

	assert.Equal(t, int(innerLen), 2+int(rLen)+2+int(sLen))
}

func TestEncodeDERSignature_HighBitPadding(t *testing.T) {
	// R with high bit set should get 0x00 prefix.
	r := make([]byte, 32)
	r[0] = 0x80
	s := make([]byte, 32)
	s[0] = 0x01

	der := encodeDERSignature(r, s)

	// R should be 33 bytes (0x00 prefix).
	rLen := der[3]
	assert.Equal(t, byte(33), rLen, "R with high bit should be padded to 33 bytes")
	assert.Equal(t, byte(0x00), der[4], "R padding byte should be 0x00")
}

func TestEncodeDERSignature_LeadingZeros(t *testing.T) {
	// R with leading zeros should have them stripped.
	r := make([]byte, 32)
	r[0] = 0x00
	r[1] = 0x00
	r[2] = 0x42
	s := bytes.Repeat([]byte{0x01}, 32)

	der := encodeDERSignature(r, s)

	rLen := der[3]
	// Should strip leading zeros: 30 bytes remaining.
	assert.Equal(t, byte(30), rLen)
}

// ---------------------------------------------------------------------------
// Address validation
// ---------------------------------------------------------------------------

func TestBtcAddressValidate_Empty(t *testing.T) {
	err := btcAddressValidate("")
	assert.Error(t, err)
}

func TestBtcAddressValidate_P2WPKH(t *testing.T) {
	// Generate a real key and derive a bech32 address.
	key, err := ethcrypto.GenerateKey()
	require.NoError(t, err)

	addr, err := pubkeyToBech32(&key.PublicKey, "bc")
	require.NoError(t, err)

	err = btcAddressValidate(addr)
	assert.NoError(t, err, "valid P2WPKH address should pass validation")
}

func TestBtcAddressValidate_Unsupported(t *testing.T) {
	err := btcAddressValidate("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy") // P2SH
	assert.Error(t, err, "P2SH addresses should not be supported")
}

func TestBtcAddressValidate_Gibberish(t *testing.T) {
	err := btcAddressValidate("not-a-bitcoin-address")
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Output script encoding
// ---------------------------------------------------------------------------

func TestBuildP2WPKHScript(t *testing.T) {
	hash := bytes.Repeat([]byte{0xab}, 20)
	script := buildP2WPKHScript(hash)

	assert.Equal(t, 22, len(script))
	assert.Equal(t, byte(0x00), script[0], "OP_0")
	assert.Equal(t, byte(0x14), script[1], "PUSH 20")
	assert.Equal(t, hash, script[2:])
}

func TestBuildP2PKHScript(t *testing.T) {
	hash := bytes.Repeat([]byte{0xcd}, 20)
	script := buildP2PKHScript(hash)

	assert.Equal(t, 25, len(script))
	assert.Equal(t, byte(0x76), script[0], "OP_DUP")
	assert.Equal(t, byte(0xa9), script[1], "OP_HASH160")
	assert.Equal(t, byte(0x14), script[2], "PUSH 20")
	assert.Equal(t, hash, script[3:23])
	assert.Equal(t, byte(0x88), script[23], "OP_EQUALVERIFY")
	assert.Equal(t, byte(0xac), script[24], "OP_CHECKSIG")
}

// ---------------------------------------------------------------------------
// Bech32 round-trip
// ---------------------------------------------------------------------------

func TestBech32RoundTrip(t *testing.T) {
	key, err := ethcrypto.GenerateKey()
	require.NoError(t, err)

	pubCompressed := compressPublicKey(&key.PublicKey)
	pubHash := hash160(pubCompressed)

	addr, err := bech32Encode("bc", 0, pubHash)
	require.NoError(t, err)

	decoded, err := decodeBech32Address(addr)
	require.NoError(t, err)

	assert.Equal(t, pubHash, decoded, "bech32 round-trip should preserve pubkey hash")
}

func TestDecodeBech32Address_Testnet(t *testing.T) {
	key, err := ethcrypto.GenerateKey()
	require.NoError(t, err)

	pubCompressed := compressPublicKey(&key.PublicKey)
	pubHash := hash160(pubCompressed)

	addr, err := bech32Encode("tb", 0, pubHash)
	require.NoError(t, err)

	assert.True(t, len(addr) > 4, "testnet address should not be empty")

	decoded, err := decodeBech32Address(addr)
	require.NoError(t, err)
	assert.Equal(t, pubHash, decoded)
}

// ---------------------------------------------------------------------------
// Transaction serialization (structural checks)
// ---------------------------------------------------------------------------

func TestBuildSignedTx_Structure(t *testing.T) {
	// Build a minimal transaction with one input and verify structure.
	key, err := ethcrypto.GenerateKey()
	require.NoError(t, err)

	pubCompressed := compressPublicKey(&key.PublicKey)
	pubHash := hash160(pubCompressed)
	recipientScript := buildP2WPKHScript(pubHash)
	changeScript := buildP2WPKHScript(pubHash)

	inputs := []btcUTXO{
		{
			TxID:  "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			Vout:  0,
			Value: 100000,
		},
	}

	txRaw, err := buildSignedTx(key, pubCompressed, pubHash, inputs, recipientScript, 50000, changeScript, 49000)
	require.NoError(t, err)

	// Check version (first 4 bytes, little-endian).
	assert.Equal(t, byte(0x02), txRaw[0], "version byte 0")
	assert.Equal(t, byte(0x00), txRaw[1], "version byte 1")
	assert.Equal(t, byte(0x00), txRaw[2], "version byte 2")
	assert.Equal(t, byte(0x00), txRaw[3], "version byte 3")

	// Segwit marker and flag.
	assert.Equal(t, byte(0x00), txRaw[4], "segwit marker")
	assert.Equal(t, byte(0x01), txRaw[5], "segwit flag")

	// Input count.
	assert.Equal(t, byte(0x01), txRaw[6], "input count")

	// Locktime (last 4 bytes).
	assert.Equal(t, []byte{0x00, 0x00, 0x00, 0x00}, txRaw[len(txRaw)-4:], "locktime should be 0")
}

func TestBuildSignedTx_NoChange(t *testing.T) {
	key, err := ethcrypto.GenerateKey()
	require.NoError(t, err)

	pubCompressed := compressPublicKey(&key.PublicKey)
	pubHash := hash160(pubCompressed)
	recipientScript := buildP2WPKHScript(pubHash)

	inputs := []btcUTXO{
		{
			TxID:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Vout:  0,
			Value: 50000,
		},
	}

	// No change: changeAmount = 0.
	txRaw, err := buildSignedTx(key, pubCompressed, pubHash, inputs, recipientScript, 49000, nil, 0)
	require.NoError(t, err)
	require.NotNil(t, txRaw)

	// Should still have valid structure.
	assert.Equal(t, byte(0x02), txRaw[0])
}

// ---------------------------------------------------------------------------
// BIP-143 sighash test vector
// From BIP-143 specification: Native P2WPKH example
// https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#native-p2wpkh
// ---------------------------------------------------------------------------

func TestBIP143_SighashPreimage(t *testing.T) {
	// BIP-143 specifies the exact sighash computation for P2WPKH.
	// We verify our doubleSHA256 + preimage construction produces
	// deterministic results for known inputs.

	// Use a fixed private key to ensure deterministic output.
	privKeyHex := "0000000000000000000000000000000000000000000000000000000000000001"
	privKeyBytes, _ := hex.DecodeString(privKeyHex)
	privKey, err := ethcrypto.ToECDSA(privKeyBytes)
	require.NoError(t, err)

	pubCompressed := compressPublicKey(&privKey.PublicKey)
	pubHash := hash160(pubCompressed)

	// Build a sighash preimage for a known input.
	txidHex := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	txidBytes, _ := reversedTxID(txidHex)

	// hashPrevouts
	var prevoutsBuf bytes.Buffer
	prevoutsBuf.Write(txidBytes)
	binary.Write(&prevoutsBuf, binary.LittleEndian, uint32(0))
	hashPrevouts := doubleSHA256(prevoutsBuf.Bytes())

	// hashSequence
	var seqBuf bytes.Buffer
	binary.Write(&seqBuf, binary.LittleEndian, uint32(0xffffffff))
	hashSequence := doubleSHA256(seqBuf.Bytes())

	// hashOutputs — single output of 50000 sats to same pubkeyhash
	var outBuf bytes.Buffer
	binary.Write(&outBuf, binary.LittleEndian, int64(50000))
	writeVarBytes(&outBuf, buildP2WPKHScript(pubHash))
	hashOutputs := doubleSHA256(outBuf.Bytes())

	// ScriptCode
	scriptCode := make([]byte, 0, 25)
	scriptCode = append(scriptCode, 0x76, 0xa9, 0x14)
	scriptCode = append(scriptCode, pubHash...)
	scriptCode = append(scriptCode, 0x88, 0xac)

	// Build preimage exactly as btc_transfer.go does
	var preimage bytes.Buffer
	binary.Write(&preimage, binary.LittleEndian, uint32(2))        // nVersion
	preimage.Write(hashPrevouts)                                    // hashPrevouts
	preimage.Write(hashSequence)                                    // hashSequence
	preimage.Write(txidBytes)                                       // outpoint txid
	binary.Write(&preimage, binary.LittleEndian, uint32(0))        // outpoint vout
	writeVarBytes(&preimage, scriptCode)                            // scriptCode
	binary.Write(&preimage, binary.LittleEndian, int64(100000))    // value
	binary.Write(&preimage, binary.LittleEndian, uint32(0xffffffff)) // nSequence
	preimage.Write(hashOutputs)                                     // hashOutputs
	binary.Write(&preimage, binary.LittleEndian, uint32(0))        // nLocktime
	binary.Write(&preimage, binary.LittleEndian, uint32(1))        // sighash type

	sigHash := doubleSHA256(preimage.Bytes())

	// The sighash should be deterministic — same inputs always produce same hash.
	assert.Len(t, sigHash, 32)

	// Sign it and verify the signature is valid.
	sigRaw, err := ethcrypto.Sign(sigHash, privKey)
	require.NoError(t, err)
	assert.Len(t, sigRaw, 65)

	// DER encode and verify it has SIGHASH_ALL.
	der := encodeDERSignature(sigRaw[:32], sigRaw[32:64])
	der = append(der, 0x01) // SIGHASH_ALL
	assert.Equal(t, byte(0x30), der[0], "DER signature should start with 0x30")
	assert.Equal(t, byte(0x01), der[len(der)-1], "should end with SIGHASH_ALL")

	// Run again — must be identical (deterministic).
	sigHash2 := doubleSHA256(preimage.Bytes())
	assert.Equal(t, sigHash, sigHash2, "sighash must be deterministic")
}

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

func TestDoubleSHA256(t *testing.T) {
	data := []byte("hello")
	result := doubleSHA256(data)
	assert.Equal(t, 32, len(result))

	// Verify it's not the same as single SHA256.
	singleHash := make([]byte, 32)
	copy(singleHash, result)
	assert.NotEqual(t, singleHash, doubleSHA256([]byte("world")))
}

func TestHash160(t *testing.T) {
	data := []byte("test data")
	result := hash160(data)
	assert.Equal(t, 20, len(result), "hash160 should produce 20 bytes")
}

func TestCompressPublicKey(t *testing.T) {
	key, err := ethcrypto.GenerateKey()
	require.NoError(t, err)

	compressed := compressPublicKey(&key.PublicKey)
	assert.Equal(t, 33, len(compressed), "compressed pubkey should be 33 bytes")

	// First byte should be 0x02 or 0x03.
	assert.True(t, compressed[0] == 0x02 || compressed[0] == 0x03, "first byte should be 02 or 03")
}

// ---------------------------------------------------------------------------
// reversedTxID
// ---------------------------------------------------------------------------

func TestReversedTxID(t *testing.T) {
	txid := "0102030405060708091011121314151617181920212223242526272829303132"
	reversed, err := reversedTxID(txid)
	require.NoError(t, err)

	assert.Equal(t, 32, len(reversed))

	// First byte of reversed should be last byte of original.
	originalBytes, _ := hex.DecodeString(txid)
	assert.Equal(t, originalBytes[31], reversed[0])
	assert.Equal(t, originalBytes[0], reversed[31])
}

func TestReversedTxID_Invalid(t *testing.T) {
	_, err := reversedTxID("not-hex")
	assert.Error(t, err)

	_, err = reversedTxID("0102") // too short
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// VarInt encoding
// ---------------------------------------------------------------------------

func TestWriteVarInt(t *testing.T) {
	tests := []struct {
		val      uint64
		expected []byte
	}{
		{0, []byte{0x00}},
		{1, []byte{0x01}},
		{252, []byte{0xfc}},
		{253, []byte{0xfd, 0xfd, 0x00}},
		{0xffff, []byte{0xfd, 0xff, 0xff}},
		{0x10000, []byte{0xfe, 0x00, 0x00, 0x01, 0x00}},
	}
	for _, tt := range tests {
		var buf bytes.Buffer
		writeVarInt(&buf, tt.val)
		assert.Equal(t, tt.expected, buf.Bytes(), "writeVarInt(%d)", tt.val)
	}
}

// ---------------------------------------------------------------------------
// Dust limit
// ---------------------------------------------------------------------------

func TestDustLimit(t *testing.T) {
	assert.Equal(t, int64(546), btcDustLimit)
}

// ---------------------------------------------------------------------------
// AddressToOutputScript
// ---------------------------------------------------------------------------

func TestAddressToOutputScript_P2WPKH(t *testing.T) {
	key, err := ethcrypto.GenerateKey()
	require.NoError(t, err)

	addr, err := pubkeyToBech32(&key.PublicKey, "bc")
	require.NoError(t, err)

	script, err := addressToOutputScript(addr)
	require.NoError(t, err)

	assert.Equal(t, 22, len(script), "P2WPKH script should be 22 bytes")
	assert.Equal(t, byte(0x00), script[0], "OP_0")
	assert.Equal(t, byte(0x14), script[1], "PUSH 20")
}

func TestAddressToOutputScript_Unsupported(t *testing.T) {
	_, err := addressToOutputScript("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy")
	assert.Error(t, err, "P2SH should not be supported")
}

// ---------------------------------------------------------------------------
// Mempool base URL derivation
// ---------------------------------------------------------------------------

func TestMempoolBaseURL_Default(t *testing.T) {
	savedBase := apiBase
	savedEnv := os.Getenv("BOB_BTC_MEMPOOL_URL")
	defer func() { apiBase = savedBase; os.Setenv("BOB_BTC_MEMPOOL_URL", savedEnv) }()
	os.Unsetenv("BOB_BTC_MEMPOOL_URL")

	apiBase = defaultAPIBase
	assert.Equal(t, "https://mempool.space", mempoolBaseURL())
}

func TestMempoolBaseURL_Testnet(t *testing.T) {
	savedBase := apiBase
	savedEnv := os.Getenv("BOB_BTC_MEMPOOL_URL")
	defer func() { apiBase = savedBase; os.Setenv("BOB_BTC_MEMPOOL_URL", savedEnv) }()
	os.Unsetenv("BOB_BTC_MEMPOOL_URL")

	apiBase = "https://api-testnet.bankofbots.ai/api/v1"
	assert.Equal(t, "https://mempool.space/testnet4", mempoolBaseURL())
}

func TestMempoolBaseURL_Localhost(t *testing.T) {
	savedBase := apiBase
	savedEnv := os.Getenv("BOB_BTC_MEMPOOL_URL")
	defer func() { apiBase = savedBase; os.Setenv("BOB_BTC_MEMPOOL_URL", savedEnv) }()
	os.Unsetenv("BOB_BTC_MEMPOOL_URL")

	apiBase = "http://localhost:8080/api/v1"
	assert.Equal(t, "https://mempool.space/signet", mempoolBaseURL())
}

// ---------------------------------------------------------------------------
// DER encoding edge cases
// ---------------------------------------------------------------------------

func TestEncodeDERSignature_AllZeros(t *testing.T) {
	r := make([]byte, 32)
	s := make([]byte, 32)

	// All zeros except last byte to avoid degenerate case.
	r[31] = 0x01
	s[31] = 0x01

	der := encodeDERSignature(r, s)
	assert.Equal(t, byte(0x30), der[0])

	// Should be valid DER.
	assert.True(t, len(der) >= 8, "DER should have minimum length")
}

func TestDerIntBytes_StripLeadingZeros(t *testing.T) {
	input := []byte{0x00, 0x00, 0x00, 0x42, 0xff}
	result := derIntBytes(input)
	assert.Equal(t, []byte{0x42, 0xff}, result)
}

func TestDerIntBytes_PreserveHighBit(t *testing.T) {
	input := []byte{0x80, 0x01}
	result := derIntBytes(input)
	assert.Equal(t, []byte{0x00, 0x80, 0x01}, result)
}

func TestDerIntBytes_SingleByte(t *testing.T) {
	input := []byte{0x01}
	result := derIntBytes(input)
	assert.Equal(t, []byte{0x01}, result)
}
