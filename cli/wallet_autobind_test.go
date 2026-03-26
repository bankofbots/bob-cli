package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

func TestSignEVMChallenge(t *testing.T) {
	key, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	privHex := hex.EncodeToString(ethcrypto.FromECDSA(key))
	msg := "BOB Score Wallet Verification\nRail: evm\nAddress: 0xabc\nOperator: op1\nNonce: abc123\nExpires: 2099-01-01T00:00:00Z"

	sig, err := signEVMChallenge(msg, privHex)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sig, "0x") {
		t.Fatal("EVM signature should have 0x prefix")
	}
	sigBytes, _ := hex.DecodeString(sig[2:])
	if len(sigBytes) != 65 {
		t.Fatalf("expected 65 byte sig, got %d", len(sigBytes))
	}
	// V should be 27 or 28
	if sigBytes[64] != 27 && sigBytes[64] != 28 {
		t.Fatalf("unexpected V value: %d", sigBytes[64])
	}
}

func TestSignBTCChallenge(t *testing.T) {
	key, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	privHex := hex.EncodeToString(ethcrypto.FromECDSA(key))
	msg := "BOB Score Wallet Verification\nRail: btc\nAddress: bc1qtest\nOperator: op1\nNonce: abc123\nExpires: 2099-01-01T00:00:00Z"

	sig, err := signBTCChallenge(msg, privHex)
	if err != nil {
		t.Fatal(err)
	}
	// BIP-137 is base64-encoded, not hex
	if strings.HasPrefix(sig, "0x") {
		t.Fatal("BTC signature should be base64, not hex")
	}
	// Base64 of 65 bytes = 88 chars
	if len(sig) != 88 {
		t.Fatalf("expected 88 char base64 sig, got %d", len(sig))
	}
}

func TestSignSolanaChallenge(t *testing.T) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privHex := hex.EncodeToString(privKey)
	msg := "BOB Score Wallet Verification\nRail: solana\nAddress: SoLtest\nOperator: op1\nNonce: abc123\nExpires: 2099-01-01T00:00:00Z"

	sig, err := signSolanaChallenge(msg, privHex)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sig, "0x") {
		t.Fatal("Solana signature should have 0x prefix")
	}
	sigBytes, _ := hex.DecodeString(sig[2:])
	if len(sigBytes) != 64 {
		t.Fatalf("expected 64 byte Ed25519 sig, got %d", len(sigBytes))
	}
}

func TestBitcoinVarint(t *testing.T) {
	tests := []struct {
		n    int
		want []byte
	}{
		{0, []byte{0}},
		{252, []byte{252}},
		{253, []byte{0xfd, 253, 0}},
		{256, []byte{0xfd, 0, 1}},
		{65535, []byte{0xfd, 255, 255}},
	}
	for _, tt := range tests {
		got := bitcoinVarint(tt.n)
		if len(got) != len(tt.want) {
			t.Errorf("bitcoinVarint(%d) = %v, want %v", tt.n, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("bitcoinVarint(%d)[%d] = %d, want %d", tt.n, i, got[i], tt.want[i])
			}
		}
	}
}
