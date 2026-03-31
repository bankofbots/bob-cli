package main

import (
	"crypto/ecdsa"
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

	sig, err := signEVMChallenge("BOB Score Wallet Verification\nNonce: abc123", privHex)
	if err != nil {
		t.Fatalf("signEVMChallenge: %v", err)
	}
	if !strings.HasPrefix(sig, "0x") {
		t.Fatalf("expected 0x prefix, got %q", sig)
	}
	// EIP-191 sig = 65 bytes = 130 hex chars + "0x"
	if len(sig) != 132 {
		t.Fatalf("expected 132 chars, got %d", len(sig))
	}
	// Decode and verify 65-byte payload with V normalization (27 or 28).
	sigBytes, decErr := hex.DecodeString(sig[2:])
	if decErr != nil {
		t.Fatalf("hex decode: %v", decErr)
	}
	if len(sigBytes) != 65 {
		t.Fatalf("expected 65 bytes, got %d", len(sigBytes))
	}
	v := sigBytes[64]
	if v != 27 && v != 28 {
		t.Fatalf("V byte should be 27 or 28, got %d", v)
	}
}

func TestSignBTCChallenge(t *testing.T) {
	key, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	privHex := hex.EncodeToString(ethcrypto.FromECDSA(key))

	sig, err := signBTCChallenge("BOB Score Wallet Verification\nNonce: abc123", privHex)
	if err != nil {
		t.Fatalf("signBTCChallenge: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("empty signature")
	}
	if strings.HasPrefix(sig, "0x") {
		t.Fatalf("BTC sig should be base64, not hex: %q", sig)
	}
}

func TestSignSolanaChallenge(t *testing.T) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privHex := hex.EncodeToString(privKey)

	sig, err := signSolanaChallenge("BOB Score Wallet Verification\nNonce: abc123", privHex)
	if err != nil {
		t.Fatalf("signSolanaChallenge: %v", err)
	}
	if !strings.HasPrefix(sig, "0x") {
		t.Fatalf("expected 0x prefix, got %q", sig)
	}
	// Ed25519 sig = 64 bytes = 128 hex chars + "0x"
	if len(sig) != 130 {
		t.Fatalf("expected 130 chars, got %d", len(sig))
	}
}

func TestSignChallengeMessage_UnsupportedRail(t *testing.T) {
	_, err := signChallengeMessage("lightning", "test", "deadbeef")
	if err == nil {
		t.Fatal("expected error for unsupported rail")
	}
	if !strings.Contains(err.Error(), "unsupported rail") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSignEVMChallenge_BadKey(t *testing.T) {
	_, err := signEVMChallenge("test message", "not-hex")
	if err == nil {
		t.Fatal("expected error for bad key")
	}
}

func TestSignSolanaChallenge_WrongKeyLength(t *testing.T) {
	_, err := signSolanaChallenge("test message", hex.EncodeToString([]byte("too-short")))
	if err == nil {
		t.Fatal("expected error for wrong key length")
	}
}

func TestWalletKeysForAgent_Lookup(t *testing.T) {
	cfg := &cliConfig{
		AgentID: "agent-a",
		WalletKeyring: map[string]agentWalletKeys{
			"agent-a": {EVMAddress: "0xAAA"},
			"agent-b": {EVMAddress: "0xBBB"},
		},
	}

	keys := cfg.activeWalletKeys()
	if keys == nil || keys.EVMAddress != "0xAAA" {
		t.Fatalf("activeWalletKeys: expected agent-a, got %+v", keys)
	}

	keys = cfg.walletKeysForAgent("agent-b")
	if keys == nil || keys.EVMAddress != "0xBBB" {
		t.Fatalf("walletKeysForAgent(agent-b): expected agent-b, got %+v", keys)
	}

	keys = cfg.walletKeysForAgent("agent-c")
	if keys != nil {
		t.Fatalf("walletKeysForAgent(agent-c): expected nil, got %+v", keys)
	}
}

func TestBitcoinVarint(t *testing.T) {
	// Check length AND byte content.
	cases := []struct {
		n    int
		want []byte
	}{
		{0, []byte{0}},
		{252, []byte{252}},
		{253, []byte{0xfd, 253, 0}},
		{65535, []byte{0xfd, 0xff, 0xff}},
		{65536, []byte{0xfe, 0x00, 0x00, 0x01, 0x00}},
	}
	for _, tc := range cases {
		got := bitcoinVarint(tc.n)
		if len(got) != len(tc.want) {
			t.Errorf("bitcoinVarint(%d): got %d bytes, want %d", tc.n, len(got), len(tc.want))
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("bitcoinVarint(%d): byte %d = %02x, want %02x", tc.n, i, got[i], tc.want[i])
			}
		}
	}
}

func TestEVMAndBTCShareKey_DifferentSignatures(t *testing.T) {
	key, _ := ethcrypto.GenerateKey()
	privHex := hex.EncodeToString(ethcrypto.FromECDSA(key))

	evmSig, err := signEVMChallenge("test", privHex)
	if err != nil {
		t.Fatal(err)
	}
	btcSig, err := signBTCChallenge("test", privHex)
	if err != nil {
		t.Fatal(err)
	}
	if evmSig == "" || btcSig == "" {
		t.Fatal("both should be non-empty")
	}
	if evmSig == btcSig {
		t.Fatal("EVM and BTC sigs should differ (different hash schemes)")
	}
}

// Compile-time check.
var _ = func() {
	key, _ := ecdsa.GenerateKey(ethcrypto.S256(), rand.Reader)
	_ = key
}

// Regression: each call to generateWalletKeys must produce unique addresses.
// This prevents reintroduction of cross-agent key reuse.
func TestGenerateWalletKeys_UniquePerCall(t *testing.T) {
	keys1, err := generateWalletKeys("bc")
	if err != nil {
		t.Fatal(err)
	}
	keys2, err := generateWalletKeys("bc")
	if err != nil {
		t.Fatal(err)
	}

	if keys1.EVMAddress == keys2.EVMAddress {
		t.Fatalf("two calls produced same EVM address: %s", keys1.EVMAddress)
	}
	if keys1.BTCAddress == keys2.BTCAddress {
		t.Fatalf("two calls produced same BTC address: %s", keys1.BTCAddress)
	}
	if keys1.SOLAddress == keys2.SOLAddress {
		t.Fatalf("two calls produced same SOL address: %s", keys1.SOLAddress)
	}
	if keys1.EVMPrivateKey == keys2.EVMPrivateKey {
		t.Fatal("two calls produced same EVM private key")
	}
	if keys1.SOLPrivateKey == keys2.SOLPrivateKey {
		t.Fatal("two calls produced same SOL private key")
	}
}

// Test that migrateWalletKeyring only runs once (when keyring is nil),
// and does NOT copy flat fields into new agent entries.
func TestMigrateWalletKeyring_OnlyRunsOnce(t *testing.T) {
	// Simulate legacy config: flat fields set, no keyring.
	cfg := &cliConfig{
		AgentID:       "agent-old",
		EVMAddress:    "0xOLD",
		EVMPrivateKey: "oldkey",
		BTCAddress:    "bc1old",
		BTCPrivateKey: "oldkey",
		SOLAddress:    "SOLold",
		SOLPrivateKey: "oldsolkey",
	}

	// First migration: should create keyring with old agent's keys.
	cfg.migrateWalletKeyring()
	if cfg.WalletKeyring == nil {
		t.Fatal("expected keyring to be created")
	}
	keys := cfg.WalletKeyring["agent-old"]
	if keys.EVMAddress != "0xOLD" {
		t.Fatalf("expected 0xOLD, got %s", keys.EVMAddress)
	}

	// Now simulate a new agent being created (agent_id changes).
	cfg.AgentID = "agent-new"

	// Second migration: keyring already exists, should NOT create entry for new agent.
	cfg.migrateWalletKeyring()

	if _, exists := cfg.WalletKeyring["agent-new"]; exists {
		t.Fatal("migrateWalletKeyring should NOT auto-populate new agent entries from flat fields")
	}

	// Old agent's keys should still be there.
	if cfg.WalletKeyring["agent-old"].EVMAddress != "0xOLD" {
		t.Fatal("old agent keys should be preserved")
	}
}

// Test that legacy config without keyring gets properly migrated.
func TestMigrateWalletKeyring_LegacyConfig(t *testing.T) {
	cfg := &cliConfig{
		AgentID:       "legacy-agent",
		EVMAddress:    "0xLEGACY",
		EVMPrivateKey: "legacykey",
	}

	cfg.migrateWalletKeyring()

	if cfg.WalletKeyring == nil {
		t.Fatal("expected keyring to be created for legacy config")
	}
	keys := cfg.WalletKeyring["legacy-agent"]
	if keys.EVMAddress != "0xLEGACY" {
		t.Fatalf("expected 0xLEGACY, got %s", keys.EVMAddress)
	}
}

// Test that migration is skipped when flat fields are empty.
func TestMigrateWalletKeyring_NoFlatFields(t *testing.T) {
	cfg := &cliConfig{AgentID: "agent-1"}

	cfg.migrateWalletKeyring()

	if cfg.WalletKeyring != nil {
		t.Fatal("should not create keyring when no flat fields exist")
	}
}
