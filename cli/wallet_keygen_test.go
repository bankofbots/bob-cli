package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateWalletKeys(t *testing.T) {
	keys, err := generateWalletKeys("bc")
	if err != nil {
		t.Fatalf("generateWalletKeys() error: %v", err)
	}

	// EVM: 0x-prefixed, 42 chars
	if !strings.HasPrefix(keys.EVMAddress, "0x") || len(keys.EVMAddress) != 42 {
		t.Errorf("EVM address invalid: %s", keys.EVMAddress)
	}
	if len(keys.EVMPrivateKey) != 64 {
		t.Errorf("EVM private key wrong length: %d", len(keys.EVMPrivateKey))
	}

	// BTC: bc1q prefix (bech32 mainnet)
	if !strings.HasPrefix(keys.BTCAddress, "bc1q") {
		t.Errorf("BTC address should start with bc1q, got: %s", keys.BTCAddress)
	}

	// Solana: base58, typically 32-44 chars
	if len(keys.SOLAddress) < 30 || len(keys.SOLAddress) > 50 {
		t.Errorf("SOL address unexpected length %d: %s", len(keys.SOLAddress), keys.SOLAddress)
	}
	if len(keys.SOLPrivateKey) != 128 { // 64 bytes hex = 128 chars
		t.Errorf("SOL private key wrong length: %d", len(keys.SOLPrivateKey))
	}

	t.Logf("EVM:  %s", keys.EVMAddress)
	t.Logf("BTC:  %s", keys.BTCAddress)
	t.Logf("SOL:  %s", keys.SOLAddress)

	// Regtest HRP
	regtestKeys, err := generateWalletKeys("bcrt")
	if err != nil {
		t.Fatalf("generateWalletKeys(bcrt) error: %v", err)
	}
	if !strings.HasPrefix(regtestKeys.BTCAddress, "bcrt1q") {
		t.Errorf("BTC regtest address should start with bcrt1q, got: %s", regtestKeys.BTCAddress)
	}
	t.Logf("BTC regtest: %s", regtestKeys.BTCAddress)

	// Testnet HRP
	testnetKeys, err := generateWalletKeys("tb")
	if err != nil {
		t.Fatalf("generateWalletKeys(tb) error: %v", err)
	}
	if !strings.HasPrefix(testnetKeys.BTCAddress, "tb1q") {
		t.Errorf("BTC testnet address should start with tb1q, got: %s", testnetKeys.BTCAddress)
	}
	t.Logf("BTC testnet: %s", testnetKeys.BTCAddress)
}

// ---------------------------------------------------------------------------
// Wallet keyring migration tests
// ---------------------------------------------------------------------------

func TestMigrateWalletKeyring_NoAgentID(t *testing.T) {
	cfg := cliConfig{
		AgentID:       "",
		EVMPrivateKey: "aaa",
		EVMAddress:    "0xAAA",
		BTCPrivateKey: "aaa",
		BTCAddress:    "bc1qAAA",
		SOLPrivateKey: "bbb",
		SOLAddress:    "SOL_AAA",
	}
	cfg.migrateWalletKeyring()

	if cfg.WalletKeyring == nil {
		t.Fatal("WalletKeyring should be initialized")
	}
	keys, ok := cfg.WalletKeyring["_unknown"]
	if !ok {
		t.Fatal("missing _unknown bucket")
	}
	if keys.EVMAddress != "0xAAA" {
		t.Errorf("expected 0xAAA, got %s", keys.EVMAddress)
	}
}

func TestMigrateWalletKeyring_WithAgentID(t *testing.T) {
	cfg := cliConfig{
		AgentID:       "agent-1",
		EVMPrivateKey: "aaa",
		EVMAddress:    "0xAAA",
		BTCPrivateKey: "aaa",
		BTCAddress:    "bc1qAAA",
		SOLPrivateKey: "bbb",
		SOLAddress:    "SOL_AAA",
	}
	cfg.migrateWalletKeyring()

	if _, ok := cfg.WalletKeyring["agent-1"]; !ok {
		t.Fatal("keys should be under agent-1")
	}
	if _, ok := cfg.WalletKeyring["_unknown"]; ok {
		t.Fatal("should NOT have _unknown bucket when agent_id is set")
	}
}

func TestMigrateWalletKeyring_DoesNotOverwrite(t *testing.T) {
	cfg := cliConfig{
		AgentID:    "agent-1",
		EVMAddress: "0xNEW",
		WalletKeyring: map[string]agentWalletKeys{
			"agent-1": {EVMAddress: "0xORIGINAL"},
		},
	}
	cfg.migrateWalletKeyring()

	if cfg.WalletKeyring["agent-1"].EVMAddress != "0xORIGINAL" {
		t.Errorf("existing keyring entry was overwritten: got %s", cfg.WalletKeyring["agent-1"].EVMAddress)
	}
}

func TestMigrateWalletKeyring_NoKeysNoOp(t *testing.T) {
	cfg := cliConfig{AgentID: "agent-1"}
	cfg.migrateWalletKeyring()

	if cfg.WalletKeyring != nil {
		t.Error("WalletKeyring should remain nil when no legacy keys exist")
	}
}

func TestActiveWalletKeys_ReturnsNilForDifferentAgent(t *testing.T) {
	cfg := cliConfig{
		AgentID: "agent-2",
		WalletKeyring: map[string]agentWalletKeys{
			"agent-1": {EVMAddress: "0xAAA"},
		},
	}
	if cfg.activeWalletKeys() != nil {
		t.Error("should return nil for agent-2 (only agent-1 in keyring)")
	}
}

func TestActiveWalletKeys_ReturnsCorrectAgent(t *testing.T) {
	cfg := cliConfig{
		AgentID: "agent-1",
		WalletKeyring: map[string]agentWalletKeys{
			"agent-1": {EVMAddress: "0xAAA"},
			"agent-2": {EVMAddress: "0xBBB"},
		},
	}
	keys := cfg.activeWalletKeys()
	if keys == nil || keys.EVMAddress != "0xAAA" {
		t.Errorf("expected 0xAAA for agent-1, got %v", keys)
	}
}

// ---------------------------------------------------------------------------
// Integration: init agent A, init agent B — addresses differ, both persist
// ---------------------------------------------------------------------------

func TestKeyringIntegration_TwoAgents(t *testing.T) {
	// Use a temp dir for config
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.json")
	t.Setenv("BOB_CONFIG_FILE", configPath)

	// Simulate agent A init: generate keys, save to keyring
	keysA, err := generateWalletKeys("bc")
	if err != nil {
		t.Fatal(err)
	}
	cfgA := cliConfig{
		AgentID:       "agent-a",
		WalletKeyring: map[string]agentWalletKeys{},
	}
	cfgA.WalletKeyring["agent-a"] = agentWalletKeys{
		EVMPrivateKey: keysA.EVMPrivateKey, EVMAddress: keysA.EVMAddress,
		BTCPrivateKey: keysA.BTCPrivateKey, BTCAddress: keysA.BTCAddress,
		SOLPrivateKey: keysA.SOLPrivateKey, SOLAddress: keysA.SOLAddress,
	}
	cfgA.EVMAddress = keysA.EVMAddress
	cfgA.EVMPrivateKey = keysA.EVMPrivateKey
	if err := writeCLIConfig(configPath, cfgA); err != nil {
		t.Fatal(err)
	}

	// Simulate agent B init: generate keys, save to keyring
	keysB, err := generateWalletKeys("bc")
	if err != nil {
		t.Fatal(err)
	}

	// Load config (should see agent-a keys)
	cfgB, err := loadCLIConfig()
	if err != nil {
		t.Fatal(err)
	}
	cfgB.AgentID = "agent-b"
	cfgB.APIKey = "bok_agent_b"
	if cfgB.WalletKeyring == nil {
		cfgB.WalletKeyring = make(map[string]agentWalletKeys)
	}
	cfgB.WalletKeyring["agent-b"] = agentWalletKeys{
		EVMPrivateKey: keysB.EVMPrivateKey, EVMAddress: keysB.EVMAddress,
		BTCPrivateKey: keysB.BTCPrivateKey, BTCAddress: keysB.BTCAddress,
		SOLPrivateKey: keysB.SOLPrivateKey, SOLAddress: keysB.SOLAddress,
	}
	cfgB.EVMAddress = keysB.EVMAddress
	cfgB.EVMPrivateKey = keysB.EVMPrivateKey
	if err := writeCLIConfig(configPath, cfgB); err != nil {
		t.Fatal(err)
	}

	// Verify: addresses must differ
	if keysA.EVMAddress == keysB.EVMAddress {
		t.Error("agent A and B should have different EVM addresses")
	}
	if keysA.BTCAddress == keysB.BTCAddress {
		t.Error("agent A and B should have different BTC addresses")
	}
	if keysA.SOLAddress == keysB.SOLAddress {
		t.Error("agent A and B should have different SOL addresses")
	}

	// Verify: both agents' keys persist in the config file
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var final cliConfig
	if err := json.Unmarshal(raw, &final); err != nil {
		t.Fatal(err)
	}

	aKeys, ok := final.WalletKeyring["agent-a"]
	if !ok {
		t.Fatal("agent-a keys missing from keyring")
	}
	if aKeys.EVMAddress != keysA.EVMAddress {
		t.Errorf("agent-a EVM mismatch: %s vs %s", aKeys.EVMAddress, keysA.EVMAddress)
	}

	bKeys, ok := final.WalletKeyring["agent-b"]
	if !ok {
		t.Fatal("agent-b keys missing from keyring")
	}
	if bKeys.EVMAddress != keysB.EVMAddress {
		t.Errorf("agent-b EVM mismatch: %s vs %s", bKeys.EVMAddress, keysB.EVMAddress)
	}

	t.Logf("Agent A EVM: %s", aKeys.EVMAddress)
	t.Logf("Agent B EVM: %s", bKeys.EVMAddress)
	t.Logf("Keyring has %d agents", len(final.WalletKeyring))
}
