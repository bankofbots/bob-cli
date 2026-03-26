package main

import (
	"testing"
)

func TestMigrateWalletKeys_SingleOldAgent(t *testing.T) {
	cfg := &cliConfig{
		AgentID: "new-agent",
		WalletKeyring: map[string]agentWalletKeys{
			"old-agent": {
				EVMPrivateKey: "aabbccdd",
				EVMAddress:    "0xOldEVM",
				BTCPrivateKey: "eeff0011",
				BTCAddress:    "bc1qold",
				SOLPrivateKey: "22334455",
				SOLAddress:    "OldSOL",
			},
		},
	}

	result := migrateWalletKeys(cfg, "new-agent")
	if result == nil {
		t.Fatal("expected migration to find old agent keys")
	}
	if result.EVMAddress != "0xOldEVM" {
		t.Fatalf("expected EVM '0xOldEVM', got '%s'", result.EVMAddress)
	}

	// Old entry should be cleaned up
	if _, exists := cfg.WalletKeyring["old-agent"]; exists {
		t.Fatal("old agent entry should be deleted after migration")
	}

	// New entry should exist
	if _, exists := cfg.WalletKeyring["new-agent"]; !exists {
		t.Fatal("new agent entry should exist after migration")
	}

	// Legacy flat fields updated
	if cfg.EVMAddress != "0xOldEVM" {
		t.Fatalf("legacy EVMAddress not updated: '%s'", cfg.EVMAddress)
	}
}

func TestMigrateWalletKeys_MultipleOldAgents_Deterministic(t *testing.T) {
	cfg := &cliConfig{
		AgentID: "new-agent",
		WalletKeyring: map[string]agentWalletKeys{
			"aaa-first": {
				EVMPrivateKey: "11",
				EVMAddress:    "0xFirst",
			},
			"zzz-last": {
				EVMPrivateKey: "22",
				EVMAddress:    "0xLast",
			},
		},
	}

	result := migrateWalletKeys(cfg, "new-agent")
	if result == nil {
		t.Fatal("expected migration")
	}
	// Should pick "zzz-last" (highest lexically)
	if result.EVMAddress != "0xLast" {
		t.Fatalf("expected deterministic pick of 'zzz-last', got '%s'", result.EVMAddress)
	}

	// zzz-last cleaned up, aaa-first remains
	if _, exists := cfg.WalletKeyring["zzz-last"]; exists {
		t.Fatal("migrated entry should be deleted")
	}
	if _, exists := cfg.WalletKeyring["aaa-first"]; !exists {
		t.Fatal("non-migrated entry should remain")
	}
}

func TestMigrateWalletKeys_NoOldKeys(t *testing.T) {
	cfg := &cliConfig{
		AgentID:       "new-agent",
		WalletKeyring: map[string]agentWalletKeys{},
	}

	result := migrateWalletKeys(cfg, "new-agent")
	if result != nil {
		t.Fatal("should return nil with empty keyring")
	}
}

func TestMigrateWalletKeys_SameAgent(t *testing.T) {
	cfg := &cliConfig{
		AgentID: "same-agent",
		WalletKeyring: map[string]agentWalletKeys{
			"same-agent": {
				EVMPrivateKey: "aa",
				EVMAddress:    "0xSame",
			},
		},
	}

	result := migrateWalletKeys(cfg, "same-agent")
	if result != nil {
		t.Fatal("should not migrate from self")
	}
}

func TestMigrateWalletKeys_NilKeyring(t *testing.T) {
	cfg := &cliConfig{
		AgentID:       "new-agent",
		WalletKeyring: nil,
	}

	result := migrateWalletKeys(cfg, "new-agent")
	if result != nil {
		t.Fatal("should return nil with nil keyring")
	}
}
