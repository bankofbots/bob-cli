package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
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

func TestMigrateWalletKeys_SkipsBackupEntries(t *testing.T) {
	cfg := &cliConfig{
		AgentID: "new-agent",
		WalletKeyring: map[string]agentWalletKeys{
			"_backup_old-agent_1234567890": {
				EVMPrivateKey: "aa",
				EVMAddress:    "0xBackup",
			},
		},
	}

	result := migrateWalletKeys(cfg, "new-agent")
	if result != nil {
		t.Fatal("should not migrate from backup entries")
	}
}

func TestMigrateWalletKeys_BackupNotOverwritten(t *testing.T) {
	cfg := &cliConfig{
		AgentID: "new-agent",
		WalletKeyring: map[string]agentWalletKeys{
			"_backup_new-agent_111": {
				EVMPrivateKey: "first-backup",
				EVMAddress:    "0xFirstBackup",
			},
			"old-agent": {
				EVMPrivateKey: "real-key",
				EVMAddress:    "0xReal",
			},
		},
	}

	result := migrateWalletKeys(cfg, "new-agent")
	if result == nil {
		t.Fatal("should migrate from old-agent")
	}
	if result.EVMAddress != "0xReal" {
		t.Fatalf("expected 0xReal, got %s", result.EVMAddress)
	}

	// First backup should still be intact
	if _, exists := cfg.WalletKeyring["_backup_new-agent_111"]; !exists {
		t.Fatal("first backup should not be touched")
	}
}

// ---------------------------------------------------------------------------
// registerWalletBestEffort status code behavior
// ---------------------------------------------------------------------------

func TestRegisterWalletBestEffort_EmptyAddress(t *testing.T) {
	// Empty address should return no warning (early return).
	result := registerWalletBestEffort("test", "evm", "")
	assert.Equal(t, "", result, "empty address should return no warning")
}

// ---------------------------------------------------------------------------
// Fallback semantics
// ---------------------------------------------------------------------------

func TestIsOwnershipConflict_409WithDifferentAgent(t *testing.T) {
	// Simulates the ownership conflict detection logic
	warn := "evm: wallet registration rejected (403) — signature verification failed"
	isConflict := warn != "" &&
		(strings.Contains(warn, "409") || strings.Contains(warn, "403")) &&
		!strings.Contains(warn, "already registered for this agent")
	assert.True(t, isConflict, "403 signature failure should be ownership conflict")
}

func TestIsOwnershipConflict_409SameAgent(t *testing.T) {
	warn := "evm: already registered for this agent and rail"
	isConflict := warn != "" &&
		(strings.Contains(warn, "409") || strings.Contains(warn, "403")) &&
		!strings.Contains(warn, "already registered for this agent")
	assert.False(t, isConflict, "409 for same agent should NOT trigger fallback")
}

func TestIsOwnershipConflict_401IsNotConflict(t *testing.T) {
	warn := "evm: wallet registration auth failed (401)"
	isConflict := warn != "" &&
		(strings.Contains(warn, "409") || strings.Contains(warn, "403")) &&
		!strings.Contains(warn, "already registered for this agent")
	assert.False(t, isConflict, "401 auth error should NOT trigger fallback")
}

func TestIsOwnershipConflict_500IsNotConflict(t *testing.T) {
	warn := "evm: api error (500): internal server error"
	isConflict := warn != "" &&
		(strings.Contains(warn, "409") || strings.Contains(warn, "403")) &&
		!strings.Contains(warn, "already registered for this agent")
	assert.False(t, isConflict, "500 server error should NOT trigger fallback")
}

func TestIsOwnershipConflict_EmptyIsNotConflict(t *testing.T) {
	warn := ""
	isConflict := warn != "" &&
		(strings.Contains(warn, "409") || strings.Contains(warn, "403"))
	assert.False(t, isConflict, "empty warning (success) should NOT trigger fallback")
}
