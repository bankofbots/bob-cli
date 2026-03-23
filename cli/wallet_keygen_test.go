package main

import (
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
