package main

import (
	"context"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestRunWalletSweep_DryRun(t *testing.T) {
	origLoad := loadCLIConfigFn
	origBalance := evmBalanceAt
	origSend := evmSendNativeValue
	origEstimate := evmEstimateNativeTransferCost
	t.Cleanup(func() {
		loadCLIConfigFn = origLoad
		evmBalanceAt = origBalance
		evmSendNativeValue = origSend
		evmEstimateNativeTransferCost = origEstimate
	})

	loadCLIConfigFn = func() (cliConfig, error) {
		return cliConfig{
			WalletKeyring: map[string]agentWalletKeys{
				"old": {
					EVMPrivateKey: "1111111111111111111111111111111111111111111111111111111111111111",
					EVMAddress:    "0x19E7E376E7C213B7E7E7E46CC70A5DD086DAFF2A",
				},
				"new": {
					EVMPrivateKey: "2222222222222222222222222222222222222222222222222222222222222222",
					EVMAddress:    "0x1563915E194D8CfBA1943570603F7606A3115508",
				},
			},
		}, nil
	}
	evmBalanceAt = func(_ context.Context, _ string, _ common.Address) (*big.Int, error) {
		return big.NewInt(200_000_000_000_000), nil
	}
	evmSendNativeValue = func(context.Context, string, string, common.Address, *big.Int) (common.Hash, error) {
		t.Fatal("evmSendNativeValue should not be called in dry-run")
		return common.Hash{}, nil
	}
	evmEstimateNativeTransferCost = func(context.Context, string, common.Address, common.Address, *big.Int) (*big.Int, error) {
		return big.NewInt(50_000_000_000_000), nil
	}

	cmd := walletCmd()
	cmd.SetArgs([]string{
		"sweep",
		"--from-agent-id", "old",
		"--to-agent-id", "new",
		"--dry-run",
	})

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	_ = w.Close()

	var env Envelope
	if err := json.NewDecoder(r).Decode(&env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if !env.OK {
		t.Fatalf("expected ok envelope, got %#v", env)
	}
	if env.Command != "bob wallet sweep" {
		t.Fatalf("unexpected command %q", env.Command)
	}
	data, ok := env.Data.(map[string]any)
	if !ok {
		t.Fatalf("unexpected data shape %#v", env.Data)
	}
	if data["dry_run"] != true {
		t.Fatalf("expected dry_run true, got %#v", data["dry_run"])
	}
	if data["reserve_wei"] != localGasFundingFeeBufferWei().String() {
		t.Fatalf("expected reserve_wei %s, got %#v", localGasFundingFeeBufferWei().String(), data["reserve_wei"])
	}
	if data["gas_estimate_wei"] != "50000000000000" {
		t.Fatalf("unexpected gas_estimate_wei %#v", data["gas_estimate_wei"])
	}
	if data["transfer_wei"] != "50000000000000" {
		t.Fatalf("unexpected transfer_wei %#v", data["transfer_wei"])
	}
	if !strings.Contains(data["transfer_native"].(string), "0.") {
		t.Fatalf("expected transfer_native formatting, got %#v", data["transfer_native"])
	}
}

func TestRunWalletSweep_RejectsSameAddress(t *testing.T) {
	origLoad := loadCLIConfigFn
	t.Cleanup(func() { loadCLIConfigFn = origLoad })

	loadCLIConfigFn = func() (cliConfig, error) {
		return cliConfig{
			WalletKeyring: map[string]agentWalletKeys{
				"old": {
					EVMPrivateKey: "1111111111111111111111111111111111111111111111111111111111111111",
					EVMAddress:    "0x19E7E376E7C213B7E7E7E46CC70A5DD086DAFF2A",
				},
			},
		}, nil
	}

	cmd := walletCmd()
	cmd.SetArgs([]string{
		"sweep",
		"--from-agent-id", "old",
		"--to-address", "0x19E7E376E7C213B7E7E7E46CC70A5DD086DAFF2A",
	})

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	_ = w.Close()

	var env Envelope
	if err := json.NewDecoder(r).Decode(&env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if env.OK {
		t.Fatalf("expected error envelope, got %#v", env)
	}
}

func TestRunWalletSweep_RejectsAddressMismatch(t *testing.T) {
	origLoad := loadCLIConfigFn
	t.Cleanup(func() { loadCLIConfigFn = origLoad })

	loadCLIConfigFn = func() (cliConfig, error) {
		return cliConfig{
			WalletKeyring: map[string]agentWalletKeys{
				"old": {
					EVMPrivateKey: "1111111111111111111111111111111111111111111111111111111111111111",
					EVMAddress:    "0x0000000000000000000000000000000000000001",
				},
			},
		}, nil
	}

	cmd := walletCmd()
	cmd.SetArgs([]string{
		"sweep",
		"--from-agent-id", "old",
		"--to-address", "0x1563915E194D8CfBA1943570603F7606A3115508",
	})

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	_ = w.Close()

	var env Envelope
	if err := json.NewDecoder(r).Decode(&env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if env.OK {
		t.Fatalf("expected error envelope, got %#v", env)
	}
}

func TestRunWalletSweep_RequiresConfirmation(t *testing.T) {
	origLoad := loadCLIConfigFn
	origBalance := evmBalanceAt
	origEstimate := evmEstimateNativeTransferCost
	t.Cleanup(func() {
		loadCLIConfigFn = origLoad
		evmBalanceAt = origBalance
		evmEstimateNativeTransferCost = origEstimate
	})

	loadCLIConfigFn = func() (cliConfig, error) {
		return cliConfig{
			WalletKeyring: map[string]agentWalletKeys{
				"old": {
					EVMPrivateKey: "1111111111111111111111111111111111111111111111111111111111111111",
					EVMAddress:    "0x19E7E376E7C213B7E7E7E46CC70A5DD086DAFF2A",
				},
			},
		}, nil
	}
	evmBalanceAt = func(context.Context, string, common.Address) (*big.Int, error) {
		return big.NewInt(200_000_000_000_000), nil
	}
	evmEstimateNativeTransferCost = func(context.Context, string, common.Address, common.Address, *big.Int) (*big.Int, error) {
		return big.NewInt(10_000_000_000_000), nil
	}

	cmd := walletCmd()
	cmd.SetArgs([]string{
		"sweep",
		"--from-agent-id", "old",
		"--to-address", "0x1563915E194D8CfBA1943570603F7606A3115508",
	})

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	_ = w.Close()

	var env Envelope
	if err := json.NewDecoder(r).Decode(&env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if env.OK {
		t.Fatalf("expected error envelope, got %#v", env)
	}
	if len(env.NextActions) == 0 {
		t.Fatalf("expected next actions for confirmation, got %#v", env.NextActions)
	}
}

func TestRunWalletSweep_RespectsMaxWei(t *testing.T) {
	origLoad := loadCLIConfigFn
	origBalance := evmBalanceAt
	origEstimate := evmEstimateNativeTransferCost
	origSend := evmSendNativeValue
	t.Cleanup(func() {
		loadCLIConfigFn = origLoad
		evmBalanceAt = origBalance
		evmEstimateNativeTransferCost = origEstimate
		evmSendNativeValue = origSend
	})

	loadCLIConfigFn = func() (cliConfig, error) {
		return cliConfig{
			WalletKeyring: map[string]agentWalletKeys{
				"old": {
					EVMPrivateKey: "1111111111111111111111111111111111111111111111111111111111111111",
					EVMAddress:    "0x19E7E376E7C213B7E7E7E46CC70A5DD086DAFF2A",
				},
			},
		}, nil
	}
	evmBalanceAt = func(context.Context, string, common.Address) (*big.Int, error) {
		return big.NewInt(400_000_000_000_000), nil
	}
	evmEstimateNativeTransferCost = func(context.Context, string, common.Address, common.Address, *big.Int) (*big.Int, error) {
		return big.NewInt(50_000_000_000_000), nil
	}
	var sent *big.Int
	evmSendNativeValue = func(_ context.Context, _ string, _ string, _ common.Address, amount *big.Int) (common.Hash, error) {
		sent = new(big.Int).Set(amount)
		return common.HexToHash("0x01"), nil
	}

	cmd := walletCmd()
	cmd.SetArgs([]string{
		"sweep",
		"--from-agent-id", "old",
		"--to-address", "0x1563915E194D8CfBA1943570603F7606A3115508",
		"--max-wei", "100000000000000",
		"--yes",
	})

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	_ = w.Close()

	var env Envelope
	if err := json.NewDecoder(r).Decode(&env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if !env.OK {
		t.Fatalf("expected ok envelope, got %#v", env)
	}
	if data, ok := env.Data.(map[string]any); ok {
		if data["transfer_wei"] != "100000000000000" {
			t.Fatalf("expected transfer_wei 100000000000000, got %#v", data["transfer_wei"])
		}
	}
	if sent == nil || sent.String() != "100000000000000" {
		t.Fatalf("expected sent 100000000000000, got %#v", sent)
	}
}

func TestRunWalletSweep_InsufficientBalance(t *testing.T) {
	origLoad := loadCLIConfigFn
	origBalance := evmBalanceAt
	origEstimate := evmEstimateNativeTransferCost
	t.Cleanup(func() {
		loadCLIConfigFn = origLoad
		evmBalanceAt = origBalance
		evmEstimateNativeTransferCost = origEstimate
	})

	loadCLIConfigFn = func() (cliConfig, error) {
		return cliConfig{
			WalletKeyring: map[string]agentWalletKeys{
				"old": {
					EVMPrivateKey: "1111111111111111111111111111111111111111111111111111111111111111",
					EVMAddress:    "0x19E7E376E7C213B7E7E7E46CC70A5DD086DAFF2A",
				},
			},
		}, nil
	}
	evmBalanceAt = func(context.Context, string, common.Address) (*big.Int, error) {
		return big.NewInt(50_000_000_000_000), nil
	}
	evmEstimateNativeTransferCost = func(context.Context, string, common.Address, common.Address, *big.Int) (*big.Int, error) {
		return big.NewInt(60_000_000_000_000), nil
	}

	cmd := walletCmd()
	cmd.SetArgs([]string{
		"sweep",
		"--from-agent-id", "old",
		"--to-address", "0x1563915E194D8CfBA1943570603F7606A3115508",
		"--dry-run",
	})

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	_ = w.Close()

	var env Envelope
	if err := json.NewDecoder(r).Decode(&env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if env.OK {
		t.Fatalf("expected error envelope, got %#v", env)
	}
}
