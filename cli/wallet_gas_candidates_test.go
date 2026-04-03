package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestCollectLocalGasCandidates_SortsAndFlagsMismatches(t *testing.T) {
	origBalanceAt := evmBalanceAt
	t.Cleanup(func() {
		evmBalanceAt = origBalanceAt
	})

	cfg := cliConfig{
		WalletKeyring: map[string]agentWalletKeys{
			"good-rich": {
				EVMAddress:    "0x19E7E376E7C213B7E7E7E46CC70A5DD086DAFF2A",
				EVMPrivateKey: "1111111111111111111111111111111111111111111111111111111111111111",
			},
			"good-small": {
				EVMAddress:    "0x1563915E194D8CfBA1943570603F7606A3115508",
				EVMPrivateKey: "2222222222222222222222222222222222222222222222222222222222222222",
			},
			"mismatch": {
				EVMAddress:    "0x0000000000000000000000000000000000000003",
				EVMPrivateKey: "3333333333333333333333333333333333333333333333333333333333333333",
			},
		},
	}

	evmBalanceAt = func(_ context.Context, chainID string, addr common.Address) (*big.Int, error) {
		if chainID != "0x2105" {
			return nil, fmt.Errorf("unexpected chain ID %s", chainID)
		}
		switch strings.ToLower(addr.Hex()) {
		case strings.ToLower("0x19E7E376E7C213B7E7E7E46CC70A5DD086DAFF2A"):
			return big.NewInt(2_000_000_000_000_000), nil
		case strings.ToLower("0x1563915E194D8CfBA1943570603F7606A3115508"):
			return big.NewInt(100_000_000_000_000), nil
		default:
			return big.NewInt(0), nil
		}
	}

	candidates, err := collectLocalGasCandidates(context.Background(), cfg, "0x2105", "0x0000000000000000000000000000000000000009", defaultGasTopUpWei())
	if err != nil {
		t.Fatalf("collectLocalGasCandidates error: %v", err)
	}
	if len(candidates) != 3 {
		t.Fatalf("expected 3 candidates, got %d", len(candidates))
	}
	if candidates[0].AgentID != "good-rich" || !candidates[0].Eligible {
		t.Fatalf("expected richest eligible wallet first, got %#v", candidates[0])
	}
	if candidates[1].AgentID != "good-small" || candidates[1].Eligible {
		t.Fatalf("expected underfunded candidate second, got %#v", candidates[1])
	}
	if candidates[2].AgentID != "mismatch" || candidates[2].AddressMatch {
		t.Fatalf("expected mismatch candidate last, got %#v", candidates[2])
	}
	if !strings.Contains(candidates[2].EligibilityNote, "does not match") {
		t.Fatalf("expected mismatch note, got %#v", candidates[2])
	}
}

func TestRunWalletGasCandidates(t *testing.T) {
	origLoadCLIConfig := loadCLIConfigFn
	origBalanceAt := evmBalanceAt
	t.Cleanup(func() {
		loadCLIConfigFn = origLoadCLIConfig
		evmBalanceAt = origBalanceAt
	})

	loadCLIConfigFn = func() (cliConfig, error) {
		return cliConfig{
			WalletKeyring: map[string]agentWalletKeys{
				"good-rich": {
					EVMAddress:    "0x19E7E376E7C213B7E7E7E46CC70A5DD086DAFF2A",
					EVMPrivateKey: "1111111111111111111111111111111111111111111111111111111111111111",
				},
			},
		}, nil
	}
	evmBalanceAt = func(_ context.Context, _ string, _ common.Address) (*big.Int, error) {
		return big.NewInt(2_000_000_000_000_000), nil
	}

	cmd := walletCmd()
	cmd.SetArgs([]string{"gas-candidates", "--exclude-address", "0x0000000000000000000000000000000000000009"})

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
	if env.Command != "bob wallet gas-candidates" {
		t.Fatalf("unexpected command %q", env.Command)
	}
	data, ok := env.Data.(map[string]any)
	if !ok {
		t.Fatalf("unexpected data shape %#v", env.Data)
	}
	if data["eligible_count"] != float64(1) {
		t.Fatalf("unexpected eligible_count %#v", data["eligible_count"])
	}
	if len(env.NextActions) == 0 || !strings.Contains(env.NextActions[0].Command, "--fund-gas-from-local") {
		t.Fatalf("expected local gas funding next action, got %#v", env.NextActions)
	}
}

func TestRunLoanRepay_BlockedStatusExplainsGasFundingWillNotHelp(t *testing.T) {
	origAPIGet := apiGetFn
	origExecuteLoanRepayment := executeLoanRepaymentFn
	t.Cleanup(func() {
		apiGetFn = origAPIGet
		executeLoanRepaymentFn = origExecuteLoanRepayment
	})

	apiGetFn = func(path string) (json.RawMessage, error) {
		if path != "/loans/agreements/loan-1" {
			t.Fatalf("unexpected path %s", path)
		}
		return json.RawMessage(`{"status":"pending_funding","chain_id":"0x2105","borrower_wallet":"0x0000000000000000000000000000000000000001","safe_address":"0x00000000000000000000000000000000000000aa"}`), nil
	}
	executeLoanRepaymentFn = func(string, string, int64) (string, int64, error) {
		t.Fatal("executeLoanRepayment should not run when the loan is not active")
		return "", 0, nil
	}

	cmd := loanCmd()
	cmd.SetArgs([]string{"repay", "loan-1", "--agent-id", "agent-1", "--amount", "10000000", "--fund-gas-from-local", "--gas-funder-agent-id", "old-agent"})

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
	if !strings.Contains(fmt.Sprint(env.Data), "pending_funding") {
		t.Fatalf("expected pending_funding error, got %#v", env.Data)
	}
	if len(env.NextActions) < 3 {
		t.Fatalf("expected blocked-status recovery actions, got %#v", env.NextActions)
	}
	if !strings.Contains(env.NextActions[0].Command, "bob loan status loan-1") {
		t.Fatalf("unexpected first next action %#v", env.NextActions[0])
	}
	if !strings.Contains(env.NextActions[len(env.NextActions)-1].Description, "will not unblock repayment") {
		t.Fatalf("expected explicit pending_funding guidance, got %#v", env.NextActions)
	}
}
