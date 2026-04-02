package main

import (
	"context"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestSelectLocalGasFunder_UsesExplicitFunderAgent(t *testing.T) {
	origBalanceAt := evmBalanceAt
	t.Cleanup(func() {
		evmBalanceAt = origBalanceAt
	})

	cfg := cliConfig{
		WalletKeyring: map[string]agentWalletKeys{
			"borrower": {EVMAddress: "0x0000000000000000000000000000000000000001", EVMPrivateKey: "skip"},
			"agent-a":  {EVMAddress: "0x0000000000000000000000000000000000000002", EVMPrivateKey: "aaa"},
			"agent-b":  {EVMAddress: "0x0000000000000000000000000000000000000003", EVMPrivateKey: "bbb"},
		},
	}

	balances := map[string]*big.Int{
		"0x0000000000000000000000000000000000000002": big.NewInt(2_000_000_000_000_000),
		"0x0000000000000000000000000000000000000003": big.NewInt(5_000_000_000_000_000),
	}
	evmBalanceAt = func(_ context.Context, chainID string, addr common.Address) (*big.Int, error) {
		if chainID != "0x2105" {
			t.Fatalf("unexpected chain id %s", chainID)
		}
		if bal, ok := balances[addr.Hex()]; ok {
			return new(big.Int).Set(bal), nil
		}
		return big.NewInt(0), nil
	}

	funder, err := selectLocalGasFunder(context.Background(), cfg, "0x2105", "0x0000000000000000000000000000000000000001", "agent-a", big.NewInt(1_000_000_000_000_000))
	if err != nil {
		t.Fatalf("selectLocalGasFunder error: %v", err)
	}
	if funder.AgentID != "agent-a" {
		t.Fatalf("expected explicit funder agent-a, got %s", funder.AgentID)
	}
	if funder.WalletAddress != "0x0000000000000000000000000000000000000002" {
		t.Fatalf("unexpected wallet address %s", funder.WalletAddress)
	}
}

func TestFundBorrowerGasFromLocalKeyring_UsesSelectedWallet(t *testing.T) {
	origBalanceAt := evmBalanceAt
	origSendNative := evmSendNativeValue
	t.Cleanup(func() {
		evmBalanceAt = origBalanceAt
		evmSendNativeValue = origSendNative
	})

	cfg := cliConfig{
		WalletKeyring: map[string]agentWalletKeys{
			"agent-a": {EVMAddress: "0x0000000000000000000000000000000000000002", EVMPrivateKey: "aaa"},
		},
	}

	evmBalanceAt = func(_ context.Context, _ string, _ common.Address) (*big.Int, error) {
		return big.NewInt(2_000_000_000_000_000), nil
	}

	called := false
	evmSendNativeValue = func(_ context.Context, privKeyHex string, chainIDHex string, to common.Address, amountWei *big.Int) (common.Hash, error) {
		called = true
		if privKeyHex != "aaa" {
			t.Fatalf("unexpected private key %s", privKeyHex)
		}
		if chainIDHex != "0x2105" {
			t.Fatalf("unexpected chain %s", chainIDHex)
		}
		if to.Hex() != "0x0000000000000000000000000000000000000001" {
			t.Fatalf("unexpected destination %s", to.Hex())
		}
		if amountWei.Cmp(big.NewInt(1_000_000_000_000_000)) != 0 {
			t.Fatalf("unexpected amount %s", amountWei.String())
		}
		return common.HexToHash("0x1234"), nil
	}

	funder, hash, err := fundBorrowerGasFromLocalKeyring(context.Background(), cfg, "0x2105", "0x0000000000000000000000000000000000000001", "agent-a", big.NewInt(1_000_000_000_000_000))
	if err != nil {
		t.Fatalf("fundBorrowerGasFromLocalKeyring error: %v", err)
	}
	if !called {
		t.Fatal("expected native transfer helper to be called")
	}
	if funder.AgentID != "agent-a" {
		t.Fatalf("unexpected funder agent %s", funder.AgentID)
	}
	if hash.Hex() != "0x0000000000000000000000000000000000000000000000000000000000001234" {
		t.Fatalf("unexpected tx hash %s", hash.Hex())
	}
}

func TestRunLoanRepay_FundsGasFromLocalAndRetries(t *testing.T) {
	origAPIBase := apiBase
	origLoadCLIConfig := loadCLIConfigFn
	origExecuteLoanRepayment := executeLoanRepaymentFn
	origAPIGet := apiGetFn
	origBalanceAt := evmBalanceAt
	origSendNative := evmSendNativeValue
	t.Cleanup(func() {
		apiBase = origAPIBase
		loadCLIConfigFn = origLoadCLIConfig
		executeLoanRepaymentFn = origExecuteLoanRepayment
		apiGetFn = origAPIGet
		evmBalanceAt = origBalanceAt
		evmSendNativeValue = origSendNative
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/repayments") {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"id":"repayment-1","tx_hash":"0xrepay"}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	apiBase = server.URL

	loadCLIConfigFn = func() (cliConfig, error) {
		return cliConfig{
			WalletKeyring: map[string]agentWalletKeys{
				"old-agent": {EVMAddress: "0x0000000000000000000000000000000000000002", EVMPrivateKey: "aaa"},
			},
		}, nil
	}

	apiGetFn = func(path string) (json.RawMessage, error) {
		if path != "/loans/agreements/loan-1" {
			t.Fatalf("unexpected apiGet path %s", path)
		}
		return json.RawMessage(`{"status":"active","chain_id":"0x2105","borrower_wallet":"0x0000000000000000000000000000000000000001","safe_address":"0x00000000000000000000000000000000000000aa"}`), nil
	}

	attempts := 0
	executeLoanRepaymentFn = func(loanID, agentID string, amount int64) (string, int64, error) {
		attempts++
		if loanID != "loan-1" || agentID != "agent-1" || amount != 10_000_000 {
			t.Fatalf("unexpected execute args %s %s %d", loanID, agentID, amount)
		}
		if attempts == 1 {
			return "", 0, annotateLoanRepaymentError(
				errString("on-chain transfer failed: send transaction: insufficient funds for gas * price + value"),
				"0x2105",
				"0x0000000000000000000000000000000000000001",
			)
		}
		return "0xrepay", amount, nil
	}

	evmBalanceAt = func(_ context.Context, _ string, _ common.Address) (*big.Int, error) {
		return big.NewInt(2_000_000_000_000_000), nil
	}
	gasTransferCalled := false
	evmSendNativeValue = func(_ context.Context, privKeyHex string, chainIDHex string, to common.Address, amountWei *big.Int) (common.Hash, error) {
		gasTransferCalled = true
		if privKeyHex != "aaa" || chainIDHex != "0x2105" || to.Hex() != "0x0000000000000000000000000000000000000001" {
			t.Fatalf("unexpected gas transfer args %s %s %s", privKeyHex, chainIDHex, to.Hex())
		}
		if amountWei.Cmp(defaultGasTopUpWei()) != 0 {
			t.Fatalf("unexpected gas top-up amount %s", amountWei.String())
		}
		return common.HexToHash("0x1234"), nil
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
		t.Fatalf("command execute error: %v", err)
	}
	w.Close()
	out, _ := io.ReadAll(r)

	if attempts != 2 {
		t.Fatalf("expected repay to retry once, got %d attempts", attempts)
	}
	if !gasTransferCalled {
		t.Fatal("expected gas top-up transfer to be attempted")
	}
	if !strings.Contains(string(out), `"ok": true`) {
		t.Fatalf("expected success envelope, got %s", string(out))
	}
}

func TestRunLoanRepay_GasErrorIncludesNextActions(t *testing.T) {
	origAPIBase := apiBase
	origExecuteLoanRepayment := executeLoanRepaymentFn
	origAPIGet := apiGetFn
	t.Cleanup(func() {
		apiBase = origAPIBase
		executeLoanRepaymentFn = origExecuteLoanRepayment
		apiGetFn = origAPIGet
	})

	executeLoanRepaymentFn = func(loanID, agentID string, amount int64) (string, int64, error) {
		return "", 0, annotateLoanRepaymentError(
			errString("on-chain transfer failed: send transaction: insufficient funds for gas * price + value"),
			"0x2105",
			"0x0000000000000000000000000000000000000001",
		)
	}
	apiGetFn = func(path string) (json.RawMessage, error) {
		return json.RawMessage(`{"status":"active","chain_id":"0x2105","borrower_wallet":"0x0000000000000000000000000000000000000001","safe_address":"0x00000000000000000000000000000000000000aa"}`), nil
	}

	cmd := loanCmd()
	cmd.SetArgs([]string{"repay", "loan-1", "--agent-id", "agent-1", "--amount", "10000000"})

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	if err := cmd.Execute(); err != nil {
		t.Fatalf("command execute error: %v", err)
	}
	w.Close()

	var env Envelope
	if err := json.NewDecoder(r).Decode(&env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if env.OK {
		t.Fatalf("expected error envelope, got %#v", env)
	}
	if len(env.NextActions) < 3 {
		t.Fatalf("expected repayment gas recovery next actions, got %#v", env.NextActions)
	}
	if env.NextActions[0].Command != "bob loan repay loan-1 --amount <usdc> --agent-id agent-1 --fund-gas-from-local --gas-funder-agent-id <agent-id>" {
		t.Fatalf("unexpected first next action: %#v", env.NextActions[0])
	}
	if !strings.Contains(env.NextActions[1].Command, "ETH on Base (chain ID 8453)") {
		t.Fatalf("unexpected manual funding action: %#v", env.NextActions[1])
	}
}

func TestFundBorrowerGasFromLocalKeyring_RejectsInvalidBorrowerAddress(t *testing.T) {
	cfg := cliConfig{
		WalletKeyring: map[string]agentWalletKeys{
			"agent-a": {EVMAddress: "0x0000000000000000000000000000000000000002", EVMPrivateKey: "aaa"},
		},
	}

	_, _, err := fundBorrowerGasFromLocalKeyring(context.Background(), cfg, "0x2105", "not-an-address", "agent-a", defaultGasTopUpWei())
	if err == nil || !strings.Contains(err.Error(), "invalid borrower wallet address") {
		t.Fatalf("expected invalid borrower wallet error, got %v", err)
	}
}

func TestSelectLocalGasFunder_RequiresGasBuffer(t *testing.T) {
	origBalanceAt := evmBalanceAt
	t.Cleanup(func() {
		evmBalanceAt = origBalanceAt
	})

	cfg := cliConfig{
		WalletKeyring: map[string]agentWalletKeys{
			"agent-a": {EVMAddress: "0x0000000000000000000000000000000000000002", EVMPrivateKey: "aaa"},
		},
	}
	evmBalanceAt = func(_ context.Context, _ string, _ common.Address) (*big.Int, error) {
		return new(big.Int).Set(defaultGasTopUpWei()), nil
	}

	_, err := selectLocalGasFunder(context.Background(), cfg, "0x2105", "0x0000000000000000000000000000000000000001", "agent-a", defaultGasTopUpWei())
	if err == nil || !strings.Contains(err.Error(), "including gas buffer") {
		t.Fatalf("expected gas buffer error, got %v", err)
	}
}

func TestRunLoanRepay_RetryFailureStillIncludesNextActions(t *testing.T) {
	origExecuteLoanRepayment := executeLoanRepaymentFn
	origAPIGet := apiGetFn
	origLoadCLIConfig := loadCLIConfigFn
	origBalanceAt := evmBalanceAt
	origSendNative := evmSendNativeValue
	t.Cleanup(func() {
		executeLoanRepaymentFn = origExecuteLoanRepayment
		apiGetFn = origAPIGet
		loadCLIConfigFn = origLoadCLIConfig
		evmBalanceAt = origBalanceAt
		evmSendNativeValue = origSendNative
	})

	loadCLIConfigFn = func() (cliConfig, error) {
		return cliConfig{
			WalletKeyring: map[string]agentWalletKeys{
				"old-agent": {EVMAddress: "0x0000000000000000000000000000000000000002", EVMPrivateKey: "aaa"},
			},
		}, nil
	}
	apiGetFn = func(path string) (json.RawMessage, error) {
		return json.RawMessage(`{"status":"active","chain_id":"8453","borrower_wallet":"0x0000000000000000000000000000000000000001","safe_address":"0x00000000000000000000000000000000000000aa"}`), nil
	}
	attempts := 0
	executeLoanRepaymentFn = func(loanID, agentID string, amount int64) (string, int64, error) {
		attempts++
		if attempts == 1 {
			return "", 0, annotateLoanRepaymentError(errString("on-chain transfer failed: send transaction: insufficient funds for gas * price + value"), "0x2105", "0x0000000000000000000000000000000000000001")
		}
		return "", 0, errString("transaction reverted on-chain")
	}
	evmBalanceAt = func(_ context.Context, _ string, _ common.Address) (*big.Int, error) {
		return big.NewInt(1_000_000_000_000_000), nil
	}
	evmSendNativeValue = func(_ context.Context, _ string, _ string, _ common.Address, _ *big.Int) (common.Hash, error) {
		return common.HexToHash("0x1234"), nil
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
		t.Fatalf("command execute error: %v", err)
	}
	w.Close()

	var env Envelope
	if err := json.NewDecoder(r).Decode(&env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if env.OK {
		t.Fatalf("expected error envelope, got %#v", env)
	}
	if len(env.NextActions) < 2 {
		t.Fatalf("expected next actions after retry failure, got %#v", env.NextActions)
	}
	if !strings.Contains(env.NextActions[0].Command, "Fund 0x0000000000000000000000000000000000000001 with ETH on Base") {
		t.Fatalf("unexpected first next action after retry failure: %#v", env.NextActions[0])
	}
}

type errString string

func (e errString) Error() string { return string(e) }
