package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/spf13/cobra"
)

func TestSignTreasuryHashForAgent_NormalizesRecoveryID(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	privHex := hex.EncodeToString(crypto.FromECDSA(key))
	wantAddr := crypto.PubkeyToAddress(key.PublicKey).Hex()

	origLoadCLIConfig := loadCLIConfigFn
	defer func() { loadCLIConfigFn = origLoadCLIConfig }()
	loadCLIConfigFn = func() (cliConfig, error) {
		return cliConfig{
			AgentID: "agent-a",
			WalletKeyring: map[string]agentWalletKeys{
				"agent-a": {
					EVMAddress:    wantAddr,
					EVMPrivateKey: privHex,
				},
			},
		}, nil
	}

	sigHex, signer, err := signTreasuryHashForAgent("agent-a", "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("signTreasuryHashForAgent: %v", err)
	}
	if signer != wantAddr {
		t.Fatalf("signer = %s, want %s", signer, wantAddr)
	}
	sig, err := hex.DecodeString(sigHex[2:])
	if err != nil {
		t.Fatalf("hex decode signature: %v", err)
	}
	if len(sig) != 65 {
		t.Fatalf("signature len = %d, want 65", len(sig))
	}
	if sig[64] != 27 && sig[64] != 28 {
		t.Fatalf("recovery byte = %d, want 27 or 28", sig[64])
	}
}

func TestRunTreasuryTransfer_UsesCanonicalSignatureAndSubmits(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	privHex := hex.EncodeToString(crypto.FromECDSA(key))
	wantAddr := crypto.PubkeyToAddress(key.PublicKey).Hex()

	origLoadCLIConfig := loadCLIConfigFn
	origAPIPost := apiPostFn
	defer func() {
		loadCLIConfigFn = origLoadCLIConfig
		apiPostFn = origAPIPost
	}()

	loadCLIConfigFn = func() (cliConfig, error) {
		return cliConfig{
			AgentID: "agent-a",
			WalletKeyring: map[string]agentWalletKeys{
				"agent-a": {
					EVMAddress:    wantAddr,
					EVMPrivateKey: privHex,
				},
			},
		}, nil
	}

	prepareCalls := 0
	submitCalls := 0
	apiPostFn = func(path string, payload any) (json.RawMessage, error) {
		body, _ := json.Marshal(payload)
		var req map[string]any
		_ = json.Unmarshal(body, &req)
		switch path {
		case "/agents/agent-a/treasury/tx-requests/prepare":
			prepareCalls++
			if req["treasury_account_id"] != "ta_123" {
				return nil, errors.New("unexpected treasury_account_id")
			}
			return json.RawMessage(`{
				"reservation_id":"res_123",
				"treasury_account_id":"ta_123",
				"chain_id":"0x2105",
				"safe_address":"0x1111111111111111111111111111111111111111",
				"safe_nonce":7,
				"safe_tx_hash":"0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				"contract_address":"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
				"data_hex":"0xa9059cbb",
				"asset_address":"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
				"amount_atomic":"1000000"
			}`), nil
		case "/agents/agent-a/treasury/tx-requests":
			submitCalls++
			sig, _ := req["agent_signature"].(string)
			if sig == "" {
				return nil, errors.New("missing agent_signature")
			}
			sigBytes, err := hex.DecodeString(sig[2:])
			if err != nil {
				return nil, err
			}
			if sigBytes[64] != 27 && sigBytes[64] != 28 {
				return nil, errors.New("agent_signature V not normalized")
			}
			return json.RawMessage(`{
				"id":"txr_123",
				"status":"pending_operator_review",
				"decision_reason":"manual_review_required",
				"safe_tx_hash":"0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				"safe_nonce":7,
				"to_address":"0x2222222222222222222222222222222222222222",
				"amount_atomic":"1000000"
			}`), nil
		default:
			return nil, errors.New("unexpected path: " + path)
		}
	}

	cmd := &cobra.Command{}
	cmd.Flags().String("agent-id", "", "Agent ID")
	cmd.Flags().String("account-id", "", "Treasury account ID")
	cmd.Flags().String("to", "", "Recipient EVM address")
	cmd.Flags().String("amount", "", "USDC amount")
	cmd.Flags().String("request-json", `{"intent":"cli_treasury_transfer"}`, "Request metadata")
	_ = cmd.Flags().Set("agent-id", "agent-a")
	_ = cmd.Flags().Set("account-id", "ta_123")
	_ = cmd.Flags().Set("to", "0x2222222222222222222222222222222222222222")
	_ = cmd.Flags().Set("amount", "1000000")

	var env Envelope
	captureEnvelope(t, func() error {
		return runTreasuryTransfer(cmd, nil)
	}, &env)

	if !env.OK {
		t.Fatalf("expected ok envelope, got %#v", env)
	}
	if prepareCalls != 1 {
		t.Fatalf("prepareCalls = %d, want 1", prepareCalls)
	}
	if submitCalls != 1 {
		t.Fatalf("submitCalls = %d, want 1", submitCalls)
	}
	data, ok := env.Data.(map[string]any)
	if !ok {
		t.Fatalf("unexpected data shape: %#v", env.Data)
	}
	signer, _ := data["signer_address"].(string)
	if signer != wantAddr {
		t.Fatalf("signer_address = %q, want %q", signer, wantAddr)
	}
	signature, _ := data["signature"].(string)
	if signature == "" {
		t.Fatal("missing signature in envelope")
	}
}

func TestRunTreasuryPrepare_RejectsInvalidRecipient(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("agent-id", "", "Agent ID")
	cmd.Flags().String("account-id", "", "Treasury account ID")
	cmd.Flags().String("to", "", "Recipient EVM address")
	cmd.Flags().String("amount", "", "USDC amount")
	_ = cmd.Flags().Set("agent-id", "agent-a")
	_ = cmd.Flags().Set("account-id", "ta_123")
	_ = cmd.Flags().Set("to", "not-an-address")
	_ = cmd.Flags().Set("amount", "1000000")

	var env Envelope
	captureEnvelope(t, func() error {
		return runTreasuryPrepare(cmd, nil)
	}, &env)

	if env.OK {
		t.Fatalf("expected invalid recipient to fail: %#v", env)
	}
	data, ok := env.Data.(map[string]any)
	if !ok {
		t.Fatalf("unexpected data shape: %#v", env.Data)
	}
	if !strings.Contains(data["error"].(string), "invalid treasury recipient address") {
		t.Fatalf("unexpected error: %#v", data)
	}
}

func TestRunTreasurySubmit_RejectsInvalidAmount(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("agent-id", "", "Agent ID")
	cmd.Flags().String("reservation-id", "", "Reservation ID")
	cmd.Flags().String("to", "", "Recipient EVM address")
	cmd.Flags().String("amount", "", "USDC amount")
	cmd.Flags().String("signature", "", "Signature")
	cmd.Flags().String("request-json", `{"intent":"cli_treasury_transfer"}`, "Request metadata")
	_ = cmd.Flags().Set("agent-id", "agent-a")
	_ = cmd.Flags().Set("reservation-id", "res_123")
	_ = cmd.Flags().Set("to", "0x2222222222222222222222222222222222222222")
	_ = cmd.Flags().Set("amount", "0")
	_ = cmd.Flags().Set("signature", "0xsig")

	var env Envelope
	captureEnvelope(t, func() error {
		return runTreasurySubmit(cmd, nil)
	}, &env)

	if env.OK {
		t.Fatalf("expected invalid amount to fail: %#v", env)
	}
	data, ok := env.Data.(map[string]any)
	if !ok {
		t.Fatalf("unexpected data shape: %#v", env.Data)
	}
	if !strings.Contains(data["error"].(string), "amount must be greater than 0") {
		t.Fatalf("unexpected error: %#v", data)
	}
}

func TestRunTreasuryTransfer_SubmitFailurePreservesReservationContext(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	privHex := hex.EncodeToString(crypto.FromECDSA(key))
	wantAddr := crypto.PubkeyToAddress(key.PublicKey).Hex()

	origLoadCLIConfig := loadCLIConfigFn
	origAPIPost := apiPostFn
	defer func() {
		loadCLIConfigFn = origLoadCLIConfig
		apiPostFn = origAPIPost
	}()

	loadCLIConfigFn = func() (cliConfig, error) {
		return cliConfig{
			AgentID: "agent-a",
			WalletKeyring: map[string]agentWalletKeys{
				"agent-a": {
					EVMAddress:    wantAddr,
					EVMPrivateKey: privHex,
				},
			},
		}, nil
	}

	apiPostFn = func(path string, payload any) (json.RawMessage, error) {
		switch path {
		case "/agents/agent-a/treasury/tx-requests/prepare":
			return json.RawMessage(`{
				"reservation_id":"res_123",
				"treasury_account_id":"ta_123",
				"chain_id":"0x2105",
				"safe_address":"0x1111111111111111111111111111111111111111",
				"safe_nonce":7,
				"safe_tx_hash":"0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				"contract_address":"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
				"data_hex":"0xa9059cbb",
				"asset_address":"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
				"amount_atomic":"1000000"
			}`), nil
		case "/agents/agent-a/treasury/tx-requests":
			return nil, errors.New("api error (500): submit failed")
		default:
			return nil, errors.New("unexpected path: " + path)
		}
	}

	cmd := &cobra.Command{}
	cmd.Flags().String("agent-id", "", "Agent ID")
	cmd.Flags().String("account-id", "", "Treasury account ID")
	cmd.Flags().String("to", "", "Recipient EVM address")
	cmd.Flags().String("amount", "", "USDC amount")
	cmd.Flags().String("request-json", `{"intent":"cli_treasury_transfer"}`, "Request metadata")
	_ = cmd.Flags().Set("agent-id", "agent-a")
	_ = cmd.Flags().Set("account-id", "ta_123")
	_ = cmd.Flags().Set("to", "0x2222222222222222222222222222222222222222")
	_ = cmd.Flags().Set("amount", "1000000")

	var env Envelope
	captureEnvelope(t, func() error {
		return runTreasuryTransfer(cmd, nil)
	}, &env)

	if env.OK {
		t.Fatalf("expected transfer failure envelope, got %#v", env)
	}
	data, ok := env.Data.(map[string]any)
	if !ok {
		t.Fatalf("unexpected data shape: %#v", env.Data)
	}
	if got := data["reservation_id"]; got != "res_123" {
		t.Fatalf("reservation_id = %#v, want res_123", got)
	}
	if got := data["safe_tx_hash"]; got != "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
		t.Fatalf("safe_tx_hash = %#v", got)
	}
	if len(env.NextActions) < 2 {
		t.Fatalf("expected recovery next actions, got %#v", env.NextActions)
	}
}

func TestParseTreasuryRequestJSON_RejectsInvalidJSON(t *testing.T) {
	_, err := parseTreasuryRequestJSON("not valid json")
	if err == nil {
		t.Fatal("expected invalid JSON to fail")
	}
	if !strings.Contains(err.Error(), "request-json must be valid JSON") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunTreasuryStatus_ShowsSpendingGuidanceWhenTreasuryMissing(t *testing.T) {
	origAPIGet := apiGetFn
	defer func() { apiGetFn = origAPIGet }()

	apiGetFn = func(path string) (json.RawMessage, error) {
		switch path {
		case "/agents/agent-a/treasury/accounts":
			return json.RawMessage(`{"accounts":[],"control_flags":{"global_freeze":false,"agent_freeze":false,"manual_only_mode":false}}`), nil
		case "/agents/agent-a/treasury/policies/active":
			return nil, errors.New("api error (404): no active treasury policy")
		default:
			return nil, errors.New("unexpected path: " + path)
		}
	}

	cmd := &cobra.Command{}
	cmd.Flags().String("agent-id", "", "Agent ID")
	_ = cmd.Flags().Set("agent-id", "agent-a")

	var env Envelope
	captureEnvelope(t, func() error {
		return runTreasuryStatus(cmd, nil)
	}, &env)

	if !env.OK {
		t.Fatalf("expected ok envelope, got %#v", env)
	}
	data, ok := env.Data.(map[string]any)
	if !ok {
		t.Fatalf("unexpected data shape: %#v", env.Data)
	}
	if ready, _ := data["treasury_ready_for_spending"].(bool); ready {
		t.Fatal("expected treasury_ready_for_spending to be false")
	}
	if required, _ := data["treasury_required_for_spending"].(bool); !required {
		t.Fatal("expected treasury_required_for_spending to be true")
	}
	guidance, _ := data["treasury_setup_guidance"].(string)
	if !strings.Contains(guidance, "2-of-3 Safe") {
		t.Fatalf("unexpected guidance: %q", guidance)
	}
}

func TestRunTreasuryStatus_FrozenAccountsDoNotCountAsReady(t *testing.T) {
	origAPIGet := apiGetFn
	defer func() { apiGetFn = origAPIGet }()

	apiGetFn = func(path string) (json.RawMessage, error) {
		switch path {
		case "/agents/agent-a/treasury/accounts":
			return json.RawMessage(`{"accounts":[{"id":"ta_1","status":"frozen"}],"control_flags":{"global_freeze":false,"agent_freeze":true,"manual_only_mode":false}}`), nil
		case "/agents/agent-a/treasury/policies/active":
			return json.RawMessage(`{"id":"pol_1","version":1,"status":"active","policy":{"kill_switch":false}}`), nil
		default:
			return nil, errors.New("unexpected path: " + path)
		}
	}

	cmd := &cobra.Command{}
	cmd.Flags().String("agent-id", "", "Agent ID")
	_ = cmd.Flags().Set("agent-id", "agent-a")

	var env Envelope
	captureEnvelope(t, func() error {
		return runTreasuryStatus(cmd, nil)
	}, &env)

	if !env.OK {
		t.Fatalf("expected ok envelope, got %#v", env)
	}
	data := env.Data.(map[string]any)
	if ready, _ := data["treasury_ready_for_spending"].(bool); ready {
		t.Fatal("expected frozen account not to count as treasury-ready")
	}
}

func TestSignTreasuryHashForAgent_DoesNotFallbackToDifferentAgentKey(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	privHex := hex.EncodeToString(crypto.FromECDSA(key))
	wantAddr := crypto.PubkeyToAddress(key.PublicKey).Hex()

	origLoadCLIConfig := loadCLIConfigFn
	defer func() { loadCLIConfigFn = origLoadCLIConfig }()
	loadCLIConfigFn = func() (cliConfig, error) {
		return cliConfig{
			AgentID: "other-agent",
			WalletKeyring: map[string]agentWalletKeys{
				"other-agent": {
					EVMAddress:    wantAddr,
					EVMPrivateKey: privHex,
				},
			},
		}, nil
	}

	_, _, err = signTreasuryHashForAgent("agent-a", "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err == nil {
		t.Fatal("expected missing agent key to fail")
	}
	if !strings.Contains(err.Error(), "no EVM wallet key found for agent agent-a") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func captureEnvelope(t *testing.T, fn func() error, out *Envelope) {
	t.Helper()
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	runErr := fn()
	_ = w.Close()
	if runErr != nil {
		t.Fatalf("command returned error: %v", runErr)
	}

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	_ = r.Close()
	if err := json.Unmarshal(buf.Bytes(), out); err != nil {
		t.Fatalf("decode envelope: %v\nraw=%s", err, buf.String())
	}
}
