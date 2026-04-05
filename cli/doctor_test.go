package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestRunDoctor_ShowsTreasuryReadinessWarningWhenMissing(t *testing.T) {
	origAPIGet := apiGetFn
	origLoadCLIConfig := loadCLIConfigFn
	origAPIKey := apiKey
	defer func() {
		apiGetFn = origAPIGet
		loadCLIConfigFn = origLoadCLIConfig
		apiKey = origAPIKey
	}()

	apiKey = "bok_test_key"
	loadCLIConfigFn = func() (cliConfig, error) {
		return cliConfig{
			AgentID: "agent-a",
			WalletKeyring: map[string]agentWalletKeys{
				"agent-a": {EVMAddress: "0x1111111111111111111111111111111111111111"},
			},
		}, nil
	}

	apiGetFn = func(path string) (json.RawMessage, error) {
		switch path {
		case "/auth/me":
			return json.RawMessage(`{"ok":true,"role":"agent","agent_id":"agent-a"}`), nil
		case "/agents/agent-a/credential":
			return json.RawMessage(`{"id":"cred_123"}`), nil
		case "/agents/agent-a/treasury/accounts":
			return json.RawMessage(`{"accounts":[],"control_flags":{"global_freeze":false,"agent_freeze":false,"manual_only_mode":false}}`), nil
		case "/agents/agent-a/treasury/policies/active":
			return nil, errors.New("api error (404): no active treasury policy")
		default:
			return nil, errors.New("unexpected path: " + path)
		}
	}

	var env Envelope
	captureEnvelope(t, func() error {
		return runDoctor(nil, nil)
	}, &env)

	if !env.OK {
		t.Fatalf("expected ok envelope, got %#v", env)
	}
	data, ok := env.Data.(map[string]any)
	if !ok {
		t.Fatalf("unexpected data shape: %#v", env.Data)
	}
	treasury, ok := data["treasury"].(map[string]any)
	if !ok {
		t.Fatalf("unexpected treasury shape: %#v", data["treasury"])
	}
	if ready, _ := treasury["ready_for_spending"].(bool); ready {
		t.Fatal("expected ready_for_spending to be false")
	}
	warnings, ok := data["warnings"].([]any)
	if !ok {
		t.Fatalf("unexpected warnings shape: %#v", data["warnings"])
	}
	found := false
	for _, warning := range warnings {
		if s, _ := warning.(string); s != "" && containsAll(s, "treasury", "governed spending") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected treasury readiness warning, got %#v", warnings)
	}
}

func TestRunDoctor_FrozenTreasuryAccountIsNotReady(t *testing.T) {
	origAPIGet := apiGetFn
	origLoadCLIConfig := loadCLIConfigFn
	origAPIKey := apiKey
	defer func() {
		apiGetFn = origAPIGet
		loadCLIConfigFn = origLoadCLIConfig
		apiKey = origAPIKey
	}()

	apiKey = "bok_test_key"
	loadCLIConfigFn = func() (cliConfig, error) {
		return cliConfig{
			AgentID: "agent-a",
			WalletKeyring: map[string]agentWalletKeys{
				"agent-a": {EVMAddress: "0x1111111111111111111111111111111111111111"},
			},
		}, nil
	}

	apiGetFn = func(path string) (json.RawMessage, error) {
		switch path {
		case "/auth/me":
			return json.RawMessage(`{"ok":true,"role":"agent","agent_id":"agent-a"}`), nil
		case "/agents/agent-a/credential":
			return json.RawMessage(`{"id":"cred_123"}`), nil
		case "/agents/agent-a/treasury/accounts":
			return json.RawMessage(`{"accounts":[{"id":"ta_1","status":"frozen"}],"control_flags":{"global_freeze":false,"agent_freeze":true,"manual_only_mode":false}}`), nil
		case "/agents/agent-a/treasury/policies/active":
			return json.RawMessage(`{"id":"pol_123","version":1,"status":"active"}`), nil
		default:
			return nil, errors.New("unexpected path: " + path)
		}
	}

	var env Envelope
	captureEnvelope(t, func() error {
		return runDoctor(nil, nil)
	}, &env)

	if !env.OK {
		t.Fatalf("expected ok envelope, got %#v", env)
	}
	data := env.Data.(map[string]any)
	treasury := data["treasury"].(map[string]any)
	if ready, _ := treasury["ready_for_spending"].(bool); ready {
		t.Fatal("expected frozen treasury account to be not ready")
	}
}

func containsAll(s string, parts ...string) bool {
	for _, part := range parts {
		if !strings.Contains(s, part) {
			return false
		}
	}
	return true
}
