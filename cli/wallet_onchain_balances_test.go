package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestRunWalletOnchainBalances(t *testing.T) {
	origAPIBase := apiBase
	t.Cleanup(func() {
		apiBase = origAPIBase
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected method %s", r.Method)
		}
		if r.URL.Path != "/agents/agent-1/onchain-balances" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"wallets":[{"wallet_id":"w1","address":"0xabc","rail":"evm","stale":false,"balances":[{"chain_id":"0x2105","symbol":"ETH","balance":"1000000000000000","decimals":18}]}]}`))
	}))
	defer server.Close()
	apiBase = server.URL

	cmd := walletCmd()
	cmd.SetArgs([]string{"onchain-balances", "--agent-id", "agent-1"})

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
	if env.Command != "bob wallet onchain-balances" {
		t.Fatalf("unexpected command %q", env.Command)
	}
	data, ok := env.Data.(map[string]any)
	if !ok {
		t.Fatalf("unexpected data shape %#v", env.Data)
	}
	if data["agent_id"] != "agent-1" {
		t.Fatalf("unexpected agent_id %#v", data["agent_id"])
	}
	if len(env.NextActions) != 3 {
		t.Fatalf("unexpected next actions %#v", env.NextActions)
	}
}

func TestRunWalletOnchainBalances_NoAgentID(t *testing.T) {
	cmd := walletCmd()
	cmd.SetArgs([]string{"onchain-balances"})

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
	if env.Command != "bob wallet onchain-balances" {
		t.Fatalf("unexpected command %q", env.Command)
	}
}
