package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/spf13/cobra"
)

func TestLoanCommandWithAgent(t *testing.T) {
	if got := loanCommandWithAgent("bob loan list", "agent_123"); got != "bob loan list --agent-id agent_123" {
		t.Fatalf("unexpected command with agent: %q", got)
	}
	if got := loanCommandWithAgent("bob loan list", ""); got != "bob loan list" {
		t.Fatalf("unexpected command without agent: %q", got)
	}
}

func TestEmitLoanPolicyError_RecognizedPatterns(t *testing.T) {
	cases := []struct {
		name                string
		command             string
		errMsg              string
		agentID             string
		wantFirstActionCmd  string
		wantSecondActionCmd string
	}{
		{
			name:               "active loan cap",
			command:            "bob loan request",
			errMsg:             `api error (409): {"error":"agent has 5 active loans — maximum is 5"}`,
			agentID:            "agent_123",
			wantFirstActionCmd: "bob loan list --agent-id agent_123",
		},
		{
			name:               "recent defaults",
			command:            "bob loan request",
			errMsg:             `api error (403): {"error":"borrower has recent loan defaults — new loans locked out for 90 days after default"}`,
			agentID:            "agent_123",
			wantFirstActionCmd: "bob loan list --agent-id agent_123",
		},
		{
			name:               "facility limit",
			command:            "bob loan request",
			errMsg:             `api error (400): {"error":"amount exceeds facility limit (100.00 USDC)"}`,
			agentID:            "agent_123",
			wantFirstActionCmd: "bob auth me",
		},
		{
			name:               "facility suspended",
			command:            "bob loan request",
			errMsg:             `api error (403): {"error":"operator credit facility is suspended"}`,
			agentID:            "agent_123",
			wantFirstActionCmd: "bob auth me",
		},
		{
			name:               "kill switch frozen",
			command:            "bob loan request",
			errMsg:             `api error (403): {"error":"agent is frozen — all transactions suspended by operator or BOB"}`,
			agentID:            "agent_123",
			wantFirstActionCmd: "bob loan list --agent-id agent_123",
		},
		{
			name:                "verify operator facility transient",
			command:             "bob loan request --amount 10",
			errMsg:              `api error (503): {"error":"unable to verify operator facility — try again later"}`,
			agentID:             "agent_123",
			wantFirstActionCmd:  "bob loan request --amount 10",
			wantSecondActionCmd: "bob auth me",
		},
	}
	for _, tc := range cases {
		env, ok := emitLoanPolicyAndCapture(t, tc.command, simpleErr(tc.errMsg), tc.agentID)
		if !ok {
			t.Fatalf("%s: expected recognized policy error for: %s", tc.name, tc.errMsg)
		}
		if len(env.NextActions) == 0 {
			t.Fatalf("%s: expected at least one next action", tc.name)
		}
		if env.NextActions[0].Command != tc.wantFirstActionCmd {
			t.Fatalf("%s: first next action mismatch: got %q want %q", tc.name, env.NextActions[0].Command, tc.wantFirstActionCmd)
		}
		if tc.wantSecondActionCmd != "" {
			if len(env.NextActions) < 2 {
				t.Fatalf("%s: expected at least two next actions", tc.name)
			}
			if env.NextActions[1].Command != tc.wantSecondActionCmd {
				t.Fatalf("%s: second next action mismatch: got %q want %q", tc.name, env.NextActions[1].Command, tc.wantSecondActionCmd)
			}
		}
	}
}

func TestEmitLoanPolicyError_UnknownPattern(t *testing.T) {
	if ok := emitLoanPolicyError("bob loan request", simpleErr(`api error (500): {"error":"boom"}`), "agent_123"); ok {
		t.Fatal("expected unknown error to return false")
	}
}

func TestEmitLoanPolicyError_LockedOutNonLoanMessageNotRecognized(t *testing.T) {
	if ok := emitLoanPolicyError("bob loan request", simpleErr(`api error (403): {"error":"account locked out after repeated auth failures"}`), "agent_123"); ok {
		t.Fatal("expected non-loan locked-out message to return false")
	}
}

func TestEmitLoanPolicyError_TransientVerificationPrecedence(t *testing.T) {
	command := "bob loan request --amount 10"
	env, ok := emitLoanPolicyAndCapture(t, command, simpleErr(`api error (503): {"error":"unable to verify operator facility — try again later"}`), "agent_123")
	if !ok {
		t.Fatal("expected recognized transient verification error")
	}
	if len(env.NextActions) == 0 {
		t.Fatal("expected next actions")
	}
	if env.NextActions[0].Command != command {
		t.Fatalf("expected retry action to be first, got %q", env.NextActions[0].Command)
	}
}

func TestEmitLoanPolicyError_RepayCommandWithoutAgentID(t *testing.T) {
	env, ok := emitLoanPolicyAndCapture(t, "bob loan request", simpleErr(`api error (409): {"error":"agent has 5 active loans — maximum is 5"}`), "")
	if !ok {
		t.Fatal("expected recognized policy error")
	}
	if len(env.NextActions) < 2 {
		t.Fatalf("expected at least two next actions, got %d", len(env.NextActions))
	}
	got := env.NextActions[1].Command
	want := "bob loan repay <loan-id> --amount <usdc>"
	if got != want {
		t.Fatalf("unexpected repay command without agent id: got %q want %q", got, want)
	}
}

func emitLoanPolicyAndCapture(t *testing.T, command string, err error, agentID string) (Envelope, bool) {
	t.Helper()
	oldStdout := os.Stdout
	r, w, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatalf("pipe create failed: %v", pipeErr)
	}
	os.Stdout = w

	ok := emitLoanPolicyError(command, err, agentID)

	_ = w.Close()
	os.Stdout = oldStdout

	if !ok {
		_ = r.Close()
		return Envelope{}, false
	}

	var env Envelope
	if decodeErr := json.NewDecoder(r).Decode(&env); decodeErr != nil {
		_ = r.Close()
		t.Fatalf("failed to decode emitted envelope: %v", decodeErr)
	}
	_ = r.Close()
	return env, true
}

type simpleErr string

func (e simpleErr) Error() string { return string(e) }

// TestRunLoanRequestCancel_PolicyErrorRouting exercises the command path:
// apiDelete returns a policy error → emitLoanPolicyError routes it → NextActions emitted.
func TestRunLoanRequestCancel_PolicyErrorRouting(t *testing.T) {
	// Mock API server that returns a 409 policy error on DELETE.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			fmt.Fprint(w, `{"error":"agent has 5 active loans — maximum is 5"}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	// Swap package-level globals to point at mock server.
	origBase := apiBase
	origKey := apiKey
	apiBase = srv.URL
	apiKey = "test-key"
	defer func() {
		apiBase = origBase
		apiKey = origKey
	}()

	// Capture stdout — runLoanRequestCancel emits JSON to stdout.
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	// Create a minimal cobra command with the --agent-id flag.
	cmd := &cobra.Command{}
	cmd.Flags().String("agent-id", "agent-test", "")
	_ = runLoanRequestCancel(cmd, []string{"req-123"})

	_ = w.Close()
	os.Stdout = oldStdout

	var env Envelope
	if err := json.NewDecoder(r).Decode(&env); err != nil {
		t.Fatalf("failed to decode output: %v", err)
	}
	_ = r.Close()

	if env.OK {
		t.Fatal("expected ok=false for policy error")
	}
	if env.Command != "bob loan request-cancel" {
		t.Fatalf("unexpected command: %q", env.Command)
	}
	if len(env.NextActions) == 0 {
		t.Fatal("expected NextActions from emitLoanPolicyError routing")
	}
}
