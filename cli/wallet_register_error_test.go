package main

import (
	"errors"
	"strings"
	"testing"
)

// classifyWalletRegisterError maps wallet-registration errors from the BOB API
// into user-facing warnings. These tests cover the branches that produce
// actionable guidance in `bob init` output — especially the recovery-key
// branch, whose case-insensitive matching guards against setup-blocking
// regressions if the API capitalizes "Recovery key required" differently.

func TestClassifyWalletRegisterError_Nil(t *testing.T) {
	if got := classifyWalletRegisterError("evm", nil); got != "" {
		t.Errorf("nil err should return empty string, got %q", got)
	}
}

func TestClassifyWalletRegisterError_409Duplicate(t *testing.T) {
	// 409 = already registered, expected on re-init. Must suppress.
	err := &APIError{StatusCode: 409, Body: `{"error":"wallet already registered"}`}
	if got := classifyWalletRegisterError("evm", err); got != "" {
		t.Errorf("409 should return empty (suppressed), got %q", got)
	}
}

func TestClassifyWalletRegisterError_401Auth(t *testing.T) {
	err := &APIError{StatusCode: 401, Body: "unauthorized"}
	got := classifyWalletRegisterError("evm", err)
	if !strings.Contains(got, "401") || !strings.Contains(got, "API key") {
		t.Errorf("401 branch should mention the status and API key hint, got %q", got)
	}
}

func TestClassifyWalletRegisterError_403Forbidden(t *testing.T) {
	err := &APIError{StatusCode: 403, Body: `{"error":"signature rejected"}`, Message: "signature rejected"}
	got := classifyWalletRegisterError("evm", err)
	if !strings.Contains(got, "403") || !strings.Contains(got, "signature rejected") {
		t.Errorf("403 branch should include status + server message, got %q", got)
	}
}

func TestClassifyWalletRegisterError_400RecoveryKey_Lowercase(t *testing.T) {
	// Current API phrasing: "operator recovery key required: generate one..."
	err := &APIError{
		StatusCode: 400,
		Body:       `{"error":"operator recovery key required: generate one in the dashboard before connecting this agent"}`,
		Message:    "operator recovery key required: generate one in the dashboard before connecting this agent",
	}
	got := classifyWalletRegisterError("evm", err)
	if !strings.Contains(got, "recovery key") {
		t.Errorf("recovery-key branch should surface the server message, got %q", got)
	}
	if !strings.Contains(got, "dashboard and generate a recovery key") {
		t.Errorf("recovery-key branch should include actionable guidance, got %q", got)
	}
}

func TestClassifyWalletRegisterError_400RecoveryKey_Capitalized(t *testing.T) {
	// Regression guard: if the API ever returns "Recovery key required" with a
	// capital R, the case-insensitive check must still route to the guidance
	// branch. Without this, users miss the dashboard-generate step entirely.
	err := &APIError{
		StatusCode: 400,
		Body:       `{"error":"Recovery key required"}`,
		Message:    "Recovery key required",
	}
	got := classifyWalletRegisterError("evm", err)
	if !strings.Contains(got, "dashboard and generate a recovery key") {
		t.Errorf("capitalized 'Recovery key' must still trigger guidance branch, got %q", got)
	}
}

func TestClassifyWalletRegisterError_400OtherBadRequest(t *testing.T) {
	// 400s unrelated to recovery key fall through to the generic 400 message,
	// NOT the recovery-key guidance.
	err := &APIError{
		StatusCode: 400,
		Body:       `{"error":"missing signature"}`,
		Message:    "missing signature",
	}
	got := classifyWalletRegisterError("evm", err)
	if strings.Contains(got, "dashboard and generate a recovery key") {
		t.Errorf("non-recovery-key 400 must not emit recovery-key guidance, got %q", got)
	}
	if !strings.Contains(got, "400") || !strings.Contains(got, "missing signature") {
		t.Errorf("generic 400 branch should surface status + server message, got %q", got)
	}
}

func TestClassifyWalletRegisterError_UnknownError(t *testing.T) {
	// Non-HTTP error (e.g., network) falls through to the default branch.
	err := errors.New("connection refused")
	got := classifyWalletRegisterError("evm", err)
	if !strings.Contains(got, "connection refused") {
		t.Errorf("default branch should surface the error, got %q", got)
	}
}
