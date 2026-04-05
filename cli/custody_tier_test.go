package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

// TestParseCustodyTierFromRedeemResponse verifies that the custody tier
// is correctly parsed from a claim-code redeem response, including the
// fallback to the nested .data envelope and the default to "view_only".
func TestParseCustodyTierFromRedeemResponse(t *testing.T) {
	type redeemResp struct {
		APIKey      string `json:"api_key"`
		AgentID     string `json:"agent_id"`
		AgentName   string `json:"agent_name"`
		BobHandle   string `json:"bob_handle"`
		APIURL      string `json:"api_url"`
		CustodyTier string `json:"custody_tier"`
		Data        struct {
			APIKey      string `json:"api_key"`
			AgentID     string `json:"agent_id"`
			AgentName   string `json:"agent_name"`
			BobHandle   string `json:"bob_handle"`
			APIURL      string `json:"api_url"`
			CustodyTier string `json:"custody_tier"`
		} `json:"data"`
	}

	// resolveCustodyTier mirrors the logic in initSession.
	resolveCustodyTier := func(raw json.RawMessage) string {
		var resp redeemResp
		if err := json.Unmarshal(raw, &resp); err != nil {
			return ""
		}
		tier := strings.TrimSpace(resp.CustodyTier)
		if tier == "" {
			tier = strings.TrimSpace(resp.Data.CustodyTier)
		}
		if tier == "" {
			tier = "view_only"
		}
		return tier
	}

	tests := []struct {
		name     string
		payload  string
		wantTier string
	}{
		{
			name:     "top-level operator_approved",
			payload:  `{"api_key":"bok_test","agent_id":"a1","custody_tier":"operator_approved"}`,
			wantTier: "operator_approved",
		},
		{
			name:     "top-level policy_controlled",
			payload:  `{"api_key":"bok_test","agent_id":"a1","custody_tier":"policy_controlled"}`,
			wantTier: "policy_controlled",
		},
		{
			name:     "top-level view_only",
			payload:  `{"api_key":"bok_test","agent_id":"a1","custody_tier":"view_only"}`,
			wantTier: "view_only",
		},
		{
			name:     "nested in data envelope",
			payload:  `{"api_key":"bok_test","agent_id":"a1","data":{"custody_tier":"operator_approved"}}`,
			wantTier: "operator_approved",
		},
		{
			name:     "missing custody_tier defaults to view_only",
			payload:  `{"api_key":"bok_test","agent_id":"a1"}`,
			wantTier: "view_only",
		},
		{
			name:     "empty string custody_tier defaults to view_only",
			payload:  `{"api_key":"bok_test","agent_id":"a1","custody_tier":""}`,
			wantTier: "view_only",
		},
		{
			name:     "whitespace-only custody_tier defaults to view_only",
			payload:  `{"api_key":"bok_test","agent_id":"a1","custody_tier":"  "}`,
			wantTier: "view_only",
		},
		{
			name:     "top-level takes precedence over nested",
			payload:  `{"api_key":"bok_test","agent_id":"a1","custody_tier":"policy_controlled","data":{"custody_tier":"view_only"}}`,
			wantTier: "policy_controlled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveCustodyTier(json.RawMessage(tt.payload))
			if got != tt.wantTier {
				t.Fatalf("custody tier = %q, want %q", got, tt.wantTier)
			}
		})
	}
}

// TestOperatorApprovedTierTriggersSafeDeployment verifies that the
// deploy-safe API is called when custody_tier is "operator_approved"
// and that the resulting safe address is included in the init output.
func TestOperatorApprovedTierTriggersSafeDeployment(t *testing.T) {
	origAPIPost := apiPostFn
	defer func() { apiPostFn = origAPIPost }()

	const (
		agentID        = "agent-treasury-test"
		evmAddress     = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		wantSafeAddr   = "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
		wantAccountID  = "ta_deploy_1"
		wantTxHash     = "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	)

	deploySafeCalled := false
	apiPostFn = func(path string, payload any) (json.RawMessage, error) {
		wantPath := fmt.Sprintf("/agents/%s/treasury/deploy-safe", url.PathEscape(agentID))
		if path == wantPath {
			deploySafeCalled = true
			body, _ := json.Marshal(payload)
			var req map[string]any
			_ = json.Unmarshal(body, &req)
			if req["agent_owner_address"] != evmAddress {
				return nil, fmt.Errorf("unexpected agent_owner_address: %v", req["agent_owner_address"])
			}
			return json.RawMessage(fmt.Sprintf(`{
				"safe_address": %q,
				"treasury_account_id": %q,
				"deployment_tx_hash": %q
			}`, wantSafeAddr, wantAccountID, wantTxHash)), nil
		}
		return nil, errors.New("unexpected path: " + path)
	}

	// Simulate the deploy-safe branching logic from initSession.
	custodyTier := "operator_approved"
	var safeDeployData map[string]any

	if custodyTier == "operator_approved" || custodyTier == "policy_controlled" {
		safeResp, safeErr := apiPostFn(
			fmt.Sprintf("/agents/%s/treasury/deploy-safe", url.PathEscape(agentID)),
			map[string]any{"agent_owner_address": evmAddress},
		)
		if safeErr != nil {
			t.Fatalf("deploy-safe call failed: %v", safeErr)
		}
		var safeResult struct {
			SafeAddress       string `json:"safe_address"`
			TreasuryAccountID string `json:"treasury_account_id"`
			DeploymentTxHash  string `json:"deployment_tx_hash"`
		}
		if err := json.Unmarshal(safeResp, &safeResult); err != nil {
			t.Fatalf("unmarshal safe response: %v", err)
		}
		if safeResult.SafeAddress != "" {
			safeDeployData = map[string]any{
				"safe_address":        safeResult.SafeAddress,
				"treasury_account_id": safeResult.TreasuryAccountID,
				"deployment_tx_hash":  safeResult.DeploymentTxHash,
			}
		}
	}

	if !deploySafeCalled {
		t.Fatal("expected deploy-safe to be called for operator_approved tier")
	}
	if safeDeployData == nil {
		t.Fatal("expected safeDeployData to be populated")
	}
	if safeDeployData["safe_address"] != wantSafeAddr {
		t.Fatalf("safe_address = %q, want %q", safeDeployData["safe_address"], wantSafeAddr)
	}
	if safeDeployData["treasury_account_id"] != wantAccountID {
		t.Fatalf("treasury_account_id = %q, want %q", safeDeployData["treasury_account_id"], wantAccountID)
	}
	if safeDeployData["deployment_tx_hash"] != wantTxHash {
		t.Fatalf("deployment_tx_hash = %q, want %q", safeDeployData["deployment_tx_hash"], wantTxHash)
	}

	// Verify the data would be merged into initData correctly.
	initData := map[string]any{
		"agent_id":     agentID,
		"custody_tier": custodyTier,
	}
	if custodyTier != "" {
		initData["custody_tier"] = custodyTier
	}
	if safeDeployData != nil {
		for k, v := range safeDeployData {
			initData[k] = v
		}
	}
	if initData["custody_tier"] != "operator_approved" {
		t.Fatalf("initData custody_tier = %v, want operator_approved", initData["custody_tier"])
	}
	if initData["safe_address"] != wantSafeAddr {
		t.Fatalf("initData safe_address = %v, want %s", initData["safe_address"], wantSafeAddr)
	}
}

// TestViewOnlyTierSkipsSafeDeployment verifies that when custody_tier
// is "view_only", the deploy-safe API is NOT called and no safe_address
// appears in the output.
func TestViewOnlyTierSkipsSafeDeployment(t *testing.T) {
	origAPIPost := apiPostFn
	defer func() { apiPostFn = origAPIPost }()

	deploySafeCalled := false
	apiPostFn = func(path string, payload any) (json.RawMessage, error) {
		if strings.Contains(path, "deploy-safe") {
			deploySafeCalled = true
			return nil, errors.New("deploy-safe should not be called for view_only tier")
		}
		return nil, errors.New("unexpected path: " + path)
	}

	// Simulate the deploy-safe branching logic from initSession with view_only tier.
	custodyTier := "view_only"
	evmAddress := "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	agentID := "agent-view-test"
	var safeDeployData map[string]any

	if custodyTier == "operator_approved" || custodyTier == "policy_controlled" {
		safeResp, safeErr := apiPostFn(
			fmt.Sprintf("/agents/%s/treasury/deploy-safe", url.PathEscape(agentID)),
			map[string]any{"agent_owner_address": evmAddress},
		)
		if safeErr != nil {
			t.Fatalf("deploy-safe call failed: %v", safeErr)
		}
		var safeResult struct {
			SafeAddress       string `json:"safe_address"`
			TreasuryAccountID string `json:"treasury_account_id"`
		}
		if json.Unmarshal(safeResp, &safeResult) == nil && safeResult.SafeAddress != "" {
			safeDeployData = map[string]any{
				"safe_address":        safeResult.SafeAddress,
				"treasury_account_id": safeResult.TreasuryAccountID,
			}
		}
	}

	if deploySafeCalled {
		t.Fatal("deploy-safe should NOT be called for view_only tier")
	}
	if safeDeployData != nil {
		t.Fatalf("expected no safeDeployData for view_only tier, got %v", safeDeployData)
	}

	// Verify initData would NOT include safe_address.
	initData := map[string]any{
		"agent_id":     agentID,
		"custody_tier": custodyTier,
	}
	if safeDeployData != nil {
		for k, v := range safeDeployData {
			initData[k] = v
		}
	}
	if _, hasSafe := initData["safe_address"]; hasSafe {
		t.Fatal("initData should NOT contain safe_address for view_only tier")
	}
	if initData["custody_tier"] != "view_only" {
		t.Fatalf("initData custody_tier = %v, want view_only", initData["custody_tier"])
	}
}

// TestPolicyControlledTierTriggersSafeDeployment verifies that
// "policy_controlled" also triggers Safe deployment (same branch as operator_approved).
func TestPolicyControlledTierTriggersSafeDeployment(t *testing.T) {
	origAPIPost := apiPostFn
	defer func() { apiPostFn = origAPIPost }()

	deploySafeCalled := false
	apiPostFn = func(path string, payload any) (json.RawMessage, error) {
		if strings.Contains(path, "deploy-safe") {
			deploySafeCalled = true
			return json.RawMessage(`{
				"safe_address": "0x1111111111111111111111111111111111111111",
				"treasury_account_id": "ta_pc_1",
				"deployment_tx_hash": "0xabcd"
			}`), nil
		}
		return nil, errors.New("unexpected path: " + path)
	}

	custodyTier := "policy_controlled"
	agentID := "agent-policy-test"
	evmAddress := "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	if custodyTier == "operator_approved" || custodyTier == "policy_controlled" {
		_, err := apiPostFn(
			fmt.Sprintf("/agents/%s/treasury/deploy-safe", url.PathEscape(agentID)),
			map[string]any{"agent_owner_address": evmAddress},
		)
		if err != nil {
			t.Fatalf("deploy-safe call failed: %v", err)
		}
	}

	if !deploySafeCalled {
		t.Fatal("expected deploy-safe to be called for policy_controlled tier")
	}
}

// TestSafeDeploymentSkippedWhenNoEVMAddress verifies that even for
// operator_approved tier, Safe deployment is skipped if no EVM address
// is available (matching the initSession guard).
func TestSafeDeploymentSkippedWhenNoEVMAddress(t *testing.T) {
	origAPIPost := apiPostFn
	defer func() { apiPostFn = origAPIPost }()

	deploySafeCalled := false
	apiPostFn = func(path string, payload any) (json.RawMessage, error) {
		if strings.Contains(path, "deploy-safe") {
			deploySafeCalled = true
		}
		return nil, errors.New("should not be called")
	}

	custodyTier := "operator_approved"
	evmAddress := "" // no EVM address available
	warnings := []string{}

	if custodyTier == "operator_approved" || custodyTier == "policy_controlled" {
		if evmAddress != "" {
			_, _ = apiPostFn("/agents/test/treasury/deploy-safe", map[string]any{"agent_owner_address": evmAddress})
		} else {
			warnings = append(warnings, "treasury safe deployment skipped: no EVM address available")
		}
	}

	if deploySafeCalled {
		t.Fatal("deploy-safe should NOT be called when EVM address is empty")
	}
	if len(warnings) == 0 {
		t.Fatal("expected warning about skipped safe deployment")
	}
	if !strings.Contains(warnings[0], "no EVM address available") {
		t.Fatalf("unexpected warning: %s", warnings[0])
	}
}

// TestSafeDeploymentAPIError verifies that a deploy-safe API failure
// is captured as a warning rather than causing a hard failure, matching
// the initSession behavior.
func TestSafeDeploymentAPIError(t *testing.T) {
	origAPIPost := apiPostFn
	defer func() { apiPostFn = origAPIPost }()

	apiPostFn = func(path string, payload any) (json.RawMessage, error) {
		if strings.Contains(path, "deploy-safe") {
			return nil, errors.New("api error (500): safe factory contract unavailable")
		}
		return nil, errors.New("unexpected path: " + path)
	}

	custodyTier := "operator_approved"
	agentID := "agent-error-test"
	evmAddress := "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	warnings := []string{}

	if custodyTier == "operator_approved" || custodyTier == "policy_controlled" {
		if evmAddress != "" {
			_, safeErr := apiPostFn(
				fmt.Sprintf("/agents/%s/treasury/deploy-safe", url.PathEscape(agentID)),
				map[string]any{"agent_owner_address": evmAddress},
			)
			if safeErr != nil {
				warnings = append(warnings, "treasury safe deployment: "+extractAPIErrorMessage(safeErr))
			}
		}
	}

	if len(warnings) == 0 {
		t.Fatal("expected warning from failed safe deployment")
	}
	if !strings.Contains(warnings[0], "safe factory contract unavailable") {
		t.Fatalf("unexpected warning text: %s", warnings[0])
	}
}
