package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func TestBuildLoanAcceptTermsProofAt_SignsDigest(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("BOB_CONFIG_FILE", configPath)

	agentID := "agent-proof-test"
	loanID := "loan-123"
	now := time.Date(2026, 3, 31, 12, 34, 56, 0, time.UTC)

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	cfg := cliConfig{
		AgentID: agentID,
		WalletKeyring: map[string]agentWalletKeys{
			agentID: {
				PassportEd25519PrivateKey: base64.RawURLEncoding.EncodeToString(privKey),
			},
		},
	}
	if err := writeCLIConfig(configPath, cfg); err != nil {
		t.Fatalf("writeCLIConfig: %v", err)
	}

	proof, err := buildLoanAcceptTermsProofAt(agentID, loanID, now)
	if err != nil {
		t.Fatalf("buildLoanAcceptTermsProofAt: %v", err)
	}

	canonicalJSON, ok := proof["canonical_loan_note_json"].(string)
	if !ok || canonicalJSON == "" {
		t.Fatalf("canonical_loan_note_json missing: %#v", proof)
	}
	messageHash, ok := proof["message_hash"].(string)
	if !ok || messageHash == "" {
		t.Fatalf("message_hash missing: %#v", proof)
	}
	signature, ok := proof["signature"].(string)
	if !ok || signature == "" {
		t.Fatalf("signature missing: %#v", proof)
	}

	var msg loanNoteAcceptanceMessage
	if err := json.Unmarshal([]byte(canonicalJSON), &msg); err != nil {
		t.Fatalf("canonical json unmarshal: %v", err)
	}
	if msg.LoanID != loanID || msg.AgentID != agentID {
		t.Fatalf("unexpected canonical message: %#v", msg)
	}
	if msg.AcceptedAt != now.Format(time.RFC3339) {
		t.Fatalf("unexpected accepted_at: %s", msg.AcceptedAt)
	}

	digestData := append([]byte(loanNoteSignatureDomainKey), []byte(canonicalJSON)...)
	expectedDigest := sha256.Sum256(digestData)
	if messageHash != base64.RawURLEncoding.EncodeToString(expectedDigest[:]) {
		t.Fatalf("message_hash mismatch: got=%s want=%s", messageHash, base64.RawURLEncoding.EncodeToString(expectedDigest[:]))
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if len(sigBytes) != ed25519.SignatureSize {
		t.Fatalf("signature length mismatch: got=%d want=%d", len(sigBytes), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pubKey, expectedDigest[:], sigBytes) {
		t.Fatal("signature does not verify")
	}
}

func TestRunLoanAcceptTerms_SendsSignatureProof(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("BOB_CONFIG_FILE", configPath)

	agentID := "agent-accept-terms"
	loanID := "loan-signature-1"

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	cfg := cliConfig{
		AgentID: agentID,
		WalletKeyring: map[string]agentWalletKeys{
			agentID: {
				PassportEd25519PrivateKey: base64.RawURLEncoding.EncodeToString(privKey),
			},
		},
	}
	if err := writeCLIConfig(configPath, cfg); err != nil {
		t.Fatalf("writeCLIConfig: %v", err)
	}

	postSeen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/loans/agreements":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"id": loanID, "status": "pending_terms", "borrower_agent_id": agentID},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/loans/agreements/"+loanID+"/accept-terms":
			postSeen = true
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode accept-terms body: %v", err)
			}
			canonicalJSON := body["canonical_loan_note_json"]
			msgHash := body["message_hash"]
			sig := body["signature"]
			if canonicalJSON == "" || msgHash == "" || sig == "" {
				t.Fatalf("missing required proof fields: %#v", body)
			}

			digestData := append([]byte(loanNoteSignatureDomainKey), []byte(canonicalJSON)...)
			expectedDigest := sha256.Sum256(digestData)
			if msgHash != base64.RawURLEncoding.EncodeToString(expectedDigest[:]) {
				t.Fatalf("message_hash mismatch: got=%s want=%s", msgHash, base64.RawURLEncoding.EncodeToString(expectedDigest[:]))
			}
			sigBytes, err := base64.RawURLEncoding.DecodeString(sig)
			if err != nil {
				t.Fatalf("decode signature: %v", err)
			}
			if !ed25519.Verify(pubKey, expectedDigest[:], sigBytes) {
				t.Fatal("signature verification failed")
			}

			_ = json.NewEncoder(w).Encode(map[string]any{"status": "pending_funding"})
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer server.Close()

	savedBase := apiBase
	savedKey := apiKey
	apiBase = server.URL
	apiKey = "test-api-key"
	defer func() {
		apiBase = savedBase
		apiKey = savedKey
	}()

	cmd := &cobra.Command{}
	cmd.Flags().String("agent-id", "", "Agent ID")
	if err := cmd.Flags().Set("agent-id", agentID); err != nil {
		t.Fatalf("set agent-id flag: %v", err)
	}

	if err := runLoanAcceptTerms(cmd, nil); err != nil {
		t.Fatalf("runLoanAcceptTerms: %v", err)
	}
	if !postSeen {
		t.Fatal("accept-terms POST was not called")
	}
}
