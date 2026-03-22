package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthKeyBindDigest(t *testing.T) {
	message := `{"kind":"agent_auth_key_bind","agent_id":"test-agent","nonce":"abc123","issued_at":"2026-03-21T00:00:00Z","expires_at":"2026-03-21T00:05:00Z"}`

	data := append([]byte(authKeyBindDomainPrefix), []byte(message)...)
	digest := sha256.Sum256(data)

	// Must be 32 bytes (SHA256)
	if len(digest) != 32 {
		t.Fatalf("digest should be 32 bytes, got %d", len(digest))
	}

	// Must be deterministic
	data2 := append([]byte(authKeyBindDomainPrefix), []byte(message)...)
	digest2 := sha256.Sum256(data2)
	if digest != digest2 {
		t.Fatal("digest should be deterministic")
	}

	// Different message = different digest
	data3 := append([]byte(authKeyBindDomainPrefix), []byte(message+"x")...)
	digest3 := sha256.Sum256(data3)
	if digest == digest3 {
		t.Fatal("different messages should produce different digests")
	}
}

func TestEd25519KeyGenAndSign(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}

	if len(pubKey) != ed25519.PublicKeySize {
		t.Fatalf("public key should be %d bytes, got %d", ed25519.PublicKeySize, len(pubKey))
	}

	// Sign a challenge digest
	message := `{"kind":"agent_auth_key_bind","agent_id":"test","nonce":"xyz"}`
	data := append([]byte(authKeyBindDomainPrefix), []byte(message)...)
	digest := sha256.Sum256(data)
	sig := ed25519.Sign(privKey, digest[:])

	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("signature should be %d bytes, got %d", ed25519.SignatureSize, len(sig))
	}

	// Verify with correct key
	if !ed25519.Verify(pubKey, digest[:], sig) {
		t.Fatal("signature should verify with correct key")
	}

	// Verify with wrong key should fail
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if ed25519.Verify(otherPub, digest[:], sig) {
		t.Fatal("signature should NOT verify with wrong key")
	}
}

func TestPublicKeyBase64Encoding(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}

	encoded := base64.RawURLEncoding.EncodeToString(pubKey)
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("base64 decode failed: %v", err)
	}

	if len(decoded) != ed25519.PublicKeySize {
		t.Fatalf("decoded key should be %d bytes, got %d", ed25519.PublicKeySize, len(decoded))
	}

	for i := range pubKey {
		if pubKey[i] != decoded[i] {
			t.Fatalf("decoded key doesn't match at byte %d", i)
		}
	}
}

func TestAutoBindAndIssuePassport_MockServer(t *testing.T) {
	// Mock API server that handles challenge, verify, and issue
	challengeCount := 0
	verifyCount := 0
	issueCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && contains(r.URL.Path, "/auth-key/challenge"):
			challengeCount++
			msg := map[string]any{
				"kind":       "agent_auth_key_bind",
				"agent_id":   "test-agent",
				"nonce":      "test-nonce-123",
				"issued_at":  "2026-03-21T00:00:00Z",
				"expires_at": "2026-03-21T00:05:00Z",
			}
			json.NewEncoder(w).Encode(map[string]any{
				"challenge_id": "ch_test",
				"message":      msg,
			})

		case r.Method == "POST" && contains(r.URL.Path, "/auth-key/verify"):
			verifyCount++
			// Validate request has expected fields
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			if body["challenge_id"] != "ch_test" {
				t.Errorf("expected challenge_id=ch_test, got %v", body["challenge_id"])
			}
			if body["signature"] == nil || body["signature"] == "" {
				t.Error("signature should be present")
			}
			keyMap, ok := body["key"].(map[string]any)
			if !ok {
				t.Error("key should be a map")
			} else {
				if keyMap["alg"] != "Ed25519" {
					t.Errorf("expected alg=Ed25519, got %v", keyMap["alg"])
				}
			}
			json.NewEncoder(w).Encode(map[string]any{
				"id":       "key-1",
				"agent_id": "test-agent",
				"status":   "active",
			})

		case r.Method == "POST" && contains(r.URL.Path, "/credential"):
			issueCount++
			json.NewEncoder(w).Encode(map[string]any{
				"@context": []string{"https://www.w3.org/ns/credentials/v2"},
				"id":       "did:bob:passport:test-agent:123",
				"type":     []string{"VerifiableCredential", "BoBAgentPassport"},
			})

		default:
			http.Error(w, "not found", 404)
		}
	}))
	defer server.Close()

	// Point global vars at mock server
	savedBase := apiBase
	savedKey := apiKey
	apiBase = server.URL
	apiKey = "test-key"
	defer func() {
		apiBase = savedBase
		apiKey = savedKey
	}()

	result := autoBindAndIssuePassport("test-agent")
	if result != "" {
		t.Fatalf("autoBindAndIssuePassport should succeed, got warning: %s", result)
	}

	if challengeCount != 1 {
		t.Errorf("expected 1 challenge call, got %d", challengeCount)
	}
	if verifyCount != 1 {
		t.Errorf("expected 1 verify call, got %d", verifyCount)
	}
	if issueCount != 1 {
		t.Errorf("expected 1 issue call, got %d", issueCount)
	}
}

func TestAutoBindAndIssuePassport_ChallengeFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"agent not found"}`, 404)
	}))
	defer server.Close()

	savedBase := apiBase
	savedKey := apiKey
	apiBase = server.URL
	apiKey = "test-key"
	defer func() {
		apiBase = savedBase
		apiKey = savedKey
	}()

	result := autoBindAndIssuePassport("nonexistent-agent")
	if result == "" {
		t.Fatal("should return a warning on failure")
	}
	if !contains(result, "challenge failed") {
		t.Errorf("warning should mention challenge failure, got: %s", result)
	}
}

func TestAutoBindAndIssuePassport_VerifyFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if contains(r.URL.Path, "/auth-key/challenge") {
			msg := map[string]any{
				"kind": "agent_auth_key_bind", "agent_id": "test", "nonce": "n",
				"issued_at": "2026-03-21T00:00:00Z", "expires_at": "2026-03-21T00:05:00Z",
			}
			json.NewEncoder(w).Encode(map[string]any{"challenge_id": "ch_test", "message": msg})
			return
		}
		if contains(r.URL.Path, "/auth-key/verify") {
			http.Error(w, `{"error":"signature verification failed"}`, 422)
			return
		}
		http.Error(w, "not found", 404)
	}))
	defer server.Close()

	savedBase := apiBase
	savedKey := apiKey
	apiBase = server.URL
	apiKey = "test-key"
	defer func() {
		apiBase = savedBase
		apiKey = savedKey
	}()

	result := autoBindAndIssuePassport("test-agent")
	if result == "" {
		t.Fatal("should return a warning on verify failure")
	}
	if !contains(result, "verify failed") {
		t.Errorf("warning should mention verify failure, got: %s", result)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func init() {
	// Suppress fmt.Fprintf(os.Stderr, ...) noise during tests
	_ = fmt.Sprint("")
}
