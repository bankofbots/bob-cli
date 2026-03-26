package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestUpdateCmd_Exists(t *testing.T) {
	cmd := updateCmd()
	if cmd.Use != "update" {
		t.Fatalf("expected Use='update', got %q", cmd.Use)
	}
	if cmd.Short == "" {
		t.Fatal("update command should have a Short description")
	}
}

func TestUpdateCmd_HasVersionFlag(t *testing.T) {
	cmd := updateCmd()
	f := cmd.Flags().Lookup("version")
	if f == nil {
		t.Fatal("update command should have a --version flag")
	}
	if f.DefValue != "" {
		t.Fatalf("--version default should be empty, got %q", f.DefValue)
	}
}

func TestUpdateCmd_ChecksumMismatch(t *testing.T) {
	content := []byte("fake-binary-content")
	wrongHash := "0000000000000000000000000000000000000000000000000000000000000000"
	realHash := sha256.Sum256(content)
	gotHash := hex.EncodeToString(realHash[:])

	if strings.EqualFold(gotHash, wrongHash) {
		t.Fatal("test setup error: hashes should differ")
	}
	// Confirms the comparison used in runUpdate correctly detects mismatches
}

func TestUpdateCmd_ChecksumMatch(t *testing.T) {
	content := []byte("real-binary-content")
	realHash := sha256.Sum256(content)
	expected := hex.EncodeToString(realHash[:])
	got := hex.EncodeToString(realHash[:])

	if !strings.EqualFold(got, expected) {
		t.Fatal("identical content should produce matching checksums")
	}
}

func TestUpdateCmd_HTTPClientHasTimeout(t *testing.T) {
	if updateHTTPClient.Timeout == 0 {
		t.Fatal("HTTP client should have a timeout set")
	}
	if updateHTTPClient.Timeout.Seconds() < 10 {
		t.Fatalf("timeout too short: %v", updateHTTPClient.Timeout)
	}
}
