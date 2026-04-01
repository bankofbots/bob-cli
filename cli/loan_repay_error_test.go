package main

import (
	"errors"
	"strings"
	"testing"
)

func TestAnnotateLoanRepaymentError_AddsBaseGasHint(t *testing.T) {
	err := annotateLoanRepaymentError(
		errors.New("on-chain transfer failed: send transaction: insufficient funds for gas * price + value"),
		"0x2105",
		"0x7AB2564D9F1ab6D384e9d1502962869f01dE50AB",
	)
	if err == nil {
		t.Fatal("expected annotated error")
	}
	got := err.Error()
	if !strings.Contains(got, "ETH on Base (chain ID 8453)") {
		t.Fatalf("expected Base gas hint, got %q", got)
	}
	if !strings.Contains(got, "0x7AB2564D9F1ab6D384e9d1502962869f01dE50AB") {
		t.Fatalf("expected borrower wallet in hint, got %q", got)
	}
}

func TestAnnotateLoanRepaymentError_PassesThroughOtherErrors(t *testing.T) {
	orig := errors.New("estimate gas: execution reverted")
	got := annotateLoanRepaymentError(orig, "0x2105", "0xabc")
	if got == nil || got.Error() != orig.Error() {
		t.Fatalf("expected passthrough error, got %#v", got)
	}
}
