package main

import "testing"

func TestCommandTreeBindingCommandsCanonicalOnly(t *testing.T) {
	tree := commandTree()

	var binding *CommandInfo
	for i := range tree.Children {
		if tree.Children[i].Name == "binding" {
			binding = &tree.Children[i]
			break
		}
	}
	if binding == nil {
		t.Fatalf("binding command not found in command tree")
	}

	foundChallenge := false
	foundVerify := false
	for _, child := range binding.Children {
		switch child.Name {
		case "challenge":
			foundChallenge = true
		case "verify":
			foundVerify = true
		case "evm-challenge", "evm-verify":
			t.Fatalf("legacy binding alias %q should not be present", child.Name)
		}
	}

	if !foundChallenge || !foundVerify {
		t.Fatalf("expected canonical binding commands challenge+verify, got challenge=%v verify=%v", foundChallenge, foundVerify)
	}
}

func TestNormalizeBindingRail(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "evm", want: "evm"},
		{in: "btc", want: "btc"},
		{in: "bitcoin", want: "btc"},
		{in: "sol", want: "solana"},
		{in: "solana", want: "solana"},
		{in: "  SOL  ", want: "solana"},
		{in: "lightning", wantErr: true},
		{in: "", wantErr: true},
	}

	for _, tc := range tests {
		got, err := normalizeBindingRail(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("normalizeBindingRail(%q): expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("normalizeBindingRail(%q): unexpected error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("normalizeBindingRail(%q): got %q, want %q", tc.in, got, tc.want)
		}
	}
}

