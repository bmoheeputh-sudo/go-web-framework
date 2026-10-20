package main

import (
	"strings"
	"testing"
)

func TestBootstrapAccessPolicyRequiresExplicitScopeAndProof(t *testing.T) {
	secret := strings.Repeat("s", 43)
	valid := []string{"--expected-activation-generation", "1", "--mode", "approved_users_only", "--default-role", "Viewer", "--reason", "planned policy rollout", "--confirm"}
	for _, args := range [][]string{nil, valid[:len(valid)-1], append(append([]string{}, valid...), "--issuer", "untrusted"), valid} {
		err := run(args, func(string) string { return "" }, strings.NewReader(secret))
		if err == nil || strings.Contains(err.Error(), secret) {
			t.Fatal("missing authorization/scope accepted or secret exposed")
		}
	}
}
