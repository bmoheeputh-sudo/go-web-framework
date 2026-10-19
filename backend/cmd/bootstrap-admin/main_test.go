package main

import "testing"

func TestBootstrapRequiresExplicitVerifiedTarget(t *testing.T) {
	for _, args := range [][]string{nil, {"--issuer", "issuer", "--subject", "subject"}, {"--confirm-verified-identity"}, {"--issuer", "issuer", "--subject", "subject", "--confirm-verified-identity", "extra"}} {
		if run(args, func(string) string { t.Fatal("invalid invocation accessed environment/database"); return "" }) == nil {
			t.Fatal("unconfirmed bootstrap accepted")
		}
	}
}
