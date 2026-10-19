package auth

import (
	"errors"
	"net/http/httptest"
	"testing"
)

func localConfig() LocalDevConfig {
	return LocalDevConfig{Subject: "dev-1", Email: "dev@example.invalid", DisplayName: "Local Developer"}
}

func TestLocalDevRequiresDevelopment(t *testing.T) {
	for _, environment := range []string{"", "test", "TEST", "prd", "PRD", "production", "staging", "dev", "Development", "development "} {
		t.Run(environment, func(t *testing.T) {
			if _, err := NewLocalDev(environment, localConfig()); err == nil {
				t.Fatal("non-development environment accepted")
			}
		})
	}
}

func TestLocalDevRequiresConfiguredIdentity(t *testing.T) {
	for _, config := range []LocalDevConfig{
		{}, {Email: "dev@example.invalid", DisplayName: "Dev"},
		{Subject: "dev", DisplayName: "Dev"}, {Subject: "dev", Email: "dev@example.invalid"},
		{Subject: "dev", Email: "invalid", DisplayName: "Dev"},
	} {
		if _, err := NewLocalDev("development", config); err == nil {
			t.Errorf("invalid local identity accepted: %+v", config)
		}
	}
}

func TestLocalDevUsesOnlyServerIdentity(t *testing.T) {
	config := localConfig()
	provider, err := NewLocalDev("development", config)
	if err != nil {
		t.Fatal(err)
	}
	config.Subject = "mutated-after-construction"
	request := httptest.NewRequest("GET", "/api/auth/me?subject=attacker&email=attacker@example.invalid", nil)
	request.RemoteAddr = "127.0.0.1:50000"
	request.Header.Set("Authorization", "Bearer arbitrary-client-token")
	request.Header.Set("X-Goog-Authenticated-User-Email", "attacker@example.invalid")
	request.Header.Set("X-Goog-IAP-JWT-Assertion", "unverified-assertion")
	request.Header.Set("X-User-ID", "attacker")
	request.Header.Set("Cookie", "subject=attacker; session=forged")
	identity, err := provider.Authenticate(request)
	if err != nil {
		t.Fatal(err)
	}
	want := Identity{Issuer: LocalDevIssuer, Subject: "dev-1", Email: "dev@example.invalid",
		DisplayName: "Local Developer", Provider: LocalDev, EmailVerified: false}
	if identity != want {
		t.Fatalf("identity = %+v; want %+v", identity, want)
	}
	identity.Subject = "mutated-return-value"
	again, err := provider.Authenticate(request)
	if err != nil || again != want {
		t.Fatalf("identity changed: %+v, %v", again, err)
	}
}

func TestLocalDevAcceptsOnlyLoopbackPeers(t *testing.T) {
	provider, err := NewLocalDev("development", localConfig())
	if err != nil {
		t.Fatal(err)
	}
	for _, peer := range []string{"127.0.0.1:1234", "[::1]:1234", "[::ffff:127.0.0.1]:1234"} {
		request := httptest.NewRequest("GET", "/", nil)
		request.RemoteAddr = peer
		if _, err := provider.Authenticate(request); err != nil {
			t.Errorf("%s: %v", peer, err)
		}
	}
	for _, peer := range []string{"192.0.2.1:1234", "[2001:db8::1]:1234", "localhost:1234", "", "127.0.0.1"} {
		request := httptest.NewRequest("GET", "/", nil)
		request.RemoteAddr = peer
		request.Header.Set("X-Forwarded-For", "127.0.0.1")
		request.Header.Set("Forwarded", "for=127.0.0.1")
		if _, err := provider.Authenticate(request); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("non-loopback peer %q accepted: %v", peer, err)
		}
	}
}

func TestZeroValueLocalDevCannotAuthenticate(t *testing.T) {
	request := httptest.NewRequest("GET", "/", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	if _, err := new(LocalDevAuthenticator).Authenticate(request); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("unconfigured provider authenticated a request")
	}
}
