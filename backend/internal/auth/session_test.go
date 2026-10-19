package auth

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionTimeoutConfiguration(t *testing.T) {
	for _, values := range []map[string]string{
		{}, {"SESSION_IDLE_TIMEOUT": "15m", "SESSION_ABSOLUTE_TIMEOUT": "4h"},
	} {
		if _, err := SessionConfigFromEnv(func(key string) string { return values[key] }); err != nil {
			t.Fatal(err)
		}
	}
	for _, values := range []map[string]string{
		{"SESSION_IDLE_TIMEOUT": "0s"}, {"SESSION_IDLE_TIMEOUT": "9h"},
		{"SESSION_ABSOLUTE_TIMEOUT": "-1h"}, {"SESSION_ABSOLUTE_TIMEOUT": "721h"},
		{"SESSION_IDLE_TIMEOUT": "invalid"},
	} {
		if _, err := SessionConfigFromEnv(func(key string) string { return values[key] }); err == nil {
			t.Fatal("invalid session timeout accepted")
		}
	}
}

func TestOIDCCookiePolicy(t *testing.T) {
	f := newTestIssuer(t)
	for _, environment := range []string{"development", "TEST", "PRD", "test", "production"} {
		config := f.config()
		config.AppEnv = environment
		if err := config.Validate(); err != nil {
			t.Fatal(err)
		}
		config.RedirectURI = "http://localhost:5173/api/auth/callback"
		if err := config.Validate(); err == nil {
			t.Fatal("implicit insecure cookie configuration accepted")
		}
		config.AllowHTTPDevelopment = true
		if err := config.Validate(); (err == nil) != (environment == "development") {
			t.Fatal("incorrect HTTP environment guard")
		}
	}
	for _, host := range []string{"attacker.example.invalid", "0.0.0.0"} {
		config := f.config()
		config.AllowHTTPDevelopment = true
		config.RedirectURI = "http://" + host + "/api/auth/callback"
		if config.Validate() == nil {
			t.Fatal("non-loopback insecure callback accepted")
		}
	}
	for _, secure := range []bool{true, false} {
		p := &OIDCAuthenticator{secureCookies: secure}
		name := sessionCookie
		if !secure {
			name = "gwf_dev_session"
		}
		response := httptest.NewRecorder()
		p.setCookie(response, name, "opaque", time.Now().Add(time.Hour))
		cookie := responseCookie(t, response, name)
		if cookie.Secure != secure || !cookie.HttpOnly || cookie.Domain != "" || cookie.Path != "/" {
			t.Fatal("incorrect cookie attributes")
		}
	}
	if _, err := NewOIDC(context.Background(), f.config(), nil); err == nil {
		t.Fatal("missing session store accepted")
	}
}
