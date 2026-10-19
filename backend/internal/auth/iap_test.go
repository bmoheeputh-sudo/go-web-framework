package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const testIAPAudience = "/projects/123456789/apps/test-project"

type iapRoundTripper func(*http.Request) (*http.Response, error)

func (f iapRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type iapFixture struct {
	provider *IAPAuthenticator
	key      *ecdsa.PrivateKey
	clock    atomic.Int64
	mu       sync.Mutex
	body     string
	status   int
	failure  error
	calls    int
}

func newIAPFixture(t *testing.T) *iapFixture {
	t.Helper()
	p, err := NewGoogleIAP(testIAPAudience)
	if err != nil {
		t.Fatal(err)
	}
	f := &iapFixture{provider: p, key: iapSigningKey(t), status: http.StatusOK}
	f.clock.Store(time.Now().Unix())
	p.now = func() time.Time { return time.Unix(f.clock.Load(), 0) }
	p.keys.now = p.now
	f.setKeys(t, iapJWK(f.key, "first"))
	p.keys.client.Transport = iapRoundTripper(func(r *http.Request) (*http.Response, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls++
		if r.URL.String() != iapKeysURL || r.Method != "GET" || len(r.Header) != 0 {
			t.Error("key request must use only the pinned public URL, with no forwarded credentials")
		}
		if f.failure != nil {
			return nil, f.failure
		}
		return &http.Response{StatusCode: f.status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(f.body)), Request: r}, nil
	})
	return f
}
func iapSigningKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
func iapJWK(key *ecdsa.PrivateKey, id string) jose.JSONWebKey {
	return jose.JSONWebKey{Key: &key.PublicKey, KeyID: id, Algorithm: string(jose.ES256), Use: "sig"}
}
func (f *iapFixture) setKeys(t *testing.T, keys ...jose.JSONWebKey) {
	t.Helper()
	body, err := json.Marshal(jose.JSONWebKeySet{Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.body = string(body)
}
func (f *iapFixture) claims() map[string]any {
	return map[string]any{"iss": iapIssuer, "sub": "google-subject", "aud": testIAPAudience,
		"iat": f.clock.Load(), "exp": f.clock.Load() + 600, "email": "user@example.invalid", "name": "IAP User"}
}
func signIAP(t *testing.T, key any, algorithm jose.SignatureAlgorithm, id string, claims any, headers map[jose.HeaderKey]any) string {
	t.Helper()
	options := (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", id)
	for k, v := range headers {
		options.WithHeader(k, v)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: algorithm, Key: key}, options)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	token, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}
func iapResponse(p *IAPAuthenticator, tokens ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "/api/auth/me?email=forged@example.invalid", nil)
	for _, token := range tokens {
		r.Header.Add(iapAssertion, token)
	}
	r.Header.Set("X-Goog-Authenticated-User-Email", "accounts.google.com:forged@example.invalid")
	r.Header.Set("X-Goog-Authenticated-User-Id", "accounts.google.com:forged-subject")
	r.Header.Set("Authorization", "Bearer forged")
	r.AddCookie(&http.Cookie{Name: "__Host-gwf_session", Value: "forged"})
	response := httptest.NewRecorder()
	Require(p, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, _ := IdentityFromContext(r.Context())
		_ = json.NewEncoder(w).Encode(identity)
	})).ServeHTTP(response, r)
	return response
}

func TestIAPAudienceConfiguration(t *testing.T) {
	for _, audience := range []string{testIAPAudience, "/projects/123/global/backendServices/456", "/projects/123/locations/europe-west1/services/my-service"} {
		if _, err := NewGoogleIAP(audience); err != nil {
			t.Fatal(err)
		}
	}
	for _, audience := range []string{"", " ", "https://service.run.app", "client.apps.googleusercontent.com", "/projects/project-id/apps/app",
		"/projects/123/global/backendServices/name", "/projects/123/locations/region/services/", testIAPAudience + "/", testIAPAudience + "\n", " " + testIAPAudience, strings.Repeat("a", 513)} {
		if _, err := NewGoogleIAP(audience); err == nil {
			t.Errorf("accepted invalid audience %q", audience)
		}
	}
}

func TestIAPAuthenticatedIdentity(t *testing.T) {
	f := newIAPFixture(t)
	for _, verified := range []bool{false, true} {
		claims := f.claims()
		if verified {
			claims["email_verified"] = true
		}
		token := signIAP(t, f.key, jose.ES256, "first", claims, nil)
		response := iapResponse(f.provider, token)
		if response.Code != http.StatusOK {
			t.Fatal(response.Code)
		}
		var got Identity
		if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		want := Identity{Issuer: iapIssuer, Subject: "google-subject", Email: "user@example.invalid", EmailVerified: verified, DisplayName: "IAP User", Provider: GoogleIAP}
		if got != want {
			t.Fatalf("identity mismatch: %+v", got)
		}
		if len(response.Result().Cookies()) != 0 || response.Header().Get("Cache-Control") != "no-store" || strings.Contains(response.Body.String(), token) {
			t.Fatal("IAP must return only identity without tokens or sessions")
		}
	}
	// No cached identity can authorize a subsequent request without an assertion.
	if iapResponse(f.provider).Code != http.StatusUnauthorized {
		t.Fatal("missing per-request assertion accepted")
	}
	if f.calls != 1 {
		t.Fatal("keys were not cached")
	}
	claims := f.claims()
	delete(claims, "email")
	delete(claims, "name")
	if iapResponse(f.provider, signIAP(t, f.key, jose.ES256, "first", claims, nil)).Code != http.StatusOK {
		t.Fatal("optional identity claims required")
	}
}

func TestIAPRejectsInvalidClaims(t *testing.T) {
	f := newIAPFixture(t)
	for _, test := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"issuer", func(c map[string]any) { c["iss"] = "https://accounts.google.com" }},
		{"audience", func(c map[string]any) { c["aud"] = "/projects/999/apps/other" }},
		{"audience array", func(c map[string]any) { c["aud"] = []string{testIAPAudience} }},
		{"missing issuer", func(c map[string]any) { delete(c, "iss") }},
		{"missing audience", func(c map[string]any) { delete(c, "aud") }},
		{"missing subject", func(c map[string]any) { delete(c, "sub") }},
		{"missing expiration", func(c map[string]any) { delete(c, "exp") }},
		{"missing issued at", func(c map[string]any) { delete(c, "iat") }},
		{"expired", func(c map[string]any) { c["iat"] = f.clock.Load() - 600; c["exp"] = f.clock.Load() - 31 }},
		{"expiration skew boundary", func(c map[string]any) { c["iat"] = f.clock.Load() - 600; c["exp"] = f.clock.Load() - 30 }},
		{"future issued at", func(c map[string]any) { c["iat"] = f.clock.Load() + 31 }},
		{"excessive lifetime", func(c map[string]any) { c["exp"] = f.clock.Load() + 661 }},
		{"reversed lifetime", func(c map[string]any) { c["exp"] = f.clock.Load() - 1 }},
		{"future not before", func(c map[string]any) { c["nbf"] = f.clock.Load() + 31 }},
		{"invalid timestamp type", func(c map[string]any) { c["iat"] = "now" }},
		{"invalid email", func(c map[string]any) { c["email"] = "not-an-email" }},
		{"verified absent email", func(c map[string]any) { delete(c, "email"); c["email_verified"] = true }},
		{"invalid verification type", func(c map[string]any) { c["email_verified"] = "true" }},
		{"invalid name", func(c map[string]any) { c["name"] = "name\n" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			claims := f.claims()
			test.change(claims)
			if response := iapResponse(f.provider, signIAP(t, f.key, jose.ES256, "first", claims, nil)); response.Code != http.StatusUnauthorized {
				t.Fatalf("status %d", response.Code)
			}
		})
	}
	for _, change := range []func(map[string]any){
		func(c map[string]any) { c["iat"] = f.clock.Load() + 30 },
		func(c map[string]any) { c["iat"] = f.clock.Load() - 600; c["exp"] = f.clock.Load() - 29 },
		func(c map[string]any) { c["exp"] = f.clock.Load() + 660 },
	} {
		claims := f.claims()
		change(claims)
		if iapResponse(f.provider, signIAP(t, f.key, jose.ES256, "first", claims, nil)).Code != http.StatusOK {
			t.Fatal("documented clock skew/lifetime boundary rejected")
		}
	}
}

func TestIAPRejectsInvalidAssertions(t *testing.T) {
	f := newIAPFixture(t)
	valid := signIAP(t, f.key, jose.ES256, "first", f.claims(), nil)
	forgedKey := iapSigningKey(t)
	unsigned := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"first"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"forged"}`)) + "."
	for _, test := range []struct {
		name   string
		tokens []string
	}{
		{"missing", nil}, {"empty", []string{""}}, {"malformed", []string{"not-a-jwt"}},
		{"unsigned", []string{unsigned}}, {"duplicate headers", []string{valid, valid}},
		{"combined headers", []string{valid + "," + valid}}, {"oversized", []string{strings.Repeat("x", iapMaxTokenBytes+1)}},
		{"whitespace", []string{" " + valid}},
		{"signature", []string{signIAP(t, forgedKey, jose.ES256, "first", f.claims(), nil)}},
		{"untrusted kid", []string{signIAP(t, f.key, jose.ES256, "unknown", f.claims(), nil)}},
		{"missing kid", []string{signIAP(t, f.key, jose.ES256, "", f.claims(), nil)}},
		{"HMAC", []string{signIAP(t, []byte(strings.Repeat("secret", 8)), jose.HS256, "first", f.claims(), nil)}},
		{"embedded key", []string{signIAP(t, forgedKey, jose.ES256, "first", f.claims(), map[jose.HeaderKey]any{"jwk": iapJWK(forgedKey, "first")})}},
		{"attacker key URL", []string{signIAP(t, forgedKey, jose.ES256, "first", f.claims(), map[jose.HeaderKey]any{"jku": "https://attacker.example.invalid/keys"})}},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := iapResponse(f.provider, test.tokens...)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status %d", response.Code)
			}
			if strings.TrimSpace(response.Body.String()) != `{"error":"unauthenticated"}` {
				t.Fatal("unexpected authentication error detail")
			}
		})
	}
}

func TestIAPKeyRotationAndRefreshBounds(t *testing.T) {
	f := newIAPFixture(t)
	first := signIAP(t, f.key, jose.ES256, "first", f.claims(), nil)
	if iapResponse(f.provider, first).Code != http.StatusOK {
		t.Fatal("initial key failed")
	}
	secondKey := iapSigningKey(t)
	second := signIAP(t, secondKey, jose.ES256, "second", f.claims(), nil)
	f.setKeys(t, iapJWK(secondKey, "second"))
	if iapResponse(f.provider, second).Code != http.StatusUnauthorized {
		t.Fatal("unknown key bypassed refresh cooldown")
	}
	f.clock.Add(31)
	if iapResponse(f.provider, second).Code != http.StatusOK {
		t.Fatal("rotated key not refreshed")
	}
	if iapResponse(f.provider, first).Code != http.StatusUnauthorized {
		t.Fatal("removed key still accepted")
	}
	for range 20 {
		if iapResponse(f.provider, first).Code != http.StatusUnauthorized {
			t.Fatal("removed key accepted")
		}
	}
	if f.calls != 2 {
		t.Fatalf("unbounded refresh: %d fetches", f.calls)
	}
}

func TestIAPExpiredKeyCacheFailsClosedAndRecovers(t *testing.T) {
	f := newIAPFixture(t)
	token := signIAP(t, f.key, jose.ES256, "first", f.claims(), nil)
	if iapResponse(f.provider, token).Code != http.StatusOK {
		t.Fatal("initial key failed")
	}
	f.failure = errors.New("private transport details")
	// Unexpired trusted keys still work during an outage.
	if iapResponse(f.provider, token).Code != http.StatusOK {
		t.Fatal("fresh cached key rejected")
	}
	f.clock.Add(int64(iapKeyTTL/time.Second) + 1)
	for range 3 {
		response := iapResponse(f.provider, token)
		if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "private") {
			t.Fatal("expired keys used or failure detail leaked")
		}
	}
	if f.calls != 2 {
		t.Fatal("outage retries not bounded")
	}
	f.failure = nil
	f.clock.Add(31)
	if iapResponse(f.provider, token).Code != http.StatusOK {
		t.Fatal("key fetch did not recover")
	}
}

func TestIAPConcurrentKeyCache(t *testing.T) {
	f := newIAPFixture(t)
	token := signIAP(t, f.key, jose.ES256, "first", f.claims(), nil)
	var group sync.WaitGroup
	for range 32 {
		group.Add(1)
		go func() {
			defer group.Done()
			if iapResponse(f.provider, token).Code != http.StatusOK {
				t.Error("concurrent authentication failed")
			}
		}()
	}
	group.Wait()
	if f.calls != 1 {
		t.Fatalf("concurrent refresh not coalesced: %d", f.calls)
	}
}

func TestIAPRejectsUntrustedJWKS(t *testing.T) {
	for _, test := range []string{"malformed", "empty", "duplicate kid", "wrong curve", "private key", "wrong algorithm", "encryption key", "missing kid", "oversized", "http error", "redirect", "timeout"} {
		t.Run(test, func(t *testing.T) {
			f := newIAPFixture(t)
			jwk := iapJWK(f.key, "first")
			switch test {
			case "malformed":
				f.body = "not JSON"
			case "empty":
				f.setKeys(t)
			case "duplicate kid":
				f.setKeys(t, jwk, jwk)
			case "wrong curve":
				key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				f.setKeys(t, iapJWK(key, "first"))
			case "private key":
				jwk.Key = f.key
				f.setKeys(t, jwk)
			case "wrong algorithm":
				jwk.Algorithm = "RS256"
				f.setKeys(t, jwk)
			case "encryption key":
				jwk.Use = "enc"
				f.setKeys(t, jwk)
			case "missing kid":
				jwk.KeyID = ""
				f.setKeys(t, jwk)
			case "oversized":
				f.body = strings.Repeat(" ", iapMaxJWKSBytes+1)
			case "http error":
				f.status = http.StatusServiceUnavailable
			case "redirect":
				f.status = http.StatusFound
			case "timeout":
				f.failure = errors.New("network timeout")
			}
			token := signIAP(t, f.key, jose.ES256, "first", f.claims(), nil)
			if iapResponse(f.provider, token).Code != http.StatusServiceUnavailable {
				t.Fatal("untrusted/unavailable key set accepted")
			}
		})
	}
	cache := newIAPKeyCache()
	if cache.client.Timeout != 5*time.Second || cache.client.CheckRedirect(&http.Request{}, nil) == nil {
		t.Fatal("unsafe key HTTP client configuration")
	}
}
