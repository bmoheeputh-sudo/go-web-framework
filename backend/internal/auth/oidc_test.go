package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
)

const testOrigin = "https://app.example.invalid"

type grant struct{ nonce, challenge string }

// A real HTTPS discovery, authorization, token and JWKS server. ID tokens are
// genuinely signed and verified; the verifier is never mocked or bypassed.
type testIssuer struct {
	server         *httptest.Server
	key            *rsa.PrivateKey
	mu             sync.Mutex
	grants         map[string]grant
	exchanges      int
	changeClaims   func(map[string]any)
	changeMetadata func(map[string]any)
	badSignature   bool
	tokenError     bool
	missingIDToken bool
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &testIssuer{key: key, grants: make(map[string]grant)}
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.serveHTTP))
	t.Cleanup(f.server.Close)
	return f
}

func (f *testIssuer) serveHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		metadata := map[string]any{
			"issuer": f.server.URL, "authorization_endpoint": f.server.URL + "/authorize",
			"token_endpoint": f.server.URL + "/token", "jwks_uri": f.server.URL + "/jwks",
			"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"code_challenge_methods_supported":      []string{"S256"},
		}
		if f.changeMetadata != nil {
			f.changeMetadata(metadata)
		}
		_ = json.NewEncoder(w).Encode(metadata)
	case "/jwks":
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &f.key.PublicKey, KeyID: "test-key", Algorithm: string(jose.RS256), Use: "sig",
		}}})
	case "/authorize":
		q := r.URL.Query()
		if q.Get("client_id") != "client-id" || q.Get("redirect_uri") != testOrigin+"/api/auth/callback" ||
			q.Get("response_type") != "code" || q.Get("response_mode") != "query" ||
			q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" ||
			q.Get("nonce") == "" || q.Get("state") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		code := oauth2.GenerateVerifier()
		f.grants[code] = grant{nonce: q.Get("nonce"), challenge: q.Get("code_challenge")}
		callback := testOrigin + "/api/auth/callback?" + url.Values{"state": {q.Get("state")}, "code": {code}, "iss": {f.server.URL}}.Encode()
		http.Redirect(w, r, callback, http.StatusFound)
	case "/token":
		f.exchanges++
		_ = r.ParseForm()
		client, secret, ok := r.BasicAuth()
		value, found := f.grants[r.Form.Get("code")]
		delete(f.grants, r.Form.Get("code"))
		challenge := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if f.tokenError || !ok || client != "client-id" || secret != "test-client-secret" || !found ||
			r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("redirect_uri") != testOrigin+"/api/auth/callback" ||
			base64.RawURLEncoding.EncodeToString(challenge[:]) != value.challenge {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"sensitive-provider-details"}`))
			return
		}
		claims := map[string]any{"iss": f.server.URL, "sub": "stable-subject", "aud": "client-id",
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(), "nonce": value.nonce,
			"email": "user@example.invalid", "email_verified": true, "name": "OIDC User"}
		if f.changeClaims != nil {
			f.changeClaims(claims)
		}
		key := f.key
		if f.badSignature {
			key, _ = rsa.GenerateKey(rand.Reader, 2048)
		}
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
			(&jose.SignerOptions{}).WithHeader("kid", "test-key").WithType("JWT"))
		payload, _ := json.Marshal(claims)
		signed, _ := signer.Sign(payload)
		raw, _ := signed.CompactSerialize()
		response := map[string]any{"token_type": "Bearer", "access_token": "access-token-secret",
			"refresh_token": "refresh-token-secret", "expires_in": 3600}
		if !f.missingIDToken {
			response["id_token"] = raw
		}
		_ = json.NewEncoder(w).Encode(response)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *testIssuer) config() OIDCConfig {
	return OIDCConfig{AppEnv: "development", Issuer: f.server.URL, ClientID: "client-id",
		ClientSecret: "test-client-secret", RedirectURI: testOrigin + "/api/auth/callback"}
}

func (f *testIssuer) provider(t *testing.T) *OIDCAuthenticator {
	t.Helper()
	p, err := NewOIDC(oidc.ClientContext(context.Background(), f.server.Client()), f.config())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func responseCookie(t *testing.T, response *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("missing cookie %s", name)
	return nil
}

func beginLogin(t *testing.T, f *testIssuer, p *OIDCAuthenticator) (string, *http.Cookie) {
	t.Helper()
	response := httptest.NewRecorder()
	p.Login(response, httptest.NewRequest("GET", testOrigin+"/api/auth/login", nil))
	if response.Code != http.StatusFound {
		t.Fatalf("login status %d", response.Code)
	}
	cookie := responseCookie(t, response, flowCookie)
	assertSecureCookie(t, cookie)
	location, _ := url.Parse(response.Header().Get("Location"))
	q := location.Query()
	for _, name := range []string{"state", "nonce", "code_challenge"} {
		if len(q.Get(name)) < 43 {
			t.Fatalf("%s lacks expected entropy", name)
		}
	}
	if q.Get("state") == cookie.Value || q.Get("state") == q.Get("nonce") {
		t.Fatal("flow values must be independent")
	}
	client := *f.server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	authorization, err := client.Get(location.String())
	if err != nil {
		t.Fatal(err)
	}
	defer authorization.Body.Close()
	if authorization.StatusCode != http.StatusFound {
		t.Fatalf("authorization status %d", authorization.StatusCode)
	}
	return authorization.Header.Get("Location"), cookie
}

func assertSecureCookie(t *testing.T, cookie *http.Cookie) {
	t.Helper()
	if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode ||
		cookie.Path != "/" || cookie.Domain != "" || !strings.HasPrefix(cookie.Name, "__Host-") {
		t.Fatal("cookie security attributes missing")
	}
}

func finishLogin(p *OIDCAuthenticator, callback string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	request := httptest.NewRequest("GET", callback, nil)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	p.Callback(response, request)
	return response
}

func me(p *OIDCAuthenticator, cookie *http.Cookie) *httptest.ResponseRecorder {
	request := httptest.NewRequest("GET", testOrigin+"/api/auth/me", nil)
	if cookie != nil {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	Require(p, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, _ := IdentityFromContext(r.Context())
		_ = json.NewEncoder(w).Encode(identity)
	})).ServeHTTP(response, request)
	return response
}

func assertFailedCallback(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != testOrigin+"/?auth_error=login_failed" {
		t.Fatal("callback did not fail with a fixed safe redirect")
	}
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == sessionCookie && cookie.Value != "" {
			t.Fatal("failed callback created a session")
		}
	}
	if response.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("callback can leak its URL via referrer")
	}
}

func TestOIDCLoginCallbackMeAndSessionRotation(t *testing.T) {
	f := newTestIssuer(t)
	p := f.provider(t)
	callback, flow := beginLogin(t, f, p)
	response := finishLogin(p, callback, flow)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != testOrigin+"/" {
		t.Fatal("login failed")
	}
	cookie := responseCookie(t, response, sessionCookie)
	assertSecureCookie(t, cookie)
	if len(cookie.Value) < 43 || cookie.MaxAge > 3600 {
		t.Fatal("unexpected session entropy or expiration")
	}
	if responseCookie(t, response, flowCookie).MaxAge != -1 {
		t.Fatal("flow cookie was not cleared")
	}
	result := me(p, cookie)
	if result.Code != http.StatusOK {
		t.Fatalf("me status %d", result.Code)
	}
	var identity Identity
	if err := json.Unmarshal(result.Body.Bytes(), &identity); err != nil {
		t.Fatal(err)
	}
	if identity.Provider != OIDC || identity.Issuer != f.server.URL || identity.Subject != "stable-subject" ||
		identity.Email != "user@example.invalid" || !identity.EmailVerified || identity.DisplayName != "OIDC User" {
		t.Fatal("incorrect identity")
	}
	for _, secret := range []string{"access-token-secret", "refresh-token-secret", "test-client-secret", "id_token"} {
		if strings.Contains(result.Body.String(), secret) || strings.Contains(response.Body.String(), secret) {
			t.Fatal("secret exposed")
		}
	}
	assertFailedCallback(t, finishLogin(p, callback, flow)) // A successful flow cannot be replayed.
	callback, flow = beginLogin(t, f, p)
	rotated := responseCookie(t, finishLogin(p, callback, flow, cookie), sessionCookie)
	if rotated.Value == cookie.Value || me(p, cookie).Code != http.StatusUnauthorized || me(p, rotated).Code != http.StatusOK {
		t.Fatal("session was not rotated")
	}
}

func TestOIDCCallbackRejectsInvalidStateAndBrowserBinding(t *testing.T) {
	f := newTestIssuer(t)
	for _, mode := range []string{"invalid state", "missing state", "missing cookie", "wrong cookie", "duplicate state", "missing code", "provider error", "wrong issuer", "expired flow", "wrong verifier"} {
		t.Run(mode, func(t *testing.T) {
			p := f.provider(t)
			callback, cookie := beginLogin(t, f, p)
			u, _ := url.Parse(callback)
			q := u.Query()
			exchangeExpected := false
			switch mode {
			case "invalid state":
				q.Set("state", "forged")
			case "missing state":
				q.Del("state")
			case "missing cookie":
				cookie = nil
			case "wrong cookie":
				cookie.Value = "forged"
			case "duplicate state":
				q.Add("state", "forged")
			case "missing code":
				q.Del("code")
			case "provider error":
				q.Set("error", "sensitive-provider-details")
			case "wrong issuer":
				q.Set("iss", "https://wrong.example.invalid")
			case "expired flow", "wrong verifier":
				key := sha256.Sum256([]byte(cookie.Value))
				flow := p.store.flows[key]
				if mode == "expired flow" {
					flow.Expires = time.Now().Add(-time.Hour)
				} else {
					flow.Verifier = "wrong"
					exchangeExpected = true
				}
				p.store.flows[key] = flow
			}
			u.RawQuery = q.Encode()
			f.mu.Lock()
			before := f.exchanges
			f.mu.Unlock()
			var response *httptest.ResponseRecorder
			if cookie == nil {
				response = finishLogin(p, u.String())
			} else {
				response = finishLogin(p, u.String(), cookie)
			}
			assertFailedCallback(t, response)
			f.mu.Lock()
			after := f.exchanges
			f.mu.Unlock()
			if !exchangeExpected && after != before {
				t.Fatal("invalid callback reached the token endpoint")
			}
		})
	}
}

func TestOIDCRejectsInvalidTokens(t *testing.T) {
	for _, mode := range []string{"invalid nonce", "missing nonce", "expired", "wrong issuer", "wrong audience", "wrong azp", "multiple audiences without azp", "missing subject", "signature", "missing ID token", "token error"} {
		t.Run(mode, func(t *testing.T) {
			f := newTestIssuer(t)
			f.changeClaims = func(claims map[string]any) {
				switch mode {
				case "invalid nonce":
					claims["nonce"] = "wrong"
				case "missing nonce":
					delete(claims, "nonce")
				case "expired":
					claims["exp"] = time.Now().Add(-time.Hour).Unix()
				case "wrong issuer":
					claims["iss"] = "https://wrong.example.invalid"
				case "wrong audience":
					claims["aud"] = "another-client"
				case "wrong azp":
					claims["azp"] = "another-client"
				case "multiple audiences without azp":
					claims["aud"] = []string{"client-id", "other"}
				case "missing subject":
					delete(claims, "sub")
				}
			}
			f.badSignature = mode == "signature"
			f.missingIDToken = mode == "missing ID token"
			f.tokenError = mode == "token error"
			p := f.provider(t)
			callback, cookie := beginLogin(t, f, p)
			assertFailedCallback(t, finishLogin(p, callback, cookie))
			if len(p.store.sessions) != 0 {
				t.Fatal("invalid token established a session")
			}
		})
	}
}

func TestOIDCLogoutAndUnauthenticatedAccess(t *testing.T) {
	f := newTestIssuer(t)
	p := f.provider(t)
	if me(p, nil).Code != http.StatusUnauthorized {
		t.Fatal("anonymous access accepted")
	}
	if me(p, &http.Cookie{Name: sessionCookie, Value: "forged"}).Code != http.StatusUnauthorized {
		t.Fatal("forged session accepted")
	}
	callback, flow := beginLogin(t, f, p)
	cookie := responseCookie(t, finishLogin(p, callback, flow), sessionCookie)
	for _, origin := range []string{"", "https://attacker.example.invalid", testOrigin} {
		request := httptest.NewRequest("POST", testOrigin+"/api/auth/logout", nil)
		request.AddCookie(cookie)
		request.Header.Set("Origin", origin)
		response := httptest.NewRecorder()
		p.Logout(response, request)
		if origin != testOrigin {
			if response.Code != http.StatusForbidden || me(p, cookie).Code != http.StatusOK {
				t.Fatal("cross-site logout was allowed")
			}
		} else {
			if response.Code != http.StatusNoContent || me(p, cookie).Code != http.StatusUnauthorized {
				t.Fatal("logout failed to revoke session")
			}
			cleared := responseCookie(t, response, sessionCookie)
			assertSecureCookie(t, cleared)
			if cleared.MaxAge != -1 {
				t.Fatal("session cookie not cleared")
			}
		}
	}
}

func TestOIDCConfigurationValidation(t *testing.T) {
	valid := OIDCConfig{AppEnv: "development", Issuer: "https://issuer.example.invalid", ClientID: "client", ClientSecret: "secret", RedirectURI: testOrigin + "/api/auth/callback"}
	for _, change := range []func(*OIDCConfig){
		func(c *OIDCConfig) { c.AppEnv = "production" },
		func(c *OIDCConfig) { c.AppEnv = "TEST" },
		func(c *OIDCConfig) { c.AppEnv = "" },
		func(c *OIDCConfig) { c.Issuer = "http://issuer.example.invalid" },
		func(c *OIDCConfig) { c.Issuer += "?query=1" },
		func(c *OIDCConfig) { c.Issuer = "https://user:pass@issuer.example.invalid" },
		func(c *OIDCConfig) { c.ClientID = "" },
		func(c *OIDCConfig) { c.ClientSecret = " " },
		func(c *OIDCConfig) { c.RedirectURI = "http://localhost:5173/api/auth/callback" },
		func(c *OIDCConfig) { c.RedirectURI = testOrigin + "/wrong-path" },
		func(c *OIDCConfig) { c.RedirectURI += "?extra=1" },
		func(c *OIDCConfig) { c.RedirectURI += "#fragment" },
	} {
		config := valid
		change(&config)
		if _, err := NewOIDC(context.Background(), config); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
	if err := valid.validate(); err != nil {
		t.Fatal(err)
	}
}

func TestOIDCDiscoveryFailsClosed(t *testing.T) {
	for _, mode := range []string{"issuer mismatch", "HTTP token", "HTTP JWKS", "HTTP authorization", "no code", "no S256", "untrusted TLS"} {
		t.Run(mode, func(t *testing.T) {
			f := newTestIssuer(t)
			f.changeMetadata = func(metadata map[string]any) {
				switch mode {
				case "issuer mismatch":
					metadata["issuer"] = "https://other.example.invalid"
				case "HTTP token":
					metadata["token_endpoint"] = "http://insecure.example.invalid/token"
				case "HTTP JWKS":
					metadata["jwks_uri"] = "http://insecure.example.invalid/jwks"
				case "HTTP authorization":
					metadata["authorization_endpoint"] = "http://insecure.example.invalid/authorize"
				case "no code":
					metadata["response_types_supported"] = []string{"token"}
				case "no S256":
					metadata["code_challenge_methods_supported"] = []string{"plain"}
				}
			}
			ctx := oidc.ClientContext(context.Background(), f.server.Client())
			if mode == "untrusted TLS" {
				ctx = context.Background()
			}
			if _, err := NewOIDC(ctx, f.config()); err == nil {
				t.Fatal("unsafe discovery accepted")
			}
		})
	}
}
