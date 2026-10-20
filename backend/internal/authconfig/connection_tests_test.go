package authconfig

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/go-jose/go-jose/v4"
)

type testRoundTrip func(*http.Request) (*http.Response, error)

func (f testRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type mockConnectionIssuer struct {
	mu                                sync.Mutex
	key                               *ecdsa.PrivateKey
	metadata                          func(map[string]any)
	claims                            func(map[string]any)
	nonce, challenge                  string
	callback                          string
	exchanges                         int
	badSignature, tokenError, badKeys bool
}

func newMockConnectionIssuer(t *testing.T) *mockConnectionIssuer {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &mockConnectionIssuer{key: key}
}

const probeIssuer = "https://provider.example.test/"

func (p *mockConnectionIssuer) expectedCallback() string {
	if p.callback != "" {
		return p.callback
	}
	return apiOrigin + "/api/auth/test/callback"
}
func (p *mockConnectionIssuer) client() *http.Client {
	return &http.Client{Transport: testRoundTrip(func(r *http.Request) (*http.Response, error) {
		p.mu.Lock()
		defer p.mu.Unlock()
		var value any
		status := 200
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			m := map[string]any{"issuer": probeIssuer, "authorization_endpoint": probeIssuer + "authorize", "token_endpoint": probeIssuer + "token", "jwks_uri": probeIssuer + "jwks", "response_types_supported": []string{"code"}, "code_challenge_methods_supported": []string{"S256"}, "id_token_signing_alg_values_supported": []string{"ES256"}}
			if p.metadata != nil {
				p.metadata(m)
			}
			value = m
		case "/jwks":
			value = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &p.key.PublicKey, KeyID: "test", Use: "sig", Algorithm: "ES256"}}}
			if p.badKeys {
				value = map[string]any{"keys": []any{}}
			}
		case "/token":
			p.exchanges++
			_ = r.ParseForm()
			client, secret, ok := r.BasicAuth()
			challenge := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if p.tokenError || !ok || client != "test-client" || secret != apiSecret || r.Form.Get("code") != "synthetic-code" || base64.RawURLEncoding.EncodeToString(challenge[:]) != p.challenge || r.Form.Get("redirect_uri") != p.expectedCallback() {
				status = 400
				value = map[string]any{"error": "invalid_grant", "error_description": "provider-secret-response"}
				break
			}
			claims := map[string]any{"iss": probeIssuer, "sub": "tested-subject", "aud": "test-client", "nonce": p.nonce, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "email": "tested@example.test", "email_verified": true}
			if p.claims != nil {
				p.claims(claims)
			}
			key := p.key
			if p.badSignature {
				key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			}
			signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "test"))
			data, _ := json.Marshal(claims)
			signed, _ := signer.Sign(data)
			raw, _ := signed.CompactSerialize()
			value = map[string]any{"id_token": raw, "token_type": "Bearer", "access_token": "synthetic-access-token", "refresh_token": "synthetic-refresh-token"}
		default:
			return nil, errors.New("unexpected provider path")
		}
		data, _ := json.Marshal(value)
		return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(data)))}, nil
	}), Timeout: time.Second}
}
func approvedProbeRevision(t *testing.T, f *fixture) Metadata {
	var m Metadata
	f.run(t, func(ctx context.Context) {
		var err error
		m, err = f.repo.CreateDraft(ctx, 0, Settings{Provider: auth.OIDC, IssuerURL: probeIssuer, ClientID: "test-client", RedirectURI: apiOrigin + "/api/auth/callback"}, NewSecret([]byte(apiSecret)))
		if err != nil {
			t.Fatal(err)
		}
		m, err = f.repo.Transition(ctx, m.ID, m.Generation, Validated)
		if err != nil {
			t.Fatal(err)
		}
		m, err = f.repo.Transition(ctx, m.ID, m.Generation, Approved)
		if err != nil {
			t.Fatal(err)
		}
	})
	return m
}
func probeHandler(f *fixture, s *connectionTests, identity auth.Identity) *http.ServeMux {
	mux := http.NewServeMux()
	route := func(pattern string, h http.HandlerFunc) {
		mux.Handle(pattern, auth.Require(fixedAuth{identity}, access.ProtectWrites(apiOrigin, f.store.Require(access.AdminManage, "", h))))
	}
	s.register(mux, route)
	return mux
}
func startProbe(t *testing.T, h http.Handler, p *mockConnectionIssuer, m Metadata) (connectionResult, *http.Cookie, string) {
	t.Helper()
	response := apiRequest(t, h, "POST", settingsPath+"/"+m.ID+"/test", map[string]int64{"expected_generation": m.Generation}, 201)
	var data struct {
		connectionResult
		URL string `json:"authorization_url"`
	}
	if json.Unmarshal(response.Body.Bytes(), &data) != nil {
		t.Fatal("invalid start")
	}
	if data.Status != "pending" {
		t.Fatalf("start did not reach pending: %s", data.Status)
	}
	u, err := url.Parse(data.URL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("prompt") != "login" || q.Get("redirect_uri") != apiOrigin+"/api/auth/test/callback" {
		t.Fatal("unsafe authorization parameters")
	}
	p.mu.Lock()
	p.nonce = q.Get("nonce")
	p.challenge = q.Get("code_challenge")
	p.mu.Unlock()
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal("expected one test cookie")
	}
	if !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode || !strings.HasPrefix(cookies[0].Name, "__Host-gwf_oidc_test_") {
		t.Fatal("unsafe test cookie")
	}
	return data.connectionResult, cookies[0], q.Get("state")
}
func callbackProbe(t *testing.T, h http.Handler, cookie *http.Cookie, state, code string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("GET", "/api/auth/test/callback?"+url.Values{"state": {state}, "code": {code}}.Encode(), nil)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 303 || w.Header().Get("Location") != apiOrigin+"/settings" || w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("unsafe callback response")
	}
	for _, c := range w.Result().Cookies() {
		if !strings.Contains(c.Name, "oidc_test_") || c.MaxAge != -1 {
			t.Fatal("callback created an application cookie")
		}
	}
	if strings.Contains(w.Body.String(), code) && code != "" {
		t.Fatal("code leaked")
	}
	return w
}
func resultProbe(t *testing.T, h http.Handler, id string) connectionResult {
	t.Helper()
	w := apiRequest(t, h, "GET", "/api/admin/auth/tests/"+id, nil, 200)
	var result connectionResult
	if json.Unmarshal(w.Body.Bytes(), &result) != nil {
		t.Fatal("invalid result")
	}
	return result
}
func TestConnectionWorkflow(t *testing.T) {
	f := newFixture(t)
	m := approvedProbeRevision(t, f)
	p := newMockConnectionIssuer(t)
	s := newConnectionTests(f.repo, apiOrigin)
	s.client = func(context.Context, string) (*http.Client, error) { return p.client(), nil }
	h := probeHandler(f, s, f.identity)
	var beforeUsers, beforeSessions int
	_ = f.owner.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM framework.users),(SELECT count(*) FROM framework.sessions)`).Scan(&beforeUsers, &beforeSessions)
	result, cookie, state := startProbe(t, h, p, m)
	callbackProbe(t, h, nil, state, "synthetic-code") // no browser binding
	callbackProbe(t, h, cookie, state+"wrong", "synthetic-code")
	if resultProbe(t, h, result.ID).Status != "pending" || p.exchanges != 0 {
		t.Fatal("uncorrelated callback consumed test")
	}
	callbackProbe(t, h, cookie, state, "synthetic-code")
	got := resultProbe(t, h, result.ID)
	if got.Status != "succeeded" || got.Identity == nil || got.Identity.Subject != "tested-subject" || got.RevisionID != m.ID || got.Generation != m.Generation {
		t.Fatal("invalid successful result")
	}
	reader, _ := NewActivationReader(f.pool, f.repo.scope)
	evidence, err := reader.Evidence(context.Background(), got.EvidenceID, m.ID, m.Generation, IsolatedConnection)
	if err != nil || got.EvidenceExpiresAt == nil || evidence.Subject != got.Identity.Subject || evidence.Issuer != got.Identity.Issuer || evidence.ActorUserID != m.CreatedBy {
		t.Fatal("verified callback did not persist scoped durable evidence", err)
	}
	callbackProbe(t, h, cookie, state, "synthetic-code")
	if p.exchanges != 1 {
		t.Fatal("token replay")
	}
	var users, sessions, events int
	_ = f.owner.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM framework.users),(SELECT count(*) FROM framework.sessions),(SELECT count(*) FROM framework.audit_log WHERE action IN ('auth_config.test_started','auth_config.test_finished'))`).Scan(&users, &sessions, &events)
	if users != beforeUsers || sessions != beforeSessions || events != 2 {
		t.Fatal("application identity/session changed or audit absent")
	}
	var details string
	_ = f.owner.QueryRow(context.Background(), `SELECT details::text FROM framework.audit_log WHERE action='auth_config.test_finished'`).Scan(&details)
	for _, secret := range []string{apiSecret, "synthetic-code", "synthetic-access-token", "synthetic-refresh-token", "tested@example.test"} {
		if strings.Contains(details, secret) {
			t.Fatal("audit leaked sensitive material")
		}
	}
	// Only a subsequent explicit admin operation can enroll the verified subject.
	w := apiRequest(t, configHandler(f, f.repo, fixedAuth{f.identity}), "POST", settingsPath+"/"+m.ID+"/enroll", enrollBody(evidence, "Admin"), 200)
	var enrolled access.User
	if json.Unmarshal(w.Body.Bytes(), &enrolled) != nil || enrolled.Issuer != got.Identity.Issuer || enrolled.Subject != got.Identity.Subject || len(enrolled.Roles) != 1 || enrolled.Roles[0] != "Admin" {
		t.Fatal("verified live-test evidence did not enroll exact identity")
	}
}

func TestConnectionEvidenceAuditFailureCannotPublishSuccess(t *testing.T) {
	f := newFixture(t)
	m := approvedProbeRevision(t, f)
	p := newMockConnectionIssuer(t)
	s := newConnectionTests(f.repo, apiOrigin)
	s.client = func(context.Context, string) (*http.Client, error) { return p.client(), nil }
	h := probeHandler(f, s, f.identity)
	result, cookie, state := startProbe(t, h, p, m)
	_, err := f.owner.Exec(context.Background(), `CREATE FUNCTION framework.fail_test_evidence() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='auth_config.test_evidence_recorded' THEN RAISE EXCEPTION 'synthetic'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_test_evidence BEFORE INSERT ON framework.audit_log FOR EACH ROW EXECUTE FUNCTION framework.fail_test_evidence()`)
	if err != nil {
		t.Fatal(err)
	}
	callbackProbe(t, h, cookie, state, "synthetic-code")
	got := resultProbe(t, h, result.ID)
	if got.Status != "failed" || got.EvidenceID != "" || got.Identity != nil {
		t.Fatal("audit failure released usable evidence")
	}
	var count int
	if err := f.owner.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM framework.auth_test_evidence)+(SELECT count(*) FROM framework.audit_log WHERE action='auth_config.test_finished')`).Scan(&count); err != nil || count != 0 {
		t.Fatal("partial test completion persisted", err)
	}
}
func TestConnectionFailures(t *testing.T) {
	f := newFixture(t)
	m := approvedProbeRevision(t, f)
	cases := []struct {
		name   string
		change func(*mockConnectionIssuer, *connectionTest)
		code   string
		want   string
	}{
		{"nonce", func(p *mockConnectionIssuer, _ *connectionTest) {
			p.claims = func(c map[string]any) { c["nonce"] = "wrong" }
		}, "synthetic-code", "failed"},
		{"expired token", func(p *mockConnectionIssuer, _ *connectionTest) {
			p.claims = func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }
		}, "synthetic-code", "failed"},
		{"issuer", func(p *mockConnectionIssuer, _ *connectionTest) {
			p.claims = func(c map[string]any) { c["iss"] = "https://wrong.test" }
		}, "synthetic-code", "failed"},
		{"audience", func(p *mockConnectionIssuer, _ *connectionTest) {
			p.claims = func(c map[string]any) { c["aud"] = "another-client" }
		}, "synthetic-code", "failed"},
		{"signature", func(p *mockConnectionIssuer, _ *connectionTest) { p.badSignature = true }, "synthetic-code", "failed"},
		{"PKCE", func(_ *mockConnectionIssuer, e *connectionTest) { e.verifier = "wrong-verifier" }, "synthetic-code", "failed"},
		{"invalid code", func(*mockConnectionIssuer, *connectionTest) {}, "invalid-code", "failed"},
		{"expired test", func(_ *mockConnectionIssuer, e *connectionTest) { e.result.Expires = time.Now().Add(-time.Second) }, "synthetic-code", "expired"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newMockConnectionIssuer(t)
			s := newConnectionTests(f.repo, apiOrigin)
			s.client = func(context.Context, string) (*http.Client, error) { return p.client(), nil }
			h := probeHandler(f, s, f.identity)
			result, cookie, state := startProbe(t, h, p, m)
			tc.change(p, s.get(result.ID))
			callbackProbe(t, h, cookie, state, tc.code)
			got := resultProbe(t, h, result.ID)
			if got.Status != tc.want || got.Identity != nil {
				t.Fatal("unsafe failed test result")
			}
		})
	}
}
func TestConnectionDiscoveryValidation(t *testing.T) {
	for _, change := range []func(map[string]any){
		func(m map[string]any) { m["issuer"] = "https://wrong.example.test/" },
		func(m map[string]any) { m["id_token_signing_alg_values_supported"] = []string{"none", "HS256"} },
		func(m map[string]any) { m["code_challenge_methods_supported"] = []string{"plain"} },
		func(m map[string]any) { m["token_endpoint"] = "https://169.254.169.254/token" },
		func(m map[string]any) { m["jwks_uri"] = "http://provider.example.test/jwks" },
		func(m map[string]any) { m["authorization_endpoint"] = "https://evil.example.test/authorize" },
	} {
		p := newMockConnectionIssuer(t)
		p.metadata = change
		_, err := newConnectionProbe(context.Background(), Metadata{Settings: Settings{IssuerURL: probeIssuer, ClientID: "test-client"}}, NewSecret([]byte(apiSecret)), apiOrigin+"/api/auth/test/callback", p.client())
		if err == nil {
			t.Fatal("unsafe discovery accepted")
		}
	}
	p := newMockConnectionIssuer(t)
	p.badKeys = true
	if _, err := newConnectionProbe(context.Background(), Metadata{Settings: Settings{IssuerURL: probeIssuer}}, Secret{}, apiOrigin, p.client()); err == nil {
		t.Fatal("invalid JWKS accepted")
	}
}
func TestConnectionNetworkPolicy(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "10.1.2.3", "169.254.169.254", "100.100.100.200", "192.168.1.1", "172.16.0.1", "0.0.0.0", "192.0.2.1", "::1", "::ffff:127.0.0.1", "fc00::1", "fe80::1", "64:ff9b::a00:1", "2002:7f00:1::", "2001:db8::1"} {
		if publicTestIP(netip.MustParseAddr(raw)) {
			t.Fatalf("accepted restricted address %s", raw)
		}
	}
	for _, raw := range []string{"8.8.8.8", "2606:4700:4700::1111"} {
		if !publicTestIP(netip.MustParseAddr(raw)) {
			t.Fatal("rejected global address")
		}
	}
	for _, raw := range []string{"http://host.test", "https://user:pass@host.test", "https://host.test:8443", "https://host.test/#x", "https://host.test/?x=1"} {
		if _, err := testHTTPS(raw); err == nil {
			t.Fatal("unsafe URL")
		}
	}
	lookups := 0
	dialed := ""
	n := testNetwork{lookup: func(context.Context, string, string) ([]netip.Addr, error) {
		lookups++
		if lookups > 1 {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}, dial: func(_ context.Context, _ string, address string) (net.Conn, error) { dialed = address; return nil, nil }}
	_, err := n.dialContext(context.Background(), "tcp", "provider.example.test:443")
	if err != nil || lookups != 1 || dialed != "8.8.8.8:443" {
		t.Fatal("did not pin checked IP")
	}
	if _, err = n.dialContext(context.Background(), "tcp", "provider.example.test:443"); err == nil {
		t.Fatal("DNS rebinding accepted")
	}
	n.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.0.0.1")}, nil
	}
	if _, err = n.resolve(context.Background(), "mixed.test"); err == nil {
		t.Fatal("mixed DNS accepted")
	}
	calls := 0
	transport := testTransport{origin: "https://provider.example.test", base: testRoundTrip(func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"https://169.254.169.254/"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errTestNetwork }}
	if _, err = client.Get("https://provider.example.test/jwks"); err == nil || calls != 1 {
		t.Fatal("redirect followed")
	}
	if _, err = client.Get("https://another.example.test/jwks"); err == nil || calls != 1 {
		t.Fatal("cross-origin outbound request")
	}
}

func TestConnectionIsolationAndCancellation(t *testing.T) {
	f := newFixture(t)
	m := approvedProbeRevision(t, f)
	p := newMockConnectionIssuer(t)
	s := newConnectionTests(f.repo, apiOrigin)
	s.client = func(context.Context, string) (*http.Client, error) { return p.client(), nil }
	h := probeHandler(f, s, f.identity)
	first, cookie, state := startProbe(t, h, p, m)
	other := auth.Identity{Issuer: f.identity.Issuer, Subject: "other-admin", Provider: auth.OIDC}
	actor, err := f.store.Resolve(context.Background(), other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.owner.Exec(context.Background(), `INSERT INTO framework.user_roles(user_id,role) VALUES($1,'Admin')`, actor.ID); err != nil {
		t.Fatal(err)
	}
	otherHandler := probeHandler(f, s, other)
	apiRequest(t, otherHandler, "GET", "/api/admin/auth/tests/"+first.ID, nil, 404)
	apiRequest(t, otherHandler, "POST", "/api/admin/auth/tests/"+first.ID+"/cancel", map[string]any{}, 404)
	// A pending test remains bound to its revision and generation.
	apiRequest(t, h, "POST", settingsPath+"/"+m.ID+"/test", map[string]int64{"expected_generation": m.Generation + 1}, 409)
	var next Metadata
	f.run(t, func(ctx context.Context) {
		var err error
		next, err = f.repo.CreateDraft(ctx, 1, m.Settings, NewSecret([]byte(apiSecret)))
		if err != nil {
			t.Fatal(err)
		}
	})
	apiRequest(t, h, "POST", settingsPath+"/"+next.ID+"/test", map[string]int64{"expected_generation": next.Generation}, 400)
	cancelled := apiRequest(t, h, "POST", "/api/admin/auth/tests/"+first.ID+"/cancel", map[string]any{}, 200)
	if !strings.Contains(cancelled.Body.String(), `"cancelled"`) {
		t.Fatal("not cancelled")
	}
	callbackProbe(t, h, cookie, state, "synthetic-code")
	if p.exchanges != 0 {
		t.Fatal("cancelled test exchanged code")
	}
	// Concurrent test cookies/state cannot be substituted; completing one does
	// not consume the other. No global flow cookie is shared between tests.
	one, c1, s1 := startProbe(t, h, p, m)
	two, c2, s2 := startProbe(t, h, p, m)
	callbackProbe(t, h, c1, s2, "synthetic-code")
	if resultProbe(t, h, one.ID).Status != "pending" || resultProbe(t, h, two.ID).Status != "pending" {
		t.Fatal("cross-test state consumed")
	}
	callbackProbe(t, h, c2, s2, "synthetic-code")
	if resultProbe(t, h, two.ID).Status != "succeeded" {
		t.Fatal("second test failed")
	}
	// Recover the first mock grant (a real provider tracks grants independently).
	e := s.get(one.ID)
	p.nonce = e.nonce
	sum := sha256.Sum256([]byte(e.verifier))
	p.challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRequest("GET", "/api/auth/test/callback?"+url.Values{"state": {s1}, "code": {"synthetic-code"}}.Encode(), nil)
			r.AddCookie(c1)
			h.ServeHTTP(httptest.NewRecorder(), r)
		}()
	}
	wg.Wait()
	if p.exchanges != 2 || resultProbe(t, h, one.ID).Status != "succeeded" {
		t.Fatal("concurrent callbacks replayed exchange")
	}
}
func TestConnectionAuthorizationAndAuditFailures(t *testing.T) {
	f := newFixture(t)
	m := approvedProbeRevision(t, f)
	p := newMockConnectionIssuer(t)
	s := newConnectionTests(f.repo, apiOrigin)
	s.client = func(context.Context, string) (*http.Client, error) { return p.client(), nil }
	h := probeHandler(f, s, f.identity)
	route := settingsPath + "/" + m.ID + "/test"
	// Missing authentication and existing users without admin.manage.
	unauth := http.NewServeMux()
	s.register(unauth, func(pattern string, fn http.HandlerFunc) { unauth.Handle(pattern, auth.Require(nil, fn)) })
	apiRequest(t, unauth, "POST", route, map[string]int64{"expected_generation": 3}, 401)
	for _, role := range []string{"User", "Viewer"} {
		identity := auth.Identity{Issuer: f.identity.Issuer, Subject: "test-" + role, Provider: auth.OIDC}
		if _, err := f.store.Resolve(context.Background(), identity); err != nil {
			t.Fatal(err)
		}
		apiRequest(t, probeHandler(f, s, identity), "POST", route, map[string]int64{"expected_generation": 3}, 403)
	}
	request := httptest.NewRequest("POST", route, strings.NewReader(`{"expected_generation":3}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://attacker.test")
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != 403 {
		t.Fatal("origin bypass")
	}
	if _, err := s.repo.testTransaction(context.Background(), m.ID, m.Generation, "test", "", "", nil, nil); !errors.Is(err, ErrDenied) {
		t.Fatal("unverified context accepted")
	}
	// Callback rechecks the original admin; the tested identity cannot replace it.
	result, cookie, state := startProbe(t, h, p, m)
	if _, err := f.owner.Exec(context.Background(), `UPDATE framework.users SET active=false WHERE subject=$1`, f.identity.Subject); err != nil {
		t.Fatal(err)
	}
	callbackProbe(t, h, cookie, state, "synthetic-code")
	if p.exchanges != 0 || s.get(result.ID).result.Status != "failed" {
		t.Fatal("revoked administrator accepted")
	}
	if _, err := f.owner.Exec(context.Background(), `UPDATE framework.users SET active=true WHERE subject=$1`, f.identity.Subject); err != nil {
		t.Fatal(err)
	}
	// Make audit inserts fail in the disposable database only.
	result, cookie, state = startProbe(t, h, p, m)
	if _, err := f.owner.Exec(context.Background(), `CREATE FUNCTION public.reject_test_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic audit failure'; END $$; CREATE TRIGGER reject_test_audit BEFORE INSERT ON framework.audit_log FOR EACH ROW EXECUTE FUNCTION public.reject_test_audit()`); err != nil {
		t.Fatal(err)
	}
	callbackProbe(t, h, cookie, state, "synthetic-code")
	got := resultProbe(t, h, result.ID)
	if got.Status != "failed" || got.Identity != nil {
		t.Fatal("success published without audit")
	}
	apiRequest(t, h, "POST", route, map[string]int64{"expected_generation": 3}, 503)
	if _, err := f.owner.Exec(context.Background(), `DROP TRIGGER reject_test_audit ON framework.audit_log; DROP FUNCTION public.reject_test_audit()`); err != nil {
		t.Fatal(err)
	}
	// Wrong/unavailable historical key never releases an authorization URL.
	wrong, err := NewRepository(f.store, f.repo.scope, testCipher(t, "other-key"))
	if err != nil {
		t.Fatal(err)
	}
	unavailable := newConnectionTests(wrong, apiOrigin)
	unavailable.client = func(context.Context, string) (*http.Client, error) {
		t.Error("network used without decryption")
		return nil, ErrUnavailable
	}
	apiRequest(t, probeHandler(f, unavailable, f.identity), "POST", route, map[string]int64{"expected_generation": 3}, 503)
	// Enforced ephemeral capacity; no unlimited concurrent handshakes.
	s = newConnectionTests(f.repo, apiOrigin)
	s.client = func(context.Context, string) (*http.Client, error) { return p.client(), nil }
	h = probeHandler(f, s, f.identity)
	for range 3 {
		startProbe(t, h, p, m)
	}
	apiRequest(t, h, "POST", route, map[string]int64{"expected_generation": 3}, 409)
}
func TestConnectionCallbackAndResponseBounds(t *testing.T) {
	m := Metadata{Scope: Scope{Environment: "development"}, Settings: Settings{IssuerURL: probeIssuer, ClientID: "test-client", AllowHTTPDevelopment: true}}
	if u, err := testCallback("http://localhost:8080", m); err != nil || u != "http://localhost:8080/api/auth/test/callback" {
		t.Fatal("local callback rejected")
	}
	m.Environment = "production"
	if _, err := testCallback("http://localhost:8080", m); err == nil {
		t.Fatal("production HTTP allowed")
	}
	body := &limitedTestBody{io.NopCloser(strings.NewReader(strings.Repeat("x", 1025))), 1024}
	if _, err := io.ReadAll(body); err == nil {
		t.Fatal("response bound ignored")
	}
}

func TestConnectionConcurrentStartAndExpiryCleanup(t *testing.T) {
	f := newFixture(t)
	m := approvedProbeRevision(t, f)
	s := newConnectionTests(f.repo, apiOrigin)
	f.run(t, func(ctx context.Context) {
		first, err := s.allocate(ctx, m.ID, m.Generation)
		if err != nil {
			t.Fatal(err)
		}
		first.mu.Lock()
		done := make(chan error, 1)
		go func() { _, err := s.allocate(ctx, m.ID, m.Generation); done <- err }()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("concurrent reservation blocked on network work")
		}
		first.mu.Unlock()
		first.result.Status = "pending"
		first.result.Expires = time.Now().Add(-11 * time.Minute)
		// A stale callback holding a pointer obtained before removal must not see a
		// pending entry with erased context and panic during authorization.
		if _, err := s.allocate(ctx, m.ID, m.Generation); err != nil {
			t.Fatal(err)
		}
		if s.get(first.result.ID) != nil || first.result.Status != "expired" || first.context != nil {
			t.Fatal("unsafe lazy expiry")
		}
	})
}
