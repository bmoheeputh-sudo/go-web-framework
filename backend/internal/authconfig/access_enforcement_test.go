package authconfig

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/jackc/pgx/v5"
	"golang.org/x/oauth2"
)

type admissionFixture struct {
	f        *fixture
	service  *ActivationService
	provider *mockConnectionIssuer
	revision Metadata
	handler  http.Handler
	policy   *AccessPolicyRepository
}

func newAdmissionFixture(t *testing.T) *admissionFixture {
	t.Helper()
	f, s, p, m := activationServiceFixture(t)
	request, admin := activationReadiness(t, f, m, "")
	if _, err := f.owner.Exec(context.Background(), `UPDATE framework.users SET email='admin@example.test',email_verified=true WHERE id=$1`, admin); err != nil {
		t.Fatal(err)
	}
	prepared := prepareActivation(t, f, s, m, 0)
	f.run(t, func(ctx context.Context) {
		if _, err := s.Activate(ctx, prepared, request); err != nil {
			t.Fatal(err)
		}
	})
	f.identity = auth.Identity{Issuer: probeIssuer, Subject: "enrolled-admin", Provider: auth.OIDC, Email: "admin@example.test", EmailVerified: true}
	mux := http.NewServeMux()
	s.runtime.RegisterRoutes(mux)
	access.Register(mux, s.runtime, f.store, apiOrigin)
	policy, _ := NewAccessPolicyRepository(f.store, f.repo.scope)
	p.callback = m.RedirectURI
	return &admissionFixture{f, s, p, m, s.runtime.Capture(mux), policy}
}
func (a *admissionFixture) login(t *testing.T, subject, email string, verified bool) *httptest.ResponseRecorder {
	t.Helper()
	a.provider.mu.Lock()
	a.provider.claims = func(c map[string]any) { c["sub"] = subject; c["email"] = email; c["email_verified"] = verified }
	a.provider.mu.Unlock()
	w := httptest.NewRecorder()
	a.handler.ServeHTTP(w, httptest.NewRequest("GET", apiOrigin+"/api/auth/login", nil))
	if w.Code != 302 {
		t.Fatal("login start", w.Code)
	}
	location, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	a.provider.mu.Lock()
	a.provider.nonce = location.Query().Get("nonce")
	a.provider.challenge = location.Query().Get("code_challenge")
	a.provider.mu.Unlock()
	r := httptest.NewRequest("GET", a.revision.RedirectURI+"?"+url.Values{"state": {location.Query().Get("state")}, "code": {"synthetic-code"}}.Encode(), nil)
	for _, c := range w.Result().Cookies() {
		r.AddCookie(c)
	}
	w = httptest.NewRecorder()
	a.handler.ServeHTTP(w, r)
	return w
}
func sessionCookieFor(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	if w.Code != 303 {
		t.Fatal("login denied", w.Code, w.Body.String())
	}
	for _, c := range w.Result().Cookies() {
		if strings.Contains(c.Name, "session") && c.Value != "" {
			return c
		}
	}
	t.Fatal("missing session")
	return nil
}
func getSession(h http.Handler, c *http.Cookie, path string) int {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", apiOrigin+path, nil)
	r.AddCookie(c)
	h.ServeHTTP(w, r)
	return w.Code
}
func (a *admissionFixture) changePolicy(t *testing.T, mode, role string, domains []string) {
	t.Helper()
	a.f.run(t, func(ctx context.Context) {
		p, err := a.policy.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = a.policy.Update(ctx, PolicyExpectation{p.Generation, 1}, AccessPolicySettings{mode, domains, role}, "explicit test policy change")
		if err != nil {
			t.Fatal(err)
		}
	})
}
func (a *admissionFixture) approval(t *testing.T, issuer, subject, status string, generation int64) {
	t.Helper()
	a.f.run(t, func(ctx context.Context) {
		p, err := a.policy.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = a.policy.SetApproval(ctx, PolicyExpectation{p.Generation, 1}, OIDCIdentityKey{issuer, subject}, generation, status, "explicit identity decision")
		if err != nil {
			t.Fatal(err)
		}
	})
}
func TestOIDCPolicyNormalCallbackAndExistingSessions(t *testing.T) {
	a := newAdmissionFixture(t)
	adminCookie := sessionCookieFor(t, a.login(t, "enrolled-admin", "admin@example.test", true))
	if getSession(a.handler, adminCookie, "/api/admin/users") != 200 {
		t.Fatal("existing OIDC administrator lost access")
	}
	var adminRoles []string
	if err := a.f.owner.QueryRow(context.Background(), `SELECT ARRAY(SELECT ur.role FROM framework.user_roles ur JOIN framework.users u ON u.id=ur.user_id WHERE u.subject='enrolled-admin' ORDER BY ur.role)`).Scan(&adminRoles); err != nil || strings.Join(adminRoles, ",") != "Admin" {
		t.Fatal("existing role grants changed", err)
	}
	cookie := sessionCookieFor(t, a.login(t, "new-user", "new@example.test", true))
	sessionCookieFor(t, a.login(t, "new-user", "new@example.test", true))
	var users, roles, audits int
	if err := a.f.owner.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM framework.users WHERE issuer=$1 AND subject='new-user'),(SELECT count(*) FROM framework.user_roles ur JOIN framework.users u ON u.id=ur.user_id WHERE u.subject='new-user' AND ur.role='Viewer'),(SELECT count(*) FROM framework.audit_log WHERE action='oidc_access.user_provisioned')`, probeIssuer).Scan(&users, &roles, &audits); err != nil || users != 1 || roles != 1 || audits != 1 {
		t.Fatal("duplicate provisioning", users, roles, audits, err)
	}
	if getSession(a.handler, cookie, "/api/auth/me") != 200 || getSession(a.handler, cookie, "/api/access/me") != 200 {
		t.Fatal("normal session unavailable")
	}
	// Second runtime reads the same policy on every request, without a cache.
	reader, _ := NewActivationReader(a.f.pool, a.f.repo.scope)
	loader, _ := NewStartupLoader(reader, a.f.repo.cipher, a.service.sessions, a.service.callback)
	loader.client = func(context.Context, string) (*http.Client, error) { return a.provider.client(), nil }
	other, err := loader.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	mux := http.NewServeMux()
	other.RegisterRoutes(mux)
	second := other.Capture(mux)
	a.approval(t, probeIssuer, "new-user", "approved", 0)
	a.approval(t, probeIssuer, "new-user", "revoked", 1)
	if getSession(second, cookie, "/api/auth/me") != 401 || getSession(a.handler, cookie, "/api/auth/me") != 401 {
		t.Fatal("revoked session accepted")
	}
	a.approval(t, probeIssuer, "new-user", "approved", 2)
	if getSession(a.handler, cookie, "/api/auth/me") != 401 {
		t.Fatal("revocation resurrected old session")
	}
	a.changePolicy(t, "approved_users_only", "User", []string{"example.test"})
	if !loginDenied(a.login(t, "missing", "user@example.test", true)) {
		t.Fatal("missing approval accepted")
	}
	a.approval(t, strings.TrimSuffix(probeIssuer, "/"), "exact", "approved", 0)
	if !loginDenied(a.login(t, "exact", "user@example.test", true)) {
		t.Fatal("issuer normalized")
	}
	a.approval(t, probeIssuer, "exact", "approved", 0)
	sessionCookieFor(t, a.login(t, "exact", "user@example.test", true))
	if !loginDenied(a.login(t, "Exact", "user@example.test", true)) {
		t.Fatal("subject case folded")
	}
	var role string
	if err := a.f.owner.QueryRow(context.Background(), `SELECT ur.role FROM framework.user_roles ur JOIN framework.users u ON u.id=ur.user_id WHERE u.subject='exact'`).Scan(&role); err != nil || role != "User" {
		t.Fatal("default role", role, err)
	}
	for _, tc := range []struct {
		email    string
		verified bool
	}{{"user@example.test", false}, {"user@sub.example.test", true}, {"user@evilexample.test", true}, {"user@example.test.evil", true}} {
		if !loginDenied(a.login(t, "exact", tc.email, tc.verified)) {
			t.Fatal("domain restriction bypass")
		}
	}
	inactiveCookie := sessionCookieFor(t, a.login(t, "exact", "user@example.test", true))
	a.f.run(t, func(ctx context.Context) {
		u, err := a.f.store.Resolve(ctx, a.f.identity)
		if err != nil {
			t.Fatal(err)
		}
		var target string
		if err := a.f.owner.QueryRow(ctx, `SELECT id::text FROM framework.users WHERE subject='exact'`).Scan(&target); err != nil {
			t.Fatal(err)
		}
		if err := a.f.store.SetActive(ctx, u.ID, target, false); err != nil {
			t.Fatal(err)
		}
	})
	if getSession(second, inactiveCookie, "/api/auth/me") != 401 || !loginDenied(a.login(t, "exact", "user@example.test", true)) {
		t.Fatal("inactive user accepted")
	}
	// Domain changes affect already issued sessions on both instances.
	a.changePolicy(t, "allow_all", "Viewer", []string{})
	outsider := sessionCookieFor(t, a.login(t, "outsider", "user@other.test", true))
	a.changePolicy(t, "allow_all", "Viewer", []string{"example.test"})
	if getSession(second, outsider, "/api/auth/me") != 401 {
		t.Fatal("policy cache admitted excluded domain")
	}
}

func TestOIDCAdmissionAtomicProvisioning(t *testing.T) {
	f, r := policyFixture(t)
	bootstrapPolicy(t, f, r)
	f.run(t, func(ctx context.Context) {
		if _, err := r.Update(ctx, PolicyExpectation{1, 1}, AccessPolicySettings{"allow_all", []string{}, "Viewer"}, "allow synthetic first logins"); err != nil {
			t.Fatal(err)
		}
	})
	admission := f.store.OIDCAdmission(f.repo.scope.DeploymentID, f.repo.scope.Environment)
	identity := auth.Identity{Issuer: f.identity.Issuer, Subject: "concurrent", Provider: auth.OIDC}
	results := make(chan error, 10)
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- admission.Login(context.Background(), identity, func(context.Context, pgx.Tx) error { return nil })
		}()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	var users, grants, admins int
	if err := f.owner.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM framework.users WHERE subject='concurrent'),(SELECT count(*) FROM framework.user_roles ur JOIN framework.users u ON u.id=ur.user_id WHERE u.subject='concurrent'),(SELECT count(*) FROM framework.user_roles ur JOIN framework.users u ON u.id=ur.user_id WHERE u.subject='concurrent' AND ur.role='Admin')`).Scan(&users, &grants, &admins); err != nil || users != 1 || grants != 1 || admins != 0 {
		t.Fatal("concurrent provisioning", err)
	}
	identity.Subject = "rollback"
	if err := admission.Login(context.Background(), identity, func(context.Context, pgx.Tx) error { return errors.New("synthetic session failure") }); err == nil {
		t.Fatal("failed session accepted")
	}
	if err := f.owner.QueryRow(context.Background(), `SELECT count(*) FROM framework.users WHERE subject='rollback'`).Scan(&users); err != nil || users != 0 {
		t.Fatal("partial user after session failure")
	}
	if _, err := f.owner.Exec(context.Background(), `CREATE FUNCTION framework.reject_provision_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='oidc_access.user_provisioned' THEN RAISE EXCEPTION 'synthetic'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_provision_audit BEFORE INSERT ON framework.audit_log FOR EACH ROW EXECUTE FUNCTION framework.reject_provision_audit()`); err != nil {
		t.Fatal(err)
	}
	called := false
	if err := admission.Login(context.Background(), identity, func(context.Context, pgx.Tx) error { called = true; return nil }); err == nil || called {
		t.Fatal("audit failure did not block session")
	}
	if err := f.owner.QueryRow(context.Background(), `SELECT count(*) FROM framework.users WHERE subject='rollback'`).Scan(&users); err != nil || users != 0 {
		t.Fatal("audit failure provisioned user")
	}
}

func TestOIDCPolicyBootstrapSession(t *testing.T) {
	f, r := policyFixture(t)
	if err := f.store.OIDCAdmission(f.repo.scope.DeploymentID, f.repo.scope.Environment).CheckStartup(context.Background(), f.identity.Issuer); !errors.Is(err, access.ErrPolicyNotReady) {
		t.Fatal("missing bootstrap accepted", err)
	}
	token := oauth2.GenerateVerifier()
	hash := sha256.Sum256([]byte(token))
	if _, err := f.owner.Exec(context.Background(), `INSERT INTO framework.sessions(token_hash,issuer,subject,email,email_verified,display_name,provider,expires_at,binding_source,deployment_id,environment,revision_id,activation_generation,client_id,flow_purpose)
 SELECT $1,r.issuer_url,$2,$3,true,'Admin','oidc',clock_timestamp()+interval '1 hour','database',h.deployment_id,h.environment,r.id,h.generation,r.client_id,'login' FROM framework.auth_activation_heads h JOIN framework.auth_config_revisions r ON r.id=h.active_revision_id`, hash[:], f.identity.Subject, f.identity.Email); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		token      string
		generation int64
	}{{oauth2.GenerateVerifier(), 1}, {token, 2}} {
		if _, err := r.BootstrapSession(context.Background(), tc.token, tc.generation, time.Minute, policySettings(), "explicit rollout bootstrap"); err == nil {
			t.Fatal("invalid proof accepted")
		}
	}
	wrong, _ := NewAccessPolicyRepository(f.store, Scope{"other", "production"})
	if _, err := wrong.BootstrapSession(context.Background(), token, 1, time.Minute, policySettings(), "wrong scope bootstrap"); err == nil {
		t.Fatal("cross scope accepted")
	}
	if _, err := r.BootstrapSession(context.Background(), token, 1, time.Minute, policySettings(), "explicit rollout bootstrap"); err != nil {
		t.Fatal(err)
	}
	if err := f.store.OIDCAdmission(f.repo.scope.DeploymentID, f.repo.scope.Environment).CheckStartup(context.Background(), f.identity.Issuer); err != nil {
		t.Fatal(err)
	}
	if _, err := r.BootstrapSession(context.Background(), token, 1, time.Minute, policySettings(), "duplicate rollout bootstrap"); !errors.Is(err, ErrConflict) {
		t.Fatal("bootstrap repeat", err)
	}
}

func TestOIDCPolicyFinalAdministratorAcrossRBAC(t *testing.T) {
	a := newAdmissionFixture(t)
	a.f.identity = auth.Identity{Issuer: "https://issuer.example.test", Subject: "config-admin", Provider: auth.OIDC}
	a.f.run(t, func(ctx context.Context) {
		actor, _ := access.Principal(ctx)
		var target string
		if err := a.f.owner.QueryRow(ctx, `SELECT id::text FROM framework.users WHERE issuer=$1 AND subject='enrolled-admin'`, probeIssuer).Scan(&target); err != nil {
			t.Fatal(err)
		}
		if err := a.f.store.SetActive(ctx, actor.ID, target, false); !errors.Is(err, access.ErrConflict) {
			t.Fatal("last eligible admin deactivated", err)
		}
		if err := a.f.store.SetRoles(ctx, actor.ID, target, []string{"Viewer"}); !errors.Is(err, access.ErrConflict) {
			t.Fatal("last eligible admin demoted", err)
		}
	})
}

func loginDenied(w *httptest.ResponseRecorder) bool {
	if w.Code != 303 || !strings.Contains(w.Header().Get("Location"), "auth_error=login_failed") {
		return false
	}
	for _, cookie := range w.Result().Cookies() {
		if strings.Contains(cookie.Name, "session") && cookie.Value != "" {
			return false
		}
	}
	return true
}

func TestOIDCAdmissionSerializesRevocationAndSessionCreation(t *testing.T) {
	f, r := policyFixture(t)
	bootstrapPolicy(t, f, r)
	key := OIDCIdentityKey{f.identity.Issuer, "serialized-user"}
	f.run(t, func(ctx context.Context) {
		if _, err := r.SetApproval(ctx, PolicyExpectation{1, 1}, key, 0, "approved", "approve serialized identity"); err != nil {
			t.Fatal(err)
		}
	})
	admission := f.store.OIDCAdmission(f.repo.scope.DeploymentID, f.repo.scope.Environment)
	identity := auth.Identity{Issuer: key.Issuer, Subject: key.Subject, Provider: auth.OIDC, Email: "user@vopak.com", EmailVerified: true}
	entered, release := make(chan struct{}), make(chan struct{})
	loginDone := make(chan error, 1)
	go func() {
		loginDone <- admission.Login(context.Background(), identity, func(ctx context.Context, tx pgx.Tx) error {
			close(entered)
			<-release
			hash := sha256.Sum256([]byte(oauth2.GenerateVerifier()))
			_, err := tx.Exec(ctx, `INSERT INTO framework.sessions(token_hash,issuer,subject,email,email_verified,provider,expires_at) VALUES($1,$2,$3,$4,true,'oidc',clock_timestamp()+interval '1 hour')`, hash[:], identity.Issuer, identity.Subject, identity.Email)
			return err
		})
	}()
	<-entered
	f.run(t, func(ctx context.Context) {
		done := make(chan error, 1)
		go func() {
			_, err := r.SetApproval(ctx, PolicyExpectation{1, 1}, key, 1, "revoked", "concurrent explicit revocation")
			done <- err
		}()
		// PostgreSQL proves that revocation waits for the login transaction; do not
		// rely on scheduler timing or reuse an unlocked policy preflight.
		deadline := time.Now().Add(2 * time.Second)
		waiting := false
		for time.Now().Before(deadline) {
			if err := f.owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event='advisory')`).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		close(release)
		if err := <-loginDone; err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if !waiting {
			t.Fatal("revocation did not serialize with credential write")
		}
	})
	var count int
	if err := f.owner.QueryRow(context.Background(), `SELECT count(*) FROM framework.sessions WHERE subject=$1`, key.Subject).Scan(&count); err != nil || count != 0 {
		t.Fatal("revocation retained session", err)
	}
	called := false
	if err := admission.Login(context.Background(), identity, func(context.Context, pgx.Tx) error { called = true; return nil }); !errors.Is(err, auth.ErrUnauthenticated) || called {
		t.Fatal("revoked login reached credential write", err)
	}
}

func TestActivationRejectsPolicyIneligibleTestedAdministrator(t *testing.T) {
	f, s, _, m := activationServiceFixture(t)
	request, user := activationReadiness(t, f, m, "")
	p := prepareActivation(t, f, s, m, 0)
	// Another approved administrator must not substitute for the specific tested
	// and enrolled identity selected for activation.
	other, err := f.store.Resolve(context.Background(), auth.Identity{Issuer: m.IssuerURL, Subject: "other-approved-admin", Provider: auth.OIDC})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.Exec(context.Background(), `INSERT INTO framework.user_roles VALUES($1,'Admin')`, other.ID); err != nil {
		t.Fatal(err)
	}
	seedAdmissionPolicy(t, f, m.IssuerURL, other.Subject, other.ID)
	if _, err := f.owner.Exec(context.Background(), `UPDATE framework.oidc_identity_approvals SET status='revoked',generation=generation+1,reason='synthetic tested administrator revoked' WHERE issuer=$1 AND subject='enrolled-admin'`, m.IssuerURL); err != nil {
		t.Fatal(err)
	}
	before := activationState(t, f)
	f.run(t, func(ctx context.Context) {
		if _, err := s.Activate(ctx, p, request); !errors.Is(err, ErrLastOIDCAdministrator) {
			t.Fatal("ineligible tested identity activated", user, err)
		}
	})
	if activationState(t, f) != before {
		t.Fatal("denied policy activation changed state")
	}
}

func TestStartupRejectsUninitializedAccessPolicy(t *testing.T) {
	f, s, provider, m := activationServiceFixture(t)
	if err := activationFixture(t, f, m, 1, "", false); err != nil {
		t.Fatal(err)
	}
	reader, _ := NewActivationReader(f.pool, f.repo.scope)
	loader, _ := NewStartupLoader(reader, f.repo.cipher, s.sessions, s.callback)
	called := false
	loader.client = func(context.Context, string) (*http.Client, error) { called = true; return provider.client(), nil }
	before := activationState(t, f)
	if runtime, err := loader.Load(context.Background()); !errors.Is(err, access.ErrPolicyNotReady) || runtime != nil || called {
		t.Fatal("uninitialized policy selected a runtime", err)
	}
	if before != activationState(t, f) {
		t.Fatal("startup silently bootstrapped")
	}
}
