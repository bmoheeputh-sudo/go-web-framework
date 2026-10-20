package authconfig

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
)

func activationServiceFixture(t *testing.T) (*fixture, *ActivationService, *mockConnectionIssuer, Metadata) {
	t.Helper()
	f := newFixture(t)
	// Production go_web_app is the schema owner; grant the equivalent operations
	// to this harness's deliberately non-owner application role, only in this cluster.
	if _, err := f.owner.Exec(context.Background(), `GRANT INSERT,UPDATE ON framework.auth_activation_heads TO go_web_app; GRANT INSERT ON framework.auth_activation_history TO go_web_app`); err != nil {
		t.Fatal(err)
	}
	m := approvedProbeRevision(t, f)
	provider := newMockConnectionIssuer(t)
	local, err := auth.NewLocalDev("development", auth.LocalDevConfig{Subject: "synthetic-local", Email: "local@example.test", DisplayName: "Local Test"})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := auth.NewEnvironmentRuntime(local, f.repo.scope.DeploymentID, f.repo.scope.Environment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Close)
	config := auth.SessionConfig{IdleTimeout: time.Minute, AbsoluteTimeout: time.Hour}
	store, _ := auth.NewPostgresStore(f.pool, config)
	s, err := NewActivationService(f.repo, runtime, store, config, apiOrigin+"/api/auth/callback")
	if err != nil {
		t.Fatal(err)
	}
	s.client = func(context.Context, string) (*http.Client, error) { return provider.client(), nil }
	return f, s, provider, m
}

// Synthetic verifier evidence is fixture-only. No HTTP endpoint can submit it.
func activationReadiness(t *testing.T, f *fixture, m Metadata, existingUser string) (ActivationRequest, string) {
	t.Helper()
	var isolated, normal TestEvidence
	var userID string
	f.run(t, func(ctx context.Context) {
		now := time.Now()
		proof := verifiedTestEvidence{revisionID: m.ID, revisionGeneration: m.Generation, identity: auth.Identity{Issuer: m.IssuerURL, Subject: "enrolled-admin", Provider: auth.OIDC}, completedAt: now, expiresAt: now.Add(5 * time.Minute), purpose: IsolatedConnection}
		var err error
		isolated, err = f.repo.recordTestEvidence(ctx, proof)
		if err != nil {
			t.Fatal(err)
		}
		if existingUser == "" {
			u, err := f.repo.EnrollIdentity(ctx, m.ID, isolated.ID, m.Generation, "Admin")
			if err != nil {
				t.Fatal(err)
			}
			userID = u.ID
		} else {
			userID = existingUser
		}
		proof.purpose = NormalCallback
		normal, err = f.repo.recordTestEvidence(ctx, proof)
		if err != nil {
			t.Fatal(err)
		}
	})
	return ActivationRequest{IsolatedEvidenceID: isolated.ID, NormalEvidenceID: normal.ID, EnrolledUserID: userID, Reason: "synthetic approved activation"}, userID
}
func prepareActivation(t *testing.T, f *fixture, s *ActivationService, m Metadata, expected int64) *PreparedActivation {
	t.Helper()
	var p *PreparedActivation
	f.run(t, func(ctx context.Context) {
		var err error
		p, err = s.Prepare(ctx, m.ID, m.Generation, expected)
		if err != nil {
			t.Fatal("prepare", err)
		}
	})
	t.Cleanup(p.Close)
	return p
}
func activationState(t *testing.T, f *fixture) string {
	t.Helper()
	var state string
	err := f.owner.QueryRow(context.Background(), `SELECT jsonb_build_array(
 (SELECT jsonb_agg(to_jsonb(h) ORDER BY generation) FROM framework.auth_activation_heads h),
 (SELECT jsonb_agg(to_jsonb(a) ORDER BY generation) FROM framework.auth_activation_history a),
 (SELECT jsonb_agg(to_jsonb(l) ORDER BY revision_id) FROM framework.auth_config_lifecycle l),
 (SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM framework.audit_log a))::text`).Scan(&state)
	if err != nil {
		t.Fatal(err)
	}
	return state
}
func TestControlledActivationAndRecovery(t *testing.T) {
	f, s, _, m := activationServiceFixture(t)
	request, userID := activationReadiness(t, f, m, "")
	p := prepareActivation(t, f, s, m, 0)
	before := activationState(t, f)
	for name, change := range map[string]func(*ActivationRequest){
		"missing normal":         func(r *ActivationRequest) { r.NormalEvidenceID = "" },
		"isolated is not normal": func(r *ActivationRequest) { r.NormalEvidenceID = r.IsolatedEvidenceID },
		"forged normal":          func(r *ActivationRequest) { r.NormalEvidenceID = "33333333-3333-4333-8333-333333333333" },
		"wrong user":             func(r *ActivationRequest) { r.EnrolledUserID = m.CreatedBy },
		"excess grace":           func(r *ActivationRequest) { r.Transition = 31 * time.Minute },
	} {
		t.Run(name, func(t *testing.T) {
			bad := request
			change(&bad)
			f.run(t, func(ctx context.Context) {
				if _, err := s.Activate(ctx, p, bad); err == nil {
					t.Fatal("unsafe activation accepted")
				}
			})
			if activationState(t, f) != before {
				t.Fatal("rejected activation changed data")
			}
		})
	}
	// Audit insertion failure must roll back head, lifecycle, history and audit.
	_, err := f.owner.Exec(context.Background(), `CREATE FUNCTION framework.reject_activation_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='auth_config.activated' THEN RAISE EXCEPTION 'synthetic'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_activation_audit BEFORE INSERT ON framework.audit_log FOR EACH ROW EXECUTE FUNCTION framework.reject_activation_audit()`)
	if err != nil {
		t.Fatal(err)
	}
	f.run(t, func(ctx context.Context) {
		if _, err := s.Activate(ctx, p, request); !errors.Is(err, ErrAudit) {
			t.Fatal("audit failure", err)
		}
	})
	if activationState(t, f) != before {
		t.Fatal("audit failure partially activated")
	}
	if _, err = f.owner.Exec(context.Background(), `DROP TRIGGER reject_activation_audit ON framework.audit_log; DROP FUNCTION framework.reject_activation_audit()`); err != nil {
		t.Fatal(err)
	}
	f.run(t, func(ctx context.Context) {
		result, err := s.Activate(ctx, p, request)
		if err != nil || !result.Applied || result.DesiredGeneration != 1 || result.AppliedGeneration != 1 {
			t.Fatal("activation", err, result)
		}
	})
	status, desired, mismatch := s.runtime.ControlStatus()
	if mismatch || status.Provider != auth.OIDC || status.Source != "database" || desired != 1 {
		t.Fatal("runtime not applied", status, desired)
	}
	reader, _ := NewActivationReader(f.pool, f.repo.scope)
	head, err := reader.Head(context.Background())
	if err != nil || head.Generation != 1 || head.ActiveRevisionID != m.ID {
		t.Fatal("head", err)
	}
	f.run(t, func(ctx context.Context) {
		if _, err := s.Activate(ctx, p, request); !errors.Is(err, ErrConflict) {
			t.Fatal("stale activation replay", err)
		}
	})
	// A second revision supersedes the first; no automatic roles or enrollment.
	var second Metadata
	f.run(t, func(ctx context.Context) {
		var err error
		second, err = f.repo.CreateDraft(ctx, m.Version, m.Settings, NewSecret([]byte(apiSecret)))
		if err != nil {
			t.Fatal(err)
		}
		for _, to := range []Status{Validated, Approved} {
			second, err = f.repo.Transition(ctx, second.ID, second.Generation, to)
			if err != nil {
				t.Fatal(err)
			}
		}
	})
	r2, _ := activationReadiness(t, f, second, userID)
	p2 := prepareActivation(t, f, s, second, 1)
	f.run(t, func(ctx context.Context) {
		if _, err := s.Activate(ctx, p2, r2); err != nil {
			t.Fatal("second activation", err)
		}
	})
	var recovery Metadata
	f.run(t, func(ctx context.Context) {
		var err error
		recovery, err = f.repo.PrepareRecoveryDraft(ctx, m.ID, second.Version)
		if err != nil {
			t.Fatal("recovery draft", err)
		}
		if recovery.Status != Draft || recovery.ID == m.ID || recovery.Settings != m.Settings {
			t.Fatal("mutated history")
		}
		oldSecret, err := f.repo.ReadSecretPrivileged(ctx, m.ID)
		if err != nil {
			t.Fatal(err)
		}
		newSecret, err := f.repo.ReadSecretPrivileged(ctx, recovery.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(oldSecret.value, newSecret.value) {
			t.Fatal("recovery changed the secret")
		}
		clear(oldSecret.value)
		clear(newSecret.value)
	})
	var oldNonce, newNonce, oldCipher, newCipher []byte
	if err = f.owner.QueryRow(context.Background(), `SELECT a.secret_nonce,b.secret_nonce,a.secret_ciphertext,b.secret_ciphertext FROM framework.auth_config_revisions a,framework.auth_config_revisions b WHERE a.id=$1 AND b.id=$2`, m.ID, recovery.ID).Scan(&oldNonce, &newNonce, &oldCipher, &newCipher); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(oldNonce, newNonce) || bytes.Equal(oldCipher, newCipher) {
		t.Fatal("recovery reused encryption envelope")
	}
	f.run(t, func(ctx context.Context) {
		if _, err := s.Prepare(ctx, recovery.ID, recovery.Generation, 2); err == nil {
			t.Fatal("unapproved recovery prepared")
		}
		for _, to := range []Status{Validated, Approved} {
			var err error
			recovery, err = f.repo.Transition(ctx, recovery.ID, recovery.Generation, to)
			if err != nil {
				t.Fatal(err)
			}
		}
	})
	rr, _ := activationReadiness(t, f, recovery, userID)
	pr := prepareActivation(t, f, s, recovery, 2)
	f.run(t, func(ctx context.Context) {
		if _, err := s.Activate(ctx, pr, rr); err != nil {
			t.Fatal("controlled rollback", err)
		}
		old, err := f.repo.Read(ctx, m.ID)
		if err != nil || old.Status != Superseded {
			t.Fatal("historical revision resurrected")
		}
	})
	events, err := reader.History(context.Background(), 0, 10)
	if err != nil || len(events) != 3 || events[0].RecoveryRevisionID != m.ID || events[0].TargetRevisionID != recovery.ID {
		t.Fatal("rollback provenance", err)
	}
}
func TestActivationPreparationRejectsUnsafeProviders(t *testing.T) {
	f, s, provider, m := activationServiceFixture(t)
	cases := []func(map[string]any){func(v map[string]any) { v["issuer"] = "https://forged.test" }, func(v map[string]any) { v["jwks_uri"] = "https://169.254.169.254/key" }, func(v map[string]any) { v["id_token_signing_alg_values_supported"] = []string{"none", "HS256"} }, func(v map[string]any) { v["token_endpoint"] = "https://other.test/token" }}
	for _, change := range cases {
		provider.metadata = change
		f.run(t, func(ctx context.Context) {
			p, err := s.Prepare(ctx, m.ID, m.Generation, 0)
			if err == nil {
				p.Close()
				t.Fatal("unsafe discovery accepted")
			}
		})
	}
	provider.metadata = nil
	provider.badKeys = true
	f.run(t, func(ctx context.Context) {
		if _, err := s.Prepare(ctx, m.ID, m.Generation, 0); err == nil {
			t.Fatal("invalid JWKS accepted")
		}
	})
	provider.badKeys = false
	s.callback = "https://other-app.test/api/auth/callback"
	f.run(t, func(ctx context.Context) {
		if _, err := s.Prepare(ctx, m.ID, m.Generation, 0); err == nil {
			t.Fatal("incompatible callback accepted")
		}
	})
	s.callback = m.RedirectURI
	other, _ := NewRepository(f.store, Scope{"wrong-deployment", "development"}, testCipher(t, "key-v1"))
	if _, err := NewActivationService(other, s.runtime, s.store, s.sessions, m.RedirectURI); err == nil {
		t.Fatal("wrong scope service accepted")
	}
	original := f.repo.cipher
	f.repo.cipher = testCipher(t, "unknown-key")
	f.run(t, func(ctx context.Context) {
		if _, err := s.Prepare(ctx, m.ID, m.Generation, 0); err == nil {
			t.Fatal("missing key accepted")
		}
	})
	f.repo.cipher = original
}
func TestActivationAuthorizationAndConcurrentAttempts(t *testing.T) {
	f, s, _, m := activationServiceFixture(t)
	request, user := activationReadiness(t, f, m, "")
	p := prepareActivation(t, f, s, m, 0)
	p2 := prepareActivation(t, f, s, m, 0)
	var ctx context.Context
	f.run(t, func(c context.Context) { ctx = context.WithoutCancel(c) })
	before := activationState(t, f)
	if _, err := s.Activate(context.Background(), p, request); !errors.Is(err, ErrDenied) {
		t.Fatal("missing admin accepted", err)
	}
	if activationState(t, f) != before {
		t.Fatal("unauthenticated operation wrote data")
	}
	if _, err := f.owner.Exec(ctx, `DELETE FROM framework.user_roles WHERE user_id=$1`, user); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Activate(ctx, p, request); !errors.Is(err, ErrDenied) {
		t.Fatal("tested identity without permission", err)
	}
	if _, err := f.owner.Exec(ctx, `INSERT INTO framework.user_roles(user_id,role) VALUES($1,'Admin')`, user); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, candidate := range []*PreparedActivation{p, p2} {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := s.Activate(ctx, candidate, request); results <- err }()
	}
	wg.Wait()
	close(results)
	successes, conflicts := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatal("concurrent activation was not serialized")
	}
}
func TestActivationExpiredEvidenceAndRevocation(t *testing.T) {
	f, s, _, m := activationServiceFixture(t)
	r, _ := activationReadiness(t, f, m, "")
	original := r
	p := prepareActivation(t, f, s, m, 0)
	var ctx context.Context
	f.run(t, func(c context.Context) {
		ctx = context.WithoutCancel(c)
		now := time.Now()
		e, err := f.repo.recordTestEvidence(c, verifiedTestEvidence{revisionID: m.ID, revisionGeneration: m.Generation, identity: auth.Identity{Issuer: m.IssuerURL, Subject: "enrolled-admin", Provider: auth.OIDC}, purpose: NormalCallback, completedAt: now, expiresAt: now.Add(100 * time.Millisecond)})
		if err != nil {
			t.Fatal(err)
		}
		r.NormalEvidenceID = e.ID
	})
	time.Sleep(150 * time.Millisecond)
	before := activationState(t, f)
	if _, err := s.Activate(ctx, p, r); !errors.Is(err, ErrDenied) {
		t.Fatal("expired evidence", err)
	}
	if activationState(t, f) != before {
		t.Fatal("expired evidence changed state")
	}
	r = original
	if _, err := f.owner.Exec(ctx, `DELETE FROM framework.user_roles WHERE user_id=$1`, m.CreatedBy); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Activate(ctx, p, r); !errors.Is(err, ErrDenied) {
		t.Fatal("revoked administrator", err)
	}
}
func TestActivationHasNoHTTPRoute(t *testing.T) {
	f, s, _, m := activationServiceFixture(t)
	_ = s
	h := configHandler(f, f.repo, fixedAuth{f.identity})
	for _, suffix := range []string{"activate", "rollback"} {
		r := httptest.NewRequest("POST", settingsPath+"/"+m.ID+"/"+suffix, strings.NewReader(`{}`))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 404 {
			t.Fatal("activation exposed over HTTP")
		}
	}
}

func TestNormalCallbackReadinessIsVerifiedSessionlessAndSingleUse(t *testing.T) {
	f, s, provider, m := activationServiceFixture(t)
	p := prepareActivation(t, f, s, m, 0)
	provider.callback = m.RedirectURI
	mux := http.NewServeMux()
	s.runtime.RegisterRoutes(mux)
	handler := s.runtime.Capture(mux)
	for _, bad := range []bool{true, false} {
		var operation *NormalCallbackResult
		w := httptest.NewRecorder()
		f.run(t, func(ctx context.Context) {
			r := httptest.NewRequest("GET", "/trusted-test-start", nil).WithContext(ctx)
			var err error
			operation, err = s.BeginNormalCallbackTest(p, w, r)
			if err != nil {
				t.Fatal(err)
			}
		})
		if w.Code != 302 {
			t.Fatal("normal test did not start")
		}
		location, err := url.Parse(w.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		provider.nonce = location.Query().Get("nonce")
		provider.challenge = location.Query().Get("code_challenge")
		if location.Query().Get("redirect_uri") != m.RedirectURI {
			t.Fatal("did not exercise the normal callback URI")
		}
		cookies := w.Result().Cookies()
		if len(cookies) != 1 || strings.Contains(cookies[0].Name, "session") {
			t.Fatal("test session cookie issued")
		}
		if bad {
			provider.nonce = "forged-nonce"
		}
		r := httptest.NewRequest("GET", m.RedirectURI+"?"+url.Values{"state": {location.Query().Get("state")}, "code": {"synthetic-code"}}.Encode(), nil)
		r.AddCookie(cookies[0])
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		evidence, ok := operation.Evidence()
		if ok == bad {
			t.Fatal("incorrect readiness evidence outcome")
		}
		if ok && (evidence.Purpose != NormalCallback || evidence.Issuer != m.IssuerURL || evidence.Subject != "tested-subject" || evidence.RevisionGeneration != m.Generation) {
			t.Fatal("normal evidence binding incorrect")
		}
		for _, cookie := range w.Result().Cookies() {
			if strings.Contains(cookie.Name, "session") {
				t.Fatal("test created a normal session cookie")
			}
		}
		replay := httptest.NewRecorder()
		handler.ServeHTTP(replay, r)
		if replay.Code != 401 {
			t.Fatal("normal callback evidence replay")
		}
	}
	var sessions, users int
	if err := f.owner.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM framework.sessions),(SELECT count(*) FROM framework.users WHERE subject='tested-subject')`).Scan(&sessions, &users); err != nil || sessions != 0 || users != 0 {
		t.Fatal("readiness test granted application access", err)
	}
	status, _, _ := s.runtime.ControlStatus()
	if status.Provider != auth.LocalDev {
		t.Fatal("readiness activated provider")
	}
}

func TestActivationCommittedPublicationFailureFencesRuntime(t *testing.T) {
	f, s, _, m := activationServiceFixture(t)
	request, _ := activationReadiness(t, f, m, "")
	p := prepareActivation(t, f, s, m, 0)
	var ctx context.Context
	f.run(t, func(c context.Context) { ctx = context.WithoutCancel(c) })
	tx, err := f.owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(78541705)`); err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		result ActivationResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() { result, err := s.Activate(ctx, p, request); done <- outcome{result, err} }()
	until := time.Now().Add(3 * time.Second)
	for {
		var waiting bool
		if err = f.owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='go_web_app' AND wait_event='advisory')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(until) {
			t.Fatal("activation did not acquire shared lock")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// A shutdown occurs after runtime preflight but before the DB commits.
	s.runtime.Close()
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	got := <-done
	if !errors.Is(got.err, auth.ErrRuntimeMismatch) || got.result.Applied || got.result.DesiredGeneration != 1 || got.result.AppliedGeneration != 0 {
		t.Fatal("desired/applied mismatch hidden", got.err, got.result)
	}
	reader, _ := NewActivationReader(f.pool, f.repo.scope)
	head, err := reader.Head(ctx)
	if err != nil || head.Generation != 1 {
		t.Fatal("expected committed desired state", err)
	}
	status, desired, mismatch := s.runtime.ControlStatus()
	if !mismatch || desired != 1 || status.Source != "environment" {
		t.Fatal("incorrect mismatch status")
	}
	w := httptest.NewRecorder()
	s.runtime.Capture(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("fallback handler executed") })).ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 503 {
		t.Fatal("failed publication allowed old authentication")
	}
}

func TestActivationRevocationAfterReservation(t *testing.T) {
	f, s, _, m := activationServiceFixture(t)
	request, _ := activationReadiness(t, f, m, "")
	p := prepareActivation(t, f, s, m, 0)
	var ctx context.Context
	f.run(t, func(c context.Context) { ctx = context.WithoutCancel(c) })
	tx, err := f.owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(78541705)`); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := s.Activate(ctx, p, request); done <- err }()
	until := time.Now().Add(3 * time.Second)
	for {
		var waiting bool
		if err = f.owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='go_web_app' AND wait_event='advisory')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(until) {
			t.Fatal("activation did not reach lock")
		}
		time.Sleep(5 * time.Millisecond)
	}
	w := httptest.NewRecorder()
	s.runtime.Capture(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("request admitted during commit reservation") })).ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 503 {
		t.Fatal("commit/publication gap not fenced")
	}
	if _, err = tx.Exec(ctx, `DELETE FROM framework.user_roles WHERE user_id=$1`, m.CreatedBy); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	before := activationState(t, f)
	if err = <-done; !errors.Is(err, ErrDenied) {
		t.Fatal("revocation lost to stale authorization", err)
	}
	if activationState(t, f) != before {
		t.Fatal("denied operation changed activation state")
	}
	status, _, mismatch := s.runtime.ControlStatus()
	if mismatch || status.Provider != auth.LocalDev {
		t.Fatal("known rollback changed runtime policy")
	}
	w = httptest.NewRecorder()
	s.runtime.Capture(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })).ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 204 {
		t.Fatal("known rollback left admission paused")
	}
}

func TestActivationCommitFailureIsNotReportedAsApplied(t *testing.T) {
	f, s, _, m := activationServiceFixture(t)
	request, _ := activationReadiness(t, f, m, "")
	p := prepareActivation(t, f, s, m, 0)
	_, err := f.owner.Exec(context.Background(), `CREATE FUNCTION framework.reject_activation_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic commit rejection'; END $$; CREATE CONSTRAINT TRIGGER reject_activation_commit AFTER INSERT ON framework.auth_activation_history DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION framework.reject_activation_commit()`)
	if err != nil {
		t.Fatal(err)
	}
	f.run(t, func(ctx context.Context) {
		result, err := s.Activate(ctx, p, request)
		if !errors.Is(err, auth.ErrRuntimeMismatch) || result.Applied || result.Committed || !result.CommitUncertain {
			t.Fatal("commit failure misreported", err, result)
		}
	})
	var heads int
	if err = f.owner.QueryRow(context.Background(), `SELECT count(*) FROM framework.auth_activation_heads`).Scan(&heads); err != nil || heads != 0 {
		t.Fatal("failed commit partially persisted", err)
	}
	_, desired, mismatch := s.runtime.ControlStatus()
	if desired != 1 || !mismatch {
		t.Fatal("uncertain commit allowed fallback")
	}
}
