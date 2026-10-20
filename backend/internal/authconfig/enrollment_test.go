package authconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
)

func enrollmentProof(t *testing.T, f *fixture, m Metadata, subject string, lifetime time.Duration) TestEvidence {
	t.Helper()
	var e TestEvidence
	f.run(t, func(ctx context.Context) {
		now := time.Now()
		var err error
		e, err = f.repo.recordTestEvidence(ctx, verifiedTestEvidence{revisionID: m.ID, revisionGeneration: m.Generation, identity: auth.Identity{Issuer: m.IssuerURL, Subject: subject, Provider: auth.OIDC}, purpose: IsolatedConnection, completedAt: now, expiresAt: now.Add(lifetime)})
		if err != nil {
			t.Fatal(err)
		}
	})
	return e
}

func enrollBody(e TestEvidence, role string) map[string]any {
	return map[string]any{"evidence_id": e.ID, "expected_generation": e.RevisionGeneration, "role": role, "confirm": true}
}

func enrollmentCounts(t *testing.T, f *fixture) string {
	t.Helper()
	var state string
	err := f.owner.QueryRow(context.Background(), `SELECT jsonb_build_array(
 (SELECT jsonb_agg(to_jsonb(u) ORDER BY id) FROM framework.users u),
 (SELECT jsonb_agg(to_jsonb(r) ORDER BY user_id,role) FROM framework.user_roles r),
 (SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM framework.audit_log a))::text`).Scan(&state)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func TestIdentityEnrollmentHTTPAndAtomicity(t *testing.T) {
	f := newFixture(t)
	m := approvedRevision(t, f, 0)
	h := configHandler(f, f.repo, fixedAuth{f.identity})
	path := settingsPath + "/" + m.ID + "/enroll"
	e := enrollmentProof(t, f, m, "enrolled-subject", 5*time.Minute)
	before := enrollmentCounts(t, f)
	for _, field := range []string{"issuer", "subject", "email", "actor", "deployment_id", "environment", "user_id"} {
		body := enrollBody(e, "Admin")
		body[field] = "forged"
		apiRequest(t, h, "POST", path, body, 400)
	}
	for _, role := range []string{"", "admin", "Owner"} {
		apiRequest(t, h, "POST", path, enrollBody(e, role), 400)
	}
	body := enrollBody(e, "Admin")
	body["confirm"] = false
	apiRequest(t, h, "POST", path, body, 400)
	body = enrollBody(e, "Admin")
	body["expected_generation"] = m.Generation + 1
	apiRequest(t, h, "POST", path, body, 409)
	body = enrollBody(e, "Admin")
	body["evidence_id"] = "11111111-1111-4111-8111-111111111111"
	apiRequest(t, h, "POST", path, body, 404)
	for _, headers := range []http.Header{{}, {"Origin": {"https://evil.test"}, "Content-Type": {"application/json"}}, {"Origin": {apiOrigin}, "Content-Type": {"text/plain"}}} {
		b, _ := json.Marshal(enrollBody(e, "Admin"))
		r := httptest.NewRequest("POST", path, bytes.NewReader(b))
		r.Header = headers
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		checkAPIResponse(t, w, 403)
	}
	if before != enrollmentCounts(t, f) {
		t.Fatal("denied enrollment changed records")
	}
	// Enrollment and role auditing must both roll back on an audit insert failure.
	_, err := f.owner.Exec(context.Background(), `CREATE FUNCTION framework.fail_enroll_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='auth_config.identity_enrolled' THEN RAISE EXCEPTION 'synthetic'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_enroll_audit BEFORE INSERT ON framework.audit_log FOR EACH ROW EXECUTE FUNCTION framework.fail_enroll_audit()`)
	if err != nil {
		t.Fatal(err)
	}
	apiRequest(t, h, "POST", path, enrollBody(e, "Admin"), 503)
	if before != enrollmentCounts(t, f) {
		t.Fatal("audit failure persisted partial enrollment or role audit")
	}
	if _, err := f.owner.Exec(context.Background(), `DROP TRIGGER fail_enroll_audit ON framework.audit_log; DROP FUNCTION framework.fail_enroll_audit()`); err != nil {
		t.Fatal(err)
	}
	w := apiRequest(t, h, "POST", path, enrollBody(e, "Admin"), 200)
	var user access.User
	if json.Unmarshal(w.Body.Bytes(), &user) != nil || user.Issuer != e.Issuer || user.Subject != e.Subject || len(user.Roles) != 1 || user.Roles[0] != "Admin" || user.Email != "" {
		t.Fatal("enrolled wrong identity/role")
	}
	var audits int
	if err := f.owner.QueryRow(context.Background(), `SELECT count(*) FROM framework.audit_log WHERE actor_user_id=$1 AND target_id=$2 AND action IN ('user.roles','auth_config.identity_enrolled')`, m.CreatedBy, user.ID).Scan(&audits); err != nil || audits != 2 {
		t.Fatal("missing atomic audit")
	}
	after := enrollmentCounts(t, f)
	apiRequest(t, h, "POST", path, enrollBody(e, "Admin"), 409)
	body = enrollBody(e, "User")
	body["evidence_id"] = strings.ToUpper(e.ID)
	apiRequest(t, h, "POST", path, body, 409)
	if after != enrollmentCounts(t, f) {
		t.Fatal("duplicate/case-variant evidence changed roles")
	}
}

func TestEnrollmentEvidenceIsolationAndAuthorization(t *testing.T) {
	f := newFixture(t)
	m := approvedRevision(t, f, 0)
	e := enrollmentProof(t, f, m, "tested-subject", 5*time.Minute)
	path := settingsPath + "/" + m.ID + "/enroll"
	apiRequest(t, configHandler(f, f.repo, nil), "POST", path, enrollBody(e, "Admin"), 401)
	for _, role := range []string{"User", "Viewer", "Admin"} {
		identity := auth.Identity{Issuer: f.identity.Issuer, Subject: "other-" + role, Provider: auth.OIDC}
		u, err := f.store.Resolve(context.Background(), identity)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.owner.Exec(context.Background(), `INSERT INTO framework.user_roles(user_id,role) VALUES($1,$2)`, u.ID, role); err != nil {
			t.Fatal(err)
		}
		before := enrollmentCounts(t, f)
		apiRequest(t, configHandler(f, f.repo, fixedAuth{identity}), "POST", path, enrollBody(e, "Admin"), 403)
		if before != enrollmentCounts(t, f) {
			t.Fatal("other user enrolled proof")
		}
	}
	for _, scope := range []Scope{{"another", "development"}, {m.DeploymentID, "test"}} {
		other, err := NewRepository(f.store, scope, testCipher(t, "key-v1"))
		if err != nil {
			t.Fatal(err)
		}
		apiRequest(t, configHandler(f, other, fixedAuth{f.identity}), "POST", path, enrollBody(e, "Admin"), 404)
	}
	expired := enrollmentProof(t, f, m, "expired-subject", 100*time.Millisecond)
	time.Sleep(150 * time.Millisecond)
	apiRequest(t, configHandler(f, f.repo, fixedAuth{f.identity}), "POST", path, enrollBody(expired, "Admin"), 409)
	otherRevision := approvedRevision(t, f, m.Version)
	apiRequest(t, configHandler(f, f.repo, fixedAuth{f.identity}), "POST", settingsPath+"/"+otherRevision.ID+"/enroll", enrollBody(e, "Admin"), 404)
	// Recheck revision lifecycle/generation, not just the submitted generation.
	if err := activationFixture(t, f, m, 1, "", false); err != nil {
		t.Fatal(err)
	}
	apiRequest(t, configHandler(f, f.repo, fixedAuth{f.identity}), "POST", path, enrollBody(e, "Admin"), 409)
}

func TestEnrollmentAssociatesOnlyExactIdentityAndPreservesRoles(t *testing.T) {
	f := newFixture(t)
	m := approvedRevision(t, f, 0)
	ctx := context.Background()
	identity := auth.Identity{Issuer: m.IssuerURL, Subject: "existing", Email: "shared@example.test", Provider: auth.OIDC}
	u, err := f.store.Resolve(ctx, identity)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.owner.Exec(ctx, `INSERT INTO framework.user_roles(user_id,role) VALUES($1,'Viewer')`, u.ID); err != nil {
		t.Fatal(err)
	}
	e := enrollmentProof(t, f, m, identity.Subject, time.Minute)
	f.run(t, func(ctx context.Context) {
		got, err := f.repo.EnrollIdentity(ctx, m.ID, e.ID, m.Generation, "Admin")
		if err != nil || got.ID != u.ID || len(got.Roles) != 2 || got.Email != identity.Email {
			t.Fatal("existing identity not preserved", err)
		}
	})
	other := enrollmentProof(t, f, m, "different-subject", time.Minute)
	f.run(t, func(ctx context.Context) {
		got, err := f.repo.EnrollIdentity(ctx, m.ID, other.ID, m.Generation, "User")
		if err != nil || got.ID == u.ID || got.Email != "" {
			t.Fatal("identity linked using profile data", err)
		}
	})
	inactive := enrollmentProof(t, f, m, "inactive", time.Minute)
	identity.Subject = "inactive"
	disabled, err := f.store.Resolve(ctx, identity)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.owner.Exec(ctx, `UPDATE framework.users SET active=false WHERE id=$1`, disabled.ID); err != nil {
		t.Fatal(err)
	}
	f.run(t, func(ctx context.Context) {
		if _, err := f.repo.EnrollIdentity(ctx, m.ID, inactive.ID, m.Generation, "Admin"); !errors.Is(err, ErrDenied) {
			t.Fatal("inactive user reactivated", err)
		}
	})
}

func TestEnrollmentRechecksRevocationAfterHTTPAuthorization(t *testing.T) {
	f := newFixture(t)
	m := approvedRevision(t, f, 0)
	e := enrollmentProof(t, f, m, "revoked-proof", time.Minute)
	h := configHandler(f, f.repo, fixedAuth{f.identity})
	body, _ := json.Marshal(enrollBody(e, "Admin"))
	reader := &revokingReader{Reader: bytes.NewReader(body), revoke: func() {
		if _, err := f.owner.Exec(context.Background(), `DELETE FROM framework.user_roles WHERE user_id=$1`, m.CreatedBy); err != nil {
			t.Fatal(err)
		}
	}}
	apiRequest(t, h, "POST", settingsPath+"/"+m.ID+"/enroll", reader, 403)
	var n int
	if err := f.owner.QueryRow(context.Background(), `SELECT count(*) FROM framework.users WHERE subject='revoked-proof'`).Scan(&n); err != nil || n != 0 {
		t.Fatal("stale administrator enrolled identity")
	}
}

func TestEnrollmentSerializesConcurrentPermissionRevocation(t *testing.T) {
	f := newFixture(t)
	m := approvedRevision(t, f, 0)
	e := enrollmentProof(t, f, m, "concurrent-proof", time.Minute)
	h := configHandler(f, f.repo, fixedAuth{f.identity})
	ctx := context.Background()
	tx, err := f.owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	// Same lock as access.withMutation; hold revocation ahead of enrollment.
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(78541705)`); err != nil {
		t.Fatal(err)
	}
	result := make(chan *httptest.ResponseRecorder, 1)
	b, _ := json.Marshal(enrollBody(e, "Admin"))
	go func() {
		r := httptest.NewRequest("POST", settingsPath+"/"+m.ID+"/enroll", bytes.NewReader(b))
		r.Header.Set("Origin", apiOrigin)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		result <- w
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		var waiting bool
		if err := f.owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='go_web_app' AND wait_event='advisory')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("enrollment did not wait for the shared lock")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err = tx.Exec(ctx, `DELETE FROM framework.role_permissions WHERE role='Admin' AND permission='admin.manage'`); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	before := enrollmentCounts(t, f)
	select {
	case w := <-result:
		checkAPIResponse(t, w, 403)
	case <-time.After(3 * time.Second):
		t.Fatal("enrollment did not finish")
	}
	if before != enrollmentCounts(t, f) {
		t.Fatal("revoked administrator changed records")
	}
}

func TestConcurrentEnrollmentConsumesEvidenceOnce(t *testing.T) {
	f := newFixture(t)
	m := approvedRevision(t, f, 0)
	e := enrollmentProof(t, f, m, "single-use", time.Minute)
	var verified context.Context
	f.run(t, func(ctx context.Context) { verified = context.WithoutCancel(ctx) })
	results := make(chan error, 2)
	for _, role := range []string{"Admin", "Viewer"} {
		go func() { _, err := f.repo.EnrollIdentity(verified, m.ID, e.ID, m.Generation, role); results <- err }()
	}
	success, conflicts := 0, 0
	for range 2 {
		err := <-results
		if err == nil {
			success++
		} else if errors.Is(err, ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflicts != 1 {
		t.Fatal("evidence replay was not serialized")
	}
	var roles, audits int
	if err := f.owner.QueryRow(context.Background(), `SELECT
 (SELECT count(*) FROM framework.user_roles r JOIN framework.users u ON r.user_id=u.id WHERE u.subject='single-use'),
 (SELECT count(*) FROM framework.audit_log WHERE action='auth_config.identity_enrolled' AND details->>'evidence_id'=$1)`, e.ID).Scan(&roles, &audits); err != nil || roles != 1 || audits != 1 {
		t.Fatal("duplicate grants/audits", err)
	}
}
