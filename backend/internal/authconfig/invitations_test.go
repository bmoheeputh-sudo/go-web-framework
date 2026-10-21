package authconfig

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func invitationFixture(t *testing.T) (*fixture, *AccessPolicyRepository, InvitationExpectation) {
	t.Helper()
	f, r := policyFixture(t)
	bootstrapPolicy(t, f, r)
	var e InvitationExpectation
	e.PolicyExpectation = PolicyExpectation{1, 1}
	if err := f.owner.QueryRow(context.Background(), `SELECT r.id::text,l.generation FROM framework.auth_config_revisions r JOIN framework.auth_config_lifecycle l ON l.revision_id=r.id WHERE l.status='active'`).Scan(&e.RevisionID, &e.RevisionGeneration); err != nil {
		t.Fatal(err)
	}
	return f, r, e
}
func invitationInput(email string) InvitationInput {
	return InvitationInput{Email: email, DisplayName: "Employee", Reason: "explicit employee onboarding"}
}
func invitationBody(e InvitationExpectation, email string) map[string]any {
	return map[string]any{"email": email, "reason": "explicit employee onboarding", "expected_policy_generation": e.Generation, "expected_activation_generation": e.ActivationGeneration, "revision_id": e.RevisionID, "expected_revision_generation": e.RevisionGeneration}
}
func invitationState(t *testing.T, f *fixture) string {
	t.Helper()
	var approvals string
	if err := f.owner.QueryRow(context.Background(), `SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY issuer,subject),'[]')::text FROM framework.oidc_identity_approvals a`).Scan(&approvals); err != nil {
		t.Fatal(err)
	}
	return policyExistingState(t, f) + approvals
}
func TestInvitationEmailValidation(t *testing.T) {
	for input, want := range map[string]string{"Employee@VOPAK.COM": "Employee@vopak.com", "employee+tag@vopak.com": "employee+tag@vopak.com", "first.last@vopak.com": "first.last@vopak.com", "O'Neil@vopak.com": "O'Neil@vopak.com"} {
		got, err := invitationEmailKey(input)
		if err != nil || got != want {
			t.Errorf("canonicalization failed for %q", input)
		}
	}
	for _, input := range []string{"", " employee@vopak.com", "Name <employee@vopak.com>", "a..b@vopak.com", "a@vopak.com\n", "a@localhost", "a@vopak.com.", "a@*.vopak.com", "a@127.0.0.1", "a@@vopak.com", "\"a\"@vopak.com", "é@vopak.com", strings.Repeat("a", 65) + "@vopak.com"} {
		if _, err := invitationEmailKey(input); !errors.Is(err, ErrInvalid) {
			t.Errorf("unsafe mailbox accepted: %q", input)
		}
	}
}
func TestInvitationsCreateListRevokeAndSecurityState(t *testing.T) {
	f, r, e := invitationFixture(t)
	f.run(t, func(ctx context.Context) {
		before := invitationState(t, f)
		i, err := r.CreateInvitation(ctx, e, invitationInput("Employee@VOPAK.COM"))
		if err != nil {
			t.Fatal(err)
		}
		if i.Status != "pending" || i.Generation != 1 || i.EmailKey != "Employee@vopak.com" || i.Issuer != f.identity.Issuer || i.ClientID == "" || !i.BindingCurrent || i.Source != "manual" || i.ImportID != "" || i.ClaimedUserID != "" {
			t.Fatal("incorrect invitation metadata")
		}
		if d := i.ExpiresAt.Sub(i.CreatedAt); d < 7*24*time.Hour-time.Second || d > 7*24*time.Hour {
			t.Fatal("default not seven DB days", d)
		}
		for _, email := range []string{"Employee@vopak.com", "employee@vopak.com"} {
			if _, err := r.CreateInvitation(ctx, e, invitationInput(email)); !errors.Is(err, ErrConflict) {
				t.Fatal("duplicate/case ambiguity accepted", err)
			}
		}
		for _, email := range []string{"Employee+tag@vopak.com", "Employee.name@vopak.com"} {
			if _, err := r.CreateInvitation(ctx, e, invitationInput(email)); err != nil {
				t.Fatal("alias changed", err)
			}
		}
		page, err := r.ListInvitations(ctx, "Employee", "pending", 1, 1)
		if err != nil || page.Total != 3 || len(page.Items) != 1 || page.RevisionID != e.RevisionID || page.PolicyGeneration != 1 {
			t.Fatal("pagination/filter failed", err)
		}
		if _, err := r.ReadInvitation(ctx, i.ID); err != nil {
			t.Fatal(err)
		}
		revoked, err := r.RevokeInvitation(ctx, e, i.ID, 1, "employee invitation cancelled")
		if err != nil || revoked.Status != "revoked" || revoked.Generation != 2 {
			t.Fatal("revocation failed", err)
		}
		if _, err := r.RevokeInvitation(ctx, e, i.ID, 1, "repeat invitation cancellation"); !errors.Is(err, ErrConflict) {
			t.Fatal("terminal invitation reused", err)
		}
		page, err = r.ListInvitations(ctx, "", "revoked", 0, 20)
		if err != nil || page.Total != 1 {
			t.Fatal("revocation history missing", err)
		}
		if invitationState(t, f) != before {
			t.Fatal("invitation changed users, approvals, grants, sessions or active config")
		}
		var audits int
		if err := f.owner.QueryRow(ctx, `SELECT count(*) FROM framework.audit_log WHERE action LIKE 'oidc_access.invitation_%' AND actor_user_id=$1`, i.CreatedBy).Scan(&audits); err != nil || audits != 4 {
			t.Fatal("missing attributed audit", err, audits)
		}
	})
}
func TestInvitationValidationScopeAndGenerations(t *testing.T) {
	f, r, e := invitationFixture(t)
	f.run(t, func(ctx context.Context) {
		for _, email := range []string{"employee@other.test", "employee@sub.vopak.com", "employee@evilvopak.com"} {
			if _, err := r.CreateInvitation(ctx, e, invitationInput(email)); !errors.Is(err, ErrInvalid) {
				t.Fatal("domain bypass", err)
			}
		}
		for _, delta := range []time.Duration{-time.Hour, 31 * 24 * time.Hour} {
			input := invitationInput("expiry@vopak.com")
			when := time.Now().Add(delta)
			input.ExpiresAt = &when
			if _, err := r.CreateInvitation(ctx, e, input); !errors.Is(err, ErrInvalid) {
				t.Fatal("bad expiry allowed", err)
			}
		}
		input := invitationInput("maximum@vopak.com")
		when := time.Now().Add(30 * 24 * time.Hour)
		input.ExpiresAt = &when
		if _, err := r.CreateInvitation(ctx, e, input); err != nil {
			t.Fatal("30-day expiry rejected", err)
		}
		input = invitationInput("bad@vopak.com")
		input.DisplayName = "injected\nname"
		if _, err := r.CreateInvitation(ctx, e, input); !errors.Is(err, ErrInvalid) {
			t.Fatal("control characters accepted", err)
		}
		for n := range 4 {
			stale := e
			switch n {
			case 0:
				stale.Generation++
			case 1:
				stale.ActivationGeneration++
			case 2:
				stale.RevisionGeneration++
			case 3:
				stale.RevisionID = "11111111-1111-4111-8111-111111111111"
			}
			if _, err := r.CreateInvitation(ctx, stale, invitationInput("stale@vopak.com")); !errors.Is(err, ErrConflict) {
				t.Fatal("stale expectation accepted", err)
			}
		}
		i, err := r.CreateInvitation(ctx, e, invitationInput("scoped@vopak.com"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.RevokeInvitation(ctx, e, i.ID, 99, "stale invitation generation"); !errors.Is(err, ErrConflict) {
			t.Fatal(err)
		}
		for _, scope := range []Scope{{"other", "development"}, {r.scope.DeploymentID, "production"}} {
			other, _ := NewAccessPolicyRepository(f.store, scope)
			if _, err := other.ReadInvitation(ctx, i.ID); !errors.Is(err, ErrNotFound) {
				t.Fatal("cross-scope read", err)
			}
			if _, err := other.CreateInvitation(ctx, e, invitationInput("cross@vopak.com")); !errors.Is(err, ErrNotFound) {
				t.Fatal("cross-scope write", err)
			}
		}
		for _, args := range []struct {
			status        string
			offset, limit int
		}{{"invalid", 0, 20}, {"", -1, 20}, {"", 0, 101}} {
			if _, err := r.ListInvitations(ctx, "", args.status, args.offset, args.limit); !errors.Is(err, ErrInvalid) {
				t.Fatal("invalid list accepted")
			}
		}
	})
	// A new active revision invalidates old write expectations; old history remains readable.
	m := approvedRevision(t, f, 1)
	if err := activationFixture(t, f, m, 2, e.RevisionID, false); err != nil {
		t.Fatal(err)
	}
	f.run(t, func(ctx context.Context) {
		if _, err := r.CreateInvitation(ctx, e, invitationInput("retired@vopak.com")); !errors.Is(err, ErrConflict) {
			t.Fatal("retired config accepted", err)
		}
		p, err := r.ListInvitations(ctx, "scoped", "", 0, 20)
		if err != nil || len(p.Items) != 1 || p.Items[0].BindingCurrent {
			t.Fatal("history rebound", err)
		}
	})
}
func TestInvitationExpirationUsesDatabaseTime(t *testing.T) {
	f, r, e := invitationFixture(t)
	f.run(t, func(ctx context.Context) {
		var when time.Time
		if err := f.owner.QueryRow(ctx, `SELECT clock_timestamp()+interval '500 milliseconds'`).Scan(&when); err != nil {
			t.Fatal(err)
		}
		input := invitationInput("expires@vopak.com")
		input.ExpiresAt = &when
		i, err := r.CreateInvitation(ctx, e, input)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.owner.Exec(ctx, `SELECT pg_sleep(0.6)`); err != nil {
			t.Fatal(err)
		}
		got, err := r.ReadInvitation(ctx, i.ID)
		if err != nil || got.Status != "expired" {
			t.Fatal("elapsed pending invitation still eligible", err)
		}
		page, err := r.ListInvitations(ctx, "", "pending", 0, 20)
		if err != nil || page.Total != 0 {
			t.Fatal("expired pending listing", err)
		}
		page, err = r.ListInvitations(ctx, "", "expired", 0, 20)
		if err != nil || page.Total != 1 {
			t.Fatal("missing effective expiry", err)
		}
		var stored string
		if err := f.owner.QueryRow(ctx, `SELECT status FROM framework.oidc_invitations WHERE id=$1`, i.ID).Scan(&stored); err != nil || stored != "pending" {
			t.Fatal("read required an expiration write", err)
		}
		if _, err := r.RevokeInvitation(ctx, e, i.ID, 1, "expired cancellation attempt"); !errors.Is(err, ErrConflict) {
			t.Fatal(err)
		}
		replacement, err := r.CreateInvitation(ctx, e, invitationInput("expires@vopak.com"))
		if err != nil || replacement.ID == i.ID {
			t.Fatal("could not replace elapsed pending record", err)
		}
		got, err = r.ReadInvitation(ctx, i.ID)
		if err != nil || got.Status != "expired" || got.Generation != 2 {
			t.Fatal("old history lost", err)
		}
	})
}
func TestInvitationConcurrentCreation(t *testing.T) {
	f, r, e := invitationFixture(t)
	f.run(t, func(ctx context.Context) {
		results := make(chan error, 5)
		var wg sync.WaitGroup
		for range 5 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := r.CreateInvitation(ctx, e, invitationInput("concurrent@vopak.com"))
				results <- err
			}()
		}
		wg.Wait()
		close(results)
		success, conflicts := 0, 0
		for err := range results {
			if err == nil {
				success++
			} else if errors.Is(err, ErrConflict) {
				conflicts++
			} else {
				t.Fatal(err)
			}
		}
		if success != 1 || conflicts != 4 {
			t.Fatal("duplicate concurrent invites", success, conflicts)
		}
	})
}
func TestInvitationDatabaseImmutability(t *testing.T) {
	f, r, e := invitationFixture(t)
	f.run(t, func(ctx context.Context) {
		i, err := r.CreateInvitation(ctx, e, invitationInput("immutable@vopak.com"))
		if err != nil {
			t.Fatal(err)
		}
		for _, sql := range []string{
			`UPDATE framework.oidc_invitations SET email='changed@vopak.com',email_key='changed@vopak.com',generation=generation+1,status='revoked'`,
			`UPDATE framework.oidc_invitations SET created_at=created_at-interval '1 day',generation=generation+1,status='revoked'`,
			`UPDATE framework.oidc_invitations SET source='csv',generation=generation+1,status='revoked'`,
			`UPDATE framework.oidc_invitations SET issuer=issuer||'/',generation=generation+1,status='revoked'`,
			`UPDATE framework.oidc_invitations SET status='expired',generation=generation+1`,
			`UPDATE framework.oidc_invitations SET status='claimed',generation=generation+1,claimed_user_id=created_by,claimed_issuer=issuer,claimed_subject='forged',claimed_at=clock_timestamp()`,
			`UPDATE framework.oidc_invitations SET status='revoked'`,
			`DELETE FROM framework.oidc_invitations`, `TRUNCATE framework.oidc_invitations`,
		} {
			if _, err := f.owner.Exec(ctx, sql); err == nil {
				t.Fatal("database accepted invalid history transition", sql)
			}
		}
		if _, err := f.owner.Exec(ctx, `UPDATE framework.oidc_invitations SET status='claimed',generation=generation+1,claimed_user_id=created_by,claimed_issuer=issuer,claimed_subject=$1,claimed_at=clock_timestamp() WHERE id=$2`, f.identity.Subject, i.ID); err != nil {
			t.Fatal("valid test-only claim binding failed", err)
		}
		if _, err := f.owner.Exec(ctx, `UPDATE framework.oidc_invitations SET status='pending',generation=generation+1 WHERE id=$1`, i.ID); err == nil {
			t.Fatal("claim reused")
		}
		// The SQL fixture does not implement or expose a claim repository/API.
		got, err := r.ReadInvitation(ctx, i.ID)
		if err != nil || got.ClaimedSubject != f.identity.Subject || got.ClaimedIssuer != f.identity.Issuer {
			t.Fatal("claim identity missing", err)
		}
	})
}
func TestInvitationAuthorizationAuditRollbackAndDatabaseErrors(t *testing.T) {
	f, r, e := invitationFixture(t)
	if _, err := r.CreateInvitation(context.Background(), e, invitationInput("noauth@vopak.com")); !errors.Is(err, ErrDenied) {
		t.Fatal("missing principal accepted", err)
	}
	f.run(t, func(ctx context.Context) {
		if _, err := f.owner.Exec(ctx, `DELETE FROM framework.role_permissions WHERE permission='admin.manage'`); err != nil {
			t.Fatal(err)
		}
		if _, err := r.CreateInvitation(ctx, e, invitationInput("revoked-admin@vopak.com")); !errors.Is(err, ErrDenied) {
			t.Fatal("authorization not rechecked", err)
		}
		if _, err := f.owner.Exec(ctx, `INSERT INTO framework.role_permissions VALUES('Admin','admin.manage')`); err != nil {
			t.Fatal(err)
		}
		i, err := r.CreateInvitation(ctx, e, invitationInput("audit@vopak.com"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.owner.Exec(ctx, `CREATE FUNCTION framework.fail_invitation_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action LIKE 'oidc_access.invitation_%' THEN RAISE EXCEPTION 'synthetic'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_invitation_audit BEFORE INSERT ON framework.audit_log FOR EACH ROW EXECUTE FUNCTION framework.fail_invitation_audit()`); err != nil {
			t.Fatal(err)
		}
		if _, err := r.CreateInvitation(ctx, e, invitationInput("rollback@vopak.com")); !errors.Is(err, ErrAudit) {
			t.Fatal("audit failed open", err)
		}
		if _, err := r.RevokeInvitation(ctx, e, i.ID, 1, "audit rollback revocation"); !errors.Is(err, ErrAudit) {
			t.Fatal("revocation failed open", err)
		}
		got, err := r.ReadInvitation(ctx, i.ID)
		if err != nil || got.Status != "pending" || got.Generation != 1 {
			t.Fatal("partial revocation", err)
		}
		page, err := r.ListInvitations(ctx, "", "", 0, 20)
		if err != nil || page.Total != 1 {
			t.Fatal("partial creation", err)
		}
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := r.ListInvitations(canceled, "", "", 0, 20); !errors.Is(err, ErrCanceled) {
			t.Fatal("cancellation ignored", err)
		}
		f.pool.Close()
		if _, err := r.ReadInvitation(ctx, i.ID); !errors.Is(err, ErrUnavailable) {
			t.Fatal("database errors leaked", err)
		}
	})
}

// Test-only lost-ack injection: the server commits, then its connection is lost
// before the transaction wrapper can receive a definitive COMMIT response.
type invitationCommitLoss struct {
	armed   atomic.Bool
	commits atomic.Int32
	err     error
}

func (c *invitationCommitLoss) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.EqualFold(data.SQL, "commit") && c.armed.CompareAndSwap(true, false) {
		c.commits.Add(1)
		_, c.err = conn.PgConn().Exec(ctx, "COMMIT").ReadAll()
		_ = conn.PgConn().Close(ctx)
	}
	return ctx
}
func (*invitationCommitLoss) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}
func TestInvitationCommitUncertaintyDoesNotRetry(t *testing.T) {
	f, _, e := invitationFixture(t)
	trace := &invitationCommitLoss{}
	config := f.pool.Config()
	config.ConnConfig.Tracer = trace
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	r, _ := NewAccessPolicyRepository(access.New(pool), f.repo.scope)
	f.run(t, func(ctx context.Context) {
		trace.armed.Store(true)
		i, err := r.CreateInvitation(ctx, e, invitationInput("uncertain@vopak.com"))
		if trace.err != nil || !errors.Is(err, ErrCommitUncertain) || trace.commits.Load() != 1 || i.ID != "" {
			t.Fatal("ambiguous write retried or misrepresented", err, trace.err)
		}
		page, err := r.ListInvitations(ctx, "uncertain", "", 0, 20)
		if err != nil || page.Total != 1 {
			t.Fatal("authoritative inspection failed", err)
		}
		w := httptest.NewRecorder()
		invitationError(w, ErrCommitUncertain)
		if w.Code != 503 || !strings.Contains(w.Body.String(), `"automatic_retry_allowed":false`) {
			t.Fatal("unsafe ambiguous response")
		}
	})
}
func TestInvitationHTTP(t *testing.T) {
	f, r, e := invitationFixture(t)
	h := policyHTTP(f, r, fixedAuth{f.identity})
	base := accessPolicyPath + "/invitations"
	response := apiRequest(t, h, "POST", base, invitationBody(e, "http@vopak.com"), 201)
	var i Invitation
	if json.Unmarshal(response.Body.Bytes(), &i) != nil || i.ID == "" || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("invalid create response")
	}
	apiRequest(t, h, "GET", base+"?status=pending&limit=1", nil, 200)
	apiRequest(t, h, "GET", base+"/"+i.ID, nil, 200)
	apiRequest(t, h, "GET", base+"/not-a-uuid", nil, 400)
	apiRequest(t, h, "GET", base+"/11111111-1111-4111-8111-111111111111", nil, 404)
	apiRequest(t, h, "POST", base, invitationBody(e, "http@vopak.com"), 409)
	for _, key := range []string{"expected_policy_generation", "expected_activation_generation", "expected_revision_generation", "revision_id"} {
		body := invitationBody(e, "invalid@vopak.com")
		delete(body, key)
		apiRequest(t, h, "POST", base, body, 400)
	}
	for _, key := range []string{"issuer", "subject", "created_by", "deployment_id", "role", "source"} {
		body := invitationBody(e, "forged@vopak.com")
		body[key] = "forged"
		apiRequest(t, h, "POST", base, body, 400)
	}
	for _, query := range []string{"?limit=0", "?status=invalid", "?deployment_id=other", "?search=a&search=b"} {
		apiRequest(t, h, "GET", base+query, nil, 400)
	}
	body := invitationBody(e, "")
	delete(body, "email")
	body["expected_invitation_generation"] = 1
	apiRequest(t, h, "POST", base+"/"+i.ID+"/revoke", body, 200)
	apiRequest(t, h, "POST", base+"/"+i.ID+"/revoke", body, 409)
	for _, role := range []string{"User", "Viewer"} {
		u := policyUser(t, f, "invite-nonadmin-"+role, "user@vopak.com", role, true)
		denied := policyHTTP(f, r, fixedAuth{auth.Identity{Issuer: u.Issuer, Subject: u.Subject, Provider: auth.OIDC}})
		apiRequest(t, denied, "GET", base, nil, 403)
		apiRequest(t, denied, "POST", base, invitationBody(e, "denied@vopak.com"), 403)
	}
	apiRequest(t, policyHTTP(f, r, nil), "GET", base, nil, 401)
	for _, headers := range [][2]string{{"https://untrusted.test", "application/json"}, {apiOrigin, "text/plain"}} {
		req := httptest.NewRequest("POST", base, strings.NewReader(`{}`))
		req.Header.Set("Origin", headers[0])
		req.Header.Set("Content-Type", headers[1])
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != 403 {
			t.Fatal("write protection bypass")
		}
	}
	req := httptest.NewRequest("POST", base, strings.NewReader(`{"email":"`+strings.Repeat("a", 17000)+`"}`))
	req.Header.Set("Origin", apiOrigin)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 400 && w.Code != 413 {
		t.Fatal("unbounded request")
	}
}

func TestInvitationDatabaseInsertConstraints(t *testing.T) {
	f, r, e := invitationFixture(t)
	f.run(t, func(ctx context.Context) {
		for _, email := range []string{"Employee@VOPAK.COM", "O'Neil@vopak.com", "first.last+tag@vopak.com", "a..b@vopak.com", "Name <user@vopak.com>", "a@localhost", "a@@vopak.com"} {
			var key *string
			if err := f.owner.QueryRow(ctx, `SELECT framework.invitation_email_key($1)`, email).Scan(&key); err != nil {
				t.Fatal(err)
			}
			want, err := invitationEmailKey(email)
			if (err != nil && key != nil) || (err == nil && (key == nil || *key != want)) {
				t.Fatal("database and repository mailbox canonicalization diverged")
			}
		}
		i, err := r.CreateInvitation(ctx, e, invitationInput("constraints@vopak.com"))
		if err != nil {
			t.Fatal(err)
		}
		for name, change := range map[string]map[string]any{
			"cross scope":                {"deployment_id": "other"},
			"wrong revision":             {"revision_id": "11111111-1111-4111-8111-111111111111"},
			"wrong issuer":               {"issuer": i.Issuer + "/"},
			"wrong client":               {"client_id": "other-client"},
			"wrong activation":           {"activation_generation": 2},
			"invalid generation":         {"generation": 2},
			"invalid source":             {"source": "arbitrary"},
			"manual import reference":    {"import_id": "11111111-1111-4111-8111-111111111111"},
			"wrong attribution":          {"updated_by": "11111111-1111-4111-8111-111111111111"},
			"invalid mailbox":            {"email": "Name <employee@vopak.com>"},
			"incorrect canonicalization": {"email_key": "another@vopak.com"},
			"premature claimed status":   {"status": "claimed"},
			"expired insert":             {"expires_at": time.Now().Add(-time.Hour)},
			"excessive lifetime":         {"expires_at": time.Now().Add(31 * 24 * time.Hour)},
		} {
			t.Run(name, func(t *testing.T) {
				base := map[string]any{"email": "different@vopak.com", "email_key": "different@vopak.com"}
				for k, v := range change {
					base[k] = v
				}
				payload, err := json.Marshal(base)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.owner.Exec(ctx, `INSERT INTO framework.oidc_invitations SELECT (jsonb_populate_record(NULL::framework.oidc_invitations,to_jsonb(i)||jsonb_build_object('id',gen_random_uuid())||$2::jsonb)).* FROM framework.oidc_invitations i WHERE id=$1`, i.ID, payload)
				if err == nil {
					t.Fatal("database accepted invalid insert")
				}
			})
		}
	})
}

func TestInvitationDoesNotAssociateExistingMailbox(t *testing.T) {
	f, r, e := invitationFixture(t)
	policyUser(t, f, "disabled-employee", "existing@vopak.com", "User", false)
	f.run(t, func(ctx context.Context) {
		before := invitationState(t, f)
		i, err := r.CreateInvitation(ctx, e, invitationInput("existing@vopak.com"))
		if err != nil || i.ClaimedUserID != "" {
			t.Fatal("email associated an existing identity", err)
		}
		if invitationState(t, f) != before {
			t.Fatal("existing disabled user changed")
		}
		if _, err := r.RevokeInvitation(ctx, e, i.ID, 1, "cancel without user mutation"); err != nil {
			t.Fatal(err)
		}
		if invitationState(t, f) != before {
			t.Fatal("cancellation changed existing user")
		}
		// Deactivation takes effect for every invitation endpoint through existing authorization.
		if _, err := f.owner.Exec(ctx, `UPDATE framework.users SET active=false WHERE id=$1`, i.CreatedBy); err != nil {
			t.Fatal(err)
		}
		if _, err := r.CreateInvitation(ctx, e, invitationInput("inactive-admin@vopak.com")); !errors.Is(err, ErrDenied) {
			t.Fatal("inactive administrator accepted", err)
		}
		if _, err := f.owner.Exec(ctx, `UPDATE framework.users SET active=true WHERE id=$1`, i.CreatedBy); err != nil {
			t.Fatal(err)
		}
	})
}

func TestInvitationRequiresInitializedPolicyAndActiveDatabaseOIDC(t *testing.T) {
	f, r := policyFixture(t)
	var e InvitationExpectation
	e.PolicyExpectation = PolicyExpectation{1, 1}
	if err := f.owner.QueryRow(context.Background(), `SELECT r.id::text,l.generation FROM framework.auth_config_revisions r JOIN framework.auth_config_lifecycle l ON l.revision_id=r.id WHERE l.status='active'`).Scan(&e.RevisionID, &e.RevisionGeneration); err != nil {
		t.Fatal(err)
	}
	f.run(t, func(ctx context.Context) {
		if _, err := r.CreateInvitation(ctx, e, invitationInput("setup@vopak.com")); !errors.Is(err, ErrNotFound) {
			t.Fatal("missing policy silently bootstrapped", err)
		}
	})
	// A separate environment-managed fixture has a policy but no activation head.
	env := newFixture(t)
	envRepo, err := NewAccessPolicyRepository(env.store, env.repo.scope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.owner.Exec(context.Background(), `INSERT INTO framework.oidc_access_policies(deployment_id,environment,mode,default_role,created_by,updated_by,reason)
 SELECT $1,$2,'allow_all','Viewer',id,id,'synthetic environment policy' FROM framework.users WHERE subject=$3`, env.repo.scope.DeploymentID, env.repo.scope.Environment, env.identity.Subject); err != nil {
		t.Fatal(err)
	}
	env.run(t, func(ctx context.Context) {
		if _, err := envRepo.CreateInvitation(ctx, e, invitationInput("environment@vopak.com")); !errors.Is(err, ErrConflict) {
			t.Fatal("environment provider accepted", err)
		}
	})
}

func TestInvitationCommitUncertaintyOutranksContextFailure(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	for _, ctx := range []context.Context{canceled, expired} {
		if err := repositoryError(ctx, access.ErrCommitUncertain); !errors.Is(err, ErrCommitUncertain) {
			t.Fatal("lost commit outcome hidden by context error", err)
		}
	}
}
