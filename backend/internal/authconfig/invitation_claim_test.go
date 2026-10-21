package authconfig

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/testdb"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/oauth2"
)

func (a *admissionFixture) invite(t *testing.T, email string, expires *time.Time) Invitation {
	t.Helper()
	var i Invitation
	a.f.run(t, func(ctx context.Context) {
		page, err := a.policy.ListInvitations(ctx, "", "", 0, 1)
		if err != nil {
			t.Fatal(err)
		}
		e := InvitationExpectation{PolicyExpectation{page.PolicyGeneration, page.ActivationGeneration}, page.RevisionID, page.RevisionGeneration}
		input := invitationInput(email)
		input.ExpiresAt = expires
		i, err = a.policy.CreateInvitation(ctx, e, input)
		if err != nil {
			t.Fatal(err)
		}
	})
	return i
}
func (a *admissionFixture) invitation(t *testing.T, id string) Invitation {
	t.Helper()
	var i Invitation
	a.f.run(t, func(ctx context.Context) {
		var err error
		i, err = a.policy.ReadInvitation(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
	})
	return i
}
func (a *admissionFixture) revokeInvite(t *testing.T, i Invitation) {
	t.Helper()
	a.f.run(t, func(ctx context.Context) {
		p, err := a.policy.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		e := InvitationExpectation{PolicyExpectation{p.Generation, i.ActivationGeneration}, i.RevisionID, i.RevisionGeneration}
		if _, err := a.policy.RevokeInvitation(ctx, e, i.ID, i.Generation, "cancel pending employee invitation"); err != nil {
			t.Fatal(err)
		}
	})
}
func admissionBinding(t *testing.T, a *admissionFixture) auth.Binding {
	t.Helper()
	b := auth.Binding{Source: "database", Purpose: "login", DeploymentID: a.f.repo.scope.DeploymentID, Environment: a.f.repo.scope.Environment}
	if err := a.f.owner.QueryRow(context.Background(), `SELECT h.active_revision_id::text,h.generation,r.issuer_url,r.client_id FROM framework.auth_activation_heads h JOIN framework.auth_config_revisions r ON r.id=h.active_revision_id`).Scan(&b.RevisionID, &b.ActivationGeneration, &b.Issuer, &b.ClientID); err != nil {
		t.Fatal(err)
	}
	return b
}
func claimState(t *testing.T, f *fixture) string {
	t.Helper()
	var data string
	if err := f.owner.QueryRow(context.Background(), `SELECT jsonb_build_array(
 (SELECT jsonb_agg(to_jsonb(i) ORDER BY id) FROM framework.oidc_invitations i),
 (SELECT jsonb_agg(to_jsonb(a) ORDER BY issuer,subject) FROM framework.oidc_identity_approvals a),
 (SELECT jsonb_agg(to_jsonb(u) ORDER BY id) FROM framework.users u),
 (SELECT jsonb_agg(to_jsonb(r) ORDER BY user_id,role) FROM framework.user_roles r),
 (SELECT jsonb_agg(to_jsonb(s) ORDER BY token_hash) FROM framework.sessions s),
 (SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM framework.audit_log a WHERE action LIKE 'oidc_access.%'))::text`).Scan(&data); err != nil {
		t.Fatal(err)
	}
	return data
}
func boundSessionWrite(identity auth.Identity, b auth.Binding) func(context.Context, pgx.Tx) error {
	return func(ctx context.Context, tx pgx.Tx) error {
		hash := sha256.Sum256([]byte(oauth2.GenerateVerifier()))
		_, err := tx.Exec(ctx, `INSERT INTO framework.sessions(token_hash,issuer,subject,email,email_verified,provider,expires_at,binding_source,deployment_id,environment,revision_id,activation_generation,client_id,flow_purpose)
   VALUES($1,$2,$3,$4,$5,'oidc',clock_timestamp()+interval '1 hour','database',$6,$7,$8,$9,$10,'login')`, hash[:], identity.Issuer, identity.Subject, identity.Email, identity.EmailVerified, b.DeploymentID, b.Environment, b.RevisionID, b.ActivationGeneration, b.ClientID)
		return err
	}
}
func invitationIdentity(subject, email string) auth.Identity {
	return auth.Identity{Issuer: probeIssuer, Subject: subject, Email: email, EmailVerified: true, DisplayName: "Verified employee", Provider: auth.OIDC}
}

func TestInvitationClaimNormalLogin(t *testing.T) {
	for _, mode := range []string{"allow_all", "approved_users_only"} {
		for _, role := range []string{"Viewer", "User"} {
			t.Run(mode+"/"+role, func(t *testing.T) {
				a := newAdmissionFixture(t)
				a.changePolicy(t, mode, role, []string{"example.test"})
				i := a.invite(t, "Employee+tag@EXAMPLE.TEST", nil)
				cookie := sessionCookieFor(t, a.login(t, "new-employee", "Employee+tag@example.test", true))
				got := a.invitation(t, i.ID)
				if got.Status != "claimed" || got.Generation != 2 || got.ClaimedSubject != "new-employee" || got.ClaimedIssuer != probeIssuer || got.ClaimedUserID == "" || got.ClaimedAt == nil || got.UpdatedBy != got.ClaimedUserID {
					t.Fatal("claim not permanently attributed")
				}
				sessionCookieFor(t, a.login(t, "new-employee", "Employee+tag@example.test", true))
				if getSession(a.handler, cookie, "/api/auth/me") != 200 || getSession(a.handler, cookie, "/api/admin/users") != 403 {
					t.Fatal("session or RBAC changed")
				}
				var users, grants, admins, claims, provisions int
				if err := a.f.owner.QueryRow(context.Background(), `SELECT
    (SELECT count(*) FROM framework.users WHERE issuer=$1 AND subject='new-employee'),
    (SELECT count(*) FROM framework.user_roles WHERE user_id=$2 AND role=$3),
    (SELECT count(*) FROM framework.user_roles WHERE user_id=$2 AND role='Admin'),
    (SELECT count(*) FROM framework.audit_log WHERE action='oidc_access.invitation_claimed' AND target_id=$4 AND actor_user_id=$2),
    (SELECT count(*) FROM framework.audit_log WHERE action='oidc_access.user_provisioned' AND actor_user_id=$2)`, probeIssuer, got.ClaimedUserID, role, i.ID).Scan(&users, &grants, &admins, &claims, &provisions); err != nil || users != 1 || grants != 1 || admins != 0 || claims != 1 || provisions != 1 {
					t.Fatal("duplicate or elevated provisioning", err)
				}
				var source, origin, creator string
				if err := a.f.owner.QueryRow(context.Background(), `SELECT source,invitation_id::text,created_by::text FROM framework.oidc_identity_approvals WHERE issuer=$1 AND subject='new-employee'`, probeIssuer).Scan(&source, &origin, &creator); err != nil || source != "invitation" || origin != i.ID || creator != i.CreatedBy {
					t.Fatal("approval provenance missing", err)
				}
				var binding auth.Binding
				if err := a.f.owner.QueryRow(context.Background(), `SELECT binding_source,deployment_id,environment,revision_id::text,activation_generation,issuer,client_id,flow_purpose FROM framework.sessions WHERE subject='new-employee' LIMIT 1`).Scan(&binding.Source, &binding.DeploymentID, &binding.Environment, &binding.RevisionID, &binding.ActivationGeneration, &binding.Issuer, &binding.ClientID, &binding.Purpose); err != nil || binding != admissionBinding(t, a) {
					t.Fatal("session binding lost", err)
				}
			})
		}
	}
}
func TestInvitationClaimWithoutInvitationAndUnverifiedEmail(t *testing.T) {
	for _, mode := range []string{"allow_all", "approved_users_only"} {
		t.Run(mode, func(t *testing.T) {
			a := newAdmissionFixture(t)
			a.changePolicy(t, mode, "Viewer", []string{})
			w := a.login(t, "no-invitation", "no-invitation@example.test", true)
			if mode == "allow_all" {
				sessionCookieFor(t, w)
			} else if !loginDenied(w) {
				t.Fatal("unapproved login allowed")
			}
			i := a.invite(t, "unverified@example.test", nil)
			w = a.login(t, "unverified", "unverified@example.test", false)
			if mode == "allow_all" {
				sessionCookieFor(t, w)
			} else if !loginDenied(w) {
				t.Fatal("unverified invite claimed")
			}
			if got := a.invitation(t, i.ID); got.Status != "pending" {
				t.Fatal("unverified email claimed invitation")
			}
		})
	}
}
func TestInvitationClaimCaseAliasesExpiryAndRevocation(t *testing.T) {
	for _, mode := range []string{"allow_all", "approved_users_only"} {
		t.Run(mode, func(t *testing.T) {
			a := newAdmissionFixture(t)
			a.changePolicy(t, mode, "Viewer", []string{})
			for _, tc := range []struct {
				name, email, login string
				expired, revoked   bool
			}{
				{name: "case", email: "Employee@example.test", login: "employee@example.test"},
				{name: "plus", email: "plus+tag@example.test", login: "plus@example.test"},
				{name: "dots", email: "first.last@example.test", login: "firstlast@example.test"},
				{name: "expired", email: "expired@example.test", login: "expired@example.test", expired: true},
				{name: "revoked", email: "revoked@example.test", login: "revoked@example.test", revoked: true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					var expires *time.Time
					if tc.expired {
						var when time.Time
						if err := a.f.owner.QueryRow(context.Background(), `SELECT clock_timestamp()+interval '500 milliseconds'`).Scan(&when); err != nil {
							t.Fatal(err)
						}
						expires = &when
					}
					i := a.invite(t, tc.email, expires)
					if tc.expired {
						if _, err := a.f.owner.Exec(context.Background(), `SELECT pg_sleep(0.6)`); err != nil {
							t.Fatal(err)
						}
					}
					if tc.revoked {
						a.revokeInvite(t, i)
					}
					w := a.login(t, tc.name, tc.login, true)
					if mode == "allow_all" {
						sessionCookieFor(t, w)
					} else if !loginDenied(w) {
						t.Fatal("invalid invitation authorized login")
					}
					if got := a.invitation(t, i.ID); got.Status == "claimed" {
						t.Fatal("invalid invitation was consumed")
					}
				})
			}
		})
	}
}
func TestInvitationClaimDomainsInactiveAndRevokedIdentities(t *testing.T) {
	a := newAdmissionFixture(t)
	outside := a.invite(t, "outside@other.test", nil)
	inactive := a.invite(t, "inactive@example.test", nil)
	revoked := a.invite(t, "revoked@example.test", nil)
	user := policyUser(t, a.f, "inactive-employee", "inactive@example.test", "User", false)
	a.approval(t, probeIssuer, "revoked-employee", "approved", 0)
	a.approval(t, probeIssuer, "revoked-employee", "revoked", 1)
	a.changePolicy(t, "approved_users_only", "Viewer", []string{"example.test"})
	for _, tc := range []struct {
		subject, email string
		verified       bool
	}{{"outside", "outside@other.test", true}, {"inactive-employee", "inactive@example.test", true}, {"revoked-employee", "revoked@example.test", true}, {"unverified", "outside@other.test", false}} {
		before := claimState(t, a.f)
		if !loginDenied(a.login(t, tc.subject, tc.email, tc.verified)) {
			t.Fatal("non-overridable eligibility bypass")
		}
		if claimState(t, a.f) != before {
			t.Fatal("denied login modified security records")
		}
	}
	for _, i := range []Invitation{outside, inactive, revoked} {
		if a.invitation(t, i.ID).Status != "pending" {
			t.Fatal("denied identity consumed invitation")
		}
	}
	var active bool
	if err := a.f.owner.QueryRow(context.Background(), `SELECT active FROM framework.users WHERE id=$1`, user.ID).Scan(&active); err != nil || active {
		t.Fatal("inactive user reactivated", err)
	}
}
func TestInvitationClaimNeverMergesMailboxIdentities(t *testing.T) {
	a := newAdmissionFixture(t)
	a.changePolicy(t, "approved_users_only", "Viewer", []string{})
	first := a.invite(t, "reassigned@example.test", nil)
	sessionCookieFor(t, a.login(t, "original-subject", "reassigned@example.test", true))
	if !loginDenied(a.login(t, "different-subject", "reassigned@example.test", true)) {
		t.Fatal("claimed invitation reused")
	}
	second := a.invite(t, "reassigned@example.test", nil)
	if !loginDenied(a.login(t, "different-subject", "reassigned@example.test", true)) {
		t.Fatal("mailbox merged or reassigned an identity")
	}
	// A changed profile cannot erase the permanent historical claim.
	sessionCookieFor(t, a.login(t, "original-subject", "changed@example.test", true))
	if !loginDenied(a.login(t, "another-subject", "reassigned@example.test", true)) {
		t.Fatal("historical claim forgotten")
	}
	a.changePolicy(t, "allow_all", "User", []string{})
	sessionCookieFor(t, a.login(t, "independent-subject", "reassigned@example.test", true))
	if a.invitation(t, second.ID).Status != "pending" || a.invitation(t, first.ID).ClaimedSubject != "original-subject" {
		t.Fatal("Allow All merged mailbox owners")
	}
	var users int
	if err := a.f.owner.QueryRow(context.Background(), `SELECT count(*) FROM framework.users WHERE issuer=$1 AND subject IN ('original-subject','independent-subject')`, probeIssuer).Scan(&users); err != nil || users != 2 {
		t.Fatal("separate exact identities lost", err)
	}
}
func TestInvitationClaimPreservesExistingApprovalAndRoles(t *testing.T) {
	a := newAdmissionFixture(t)
	a.changePolicy(t, "approved_users_only", "Viewer", []string{})
	u := policyUser(t, a.f, "existing-employee", "existing@example.test", "User", true)
	a.approval(t, probeIssuer, u.Subject, "approved", 0)
	i := a.invite(t, u.Email, nil)
	var before string
	if err := a.f.owner.QueryRow(context.Background(), `SELECT to_jsonb(a)::text FROM framework.oidc_identity_approvals a WHERE subject=$1`, u.Subject).Scan(&before); err != nil {
		t.Fatal(err)
	}
	sessionCookieFor(t, a.login(t, u.Subject, u.Email, true))
	var after string
	var roles []string
	if err := a.f.owner.QueryRow(context.Background(), `SELECT to_jsonb(a)::text,ARRAY(SELECT role FROM framework.user_roles WHERE user_id=$2) FROM framework.oidc_identity_approvals a WHERE subject=$1`, u.Subject, u.ID).Scan(&after, &roles); err != nil || before != after || strings.Join(roles, ",") != "User" {
		t.Fatal("existing approval or roles overwritten", err)
	}
	if got := a.invitation(t, i.ID); got.ClaimedUserID != u.ID {
		t.Fatal("existing exact user duplicated")
	}
	// Exact approved identities still log in without a fresh invitation.
	sessionCookieFor(t, a.login(t, u.Subject, "different@example.test", true))
	adminInvite := a.invite(t, "admin@example.test", nil)
	adminCookie := sessionCookieFor(t, a.login(t, "enrolled-admin", "admin@example.test", true))
	if getSession(a.handler, adminCookie, "/api/admin/users") != 200 || a.invitation(t, adminInvite.ID).ClaimedSubject != "enrolled-admin" {
		t.Fatal("explicit administrator access changed")
	}

}
func TestInvitationClaimBoundaries(t *testing.T) {
	a := newAdmissionFixture(t)
	a.changePolicy(t, "approved_users_only", "Viewer", []string{})
	i := a.invite(t, "bound@example.test", nil)
	b := admissionBinding(t, a)
	p := a.f.store.OIDCAdmission(b.DeploymentID, b.Environment)
	identity := invitationIdentity("bound-subject", i.Email)
	for name, change := range map[string]func(*auth.Binding){
		"legacy":      func(b *auth.Binding) { *b = auth.Binding{} },
		"revision":    func(b *auth.Binding) { b.RevisionID = "11111111-1111-4111-8111-111111111111" },
		"generation":  func(b *auth.Binding) { b.ActivationGeneration++ },
		"client":      func(b *auth.Binding) { b.ClientID = "other-client" },
		"deployment":  func(b *auth.Binding) { b.DeploymentID = "other" },
		"environment": func(b *auth.Binding) { b.Environment = "production" },
		"issuer":      func(b *auth.Binding) { b.Issuer = strings.TrimSuffix(b.Issuer, "/") },
		"isolated":    func(b *auth.Binding) { b.Purpose = "isolated_connection" },
		"readiness":   func(b *auth.Binding) { b.Purpose = "normal_callback" },
	} {
		t.Run(name, func(t *testing.T) {
			altered := b
			change(&altered)
			before := claimState(t, a.f)
			called := false
			err := p.Login(context.Background(), identity, altered, func(context.Context, pgx.Tx) error { called = true; return nil })
			if !errors.Is(err, auth.ErrUnauthenticated) || called || claimState(t, a.f) != before {
				t.Fatal("untrusted/stale binding claimed invitation", err)
			}
		})
	}
	// Even Allow All cannot provision through a verification-only purpose.
	a.changePolicy(t, "allow_all", "Viewer", []string{})
	for _, purpose := range []string{"normal_callback", "isolated_connection"} {
		altered := b
		altered.Purpose = purpose
		if err := p.Login(context.Background(), identity, altered, boundSessionWrite(identity, b)); !errors.Is(err, auth.ErrUnauthenticated) {
			t.Fatal("verification flow provisioned a user", err)
		}
	}
}
func TestInvitationClaimConcurrentInstances(t *testing.T) {
	for _, sameIdentity := range []bool{true, false} {
		t.Run(map[bool]string{true: "same identity", false: "competing identities"}[sameIdentity], func(t *testing.T) {
			a := newAdmissionFixture(t)
			a.changePolicy(t, "approved_users_only", "User", []string{})
			i := a.invite(t, "concurrent@example.test", nil)
			b := admissionBinding(t, a)
			readers := []*access.OIDCAdmission{a.f.store.OIDCAdmission(b.DeploymentID, b.Environment), access.New(a.f.pool).OIDCAdmission(b.DeploymentID, b.Environment)}
			results := make(chan error, 8)
			var wg sync.WaitGroup
			for n := range 8 {
				wg.Add(1)
				go func(n int) {
					defer wg.Done()
					subject := "concurrent"
					if !sameIdentity && n%2 == 1 {
						subject = "competitor"
					}
					identity := invitationIdentity(subject, i.Email)
					results <- readers[n%2].Login(context.Background(), identity, b, boundSessionWrite(identity, b))
				}(n)
			}
			wg.Wait()
			close(results)
			success := 0
			for err := range results {
				if err == nil {
					success++
				} else if !errors.Is(err, auth.ErrUnauthenticated) {
					t.Fatal(err)
				}
			}
			want := 8
			if !sameIdentity {
				want = 4
			}
			if success != want {
				t.Fatal("concurrent claim result", success, want)
			}
			var users, grants, claims, approvals int
			if err := a.f.owner.QueryRow(context.Background(), `SELECT
   (SELECT count(*) FROM framework.users WHERE subject IN ('concurrent','competitor')),
   (SELECT count(*) FROM framework.user_roles r JOIN framework.users u ON u.id=r.user_id WHERE u.subject IN ('concurrent','competitor')),
   (SELECT count(*) FROM framework.audit_log WHERE action='oidc_access.invitation_claimed' AND target_id=$1),
   (SELECT count(*) FROM framework.oidc_identity_approvals WHERE invitation_id=$1::uuid)`, i.ID).Scan(&users, &grants, &claims, &approvals); err != nil || users != 1 || grants != 1 || claims != 1 || approvals != 1 {
				t.Fatal("duplicate provisioning/claims", err)
			}
		})
	}
}
func TestInvitationClaimTransactionRollback(t *testing.T) {
	for name, sql := range map[string]string{
		"provision audit":    `CREATE FUNCTION framework.reject_claim() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='oidc_access.user_provisioned' THEN RAISE EXCEPTION 'synthetic'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_claim BEFORE INSERT ON framework.audit_log FOR EACH ROW EXECUTE FUNCTION framework.reject_claim()`,
		"claim audit":        `CREATE FUNCTION framework.reject_claim() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='oidc_access.invitation_claimed' THEN RAISE EXCEPTION 'synthetic'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_claim BEFORE INSERT ON framework.audit_log FOR EACH ROW EXECUTE FUNCTION framework.reject_claim()`,
		"approval insertion": `CREATE FUNCTION framework.reject_claim() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic'; END $$; CREATE TRIGGER reject_claim BEFORE INSERT ON framework.oidc_identity_approvals FOR EACH ROW EXECUTE FUNCTION framework.reject_claim()`,
		"session insertion":  `CREATE FUNCTION framework.reject_claim() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic'; END $$; CREATE TRIGGER reject_claim BEFORE INSERT ON framework.sessions FOR EACH ROW EXECUTE FUNCTION framework.reject_claim()`,
	} {
		t.Run(name, func(t *testing.T) {
			a := newAdmissionFixture(t)
			a.changePolicy(t, "approved_users_only", "Viewer", []string{})
			if name == "session insertion" {
				policyUser(t, a.f, "rollback-subject", "previous@example.test", "User", true)
			}
			a.invite(t, "rollback@example.test", nil)
			if _, err := a.f.owner.Exec(context.Background(), sql); err != nil {
				t.Fatal(err)
			}
			before := claimState(t, a.f)
			if !loginDenied(a.login(t, "rollback-subject", "rollback@example.test", true)) {
				t.Fatal("failed transaction authenticated")
			}
			if claimState(t, a.f) != before {
				t.Fatal("partial claim/provisioning/approval/session/audit changes")
			}
		})
	}
}
func TestInvitationClaimCommitUncertainty(t *testing.T) {
	a := newAdmissionFixture(t)
	a.changePolicy(t, "approved_users_only", "Viewer", []string{})
	i := a.invite(t, "uncertain@example.test", nil)
	b := admissionBinding(t, a)
	trace := &invitationCommitLoss{}
	config := a.f.pool.Config()
	config.ConnConfig.Tracer = trace
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	admission := access.New(pool).OIDCAdmission(b.DeploymentID, b.Environment)
	identity := invitationIdentity("uncertain-subject", i.Email)
	trace.armed.Store(true)
	err = admission.Login(context.Background(), identity, b, boundSessionWrite(identity, b))
	if !errors.Is(err, auth.ErrStoreUnavailable) || trace.err != nil || trace.commits.Load() != 1 {
		t.Fatal("uncertain commit accepted or retried", err, trace.err)
	}
	// Authoritative inspection can discover the commit; no cookie/token was issued by Login.
	if got := a.invitation(t, i.ID); got.Status != "claimed" {
		t.Fatal("committed state not available for investigation")
	}
}

// Start a real bound flow separately so activation/expiry can occur before callback.
func invitationLoginFlow(t *testing.T, a *admissionFixture, subject, email string) *http.Request {
	t.Helper()
	a.provider.mu.Lock()
	a.provider.claims = func(c map[string]any) { c["sub"] = subject; c["email"] = email; c["email_verified"] = true }
	a.provider.mu.Unlock()
	w := httptest.NewRecorder()
	a.handler.ServeHTTP(w, httptest.NewRequest("GET", apiOrigin+"/api/auth/login", nil))
	if w.Code != 302 {
		t.Fatal("could not start bound login", w.Code)
	}
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	a.provider.mu.Lock()
	a.provider.nonce = u.Query().Get("nonce")
	a.provider.challenge = u.Query().Get("code_challenge")
	a.provider.mu.Unlock()
	r := httptest.NewRequest("GET", a.revision.RedirectURI+"?"+url.Values{"state": {u.Query().Get("state")}, "code": {"synthetic-code"}}.Encode(), nil)
	for _, c := range w.Result().Cookies() {
		r.AddCookie(c)
	}
	return r
}
func TestInvitationClaimRetiredCallbackCannotOnboard(t *testing.T) {
	for _, approved := range []bool{false, true} {
		t.Run(map[bool]string{false: "unapproved", true: "already approved"}[approved], func(t *testing.T) {
			a := newAdmissionFixture(t)
			a.changePolicy(t, "approved_users_only", "Viewer", []string{})
			i := a.invite(t, "retired@example.test", nil)
			if approved {
				a.approval(t, probeIssuer, "retired-subject", "approved", 0)
			}
			request := invitationLoginFlow(t, a, "retired-subject", i.Email)
			var next Metadata
			a.f.run(t, func(ctx context.Context) {
				var err error
				next, err = a.f.repo.CreateDraft(ctx, 1, a.revision.Settings, NewSecret([]byte(apiSecret)))
				if err != nil {
					t.Fatal(err)
				}
				for _, state := range []Status{Validated, Approved} {
					next, err = a.f.repo.Transition(ctx, next.ID, next.Generation, state)
					if err != nil {
						t.Fatal(err)
					}
				}
			})
			if err := activationFixture(t, a.f, next, 2, a.revision.ID, false); err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			a.handler.ServeHTTP(w, request)
			if approved {
				sessionCookieFor(t, w)
			} else if !loginDenied(w) {
				t.Fatal("retired callback used old invitation")
			}
			var status string
			if err := a.f.owner.QueryRow(context.Background(), `SELECT status FROM framework.oidc_invitations WHERE id=$1`, i.ID).Scan(&status); err != nil || status != "pending" {
				t.Fatal("draining callback claimed invitation", err)
			}
		})
	}
}
func TestInvitationClaimFailedExpiredAndReplayedCallbacks(t *testing.T) {
	a := newAdmissionFixture(t)
	a.changePolicy(t, "approved_users_only", "Viewer", []string{})
	i := a.invite(t, "callback@example.test", nil)
	for _, failure := range []string{"nonce", "state", "expired"} {
		request := invitationLoginFlow(t, a, "callback-subject", i.Email)
		switch failure {
		case "nonce":
			a.provider.mu.Lock()
			a.provider.nonce = "wrong-nonce"
			a.provider.mu.Unlock()
		case "state":
			q := request.URL.Query()
			q.Set("state", "wrong-state")
			request.URL.RawQuery = q.Encode()
		case "expired":
			if _, err := a.f.owner.Exec(context.Background(), `UPDATE framework.oidc_login_flows SET created_at=clock_timestamp()-interval '2 minutes',expires_at=clock_timestamp()-interval '1 minute'`); err != nil {
				t.Fatal(err)
			}
		}
		before := claimState(t, a.f)
		w := httptest.NewRecorder()
		a.handler.ServeHTTP(w, request)
		if !claimCallbackDenied(w) || claimState(t, a.f) != before {
			t.Fatal("failed callback changed onboarding state", failure)
		}
		w = httptest.NewRecorder()
		a.handler.ServeHTTP(w, request)
		if !claimCallbackDenied(w) || claimState(t, a.f) != before {
			t.Fatal("failed callback replayed", failure)
		}
	}
	request := invitationLoginFlow(t, a, "callback-subject", i.Email)
	w := httptest.NewRecorder()
	a.handler.ServeHTTP(w, request)
	sessionCookieFor(t, w)
	before := claimState(t, a.f)
	w = httptest.NewRecorder()
	a.handler.ServeHTTP(w, request)
	if !claimCallbackDenied(w) || claimState(t, a.f) != before {
		t.Fatal("successful callback replay changed records")
	}
}
func TestInvitationClaimVerificationIsolation(t *testing.T) {
	a := newAdmissionFixture(t)
	i := a.invite(t, "tested@example.test", nil)
	var candidate Metadata
	a.f.run(t, func(ctx context.Context) {
		var err error
		candidate, err = a.f.repo.CreateDraft(ctx, 1, a.revision.Settings, NewSecret([]byte(apiSecret)))
		if err != nil {
			t.Fatal(err)
		}
		for _, state := range []Status{Validated, Approved} {
			candidate, err = a.f.repo.Transition(ctx, candidate.ID, candidate.Generation, state)
			if err != nil {
				t.Fatal(err)
			}
		}
	})
	a.provider.mu.Lock()
	a.provider.claims = func(c map[string]any) { c["sub"] = "tested-subject"; c["email"] = i.Email; c["email_verified"] = true }
	a.provider.mu.Unlock()
	before := claimState(t, a.f)
	a.provider.callback = apiOrigin + "/api/auth/test/callback"
	tests := newConnectionTests(a.f.repo, apiOrigin)
	tests.client = func(context.Context, string) (*http.Client, error) { return a.provider.client(), nil }
	h := probeHandler(a.f, tests, a.f.identity)
	result, cookie, state := startProbe(t, h, a.provider, candidate)
	callbackProbe(t, h, cookie, state, "synthetic-code")
	if resultProbe(t, h, result.ID).Status != "succeeded" || claimState(t, a.f) != before {
		t.Fatal("isolated test claimed/provisioned")
	}
	a.provider.callback = candidate.RedirectURI
	prepared := prepareActivation(t, a.f, a.service, candidate, 1)
	var operation *NormalCallbackResult
	w := httptest.NewRecorder()
	a.f.run(t, func(ctx context.Context) {
		var err error
		operation, err = a.service.BeginNormalCallbackTest(prepared, w, httptest.NewRequest("GET", "/test-only", nil).WithContext(ctx))
		if err != nil {
			t.Fatal(err)
		}
	})
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil || w.Code != 302 {
		t.Fatal("readiness did not start", err)
	}
	a.provider.mu.Lock()
	a.provider.nonce = u.Query().Get("nonce")
	a.provider.challenge = u.Query().Get("code_challenge")
	a.provider.mu.Unlock()
	request := httptest.NewRequest("GET", candidate.RedirectURI+"?"+url.Values{"state": {u.Query().Get("state")}, "code": {"synthetic-code"}}.Encode(), nil)
	for _, c := range w.Result().Cookies() {
		request.AddCookie(c)
	}
	w = httptest.NewRecorder()
	a.handler.ServeHTTP(w, request)
	if _, ok := operation.Evidence(); !ok || claimState(t, a.f) != before {
		t.Fatal("normal readiness test claimed/provisioned")
	}
}
func TestInvitationClaimProvenanceConstraints(t *testing.T) {
	a := newAdmissionFixture(t)
	a.changePolicy(t, "approved_users_only", "Viewer", []string{})
	i := a.invite(t, "provenance@example.test", nil)
	// Pending records cannot be passed off as already verified identity approvals.
	_, err := a.f.owner.Exec(context.Background(), `INSERT INTO framework.oidc_identity_approvals(deployment_id,environment,issuer,subject,status,source,invitation_id,created_by,updated_by,reason)
 VALUES($1,$2,$3,'forged','approved','invitation',$4,$5,$5,'synthetic forged approval')`, i.DeploymentID, i.Environment, i.Issuer, i.ID, i.CreatedBy)
	if err == nil {
		t.Fatal("unclaimed invitation approved identity")
	}
	cookie := sessionCookieFor(t, a.login(t, "provenance-subject", i.Email, true))
	for _, sql := range []string{
		`UPDATE framework.oidc_identity_approvals SET invitation_id=NULL,generation=generation+1 WHERE invitation_id=$1`,
		`UPDATE framework.oidc_identity_approvals SET source='administrator',invitation_id=NULL,generation=generation+1 WHERE invitation_id=$1`,
	} {
		if _, err := a.f.owner.Exec(context.Background(), sql, i.ID); err == nil {
			t.Fatal("claim provenance rewritten")
		}
	}
	_, err = a.f.owner.Exec(context.Background(), `INSERT INTO framework.oidc_identity_approvals(deployment_id,environment,issuer,subject,status,source,invitation_id,created_by,updated_by,reason)
 VALUES($1,$2,$3,'different-subject','approved','invitation',$4,$5,$5,'synthetic mismatched approval')`, i.DeploymentID, i.Environment, i.Issuer, i.ID, i.CreatedBy)
	if err == nil {
		t.Fatal("invitation proof crossed subjects")
	}
	a.approval(t, probeIssuer, "provenance-subject", "revoked", 1)
	if getSession(a.handler, cookie, "/api/auth/me") != 401 || !loginDenied(a.login(t, "provenance-subject", i.Email, true)) {
		t.Fatal("invitation source bypassed revocation")
	}
}
func TestInvitationClaimMigrationPreservesExistingRecords(t *testing.T) {
	owner, _ := testdb.New(t)
	testdb.MigrationsThrough(t, owner, "up", 9)
	store := access.New(owner)
	identity := auth.Identity{Issuer: "https://issuer.example.test", Subject: "config-admin", Provider: auth.OIDC, Email: "admin@vopak.com", EmailVerified: true}
	if _, err := store.Resolve(context.Background(), identity); err != nil {
		t.Fatal(err)
	}
	if err := store.Bootstrap(context.Background(), identity.Issuer, identity.Subject, "development"); err != nil {
		t.Fatal(err)
	}
	repo, err := NewRepository(store, Scope{"installation-a", "development"}, testCipher(t, "key-v1"))
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{owner: owner, pool: owner, store: store, repo: repo, identity: identity}
	revision := approvedRevision(t, f, 0)
	if err := activationFixture(t, f, revision, 1, "", false); err != nil {
		t.Fatal(err)
	}
	policy, _ := NewAccessPolicyRepository(store, repo.scope)
	bootstrapPolicy(t, f, policy)
	f.run(t, func(ctx context.Context) {
		if _, err := policy.CreateInvitation(ctx, InvitationExpectation{PolicyExpectation{1, 1}, revision.ID, 4}, invitationInput("pending@vopak.com")); err != nil {
			t.Fatal(err)
		}
	})
	snapshot := func() string {
		var s string
		if err := owner.QueryRow(context.Background(), `SELECT jsonb_build_array(
  (SELECT jsonb_agg(to_jsonb(a)-'invitation_id' ORDER BY issuer,subject) FROM framework.oidc_identity_approvals a),
  (SELECT jsonb_agg(to_jsonb(i) ORDER BY id) FROM framework.oidc_invitations i))::text`).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s + policyExistingState(t, f)
	}
	before := snapshot()
	sql, err := os.ReadFile("../../../database/migrations/000010_oidc_invitation_approvals.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(context.Background(), string(sql)); err != nil {
		t.Fatal(err)
	}
	if snapshot() != before {
		t.Fatal("migration changed existing authentication data or invitation history")
	}
}

func claimCallbackDenied(w *httptest.ResponseRecorder) bool {
	if loginDenied(w) {
		return true
	}
	if w.Code != http.StatusUnauthorized {
		return false
	}
	for _, cookie := range w.Result().Cookies() {
		if strings.Contains(cookie.Name, "session") && cookie.Value != "" {
			return false
		}
	}
	return true
}

func TestInvitationClaimSerializesIdentityRevocation(t *testing.T) {
	a := newAdmissionFixture(t)
	a.changePolicy(t, "approved_users_only", "Viewer", []string{})
	i := a.invite(t, "serialized@example.test", nil)
	b := admissionBinding(t, a)
	identity := invitationIdentity("serialized-invitation", i.Email)
	admission := a.f.store.OIDCAdmission(b.DeploymentID, b.Environment)
	entered, release := make(chan struct{}), make(chan struct{})
	loginDone := make(chan error, 1)
	go func() {
		loginDone <- admission.Login(context.Background(), identity, b, func(ctx context.Context, tx pgx.Tx) error {
			close(entered)
			<-release
			return boundSessionWrite(identity, b)(ctx, tx)
		})
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("claim did not reach session creation")
	}
	a.f.run(t, func(ctx context.Context) {
		done := make(chan error, 1)
		go func() {
			_, err := a.policy.SetApproval(ctx, PolicyExpectation{2, 1}, OIDCIdentityKey{identity.Issuer, identity.Subject}, 1, "revoked", "concurrent invitation access revocation")
			done <- err
		}()
		waiting := false
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if err := a.f.owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event='advisory')`).Scan(&waiting); err != nil {
				close(release)
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
			t.Fatal("revocation failed to serialize with claim")
		}
	})
	var sessions int
	if err := a.f.owner.QueryRow(context.Background(), `SELECT count(*) FROM framework.sessions WHERE subject=$1`, identity.Subject).Scan(&sessions); err != nil || sessions != 0 {
		t.Fatal("revocation retained issued session", err)
	}
	if !loginDenied(a.login(t, identity.Subject, identity.Email, true)) {
		t.Fatal("revocation did not remain effective")
	}
}
func TestInvitationClaimDatabaseFailure(t *testing.T) {
	a := newAdmissionFixture(t)
	a.changePolicy(t, "approved_users_only", "Viewer", []string{})
	i := a.invite(t, "database@example.test", nil)
	b := admissionBinding(t, a)
	admission := a.f.store.OIDCAdmission(b.DeploymentID, b.Environment)
	before := claimState(t, a.f)
	a.f.pool.Close()
	called := false
	err := admission.Login(context.Background(), invitationIdentity("database-subject", i.Email), b, func(context.Context, pgx.Tx) error { called = true; return nil })
	if !errors.Is(err, auth.ErrStoreUnavailable) || called || claimState(t, a.f) != before {
		t.Fatal("database failure admitted or modified user", err)
	}
}
