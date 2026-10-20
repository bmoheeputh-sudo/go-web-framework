package authconfig

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/testdb"
)

func policyFixture(t *testing.T) (*fixture, *AccessPolicyRepository) {
	t.Helper()
	f := newFixture(t)
	f.identity.Email, f.identity.EmailVerified = "admin@vopak.com", true
	if _, err := f.store.Resolve(context.Background(), f.identity); err != nil {
		t.Fatal(err)
	}
	m := approvedRevision(t, f, 0)
	if err := activationFixture(t, f, m, 1, "", false); err != nil {
		t.Fatal(err)
	}
	r, err := NewAccessPolicyRepository(f.store, f.repo.scope)
	if err != nil {
		t.Fatal(err)
	}
	return f, r
}

func policySettings() AccessPolicySettings {
	return AccessPolicySettings{"approved_users_only", []string{"vopak.com"}, "Viewer"}
}

func bootstrapPolicy(t *testing.T, f *fixture, r *AccessPolicyRepository) {
	t.Helper()
	f.run(t, func(ctx context.Context) {
		if _, err := r.Bootstrap(ctx, 1, policySettings(), "explicit administrator bootstrap"); err != nil {
			t.Fatal(err)
		}
	})
}

func TestAccessPolicyValidation(t *testing.T) {
	s := policySettings()
	s.AllowedEmailDomains = []string{"Example.COM", "VOPAK.com"}
	got, err := normalizePolicy(s)
	if err != nil || strings.Join(got.AllowedEmailDomains, ",") != "example.com,vopak.com" || s.AllowedEmailDomains[0] != "Example.COM" {
		t.Fatal("domain canonicalization mutated caller or returned incorrect result")
	}
	for _, domains := range [][]string{
		{"vopak.com", "VOPAK.com"}, {""}, {" vopak.com"}, {"*.vopak.com"}, {"https://vopak.com"},
		{"a@vopak.com"}, {"vopak.com."}, {"localhost"}, {"127.0.0.1"}, {"éxample.com"},
		{strings.Repeat("a", 64) + ".com"}, make([]string, 21),
	} {
		s.AllowedEmailDomains = domains
		if _, err := normalizePolicy(s); !errors.Is(err, ErrInvalid) {
			t.Errorf("invalid domain list accepted: %q", domains)
		}
	}
	for _, role := range []string{"Admin", "", "viewer"} {
		s = policySettings()
		s.DefaultRole = role
		if _, err := normalizePolicy(s); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid default role accepted")
		}
	}
	s = policySettings()
	s.Mode = "allow"
	if _, err := normalizePolicy(s); !errors.Is(err, ErrInvalid) {
		t.Fatal("invalid mode accepted")
	}
	for _, reason := range []string{"short", "valid reason\n", strings.Repeat("x", 513)} {
		if validPolicyReason(reason) {
			t.Fatal("invalid reason accepted")
		}
	}
	for _, email := range []string{"admin@evilvopak.com", "admin@sub.vopak.com", "Name <admin@vopak.com>", "admin@vopak.com.evil"} {
		if policyEmailAllowed([]string{"vopak.com"}, email, true) {
			t.Fatal("unsafe domain comparison")
		}
	}
	if policyEmailAllowed([]string{"vopak.com"}, "admin@vopak.com", false) ||
		!policyEmailAllowed([]string{"vopak.com"}, "admin@VOPAK.COM", true) {
		t.Fatal("email verification/domain casing")
	}
	for _, key := range []OIDCIdentityKey{{"http://issuer.test", "id"}, {"https://user@issuer.test", "id"},
		{"https://issuer.test?q=x", "id"}, {"https://issuer.test", ""}, {"https://issuer.test", " id"}} {
		if key.valid() {
			t.Fatal("invalid identity accepted")
		}
	}
}

func TestAccessPolicyBootstrapAndApprovals(t *testing.T) {
	f, r := policyFixture(t)
	var before string
	f.run(t, func(ctx context.Context) {
		before = policyExistingState(t, f)
		if _, err := r.Read(ctx); !errors.Is(err, ErrNotFound) {
			t.Fatal("migration silently initialized policy")
		}
		if _, err := r.Bootstrap(ctx, 2, policySettings(), "explicit bootstrap"); !errors.Is(err, ErrConflict) {
			t.Fatal("stale activation accepted")
		}
		p, err := r.Bootstrap(ctx, 1, policySettings(), "explicit bootstrap")
		if err != nil || p.Generation != 1 || p.CreatedBy == "" {
			t.Fatal("bootstrap failed", err)
		}
		if _, err := r.Bootstrap(ctx, 1, policySettings(), "duplicate bootstrap"); !errors.Is(err, ErrConflict) {
			t.Fatal("duplicate bootstrap accepted")
		}
		a, err := r.ReadApproval(ctx, OIDCIdentityKey{f.identity.Issuer, f.identity.Subject})
		if err != nil || a.Status != "approved" || a.Source != "bootstrap" {
			t.Fatal("bootstrap approval missing", err)
		}
		for _, scope := range []Scope{{"other", "development"}, {r.scope.DeploymentID, "production"}} {
			other, _ := NewAccessPolicyRepository(f.store, scope)
			if _, err := other.Read(ctx); !errors.Is(err, ErrNotFound) {
				t.Fatal("cross-scope policy leaked")
			}
			if _, err := other.Bootstrap(ctx, 1, policySettings(), "wrong scope attempt"); !errors.Is(err, ErrConflict) {
				t.Fatal("cross-scope bootstrap accepted")
			}
		}
		// Same mailbox cannot merge identities: approvals have no email input,
		// and exact issuer/subject variants remain separate records.
		for _, key := range []OIDCIdentityKey{
			{f.identity.Issuer + "/", "user"}, {"https://ISSUER.example.test", "user"},
			{f.identity.Issuer, "user"}, {f.identity.Issuer, "User"},
		} {
			a, err := r.SetApproval(ctx, PolicyExpectation{1, 1}, key, 0, "approved", "explicit identity approval")
			if err != nil || a.OIDCIdentityKey != key || a.Generation != 1 {
				t.Fatal("exact identity approval failed", err)
			}
			if _, err := r.SetApproval(ctx, PolicyExpectation{1, 1}, key, 0, "approved", "duplicate identity approval"); !errors.Is(err, ErrConflict) {
				t.Fatal("duplicate silently upserted")
			}
			if _, err := r.SetApproval(ctx, PolicyExpectation{1, 1}, key, 99, "revoked", "stale identity revocation"); !errors.Is(err, ErrConflict) {
				t.Fatal("stale approval accepted")
			}
		}
		list, err := r.ListApprovals(ctx, 0, 100)
		if err != nil || len(list) != 5 {
			t.Fatal("approvals list", err)
		}
		key := OIDCIdentityKey{f.identity.Issuer, "user"}
		revoked, err := r.SetApproval(ctx, PolicyExpectation{1, 1}, key, 1, "revoked", "explicit identity revocation")
		if err != nil || revoked.Generation != 2 || revoked.Status != "revoked" {
			t.Fatal("revocation", err)
		}
		if _, err := r.SetApproval(ctx, PolicyExpectation{1, 1}, key, 2, "approved", "explicit identity reapproval"); err != nil {
			t.Fatal(err)
		}
	})
	if policyExistingState(t, f) != before {
		t.Fatal("policy changed users, roles, sessions or active authentication")
	}
	var count int
	if err := f.owner.QueryRow(context.Background(), `SELECT count(*) FROM framework.audit_log
 WHERE action LIKE 'oidc_access.%' AND actor_user_id=(SELECT id FROM framework.users WHERE subject='config-admin')`).Scan(&count); err != nil || count != 8 {
		t.Fatal("missing attributed audit events", count, err)
	}
}

// Snapshot existing security state; no sensitive snapshot data is printed.
func policyExistingState(t *testing.T, f *fixture) string {
	t.Helper()
	var state string
	err := f.owner.QueryRow(context.Background(), `SELECT jsonb_build_array(
 (SELECT jsonb_agg(to_jsonb(u) ORDER BY id) FROM framework.users u),
 (SELECT jsonb_agg(to_jsonb(u) ORDER BY user_id,role) FROM framework.user_roles u),
 (SELECT jsonb_agg(to_jsonb(u) ORDER BY role,permission) FROM framework.role_permissions u),
 (SELECT jsonb_agg(to_jsonb(u)) FROM framework.sessions u),
 (SELECT jsonb_agg(to_jsonb(u)) FROM framework.auth_activation_heads u),
 (SELECT jsonb_agg(to_jsonb(u)) FROM framework.auth_config_revisions u),
 (SELECT jsonb_agg(to_jsonb(u)) FROM framework.auth_config_lifecycle u))::text`).Scan(&state)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func TestAccessPolicyLockoutAndConflicts(t *testing.T) {
	f, r := policyFixture(t)
	bootstrapPolicy(t, f, r)
	f.run(t, func(ctx context.Context) {
		s := policySettings()
		s.AllowedEmailDomains = []string{"other.example"}
		if _, err := r.Update(ctx, PolicyExpectation{1, 1}, s, "exclude administrator domain"); !errors.Is(err, ErrLastOIDCAdministrator) {
			t.Fatal("last administrator domain exclusion allowed", err)
		}
		key := OIDCIdentityKey{f.identity.Issuer, f.identity.Subject}
		if _, err := r.SetApproval(ctx, PolicyExpectation{1, 1}, key, 1, "revoked", "revoke final administrator"); !errors.Is(err, ErrLastOIDCAdministrator) {
			t.Fatal("last administrator revocation allowed", err)
		}
		if p, err := r.Read(ctx); err != nil || p.Generation != 1 {
			t.Fatal("denied policy change persisted")
		}
		if a, err := r.ReadApproval(ctx, key); err != nil || a.Generation != 1 || a.Status != "approved" {
			t.Fatal("denied approval change persisted")
		}
		for _, expected := range []PolicyExpectation{{2, 1}, {1, 2}} {
			if _, err := r.Update(ctx, expected, policySettings(), "stale update attempt"); !errors.Is(err, ErrConflict) {
				t.Fatal("stale policy/activation generation accepted")
			}
		}
		// Concurrent administrators with the same generation cannot overwrite.
		results := make(chan error, 2)
		var wg sync.WaitGroup
		for range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := r.Update(ctx, PolicyExpectation{1, 1}, policySettings(), "concurrent explicit update")
				results <- err
			}()
		}
		wg.Wait()
		close(results)
		success, conflicts := 0, 0
		for err := range results {
			switch {
			case err == nil:
				success++
			case errors.Is(err, ErrConflict):
				conflicts++
			default:
				t.Fatal(err)
			}
		}
		if success != 1 || conflicts != 1 {
			t.Fatal("lost-update protection failed")
		}
		// Explicit revocation also excludes an identity in allow_all mode.
		s = policySettings()
		s.Mode = "allow_all"
		if _, err := r.Update(ctx, PolicyExpectation{2, 1}, s, "switch to open admission"); err != nil {
			t.Fatal(err)
		}
		if _, err := r.SetApproval(ctx, PolicyExpectation{3, 1}, key, 1, "revoked", "revoke last allow-all admin"); !errors.Is(err, ErrLastOIDCAdministrator) {
			t.Fatal("allow-all revocation bypass", err)
		}
	})
}

func TestAccessPolicyAuthorizationAndAuditRollback(t *testing.T) {
	f, r := policyFixture(t)
	if _, err := r.Read(context.Background()); !errors.Is(err, ErrDenied) {
		t.Fatal("unauthenticated read allowed")
	}
	bootstrapPolicy(t, f, r)
	f.run(t, func(ctx context.Context) {
		// Stale framework principal must not authorize after a revocation.
		_, err := f.owner.Exec(ctx, `DELETE FROM framework.role_permissions WHERE permission='admin.manage'`)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.Update(ctx, PolicyExpectation{1, 1}, policySettings(), "revoked administrator write"); !errors.Is(err, ErrDenied) {
			t.Fatal("transaction failed to reauthorize", err)
		}
		if _, err = f.owner.Exec(ctx, `INSERT INTO framework.role_permissions VALUES('Admin','admin.manage')`); err != nil {
			t.Fatal(err)
		}
		if _, err = f.owner.Exec(ctx, `UPDATE framework.users SET active=false WHERE subject='config-admin'`); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Read(ctx); !errors.Is(err, ErrDenied) {
			t.Fatal("inactive administrator accepted")
		}
		if _, err = f.owner.Exec(ctx, `UPDATE framework.users SET active=true WHERE subject='config-admin'`); err != nil {
			t.Fatal(err)
		}
		if _, err = f.owner.Exec(ctx, `INSERT INTO framework.role_permissions VALUES('Viewer','admin.manage')`); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Update(ctx, PolicyExpectation{1, 1}, policySettings(), "unsafe default role selection"); !errors.Is(err, ErrUnavailable) {
			t.Fatal("effective admin default role allowed", err)
		}
		if _, err = f.owner.Exec(ctx, `DELETE FROM framework.role_permissions WHERE role='Viewer' AND permission='admin.manage'`); err != nil {
			t.Fatal(err)
		}
		if _, err = f.owner.Exec(ctx, `CREATE FUNCTION framework.reject_policy_audit() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN RAISE EXCEPTION 'synthetic audit failure'; END $$;
 CREATE TRIGGER reject_policy_audit BEFORE INSERT ON framework.audit_log FOR EACH ROW EXECUTE FUNCTION framework.reject_policy_audit()`); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Update(ctx, PolicyExpectation{1, 1}, policySettings(), "audit failure update"); !errors.Is(err, ErrAudit) {
			t.Fatal("audit failure not surfaced", err)
		}
		key := OIDCIdentityKey{f.identity.Issuer, "new-user"}
		if _, err := r.SetApproval(ctx, PolicyExpectation{1, 1}, key, 0, "approved", "audit failure approval"); !errors.Is(err, ErrAudit) {
			t.Fatal("approval audit failure not surfaced", err)
		}
		if p, err := r.Read(ctx); err != nil || p.Generation != 1 {
			t.Fatal("failed audit left policy changes")
		}
		if _, err := r.ReadApproval(ctx, key); !errors.Is(err, ErrNotFound) {
			t.Fatal("failed audit left approval")
		}
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := r.Read(canceled); !errors.Is(err, ErrCanceled) {
			t.Fatal("cancellation not respected", err)
		}
		f.pool.Close()
		if _, err := r.Read(ctx); !errors.Is(err, ErrUnavailable) {
			t.Fatal("database error leaked", err)
		}
	})
}

func TestAccessPolicyBootstrapRejectsUntrustedIdentity(t *testing.T) {
	f, r := policyFixture(t)
	// Exact issuer: a different trailing slash cannot bootstrap.
	other := f.identity
	other.Issuer += "/"
	user, err := f.store.Resolve(context.Background(), other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.owner.Exec(context.Background(), `INSERT INTO framework.user_roles VALUES($1,'Admin')`, user.ID); err != nil {
		t.Fatal(err)
	}
	f.identity = other
	f.run(t, func(ctx context.Context) {
		if _, err := r.Bootstrap(ctx, 1, policySettings(), "wrong issuer bootstrap"); !errors.Is(err, ErrDenied) {
			t.Fatal("non-active issuer bootstrap accepted", err)
		}
	})
	other.Issuer, other.Provider = "local-dev", auth.LocalDev
	user, err = f.store.Resolve(context.Background(), other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.owner.Exec(context.Background(), `INSERT INTO framework.user_roles VALUES($1,'Admin')`, user.ID); err != nil {
		t.Fatal(err)
	}
	f.identity = other
	f.run(t, func(ctx context.Context) {
		if _, err := r.Bootstrap(ctx, 1, policySettings(), "local developer bootstrap"); !errors.Is(err, ErrDenied) {
			t.Fatal("local dev bootstrap accepted", err)
		}
	})
}

func TestAccessPolicyDatabaseConstraints(t *testing.T) {
	f, r := policyFixture(t)
	bootstrapPolicy(t, f, r)
	ctx := context.Background()
	for name, sql := range map[string]string{
		"default Admin":     `UPDATE framework.oidc_access_policies SET default_role='Admin',generation=generation+1`,
		"invalid mode":      `UPDATE framework.oidc_access_policies SET mode='anything',generation=generation+1`,
		"null domain":       `UPDATE framework.oidc_access_policies SET allowed_email_domains=ARRAY[NULL]::text[],generation=generation+1`,
		"wildcard domain":   `UPDATE framework.oidc_access_policies SET allowed_email_domains=ARRAY['*.vopak.com'],generation=generation+1`,
		"duplicate domain":  `UPDATE framework.oidc_access_policies SET allowed_email_domains=ARRAY['vopak.com','vopak.com'],generation=generation+1`,
		"stale generation":  `UPDATE framework.oidc_access_policies SET mode='allow_all'`,
		"change scope":      `UPDATE framework.oidc_access_policies SET deployment_id='other',generation=generation+1`,
		"change identity":   `UPDATE framework.oidc_identity_approvals SET subject='other',generation=generation+1`,
		"delete approval":   `DELETE FROM framework.oidc_identity_approvals`,
		"truncate approval": `TRUNCATE framework.oidc_identity_approvals`,
		"unknown creator":   `UPDATE framework.oidc_access_policies SET updated_by='11111111-1111-4111-8111-111111111111',generation=generation+1`,
	} {
		t.Run(name, func(t *testing.T) {
			tx, err := f.owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if _, err := tx.Exec(ctx, sql); err == nil {
				t.Fatal("database accepted invalid mutation")
			}
		})
	}
	// An independent eligible administrator makes revocation safe.
	other := f.identity
	other.Subject = "second-admin"
	u, err := f.store.Resolve(ctx, other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.owner.Exec(ctx, `INSERT INTO framework.user_roles VALUES($1,'Admin')`, u.ID); err != nil {
		t.Fatal(err)
	}
	f.run(t, func(ctx context.Context) {
		if _, err := r.SetApproval(ctx, PolicyExpectation{1, 1}, OIDCIdentityKey{other.Issuer, other.Subject}, 0, "approved", "approve second administrator"); err != nil {
			t.Fatal(err)
		}
		if _, err := f.owner.Exec(ctx, `UPDATE framework.users SET active=false WHERE id=$1`, u.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := r.SetApproval(ctx, PolicyExpectation{1, 1}, OIDCIdentityKey{f.identity.Issuer, f.identity.Subject}, 1, "revoked", "inactive replacement administrator"); !errors.Is(err, ErrLastOIDCAdministrator) {
			t.Fatal("inactive replacement satisfied lockout guard", err)
		}
		if _, err := f.owner.Exec(ctx, `UPDATE framework.users SET active=true WHERE id=$1`, u.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := r.SetApproval(ctx, PolicyExpectation{1, 1}, OIDCIdentityKey{f.identity.Issuer, f.identity.Subject}, 1, "revoked", "revoke first administrator"); err != nil {
			t.Fatal(err)
		}
	})
}

func TestAccessPolicyBootstrapAuditFailureIsAtomic(t *testing.T) {
	f, r := policyFixture(t)
	_, err := f.owner.Exec(context.Background(), `CREATE FUNCTION framework.fail_bootstrap_audit() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN IF NEW.action='oidc_access.policy_bootstrapped' THEN RAISE EXCEPTION 'synthetic second audit failure'; END IF; RETURN NEW; END $$;
 CREATE TRIGGER fail_bootstrap_audit BEFORE INSERT ON framework.audit_log FOR EACH ROW EXECUTE FUNCTION framework.fail_bootstrap_audit()`)
	if err != nil {
		t.Fatal(err)
	}
	f.run(t, func(ctx context.Context) {
		if _, err := r.Bootstrap(ctx, 1, policySettings(), "atomic bootstrap test"); !errors.Is(err, ErrAudit) {
			t.Fatal(err)
		}
		if _, err := r.Read(ctx); !errors.Is(err, ErrNotFound) {
			t.Fatal("bootstrap leaked policy")
		}
		a, err := r.ListApprovals(ctx, 0, 100)
		if err != nil || len(a) != 0 {
			t.Fatal("bootstrap leaked approvals")
		}
		var n int
		if err := f.owner.QueryRow(ctx, `SELECT count(*) FROM framework.audit_log WHERE action LIKE 'oidc_access.%'`).Scan(&n); err != nil || n != 0 {
			t.Fatal("bootstrap leaked audit")
		}
	})
}

func TestAccessPolicySchema7Compatibility(t *testing.T) {
	pool, _ := testdb.New(t)
	testdb.MigrationsThrough(t, pool, "up", 7)
	ctx := context.Background()
	store := access.New(pool)
	identity := auth.Identity{Issuer: "https://issuer.example.test", Subject: "config-admin", Provider: auth.OIDC}
	if _, err := store.Resolve(ctx, identity); err != nil {
		t.Fatal(err)
	}
	if err := store.Bootstrap(ctx, identity.Issuer, identity.Subject, "development"); err != nil {
		t.Fatal(err)
	}
	repo, err := NewRepository(store, Scope{"installation-a", "development"}, testCipher(t, "key-v1"))
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{pool, pool, store, repo, identity}
	m := approvedRevision(t, f, 0)
	if err := activationFixture(t, f, m, 1, "", false); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO framework.sessions(token_hash,issuer,subject,provider,expires_at)
 VALUES(decode(repeat('ab',32),'hex'),'https://issuer.example.test','config-admin','oidc',clock_timestamp()+interval '1 hour')`); err != nil {
		t.Fatal(err)
	}
	r, err := NewAccessPolicyRepository(store, repo.scope)
	if err != nil {
		t.Fatal(err)
	}
	f.run(t, func(ctx context.Context) {
		if err := store.Check(ctx); err != nil {
			t.Fatal("existing RBAC cannot run at schema 7", err)
		}
		if _, err := repo.CurrentActive(ctx); err != nil {
			t.Fatal("existing active OIDC metadata unavailable", err)
		}
		if _, err := r.Read(ctx); !errors.Is(err, ErrUnavailable) {
			t.Fatal("missing policy schema did not fail safely", err)
		}
	})
	before := policyExistingState(t, f)
	sql, err := os.ReadFile("../../../database/migrations/000008_oidc_access_policy.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(sql)); err != nil {
		t.Fatal(err)
	}
	if policyExistingState(t, f) != before {
		t.Fatal("migration changed existing users, roles, sessions or active OIDC state")
	}
	f.run(t, func(ctx context.Context) {
		if _, err := r.Read(ctx); !errors.Is(err, ErrNotFound) {
			t.Fatal("migration created implicit policy", err)
		}
	})
}

func TestAccessPolicyConcurrentAuthorizationRevocation(t *testing.T) {
	f, r := policyFixture(t)
	bootstrapPolicy(t, f, r)
	f.run(t, func(ctx context.Context) {
		tx, err := f.owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(78541705)`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM framework.role_permissions WHERE permission='admin.manage'`); err != nil {
			t.Fatal(err)
		}
		started, result := make(chan struct{}), make(chan error, 1)
		go func() {
			close(started)
			_, err := r.Update(ctx, PolicyExpectation{1, 1}, policySettings(), "concurrent revocation attempt")
			result <- err
		}()
		<-started
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-result; !errors.Is(err, ErrDenied) {
			t.Fatal("revoked permission survived shared mutation lock", err)
		}
		var generation int64
		if err := f.owner.QueryRow(ctx, `SELECT generation FROM framework.oidc_access_policies`).Scan(&generation); err != nil || generation != 1 {
			t.Fatal("denied concurrent change persisted", err)
		}
	})
}

func TestAccessPolicyNonAdministratorDenied(t *testing.T) {
	f, repo := policyFixture(t)
	bootstrapPolicy(t, f, repo)
	for _, role := range []string{"User", "Viewer"} {
		t.Run(role, func(t *testing.T) {
			identity := f.identity
			identity.Subject = "non-admin-" + role
			u, err := f.store.Resolve(context.Background(), identity)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.owner.Exec(context.Background(), `INSERT INTO framework.user_roles VALUES($1,$2)`, u.ID, role); err != nil {
				t.Fatal(err)
			}
			f.run(t, func(ctx context.Context) {
				if _, err := repo.SetApproval(ctx, PolicyExpectation{1, 1}, OIDCIdentityKey{identity.Issuer, identity.Subject}, 0, "approved", "approve synthetic non-admin"); err != nil {
					t.Fatal(err)
				}
			})
			called := false
			h := auth.Require(fixedAuth{identity}, f.store.Require(access.AccountRead, "", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				called = true
				if _, err := repo.Read(r.Context()); !errors.Is(err, ErrDenied) {
					t.Fatal("non-administrator read accepted", err)
				}
				if _, err := repo.Update(r.Context(), PolicyExpectation{1, 1}, policySettings(), "non-admin write attempt"); !errors.Is(err, ErrDenied) {
					t.Fatal("non-administrator write accepted", err)
				}
			})))
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/test-only", nil))
			if !called {
				t.Fatal("test principal missing")
			}
		})
	}
	// Verified identity alone, without the framework principal, is insufficient.
	h := auth.Require(fixedAuth{f.identity}, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if _, err := repo.Read(r.Context()); !errors.Is(err, ErrDenied) {
			t.Fatal("missing principal accepted", err)
		}
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/test-only", nil))
}

func TestAccessPolicyBootstrapRequiresActiveOIDCAndVerifiedDomain(t *testing.T) {
	f := newFixture(t)
	r, _ := NewAccessPolicyRepository(f.store, f.repo.scope)
	f.run(t, func(ctx context.Context) {
		if _, err := r.Bootstrap(ctx, 1, policySettings(), "bootstrap without activation"); !errors.Is(err, ErrConflict) {
			t.Fatal("no active database OIDC head accepted", err)
		}
	})
	m := approvedRevision(t, f, 0)
	if err := activationFixture(t, f, m, 1, "", false); err != nil {
		t.Fatal(err)
	}
	// This fixture has an administrator without verified email claims.
	f.run(t, func(ctx context.Context) {
		if _, err := r.Bootstrap(ctx, 1, policySettings(), "bootstrap with unknown domain"); !errors.Is(err, ErrLastOIDCAdministrator) {
			t.Fatal("unverified domain satisfied administrator eligibility", err)
		}
		if _, err := r.Read(ctx); !errors.Is(err, ErrNotFound) {
			t.Fatal("failed bootstrap left a policy")
		}
		s := policySettings()
		s.AllowedEmailDomains = nil
		if _, err := r.Bootstrap(ctx, 1, s, "bootstrap without domain restriction"); err != nil {
			t.Fatal("optional domains rejected", err)
		}
	})
}
