package authconfig

import (
	"context"
	"errors"
	"testing"
)

func TestAuthoritativeStartupPolicy(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	r, _ := NewActivationReader(f.pool, f.repo.scope)
	if err := r.RequireEnvironmentStartup(ctx); err != nil {
		t.Fatal("no head should preserve environment", err)
	}
	var count int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM framework.auth_activation_heads`).Scan(&count); err != nil || count != 0 {
		t.Fatal("startup wrote a policy")
	}
	_, err := f.owner.Exec(ctx, `INSERT INTO framework.auth_activation_heads(deployment_id,environment) VALUES($1,$2)`, f.repo.scope.DeploymentID, f.repo.scope.Environment)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.RequireEnvironmentStartup(ctx); err != nil {
		t.Fatal("explicit environment policy rejected", err)
	}
	// Use a second scope for the activation fixture (never the development DB).
	other, err := NewRepository(f.store, Scope{"enrolled", "development"}, testCipher(t, "key-v1"))
	if err != nil {
		t.Fatal(err)
	}
	old := f.repo
	f.repo = other
	m := approvedRevision(t, f, 0)
	if err := activationFixture(t, f, m, 1, "", false); err != nil {
		t.Fatal(err)
	}
	f.repo = old
	enrolled, _ := NewActivationReader(f.pool, other.scope)
	if err := enrolled.RequireEnvironmentStartup(ctx); !errors.Is(err, ErrDatabaseRuntimeRequired) {
		t.Fatal("database policy allowed environment startup", err)
	}
	if err := r.RequireEnvironmentStartup(ctx); err != nil {
		t.Fatal("explicitly permitted independent deployment rejected", err)
	}
	for _, scope := range []Scope{{"typo", "development"}, {"enrolled", "test"}} {
		wrong, _ := NewActivationReader(f.pool, scope)
		if err := wrong.RequireEnvironmentStartup(ctx); err == nil {
			t.Fatal("incorrect scope fell back to an implicit environment policy")
		}
	}
	f.pool.Close()
	if err := r.RequireEnvironmentStartup(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatal("unreadable policy allowed fallback", err)
	}
}

func TestStartupMissingOrInconsistentPolicyFailsClosed(t *testing.T) {
	f := newFixture(t)
	r, _ := NewActivationReader(f.pool, f.repo.scope)
	ctx := context.Background()
	// A version-5 active lifecycle without a v6 head is insufficient policy.
	m := approvedRevision(t, f, 0)
	if _, err := f.owner.Exec(ctx, `UPDATE framework.auth_config_lifecycle SET status='active',generation=generation+1 WHERE revision_id=$1`, m.ID); err != nil {
		t.Fatal(err)
	}
	if err := r.RequireEnvironmentStartup(ctx); err == nil {
		t.Fatal("orphan active revision permitted environment")
	}
	if _, err := f.owner.Exec(ctx, `ALTER TABLE framework.auth_activation_heads RENAME TO test_missing_heads`); err != nil {
		t.Fatal(err)
	}
	if err := r.RequireEnvironmentStartup(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatal("missing journal permitted fallback", err)
	}
}
