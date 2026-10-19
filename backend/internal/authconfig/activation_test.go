package authconfig

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/jackc/pgx/v5/pgxpool"
)

func approvedRevision(t *testing.T, f *fixture, version int64) Metadata {
	t.Helper()
	m := f.draft(t, version)
	f.run(t, func(ctx context.Context) {
		for _, status := range []Status{Validated, Approved} {
			var err error
			m, err = f.repo.Transition(ctx, m.ID, m.Generation, status)
			if err != nil {
				t.Fatal(err)
			}
		}
	})
	return m
}

// Fixture-only SQL: no production activation mutation API exists. Each fixture
// changes only the disposable cluster and reproduces a future atomic transition.
func activationFixture(t *testing.T, f *fixture, m Metadata, generation int64, previous string, fail bool) error {
	t.Helper()
	ctx := context.Background()
	tx, err := f.owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if previous != "" {
		if _, err = tx.Exec(ctx, `UPDATE framework.auth_config_lifecycle SET status='superseded',generation=generation+1 WHERE revision_id=$1`, previous); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE framework.auth_config_lifecycle SET status='active',generation=generation+1 WHERE revision_id=$1`, m.ID); err != nil {
		return err
	}
	var when time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&when); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO framework.auth_activation_history(deployment_id,environment,generation,previous_revision_id,target_revision_id,actor_user_id,activated_at,transition_deadline,reason)
      VALUES($1,$2,$3,NULLIF($4,'')::uuid,$5,$6,$7,$7::timestamptz+interval '30 minutes','synthetic activation fixture')`, m.DeploymentID, m.Environment, generation, previous, m.ID, m.CreatedBy, when)
	if err != nil {
		return err
	}
	if generation == 1 {
		_, err = tx.Exec(ctx, `INSERT INTO framework.auth_activation_heads(deployment_id,environment,generation,runtime_source,active_revision_id,activated_at) VALUES($1,$2,$3,'database',$4,$5)`, m.DeploymentID, m.Environment, generation, m.ID, when)
	} else {
		_, err = tx.Exec(ctx, `UPDATE framework.auth_activation_heads SET generation=$3,active_revision_id=$4,activated_at=$5 WHERE deployment_id=$1 AND environment=$2`, m.DeploymentID, m.Environment, generation, m.ID, when)
	}
	if err != nil {
		return err
	}
	if fail {
		return ErrAudit
	}
	if err = access.RecordAudit(ctx, tx, m.CreatedBy, "auth_config.activation_fixture", m.ID, struct {
		Generation int64 `json:"generation"`
	}{generation}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func TestActivationPersistence(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	reader, err := NewActivationReader(f.pool, f.repo.scope)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("empty stays environment and reads never enroll", func(t *testing.T) {
		for range 2 {
			h, err := reader.Head(ctx)
			if err != nil || h.RuntimeSource != "environment" || h.Generation != 0 || h.ActiveRevisionID != "" {
				t.Fatal("empty head changed runtime policy")
			}
		}
		var n int
		if err := f.owner.QueryRow(ctx, `SELECT count(*) FROM framework.auth_activation_heads`).Scan(&n); err != nil || n != 0 {
			t.Fatal("reader wrote head")
		}
		events, err := reader.History(ctx, 0, 10)
		if err != nil || len(events) != 0 {
			t.Fatal("unexpected history")
		}
		if err := reader.CheckGeneration(ctx, 1); !errors.Is(err, ErrConflict) {
			t.Fatal("stale expected generation accepted")
		}
	})
	first := approvedRevision(t, f, 0)
	second := approvedRevision(t, f, 1)
	t.Run("scope and revision checks", func(t *testing.T) {
		if err := reader.ValidateRevision(ctx, first.ID, first.Generation); err != nil {
			t.Fatal(err)
		}
		if err := reader.ValidateRevision(ctx, first.ID, 99); !errors.Is(err, ErrConflict) {
			t.Fatal("wrong revision generation accepted")
		}
		for _, scope := range []Scope{{"other", first.Environment}, {first.DeploymentID, "production"}} {
			other, _ := NewActivationReader(f.pool, scope)
			if err := other.ValidateRevision(ctx, first.ID, first.Generation); !errors.Is(err, ErrNotFound) {
				t.Fatal("cross scope revision accepted")
			}
		}
		if _, err := NewActivationReader(f.pool, Scope{"bad/name", "development"}); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid scope accepted")
		}
	})
	if err := activationFixture(t, f, first, 1, "", false); err != nil {
		t.Fatal(err)
	}
	t.Run("head history consistency and rollback", func(t *testing.T) {
		head, err := reader.Head(ctx)
		if err != nil || head.Generation != 1 || head.ActiveRevisionID != first.ID || head.RuntimeSource != "database" {
			t.Fatal("incorrect persisted head")
		}
		events, err := reader.History(ctx, 0, 10)
		if err != nil || len(events) != 1 || events[0].TargetRevisionID != first.ID || events[0].TransitionDeadline.Sub(events[0].ActivatedAt) != 30*time.Minute {
			t.Fatal("incorrect history")
		}
		before := f.counts(t)
		if err := activationFixture(t, f, second, 2, first.ID, true); !errors.Is(err, ErrAudit) {
			t.Fatal("expected aborted fixture")
		}
		head, err = reader.Head(ctx)
		if err != nil || head.Generation != 1 || f.counts(t) != before {
			t.Fatal("failed transaction left partial state")
		}
		events, err = reader.History(ctx, 0, 10)
		if err != nil || len(events) != 1 {
			t.Fatal("rolled back history persisted")
		}
	})
	t.Run("immutable history and monotonic head", func(t *testing.T) {
		for _, sql := range []string{
			`UPDATE framework.auth_activation_history SET reason='rewritten'`,
			`DELETE FROM framework.auth_activation_history`, `TRUNCATE framework.auth_activation_history CASCADE`,
			`DELETE FROM framework.auth_activation_heads`, `TRUNCATE framework.auth_activation_heads`,
			`UPDATE framework.auth_activation_heads SET generation=0,runtime_source='environment',active_revision_id=NULL,activated_at=NULL`,
			`UPDATE framework.auth_activation_heads SET generation=generation`,
			`UPDATE framework.auth_activation_heads SET generation=3`,
			`UPDATE framework.auth_config_lifecycle SET status='superseded',generation=generation+1 WHERE status='active'`,
		} {
			if _, err := f.owner.Exec(ctx, sql); err == nil {
				t.Fatalf("invalid mutation accepted: %s", sql)
			}
		}
	})
	t.Run("history integrity", func(t *testing.T) {
		for _, edit := range []string{
			"generation=1", "generation=3", "deployment_id='other'", "environment='production'",
			"transition_deadline=activated_at+interval '31 minutes'", "transition_deadline=activated_at-interval '1 second'", "activated_at='infinity',transition_deadline='infinity'",
			"reason=''", "actor_user_id='99999999-9999-4999-8999-999999999999'", "recovery_revision_id='99999999-9999-4999-8999-999999999999'",
		} {
			tx, err := f.owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			// A copied row permits testing each independent constraint at insert.
			_, err = tx.Exec(ctx, `CREATE TEMP TABLE candidate ON COMMIT DROP AS SELECT deployment_id,environment,generation,previous_revision_id,target_revision_id,recovery_revision_id,activated_at,transition_deadline,actor_user_id,reason FROM framework.auth_activation_history`)
			if err == nil {
				_, err = tx.Exec(ctx, `UPDATE candidate SET generation=2,previous_revision_id=$1,target_revision_id=$2`, first.ID, second.ID)
			}
			if err == nil {
				_, err = tx.Exec(ctx, `UPDATE candidate SET `+edit)
			}
			if err == nil {
				_, err = tx.Exec(ctx, `INSERT INTO framework.auth_activation_history(deployment_id,environment,generation,previous_revision_id,target_revision_id,recovery_revision_id,activated_at,transition_deadline,actor_user_id,reason) SELECT * FROM candidate`)
			}
			_ = tx.Rollback(ctx)
			if err == nil {
				t.Fatalf("invalid history accepted: %s", edit)
			}
		}
	})
	if err := activationFixture(t, f, second, 2, first.ID, false); err != nil {
		t.Fatal(err)
	}
	if err := reader.CheckGeneration(ctx, 1); !errors.Is(err, ErrConflict) {
		t.Fatal("stale activation accepted")
	}
	if err := reader.CheckGeneration(ctx, 2); err != nil {
		t.Fatal(err)
	}
	events, err := reader.History(ctx, 2, 1)
	if err != nil || len(events) != 1 || events[0].Generation != 1 {
		t.Fatal("history pagination failed")
	}
	t.Run("reader failure is sanitized", func(t *testing.T) {
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := reader.Head(canceled); !errors.Is(err, ErrCanceled) {
			t.Fatal("cancellation hidden")
		}
		if _, err := reader.History(ctx, 0, 0); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid limit accepted")
		}
		closed := *reader
		pool, err := pgxpool.New(ctx, "postgres://unused.invalid/unused?sslmode=disable")
		if err != nil {
			t.Fatal("test pool construction failed")
		}
		pool.Close()
		closed.pool = pool
		if _, err := closed.Head(ctx); !errors.Is(err, ErrUnavailable) {
			t.Fatal("database internals exposed")
		}
	})
}

// Verify deferred consistency permits head-first insertion, but rejects an
// orphan head at commit. No actual runtime or activation endpoint is involved.
func TestActivationDeferredConsistency(t *testing.T) {
	f := newFixture(t)
	m := approvedRevision(t, f, 0)
	ctx := context.Background()
	tx, err := f.owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO framework.auth_activation_heads(deployment_id,environment,generation,runtime_source,active_revision_id,activated_at) VALUES($1,$2,1,'database',$3,clock_timestamp())`, m.DeploymentID, m.Environment, m.ID)
	if err != nil {
		t.Fatal("head insertion prematurely checked", err)
	}
	if err = tx.Commit(ctx); err == nil {
		t.Fatal("orphan head committed")
	}
	var n int
	_ = f.owner.QueryRow(ctx, `SELECT count(*) FROM framework.auth_activation_heads`).Scan(&n)
	if n != 0 {
		t.Fatal("failed commit wrote head")
	}
}

func TestActivationHeadFirstAtomicCommit(t *testing.T) {
	f := newFixture(t)
	m := approvedRevision(t, f, 0)
	ctx := context.Background()
	tx, err := f.owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	var when time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&when); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO framework.auth_activation_heads(deployment_id,environment,generation,runtime_source,active_revision_id,activated_at)
       VALUES($1,$2,1,'database',$3,$4)`, m.DeploymentID, m.Environment, m.ID, when); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE framework.auth_config_lifecycle SET status='active',generation=generation+1 WHERE revision_id=$1`, m.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO framework.auth_activation_history(deployment_id,environment,generation,target_revision_id,actor_user_id,activated_at,transition_deadline,reason)
       VALUES($1,$2,1,$3,$4,$5,$5,'synthetic zero-grace transition')`, m.DeploymentID, m.Environment, m.ID, m.CreatedBy, when); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal("valid atomic head-first transaction rejected", err)
	}
}
