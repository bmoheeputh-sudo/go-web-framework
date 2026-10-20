package authconfig

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func testOfflineOperator(t *testing.T, id string) *OfflineOperator {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(key)
	clear(key)
	operator, err := OfflineOperatorFromEnv(func(name string) string {
		return map[string]string{
			"AUTH_RECOVERY_ENABLED": "true", "AUTH_RECOVERY_OPERATOR_ID": id,
			"AUTH_RECOVERY_AUTHORIZATION_KEY_ID": "offline-v1", "AUTH_RECOVERY_AUTHORIZATION_KEY": encoded,
		}[name]
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(operator.Close)
	return operator
}

type recoveryFixture struct {
	f                     *fixture
	activation            *ActivationService
	provider              *mockConnectionIssuer
	first, second, target Metadata
	service               *RecoveryService
	operator              *OfflineOperator
}

func newRecoveryFixture(t *testing.T) *recoveryFixture {
	t.Helper()
	f, activation, provider, first := activationServiceFixture(t)
	request, user := activationReadiness(t, f, first, "")
	prepared := prepareActivation(t, f, activation, first, 0)
	f.run(t, func(ctx context.Context) {
		if _, err := activation.Activate(ctx, prepared, request); err != nil {
			t.Fatal(err)
		}
	})
	second := nextStartupRevision(t, f, first)
	request, _ = activationReadiness(t, f, second, user)
	prepared = prepareActivation(t, f, activation, second, 1)
	f.run(t, func(ctx context.Context) {
		if _, err := activation.Activate(ctx, prepared, request); err != nil {
			t.Fatal(err)
		}
	})
	var target Metadata
	f.run(t, func(ctx context.Context) {
		var err error
		target, err = f.repo.PrepareRecoveryDraft(ctx, first.ID, second.Version)
		if err != nil {
			t.Fatal(err)
		}
		for _, status := range []Status{Validated, Approved} {
			target, err = f.repo.Transition(ctx, target.ID, target.Generation, status)
			if err != nil {
				t.Fatal(err)
			}
		}
	})
	service, err := NewRecoveryService(f.repo, activation.store, activation.sessions, activation.callback, false)
	if err != nil {
		t.Fatal(err)
	}
	service.client = func(context.Context, string) (*http.Client, error) { return provider.client(), nil }
	return &recoveryFixture{f: f, activation: activation, provider: provider, first: first, second: second, target: target, service: service, operator: testOfflineOperator(t, "security-operator@example.test")}
}

func (r *recoveryFixture) prepare(t *testing.T) *PreparedRecovery {
	t.Helper()
	p, err := r.service.Prepare(context.Background(), r.operator, r.target.ID, 2, "Emergency recovery for incident INC-925G")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

func recoverySnapshot(t *testing.T, f *fixture) string {
	t.Helper()
	var value string
	err := f.owner.QueryRow(context.Background(), `SELECT jsonb_build_array(
 (SELECT jsonb_agg(to_jsonb(h) ORDER BY generation) FROM framework.auth_activation_heads h),
 (SELECT jsonb_agg(to_jsonb(h) ORDER BY generation) FROM framework.auth_activation_history h),
 (SELECT jsonb_agg(to_jsonb(l) ORDER BY revision_id) FROM framework.auth_config_lifecycle l),
 (SELECT jsonb_agg(to_jsonb(a) ORDER BY generation) FROM framework.auth_recovery_audit a))::text`).Scan(&value)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestOfflineRecoveryCommitsAttributedHistoryAndRehydrates(t *testing.T) {
	r := newRecoveryFixture(t)
	p := r.prepare(t)
	preview := p.Preview()
	if !preview.RequiresReauthentication || preview.ExpectedGeneration != 2 || preview.TargetGeneration != 3 || preview.SourceRevisionID != r.first.ID || preview.CurrentRevisionID != r.second.ID {
		t.Fatal("unsafe recovery preview", preview)
	}
	listener, err := pgx.ConnectConfig(context.Background(), r.f.pool.Config().ConnConfig.Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer closeListener(listener)
	if _, err = listener.Exec(context.Background(), `LISTEN framework_auth_activation`); err != nil {
		t.Fatal(err)
	}
	var permissions, roles int
	if err = r.f.owner.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM framework.role_permissions),(SELECT count(*) FROM framework.user_roles)`).Scan(&permissions, &roles); err != nil {
		t.Fatal(err)
	}
	// An already expired session remains data, but recovery cannot revive it.
	_, err = r.f.owner.Exec(context.Background(), `INSERT INTO framework.sessions(token_hash,issuer,subject,provider,created_at,expires_at,last_activity_at,binding_source,deployment_id,environment,revision_id,activation_generation,client_id,flow_purpose)
	 VALUES(decode(repeat('42',32),'hex'),$1,'expired-before-recovery','oidc',clock_timestamp()-interval '2 minutes',clock_timestamp()-interval '1 minute',clock_timestamp()-interval '2 minutes','database',$2,$3,$4,2,$5,'login')`, r.second.IssuerURL, r.second.DeploymentID, r.second.Environment, r.second.ID, r.second.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	result, err := r.service.Recover(context.Background(), r.operator, p)
	if err != nil || !result.Committed || result.CommitUncertain || result.Generation != 3 || result.RevisionID != r.target.ID {
		t.Fatal("recovery failed", result, err)
	}
	if _, err := r.service.Recover(context.Background(), r.operator, p); !errors.Is(err, ErrDenied) {
		t.Fatal("one-shot recovery preparation replayed", err)
	}
	if _, err := r.service.Prepare(context.Background(), r.operator, r.target.ID, 2, "Emergency recovery for incident INC-925G"); !errors.Is(err, ErrConflict) {
		t.Fatal("stale activation generation prepared", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	notice, err := listener.WaitForNotification(ctx)
	if err != nil || notice.Channel != activationChannel {
		t.Fatal("committed recovery notification missing", err)
	}
	var generation int64
	var format int
	var active, operatorID, keyID, actor, auditID string
	var activated, deadline time.Time
	var fingerprint, nonce, tag []byte
	err = r.f.owner.QueryRow(context.Background(), `SELECT h.generation,h.active_revision_id::text,a.operator_id,a.authorization_key_id,a.authorization_format,
 COALESCE(e.actor_user_id::text,''),e.recovery_audit_id::text,e.activated_at,e.transition_deadline,
 a.authorization_key_fingerprint,a.authorization_nonce,a.authorization_tag
 FROM framework.auth_activation_heads h
 JOIN framework.auth_activation_history e ON e.deployment_id=h.deployment_id AND e.environment=h.environment AND e.generation=h.generation
 JOIN framework.auth_recovery_audit a ON a.id=e.recovery_audit_id
	 WHERE h.deployment_id=$1 AND h.environment=$2`, r.target.DeploymentID, r.target.Environment).Scan(&generation, &active, &operatorID, &keyID, &format, &actor, &auditID, &activated, &deadline, &fingerprint, &nonce, &tag)
	if err != nil || generation != 3 || active != r.target.ID || operatorID != r.operator.id || keyID != r.operator.keyID || format != 1 || actor != "" || !validID(auditID) || !deadline.Equal(activated) || len(fingerprint) != 32 || len(nonce) != 32 || len(tag) != 32 {
		t.Fatal("recovery attribution invalid", err)
	}
	var newPermissions, newRoles, sessions int
	if err = r.f.owner.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM framework.role_permissions),(SELECT count(*) FROM framework.user_roles),(SELECT count(*) FROM framework.sessions WHERE subject='expired-before-recovery' AND expires_at<clock_timestamp())`).Scan(&newPermissions, &newRoles, &sessions); err != nil || permissions != newPermissions || roles != newRoles || sessions != 1 {
		t.Fatal("recovery changed permissions or resurrected session", err)
	}
	reader, _ := NewActivationReader(r.f.pool, r.f.repo.scope)
	loader, _ := NewStartupLoader(reader, r.f.repo.cipher, r.activation.sessions, r.activation.callback, false)
	loader.client = func(context.Context, string) (*http.Client, error) { return r.provider.client(), nil }
	runtime, err := loader.Load(context.Background())
	if err != nil {
		t.Fatal("recovery runtime did not rehydrate", err)
	}
	defer runtime.Close()
	status, desired, mismatch := runtime.ControlStatus()
	if mismatch || desired != 3 || status.ActiveRevisionID != r.target.ID || status.PreviousRevisionID != "" || status.TransitionState != "none" {
		t.Fatal("rehydration restored a retired provider", status)
	}
}

func TestOfflineRecoveryRejectsUnsafeInputsAndRollsBack(t *testing.T) {
	t.Run("operator mismatch", func(t *testing.T) {
		r := newRecoveryFixture(t)
		p := r.prepare(t)
		before := recoverySnapshot(t, r.f)
		if _, err := r.service.Recover(context.Background(), testOfflineOperator(t, "different@example.test"), p); !errors.Is(err, ErrDenied) {
			t.Fatal(err)
		}
		if recoverySnapshot(t, r.f) != before {
			t.Fatal("denial changed state")
		}
	})
	t.Run("unapproved and wrong scope", func(t *testing.T) {
		r := newRecoveryFixture(t)
		var draft Metadata
		r.f.run(t, func(ctx context.Context) { draft, _ = r.f.repo.PrepareRecoveryDraft(ctx, r.first.ID, r.target.Version) })
		if _, err := r.service.Prepare(context.Background(), r.operator, draft.ID, 2, "Emergency incident INC-1"); !errors.Is(err, ErrConflict) {
			t.Fatal("unapproved revision accepted", err)
		}
		other := *r.service
		repo := *r.f.repo
		repo.scope.DeploymentID = "other"
		other.repo = &repo
		if _, err := other.Prepare(context.Background(), r.operator, r.target.ID, 2, "Emergency incident INC-1"); err == nil {
			t.Fatal("cross-scope revision accepted")
		}
	})
	t.Run("missing decryption key", func(t *testing.T) {
		r := newRecoveryFixture(t)
		repo := *r.f.repo
		repo.cipher = testCipher(t, "missing-key")
		service, _ := NewRecoveryService(&repo, r.activation.store, r.activation.sessions, r.activation.callback, false)
		service.client = r.service.client
		if _, err := service.Prepare(context.Background(), r.operator, r.target.ID, 2, "Emergency incident INC-1"); !errors.Is(err, ErrSecret) {
			t.Fatal("missing key accepted", err)
		}
	})
	t.Run("audit failure", func(t *testing.T) {
		r := newRecoveryFixture(t)
		p := r.prepare(t)
		before := recoverySnapshot(t, r.f)
		listener, err := pgx.ConnectConfig(context.Background(), r.f.pool.Config().ConnConfig.Copy())
		if err != nil {
			t.Fatal(err)
		}
		defer closeListener(listener)
		if _, err = listener.Exec(context.Background(), `LISTEN framework_auth_activation`); err != nil {
			t.Fatal(err)
		}
		if _, err := r.f.owner.Exec(context.Background(), `CREATE FUNCTION framework.reject_recovery_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic'; END $$; CREATE TRIGGER reject_recovery_audit BEFORE INSERT ON framework.auth_recovery_audit FOR EACH ROW EXECUTE FUNCTION framework.reject_recovery_audit()`); err != nil {
			t.Fatal(err)
		}
		if _, err := r.service.Recover(context.Background(), r.operator, p); !errors.Is(err, ErrAudit) {
			t.Fatal("audit failure accepted", err)
		}
		if recoverySnapshot(t, r.f) != before {
			t.Fatal("audit failure partially recovered")
		}
		wait, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		if _, err := listener.WaitForNotification(wait); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("rolled-back recovery emitted notification", err)
		}
	})
	t.Run("database unavailable", func(t *testing.T) {
		r := newRecoveryFixture(t)
		p := r.prepare(t)
		r.f.pool.Close()
		if _, err := r.service.Recover(context.Background(), r.operator, p); !errors.Is(err, ErrUnavailable) {
			t.Fatal("database failure was not safe", err)
		}
	})
	t.Run("uncertain commit is fenced from retry", func(t *testing.T) {
		r := newRecoveryFixture(t)
		p := r.prepare(t)
		before := recoverySnapshot(t, r.f)
		_, err := r.f.owner.Exec(context.Background(), `CREATE FUNCTION framework.fail_recovery_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.recovery_audit_id IS NOT NULL THEN RAISE EXCEPTION 'synthetic deferred failure'; END IF; RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER fail_recovery_commit AFTER INSERT ON framework.auth_activation_history DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION framework.fail_recovery_commit()`)
		if err != nil {
			t.Fatal(err)
		}
		result, err := r.service.Recover(context.Background(), r.operator, p)
		if !errors.Is(err, ErrCommitUncertain) || !result.CommitUncertain || result.Committed {
			t.Fatal("uncertain commit was reported as safe", result, err)
		}
		if recoverySnapshot(t, r.f) != before {
			t.Fatal("failed deferred commit changed activation state")
		}
		if _, err := r.service.Recover(context.Background(), r.operator, p); !errors.Is(err, ErrDenied) {
			t.Fatal("uncertain preparation was retryable", err)
		}
	})
}

func TestOfflineRecoveryConflictsSerialize(t *testing.T) {
	r := newRecoveryFixture(t)
	one, two := r.prepare(t), r.prepare(t)
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, p := range []*PreparedRecovery{one, two} {
		wg.Add(1)
		go func(p *PreparedRecovery) {
			defer wg.Done()
			_, err := r.service.Recover(context.Background(), r.operator, p)
			results <- err
		}(p)
	}
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrConflict) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatal("conflicting recoveries were not serialized", success, conflict)
	}
}

func TestOfflineOperatorConfiguration(t *testing.T) {
	valid := testOfflineOperator(t, "operator@example.test")
	if len(valid.key) != 32 {
		t.Fatal("operator key missing")
	}
	reused := base64.StdEncoding.EncodeToString(valid.key)
	for _, formatted := range []string{fmt.Sprintf("%v", valid), fmt.Sprintf("%+v", *valid)} {
		if strings.Contains(formatted, reused) || formatted != "[OFFLINE RECOVERY OPERATOR]" {
			t.Fatal("operator capability formatting leaked key material")
		}
	}
	for _, encryption := range []map[string]string{{"AUTH_ENCRYPTION_KEY": reused}, {"AUTH_ENCRYPTION_KEYS_JSON": `{"current":"` + reused + `"}`}} {
		if _, err := OfflineOperatorFromEnv(func(name string) string {
			values := map[string]string{"AUTH_RECOVERY_ENABLED": "true", "AUTH_RECOVERY_OPERATOR_ID": "operator@example.test", "AUTH_RECOVERY_AUTHORIZATION_KEY_ID": "offline-v1", "AUTH_RECOVERY_AUTHORIZATION_KEY": reused}
			if value := encryption[name]; value != "" {
				return value
			}
			return values[name]
		}); !errors.Is(err, ErrDenied) {
			t.Fatal("encryption key reuse accepted")
		}
	}
	for _, override := range []map[string]string{
		{"AUTH_RECOVERY_ENABLED": "false"}, {"AUTH_RECOVERY_OPERATOR_ID": ""},
		{"AUTH_RECOVERY_AUTHORIZATION_KEY_ID": "bad id"}, {"AUTH_RECOVERY_AUTHORIZATION_KEY": "invalid"},
	} {
		if _, err := OfflineOperatorFromEnv(func(name string) string { return override[name] }); !errors.Is(err, ErrDenied) {
			t.Fatal("unsafe operator accepted")
		}
	}
}
