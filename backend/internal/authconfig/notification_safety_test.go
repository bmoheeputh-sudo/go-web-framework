package authconfig

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/notifications"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func notificationCounts(t *testing.T, f *fixture) string {
	t.Helper()
	var result string
	if err := f.owner.QueryRow(context.Background(), `SELECT jsonb_build_array((SELECT count(*) FROM framework.notification_requests),(SELECT count(*) FROM framework.notification_jobs),(SELECT count(*) FROM framework.notification_attempts),(SELECT count(*) FROM framework.audit_log))::text`).Scan(&result); err != nil {
		t.Fatal(err)
	}
	return result
}
func TestNotificationAuditRollbackAndValidation(t *testing.T) {
	f, r, e := notificationFixture(t)
	f.run(t, func(ctx context.Context) {
		input := notificationInput(t, ctx, r, e, 1)
		before := notificationCounts(t, f)
		for _, change := range []func(*NotificationInput){func(i *NotificationInput) { i.Confirm = false }, func(i *NotificationInput) { i.Reason = "short" }, func(i *NotificationInput) { i.Locale = "unknown" }, func(i *NotificationInput) { i.TemplateVersion = "arbitrary-html" }, func(i *NotificationInput) { i.Expected.Generation++ }, func(i *NotificationInput) { i.ConnectorGeneration++ }, func(i *NotificationInput) { i.Targets = append(i.Targets, i.Targets[0]) }} {
			changed := input
			change(&changed)
			if _, err := r.Enqueue(ctx, changed); err == nil {
				t.Fatal("invalid request accepted")
			}
			if notificationCounts(t, f) != before {
				t.Fatal("invalid request wrote data")
			}
		}
		if _, err := f.owner.Exec(ctx, `CREATE FUNCTION framework.reject_notification_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='notification.enqueued' THEN RAISE EXCEPTION 'synthetic'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_notification_audit BEFORE INSERT ON framework.audit_log FOR EACH ROW EXECUTE FUNCTION framework.reject_notification_audit()`); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Enqueue(ctx, input); !errors.Is(err, ErrAudit) {
			t.Fatal("audit failure", err)
		}
		if notificationCounts(t, f) != before {
			t.Fatal("request/jobs escaped audit rollback")
		}
		if _, err := f.owner.Exec(ctx, `DROP TRIGGER reject_notification_audit ON framework.audit_log`); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Enqueue(ctx, input); err != nil {
			t.Fatal(err)
		}
		j := jobFor(t, ctx, r, input.ID)
		for _, sql := range []string{
			`UPDATE framework.notification_jobs SET connector_id='10000000-0000-4000-8000-000000000002',generation=generation+1 WHERE id=$1`,
			`UPDATE framework.notification_jobs SET status='sent',generation=generation+1 WHERE id=$1`,
			`DELETE FROM framework.notification_jobs WHERE id=$1`,
		} {
			if _, err := f.owner.Exec(ctx, sql, j.ID); err == nil {
				t.Fatal("job history/binding constraint absent")
			}
		}
		if _, err := f.owner.Exec(ctx, `TRUNCATE framework.notification_attempts`); err == nil {
			t.Fatal("attempt retention absent")
		}
		bad := NotificationConnectorInput{ID: "99999999-9999-4999-8999-999999999999", Provider: "ses", Sender: "onboarding@vopak.com", SenderApproved: true, Region: "eu-west-1", CredentialReference: "notifications/aws-static-key", PerMinute: 30, PerDay: 1500, Reason: "static keys are not supported"}
		if _, err := r.CreateConnector(ctx, bad); !errors.Is(err, ErrInvalid) {
			t.Fatal("stored SES credentials accepted", err)
		}
	})
}

func TestNotificationRecipientEligibility(t *testing.T) {
	f, r, e := notificationFixture(t)
	f.run(t, func(ctx context.Context) {
		for n, tc := range []struct {
			subject        string
			active         bool
			approval, want string
		}{{"inactive", false, "", "inactive_user"}, {"revoked", true, "revoked", "revoked_identity"}, {"unobserved", true, "approved", ""}, {"unknown-approval", true, "", "review_required"}} {
			id := policyUser(t, f, tc.subject, fmt.Sprintf("recipient%d@vopak.com", n), "Viewer", tc.active)
			if tc.approval != "" {
				if _, err := r.policy.SetApproval(ctx, e.PolicyExpectation, OIDCIdentityKey{f.identity.Issuer, tc.subject}, 0, "approved", "review exact notification identity"); err != nil {
					t.Fatal(err)
				}
				if tc.approval == "revoked" {
					if _, err := r.policy.SetApproval(ctx, e.PolicyExpectation, OIDCIdentityKey{f.identity.Issuer, tc.subject}, 1, "revoked", "explicit identity access revocation"); err != nil {
						t.Fatal(err)
					}
				}
			}
			if code, err := r.Eligibility(ctx, NotificationTarget{UserID: id.ID}, "reminder"); err != nil || code != tc.want {
				t.Fatal("eligibility", tc.subject, code, err)
			}
		}
		input := notificationInput(t, ctx, r, e, 50)
		req, err := r.Enqueue(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = r.policy.RevokeInvitation(ctx, e, input.Targets[0].InvitationID, 1, "employee invitation revoked before send"); err != nil {
			t.Fatal(err)
		}
		leases, err := r.Worker().Acquire(ctx, workerOne, 1, time.Minute)
		if err != nil || len(leases) != 1 {
			t.Fatal(err)
		}
		if _, err = r.Worker().Begin(ctx, leases[0]); !errors.Is(err, ErrConflict) {
			t.Fatal("revoked invitation dispatch", err)
		}
		j := jobFor(t, ctx, r, req.ID)
		if j.Disposition != "invitation_unavailable" {
			t.Fatal(j)
		}
		// Communication policy is independent of admission, including Allow All.
		if _, err = r.policy.Update(ctx, e.PolicyExpectation, AccessPolicySettings{"allow_all", []string{"vopak.com"}, "Viewer"}, "allow independent OIDC admission"); err != nil {
			t.Fatal(err)
		}
		id := policyUser(t, f, "suppressed-eligible", "suppressed@vopak.com", "Viewer", true)
		if _, err = r.SetSuppression(ctx, SuppressionTarget{NotificationTarget: NotificationTarget{UserID: id.ID}}, 0, true, "suppress communications not login"); err != nil {
			t.Fatal(err)
		}
		identity := auth.Identity{Issuer: f.identity.Issuer, Subject: "suppressed-eligible", Provider: auth.OIDC, Email: "suppressed@vopak.com", EmailVerified: true}
		if err = f.store.OIDCAdmission(f.repo.scope.DeploymentID, f.repo.scope.Environment).Login(ctx, identity, auth.Binding{}, normalSessionWrite(identity)); err != nil {
			t.Fatal("suppression restricted login", err)
		}
		if code, err := r.Eligibility(ctx, NotificationTarget{UserID: id.ID}, "reminder"); err != nil || code != "onboarded" {
			t.Fatal("successful user not recognized", code, err)
		}
	})
}

func TestNotificationStaleConfigurationAndCooldown(t *testing.T) {
	f, r, e := notificationFixture(t)
	f.run(t, func(ctx context.Context) {
		input := notificationInput(t, ctx, r, e, 1)
		if _, err := r.Enqueue(ctx, input); err != nil {
			t.Fatal(err)
		}
		other, err := NewNotificationRepository(r.policy, CommunicationPolicy{Origin: "https://different.example.test", AllowedDomains: []string{"vopak.com"}})
		if err != nil {
			t.Fatal(err)
		}
		leases, err := other.Worker().Acquire(ctx, workerOne, 1, time.Minute)
		if err != nil || len(leases) != 1 {
			t.Fatal(err)
		}
		if _, err = other.Worker().Begin(ctx, leases[0]); !errors.Is(err, ErrConflict) {
			t.Fatal("different login URL policy dispatched", err)
		}
		j := jobFor(t, ctx, r, input.ID)
		if j.Disposition != "stale_configuration" {
			t.Fatal(j)
		}
		input = notificationInput(t, ctx, r, e, 2)
		if _, err = r.Enqueue(ctx, input); err != nil {
			t.Fatal(err)
		}
		fake := notifications.NewFake("gmail", notifications.Result{Outcome: notifications.Accepted, ProviderMessageID: "fake-accepted"})
		if err = notifications.RunOnce(ctx, r.Worker(), workerOne, map[string]notifications.Adapter{gmailConnector: fake}, 20, time.Minute); err != nil || fake.Calls() != 1 {
			t.Fatal("fake worker", err, fake.Calls())
		}
		input.ID = "77777777-1111-4111-8111-111111111111"
		input.IdempotencyKey = "77777777-2222-4222-8222-222222222222"
		if _, err = r.Enqueue(ctx, input); !errors.Is(err, ErrConflict) {
			t.Fatal("cooldown bypass", err)
		}
	})
}

func TestNotificationCommitUncertaintyInspection(t *testing.T) {
	f, r, e := notificationFixture(t)
	trace := &invitationCommitLoss{}
	config := f.pool.Config()
	config.ConnConfig.Tracer = trace
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	p, _ := NewAccessPolicyRepository(access.New(pool), f.repo.scope)
	uncertain, _ := NewNotificationRepository(p, r.communication)
	f.run(t, func(ctx context.Context) {
		input := notificationInput(t, ctx, r, e, 1)
		trace.armed.Store(true)
		if req, err := uncertain.Enqueue(ctx, input); !errors.Is(err, ErrCommitUncertain) || req.ID != "" || trace.commits.Load() != 1 {
			t.Fatal("uncertain enqueue retried", err)
		}
		if req, err := r.ReadRequest(ctx, input.ID); err != nil || req.JobCount != 1 {
			t.Fatal("cannot inspect committed request", err)
		}
		leases, err := uncertain.Worker().Acquire(ctx, workerOne, 1, time.Minute)
		if err != nil || len(leases) != 1 {
			t.Fatal(err)
		}
		trace.armed.Store(true)
		if d, err := uncertain.Worker().Begin(ctx, leases[0]); !errors.Is(err, ErrCommitUncertain) || d.Lease.ID != "" {
			t.Fatal("uncertain dispatch marker returned send capability", err)
		}
		expireNotificationLeases(t, f)
		if n, err := r.Worker().ResolveExpired(ctx, 20); err != nil || n != 1 {
			t.Fatal(err)
		}
		j := jobFor(t, ctx, r, input.ID)
		if j.Status != "needs_inspection" {
			t.Fatal("uncertain dispatch automatically retried", j)
		}
	})
}

type observingAdapter struct {
	provider string
	send     func(notifications.Message) notifications.Result
}

func (a observingAdapter) Provider() string { return a.provider }
func (a observingAdapter) Send(_ context.Context, m notifications.Message) notifications.Result {
	return a.send(m)
}
func TestNotificationProviderCallOutsideTransaction(t *testing.T) {
	f, r, e := notificationFixture(t)
	f.run(t, func(ctx context.Context) {
		input := notificationInput(t, ctx, r, e, 1)
		if _, err := r.Enqueue(ctx, input); err != nil {
			t.Fatal(err)
		}
		adapter := observingAdapter{"gmail", func(m notifications.Message) notifications.Result {
			tx, err := f.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			var unlocked bool
			if err = tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(78541705)`).Scan(&unlocked); err != nil || !unlocked {
				t.Fatal("provider called while security transaction open", err)
			}
			return notifications.Result{Outcome: notifications.Accepted, ProviderMessageID: "fake-network-free"}
		}}
		if err := notifications.RunOnce(ctx, r.Worker(), workerOne, map[string]notifications.Adapter{gmailConnector: adapter}, 1, time.Minute); err != nil {
			t.Fatal(err)
		}
	})
}

func TestNotificationConcurrentIdempotencyAndAdministratorRecheck(t *testing.T) {
	f, r, e := notificationFixture(t)
	f.run(t, func(ctx context.Context) {
		input := notificationInput(t, ctx, r, e, 1)
		var wg sync.WaitGroup
		for range 6 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if req, err := r.Enqueue(ctx, input); err != nil || req.ID != input.ID {
					t.Error("concurrent identical enqueue", err)
				}
			}()
		}
		wg.Wait()
		var requests, jobs int
		if err := f.owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM framework.notification_requests),(SELECT count(*) FROM framework.notification_jobs)`).Scan(&requests, &jobs); err != nil || requests != 1 || jobs != 1 {
			t.Fatal("idempotency duplicated rows", err)
		}
		var actor string
		if err := f.owner.QueryRow(ctx, `SELECT id::text FROM framework.users WHERE subject=$1`, f.identity.Subject).Scan(&actor); err != nil {
			t.Fatal(err)
		}
		if _, err := f.owner.Exec(ctx, `DELETE FROM framework.user_roles WHERE user_id=$1 AND role='Admin'`, actor); err != nil {
			t.Fatal(err)
		}
		if _, err := r.ReadRequest(ctx, input.ID); !errors.Is(err, ErrDenied) {
			t.Fatal("lost administrator permission not rechecked", err)
		}
		if _, err := f.owner.Exec(ctx, `INSERT INTO framework.user_roles(user_id,role) VALUES($1,'Admin')`, actor); err != nil {
			t.Fatal(err)
		}
	})
}

func TestNotificationWorkerUsesRestrictedProductionRole(t *testing.T) {
	f, r, e := notificationFixture(t)
	f.run(t, func(ctx context.Context) {
		if _, err := r.Enqueue(ctx, notificationInput(t, ctx, r, e, 1)); err != nil {
			t.Fatal(err)
		}
	})
	script, err := os.ReadFile("../../../database/scripts/production-roles.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.owner.Exec(context.Background(), string(script)); err != nil {
		t.Fatal(err)
	}
	config := f.pool.Config()
	config.ConnConfig.User = "go_web_notification_worker"
	config.ConnConfig.Tracer = notificationTestTrace{t}
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	policy, _ := NewAccessPolicyRepository(access.New(pool), f.repo.scope)
	workerRepo, err := NewNotificationRepository(policy, r.communication)
	if err != nil {
		t.Fatal(err)
	}
	fake := notifications.NewFake("gmail", notifications.Result{Outcome: notifications.Accepted, ProviderMessageID: "fake-role-test"})
	if err = notifications.RunOnce(context.Background(), workerRepo.Worker(), workerOne, map[string]notifications.Adapter{gmailConnector: fake}, 1, time.Minute); err != nil || fake.Calls() != 1 {
		t.Fatal("restricted worker cannot execute queue", err)
	}
	for _, query := range []string{
		`UPDATE framework.users SET active=false WHERE false`,
		`DELETE FROM framework.user_roles WHERE false`,
		`UPDATE framework.oidc_identity_approvals SET status='revoked' WHERE false`,
		`UPDATE framework.notification_connectors SET enabled=false WHERE false`,
		`SELECT secret_ciphertext FROM framework.auth_config_revisions LIMIT 0`,
	} {
		if _, err = pool.Exec(context.Background(), query); err == nil {
			t.Fatal("worker exceeded queue capability")
		}
	}
}

type notificationTestTrace struct{ t *testing.T }

func (n notificationTestTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	return ctx
}
func (n notificationTestTrace) TraceQueryEnd(_ context.Context, _ *pgx.Conn, d pgx.TraceQueryEndData) {
	if d.Err != nil {
		n.t.Logf("disposable worker database: %v", d.Err)
	}
}

func TestNotificationOutcomeAuditFailureRequiresInspection(t *testing.T) {
	f, r, e := notificationFixture(t)
	f.run(t, func(ctx context.Context) {
		if _, err := r.Enqueue(ctx, notificationInput(t, ctx, r, e, 1)); err != nil {
			t.Fatal(err)
		}
	})
	w := r.Worker()
	leases, err := w.Acquire(context.Background(), workerOne, 1, time.Minute)
	if err != nil || len(leases) != 1 {
		t.Fatal(err)
	}
	d, err := w.Begin(context.Background(), leases[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.owner.Exec(context.Background(), `CREATE FUNCTION framework.reject_notification_result() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='notification.delivery_recorded' THEN RAISE EXCEPTION 'synthetic'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_notification_result BEFORE INSERT ON framework.audit_log FOR EACH ROW EXECUTE FUNCTION framework.reject_notification_result()`); err != nil {
		t.Fatal(err)
	}
	if err = w.Complete(context.Background(), d.Lease, notifications.Result{Outcome: notifications.Accepted, ProviderMessageID: "accepted-but-recording-failed"}); !errors.Is(err, ErrAudit) {
		t.Fatal("audit result failure", err)
	}
	expireNotificationLeases(t, f)
	if _, err = w.ResolveExpired(context.Background(), 20); err != nil {
		t.Fatal(err)
	}
	f.run(t, func(ctx context.Context) {
		j, err := r.ReadJob(ctx, d.Lease.ID)
		if err != nil || j.Status != "needs_inspection" {
			t.Fatal("post-send failure retried", err, j.Status)
		}
		a, err := r.ReadAttempts(ctx, j.ID)
		if err != nil || len(a) != 1 || a[0].Outcome != "uncertain" || a[0].ProviderMessageID != "" {
			t.Fatal("unsafe result history", err)
		}
	})
}

func TestNotificationBatchBoundAndIndependentQuota(t *testing.T) {
	f, r, e := notificationFixture(t)
	f.run(t, func(ctx context.Context) {
		input := notificationInput(t, ctx, r, e, 1)
		for n := 2; n <= NotificationMaxJobs; n++ {
			i, err := r.policy.CreateInvitation(ctx, e, invitationInput(fmt.Sprintf("bounded%d@vopak.com", n)))
			if err != nil {
				t.Fatal(err)
			}
			input.Targets = append(input.Targets, NotificationTarget{InvitationID: i.ID})
		}
		start := time.Now()
		req, err := r.Enqueue(ctx, input)
		elapsed := time.Since(start)
		if err != nil || req.JobCount != NotificationMaxJobs {
			t.Fatal("bounded batch enqueue", err)
		}
		t.Logf("100-job enqueue including eligibility and audit: %s", elapsed)
		if elapsed >= 4*time.Second {
			t.Fatal("bounded batch lacks transaction deadline margin")
		}
		oversized := input
		oversized.Targets = append(oversized.Targets, oversized.Targets[0])
		if _, err = r.Enqueue(ctx, oversized); !errors.Is(err, ErrInvalid) {
			t.Fatal("unbounded batch", err)
		}
		if err = r.ConfigureConnector(ctx, gmailConnector, 1, true, true, 1, 1, "one-message connector test quota"); err != nil {
			t.Fatal(err)
		}
		leases, err := r.Worker().Acquire(ctx, workerOne, 2, time.Minute)
		if err != nil || len(leases) != 2 {
			t.Fatal(err)
		}
		d, err := r.Worker().Begin(ctx, leases[0])
		if err != nil {
			t.Fatal(err)
		}
		if err = r.Worker().Complete(ctx, d.Lease, notifications.Result{Outcome: notifications.Accepted}); err != nil {
			t.Fatal(err)
		}
		if _, err = r.Worker().Begin(ctx, leases[1]); !errors.Is(err, ErrConflict) {
			t.Fatal("connector quota not reserved atomically", err)
		}
	})
}

func TestNotificationAllowAllInvitationAndStalePolicy(t *testing.T) {
	f, r, e := notificationFixture(t)
	f.run(t, func(ctx context.Context) {
		if _, err := r.policy.Update(ctx, e.PolicyExpectation, AccessPolicySettings{"allow_all", []string{"vopak.com"}, "Viewer"}, "allow all optional communications"); err != nil {
			t.Fatal(err)
		}
		e.Generation++
		input := notificationInput(t, ctx, r, e, 1)
		req, err := r.Enqueue(ctx, input)
		if err != nil {
			t.Fatal("Allow All invitation enqueue", err)
		}
		if _, err = r.policy.Update(ctx, e.PolicyExpectation, AccessPolicySettings{"approved_users_only", []string{"vopak.com"}, "Viewer"}, "change policy after enqueue"); err != nil {
			t.Fatal(err)
		}
		leases, err := r.Worker().Acquire(ctx, workerOne, 1, time.Minute)
		if err != nil || len(leases) != 1 {
			t.Fatal(err)
		}
		if _, err = r.Worker().Begin(ctx, leases[0]); !errors.Is(err, ErrConflict) {
			t.Fatal("stale policy dispatched", err)
		}
		j := jobFor(t, ctx, r, req.ID)
		if j.Status != "cancelled" || j.Disposition != "stale_configuration" {
			t.Fatal(j)
		}
	})
}
