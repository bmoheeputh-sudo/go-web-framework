package authconfig

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/notifications"
)

const gmailConnector = "10000000-0000-4000-8000-000000000001"
const sesConnector = "10000000-0000-4000-8000-000000000002"
const workerOne = "10000000-0000-4000-8000-000000000003"
const workerTwo = "10000000-0000-4000-8000-000000000004"

func notificationFixture(t *testing.T) (*fixture, *NotificationRepository, InvitationExpectation) {
	t.Helper()
	f, p, e := invitationFixture(t)
	r, err := NewNotificationRepository(p, CommunicationPolicy{Origin: "https://vgca.example.test", AllowedDomains: []string{"vopak.com"}})
	if err != nil {
		t.Fatal(err)
	}
	f.run(t, func(ctx context.Context) {
		for _, c := range []NotificationConnectorInput{
			{ID: gmailConnector, Provider: "gmail", Sender: "onboarding@vopak.com", SenderApproved: true, CredentialReference: "notifications/gmail/onboarding", Enabled: true, Default: true, PerMinute: 30, PerDay: 1500, Reason: "approved dedicated Gmail connector"},
			{ID: sesConnector, Provider: "ses", Sender: "onboarding@vopak.com", SenderApproved: true, Region: "eu-west-1", Enabled: true, PerMinute: 30, PerDay: 1500, Reason: "approved SES role based connector"},
		} {
			if _, err := r.CreateConnector(ctx, c); err != nil {
				t.Fatal("create connector", err)
			}
		}
	})
	return f, r, e
}
func notificationInput(t *testing.T, ctx context.Context, r *NotificationRepository, e InvitationExpectation, n int) NotificationInput {
	t.Helper()
	i, err := r.policy.CreateInvitation(ctx, e, invitationInput(fmt.Sprintf("employee%d@vopak.com", n)))
	if err != nil {
		t.Fatal(err)
	}
	return NotificationInput{ID: fmt.Sprintf("%08x-1111-4111-8111-111111111111", n), IdempotencyKey: fmt.Sprintf("%08x-2222-4222-8222-222222222222", n), Type: "invitation", TemplateVersion: notifications.TemplateVersion, Locale: "en", ConnectorGeneration: 1, Expected: e, Targets: []NotificationTarget{{InvitationID: i.ID}}, Reason: "explicit employee notification", Confirm: true}
}
func jobFor(t *testing.T, ctx context.Context, r *NotificationRepository, request string) NotificationJob {
	t.Helper()
	jobs, err := r.ListJobs(ctx, request, 0, 100)
	if err != nil || len(jobs) != 1 {
		t.Fatal("jobs unavailable", err, len(jobs))
	}
	return jobs[0]
}

func TestNotificationRequestsAndDualConnectors(t *testing.T) {
	f, r, e := notificationFixture(t)
	f.run(t, func(ctx context.Context) {
		before := invitationState(t, f)
		input := notificationInput(t, ctx, r, e, 1)
		n, err := r.Enqueue(ctx, input)
		if err != nil || n.ConnectorID != gmailConnector || n.JobCount != 1 {
			t.Fatal("enqueue", err, n)
		}
		again, err := r.Enqueue(ctx, input)
		if err != nil || again.ID != n.ID {
			t.Fatal("idempotency", err)
		}
		changed := input
		changed.Reason += " changed"
		if _, err = r.Enqueue(ctx, changed); !errors.Is(err, ErrConflict) {
			t.Fatal("reused key changed payload", err)
		}
		if err = r.ConfigureConnector(ctx, sesConnector, 1, true, true, 30, 1500, "switch approved default connector"); err != nil {
			t.Fatal(err)
		}
		j := jobFor(t, ctx, r, n.ID)
		if j.ConnectorID != gmailConnector || j.Sender != "onboarding@vopak.com" {
			t.Fatal("queued job rebound")
		}
		second := notificationInput(t, ctx, r, e, 2)
		second.ConnectorGeneration = 2
		n2, err := r.Enqueue(ctx, second)
		if err != nil || n2.ConnectorID != sesConnector {
			t.Fatal("SES default", err, n2)
		}
		third := notificationInput(t, ctx, r, e, 3)
		third.ConnectorID = gmailConnector
		third.ConnectorGeneration = 2
		n3, err := r.Enqueue(ctx, third)
		if err != nil || n3.ConnectorID != gmailConnector {
			t.Fatal("explicit Gmail selection", err)
		}
		if invitationState(t, f) != before {
			t.Fatal("notification changed identities/roles/sessions/approvals")
		}
		var retained bool
		if err = f.owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM framework.notification_requests WHERE idempotency_digest=$1)`, []byte(input.IdempotencyKey)).Scan(&retained); err != nil || retained {
			t.Fatal("plaintext key retained", err)
		}
	})
}

func TestNotificationOutcomesAndUncertainty(t *testing.T) {
	f, r, e := notificationFixture(t)
	var ids []string
	f.run(t, func(ctx context.Context) {
		for n := 1; n <= 3; n++ {
			input := notificationInput(t, ctx, r, e, n)
			if n == 2 {
				input.ConnectorID = sesConnector
			}
			req, err := r.Enqueue(ctx, input)
			if err != nil {
				t.Fatal(err)
			}
			ids = append(ids, jobFor(t, ctx, r, req.ID).ID)
		}
	})
	w := r.Worker()
	ctx := context.Background()
	leases, err := w.Acquire(ctx, workerOne, 3, time.Minute)
	if err != nil || len(leases) != 3 {
		t.Fatal("acquire", err, len(leases))
	}
	for _, l := range leases {
		d, err := w.Begin(ctx, l)
		if err != nil {
			t.Fatal("begin", err)
		}
		if d.Message.Sender() != "onboarding@vopak.com" || !strings.HasPrefix(d.Message.Reference(), "vgca.") {
			t.Fatal("message not bound")
		}
		result := notifications.Result{Outcome: notifications.Accepted, ProviderMessageID: "provider-id"}
		if l.ID == ids[1] {
			result = notifications.Result{Outcome: notifications.Rejected, ErrorCode: "provider_rejected"}
		}
		if l.ID == ids[2] {
			result = notifications.Result{Outcome: notifications.Uncertain, ErrorCode: "provider_uncertain"}
		}
		if err = w.Complete(ctx, d.Lease, result); err != nil {
			t.Fatal("complete", err)
		}
		if err = w.Complete(ctx, d.Lease, result); !errors.Is(err, ErrConflict) {
			t.Fatal("completion replay", err)
		}
	}
	if again, err := w.Acquire(ctx, workerTwo, 20, time.Minute); err != nil || len(again) != 0 {
		t.Fatal("terminal job redispatched", err)
	}
	f.run(t, func(ctx context.Context) {
		for n, id := range ids {
			j, err := r.ReadJob(ctx, id)
			if err != nil || j.Status != []string{"sent", "failed", "needs_inspection"}[n] {
				t.Fatal("outcome", err, j.Status)
			}
			a, err := r.ReadAttempts(ctx, id)
			if err != nil || len(a) != 1 {
				t.Fatal("attempt history", err)
			}
		}
		c, err := r.ReadConnector(ctx, gmailConnector)
		if err != nil || c.FailureCount != 1 || c.LastAcceptedAt == nil {
			t.Fatal("independent Gmail health", err, c)
		}
		c, err = r.ReadConnector(ctx, sesConnector)
		if err != nil || c.FailureCount != 1 {
			t.Fatal("independent SES health", err, c)
		}
		// Uncertainty blocks another provider for the same recipient too.
		input := NotificationInput{ID: "99999999-1111-4111-8111-111111111111", IdempotencyKey: "99999999-2222-4222-8222-222222222222", Type: "reminder", TemplateVersion: notifications.TemplateVersion, Locale: "en", ConnectorID: sesConnector, ConnectorGeneration: c.Generation, Expected: e, Reason: "inspect before another delivery", Confirm: true}
		j, _ := r.ReadJob(ctx, ids[2])
		input.Targets = []NotificationTarget{j.NotificationTarget}
		if _, err = r.Enqueue(ctx, input); !errors.Is(err, ErrConflict) {
			t.Fatal("uncertain cross-provider retry", err)
		}
	})
}

func TestNotificationConcurrentAcquisitionAndFencing(t *testing.T) {
	f, r, e := notificationFixture(t)
	f.run(t, func(ctx context.Context) {
		for n := 1; n <= 8; n++ {
			if _, err := r.Enqueue(ctx, notificationInput(t, ctx, r, e, n)); err != nil {
				t.Fatal(err)
			}
		}
	})
	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := map[string]bool{}
	var leases []notifications.Lease
	for _, owner := range []string{workerOne, workerTwo} {
		wg.Add(1)
		go func(owner string) {
			defer wg.Done()
			got, err := r.Worker().Acquire(context.Background(), owner, 8, time.Minute)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				t.Error(err)
				return
			}
			for _, l := range got {
				if seen[l.ID] {
					t.Error("duplicate acquisition")
				}
				seen[l.ID] = true
				leases = append(leases, l)
			}
		}(owner)
	}
	wg.Wait()
	if len(seen) != 8 {
		t.Fatal("missing jobs", len(seen))
	}
	l := leases[0]
	forged := l
	forged.Owner = workerTwo
	if forged.Owner == l.Owner {
		forged.Owner = workerOne
	}
	if _, err := r.Worker().Begin(context.Background(), forged); !errors.Is(err, ErrConflict) {
		t.Fatal("wrong lease owner", err)
	}
	d, err := r.Worker().Begin(context.Background(), l)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.Worker().Begin(context.Background(), l); !errors.Is(err, ErrConflict) {
		t.Fatal("stale generation dispatched", err)
	}
	if err = r.Worker().Complete(context.Background(), d.Lease, notifications.Result{Outcome: notifications.Accepted}); err != nil {
		t.Fatal(err)
	}
}

func expireNotificationLeases(t *testing.T, f *fixture) {
	t.Helper()
	_, err := f.owner.Exec(context.Background(), `ALTER TABLE framework.notification_jobs DISABLE TRIGGER notification_history;
 UPDATE framework.notification_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE status IN ('leased','dispatching');
 ALTER TABLE framework.notification_jobs ENABLE TRIGGER notification_history;`)
	if err != nil {
		t.Fatal(err)
	}
}
func TestNotificationCrashRecovery(t *testing.T) {
	f, r, e := notificationFixture(t)
	var ids []string
	f.run(t, func(ctx context.Context) {
		for n := 1; n <= 2; n++ {
			input := notificationInput(t, ctx, r, e, n)
			req, err := r.Enqueue(ctx, input)
			if err != nil {
				t.Fatal(err)
			}
			ids = append(ids, jobFor(t, ctx, r, req.ID).ID)
		}
	})
	w := r.Worker()
	leases, err := w.Acquire(context.Background(), workerOne, 2, time.Minute)
	if err != nil || len(leases) != 2 {
		t.Fatal(err)
	}
	d, err := w.Begin(context.Background(), leases[0])
	if err != nil {
		t.Fatal(err)
	}
	expireNotificationLeases(t, f)
	if n, err := w.ResolveExpired(context.Background(), 20); err != nil || n != 2 {
		t.Fatal("recovery", err, n)
	}
	if err = w.Complete(context.Background(), d.Lease, notifications.Result{Outcome: notifications.Accepted}); !errors.Is(err, ErrConflict) {
		t.Fatal("late provider outcome defeated fencing", err)
	}
	f.run(t, func(ctx context.Context) {
		for _, id := range ids {
			j, _ := r.ReadJob(ctx, id)
			want := "queued"
			if id == d.Lease.ID {
				want = "needs_inspection"
			}
			if j.Status != want {
				t.Fatal("unsafe crash recovery", j.Status, want)
			}
		}
	})
	again, err := w.Acquire(context.Background(), workerTwo, 20, time.Minute)
	if err != nil || len(again) != 1 || again[0].ID == d.Lease.ID {
		t.Fatal("uncertain send reclaimed", err)
	}
}

func TestNotificationSuppressionCancellationAndAuthority(t *testing.T) {
	f, r, e := notificationFixture(t)
	f.run(t, func(ctx context.Context) {
		input := notificationInput(t, ctx, r, e, 1)
		req, err := r.Enqueue(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		j := jobFor(t, ctx, r, req.ID)
		s, err := r.SetSuppression(ctx, SuppressionTarget{Email: j.RecipientKey}, 0, true, "employee communication suppression")
		if err != nil || s.Generation != 1 {
			t.Fatal(err)
		}
		if _, err = r.SetSuppression(ctx, s.Target, 0, false, "duplicate suppression generation"); !errors.Is(err, ErrConflict) {
			t.Fatal("suppression conflict", err)
		}
		if got, err := r.ReadSuppression(ctx, s.Target); err != nil || !got.Active {
			t.Fatal(err)
		}
		leases, err := r.Worker().Acquire(ctx, workerOne, 1, time.Minute)
		if err != nil || len(leases) != 1 {
			t.Fatal(err)
		}
		if _, err = r.Worker().Begin(ctx, leases[0]); !errors.Is(err, ErrConflict) {
			t.Fatal("suppressed dispatch", err)
		}
		j, _ = r.ReadJob(ctx, j.ID)
		if j.Status != "cancelled" || j.Disposition != "suppressed" {
			t.Fatal("suppression not recorded", j)
		}
		input = notificationInput(t, ctx, r, e, 2)
		req, err = r.Enqueue(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		j = jobFor(t, ctx, r, req.ID)
		if err = r.Cancel(ctx, j.ID, j.Generation, "administrator cancelled notification"); err != nil {
			t.Fatal(err)
		}
		if err = r.Cancel(ctx, j.ID, j.Generation, "repeat administrator cancellation"); !errors.Is(err, ErrConflict) {
			t.Fatal(err)
		}
		other, _ := NewAccessPolicyRepository(f.store, Scope{"other-deployment", "development"})
		cross, _ := NewNotificationRepository(other, r.communication)
		if _, err = cross.ReadRequest(ctx, req.ID); err == nil {
			t.Fatal("cross-scope read")
		}
	})
	if _, err := r.ReadConnector(context.Background(), gmailConnector); !errors.Is(err, ErrDenied) {
		t.Fatal("anonymous administrator", err)
	}
	// A worker capability cannot create an administrator context.
	if _, err := access.Principal(context.Background()); err {
		t.Fatal("fabricated principal")
	}
}
