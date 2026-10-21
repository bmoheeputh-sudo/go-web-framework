package authconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/notifications"
	"github.com/jackc/pgx/v5/pgxpool"
)

func managementFixture(t *testing.T) (*fixture, *NotificationManagement) {
	t.Helper()
	f, c, _, _ := emailServiceFixture(t)
	s := NewNotificationManagement(c.repository.policy, c, CommunicationPolicy{Origin: "https://vgca.example.test", AllowedDomains: []string{"vopak.com"}})
	f.run(t, func(ctx context.Context) {
		if _, err := c.Test(ctx, sesConnector, 1, "prepare isolated fake provider readiness"); err != nil {
			t.Fatal(err)
		}
	})
	return f, s
}
func managementInput(t *testing.T, ctx context.Context, s *NotificationManagement, n int) NotificationPreviewInput {
	t.Helper()
	p, err := s.repository.policy.ListInvitations(ctx, "", "", 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	e := InvitationExpectation{PolicyExpectation{p.PolicyGeneration, p.ActivationGeneration}, p.RevisionID, p.RevisionGeneration}
	i, err := s.repository.policy.CreateInvitation(ctx, e, invitationInput(fmt.Sprintf("management%d@vopak.com", n)))
	if err != nil {
		t.Fatal(err)
	}
	return NotificationPreviewInput{RequestID: operationID(), Type: "invitation", Locale: "en", ConnectorID: sesConnector, Targets: []string{"invitation:" + i.ID}}
}
func managementEnqueue(p NotificationPreview) NotificationEnqueueInput {
	return NotificationEnqueueInput{Input: p.Input, Expected: p.Expected, ConnectorGeneration: p.ConnectorGeneration, SelectedTargets: p.SelectedTargets, Digest: p.Digest, ExpiresAt: p.ExpiresAt, IdempotencyKey: operationID(), Reason: "confirmed administrative onboarding batch", Confirm: true}
}
func TestNotificationManagementPreviewQueueAndIdempotency(t *testing.T) {
	f, s := managementFixture(t)
	f.run(t, func(ctx context.Context) {
		input := managementInput(t, ctx, s, 1)
		other := managementInput(t, ctx, s, 2)
		input.Targets = append(input.Targets, other.Targets...)
		target, _ := notificationTarget(other.Targets[0])
		if _, err := s.repository.SetSuppression(ctx, SuppressionTarget{NotificationTarget: target}, 0, true, "suppress isolated recipient communications"); err != nil {
			t.Fatal(err)
		}
		before := notificationCounts(t, f)
		p, err := s.Preview(ctx, input)
		if err != nil || p.Ready != 1 || p.Skipped != 1 || len(p.Rows) != 2 || p.DeliveryEnabled || p.Digest == "" {
			t.Fatal("invalid preview", err, p.Ready, p.Skipped)
		}
		if notificationCounts(t, f) != before {
			t.Fatal("preview changed records")
		}
		if !strings.Contains(p.Rows[0].Text+p.Rows[1].Text, "https://vgca.example.test/api/auth/login") {
			t.Fatal("missing approved login URL")
		}
		write := managementEnqueue(p)
		var wg sync.WaitGroup
		for range 3 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if n, err := s.Enqueue(ctx, write); err != nil || n.ID != input.RequestID {
					t.Error("concurrent identical enqueue", err)
				}
			}()
		}
		wg.Wait()
		receipt, err := s.Receipt(ctx, input.RequestID, 0, 20)
		if err != nil || receipt.JobCount != 1 || receipt.Jobs.Total != 1 || receipt.Jobs.Items[0].Status != "queued" || receipt.Jobs.Items[0].AttemptOutcome != "" || receipt.DeliveryEnabled {
			t.Fatal("receipt", err, receipt)
		}
		detail, err := s.Job(ctx, receipt.Jobs.Items[0].ID)
		if err != nil || len(detail.Attempts) != 0 {
			t.Fatal("queue attempted delivery", err)
		}
		changed := write
		changed.Reason = "different payload must conflict"
		if _, err = s.Enqueue(ctx, changed); !errors.Is(err, ErrConflict) {
			t.Fatal("reused idempotency key changed payload", err)
		}
		if _, err = f.owner.Exec(ctx, `UPDATE framework.notification_connector_readiness SET tested_at=clock_timestamp()-interval '6 minutes',expires_at=clock_timestamp()-interval '2 minutes',generation=generation+1 WHERE connector_id=$1`, sesConnector); err != nil {
			t.Fatal(err)
		}
		if n, err := s.Enqueue(ctx, write); err != nil || n.ID != receipt.ID {
			t.Fatal("idempotency depended on expired readiness", err)
		}
	})
}
func TestNotificationManagementStaleAndTamperedPreviews(t *testing.T) {
	f, s := managementFixture(t)
	f.run(t, func(ctx context.Context) {
		input := managementInput(t, ctx, s, 11)
		p, err := s.Preview(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		write := managementEnqueue(p)
		before := notificationCounts(t, f)
		for _, change := range []func(*NotificationEnqueueInput){
			func(i *NotificationEnqueueInput) { i.Digest = strings.Repeat("0", 64) },
			func(i *NotificationEnqueueInput) { i.ExpiresAt = time.Now().Add(-time.Minute) },
			func(i *NotificationEnqueueInput) { i.ConnectorGeneration++ },
			func(i *NotificationEnqueueInput) { i.Expected.PolicyGeneration++ },
			func(i *NotificationEnqueueInput) { i.Input.Type = "reminder" },
			func(i *NotificationEnqueueInput) { i.Confirm = false },
			func(i *NotificationEnqueueInput) { i.Reason = "short" },
			func(i *NotificationEnqueueInput) { i.SelectedTargets = []string{} },
			func(i *NotificationEnqueueInput) { i.Input.Targets = []string{i.Input.Targets[0], i.Input.Targets[0]} },
		} {
			changed := write
			change(&changed)
			if _, err = s.Enqueue(ctx, changed); err == nil {
				t.Fatal("tampered preview accepted")
			}
			if notificationCounts(t, f) != before {
				t.Fatal("invalid request changed records")
			}
		}
		target, _ := notificationTarget(input.Targets[0])
		if _, err = s.repository.SetSuppression(ctx, SuppressionTarget{NotificationTarget: target}, 0, true, "recipient suppressed after preview"); err != nil {
			t.Fatal(err)
		}
		if _, err = s.Enqueue(ctx, write); !errors.Is(err, ErrConflict) {
			t.Fatal("suppression change not rechecked", err)
		}
		if _, err = s.repository.SetSuppression(ctx, SuppressionTarget{NotificationTarget: target}, 1, false, "restore recipient for revocation check"); err != nil {
			t.Fatal(err)
		}
		p, err = s.Preview(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.repository.policy.RevokeInvitation(ctx, p.Expected.invitation(), target.InvitationID, 1, "revoke invitation after email preview"); err != nil {
			t.Fatal(err)
		}
		if _, err = s.Enqueue(ctx, managementEnqueue(p)); !errors.Is(err, ErrConflict) {
			t.Fatal("revoked invitation queued", err)
		}
		input = managementInput(t, ctx, s, 12)
		p, err = s.Preview(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.connectors.Configure(ctx, sesConnector, EmailConnectorUpdate{ExpectedGeneration: 1, Enabled: false, PerMinute: 30, PerDay: 1500, Reason: "disable connector after preview"}); err != nil {
			t.Fatal(err)
		}
		if _, err = s.Enqueue(ctx, managementEnqueue(p)); !errors.Is(err, ErrConflict) {
			t.Fatal("disabled connector queued", err)
		}
	})
}
func TestNotificationManagementAuditRollbackAndUncertainInspection(t *testing.T) {
	f, s := managementFixture(t)
	f.run(t, func(ctx context.Context) {
		input := managementInput(t, ctx, s, 21)
		p, err := s.Preview(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		write := managementEnqueue(p)
		if _, err = f.owner.Exec(ctx, `CREATE FUNCTION framework.reject_management_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='notification.enqueued' THEN RAISE EXCEPTION 'synthetic'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_management_audit BEFORE INSERT ON framework.audit_log FOR EACH ROW EXECUTE FUNCTION framework.reject_management_audit()`); err != nil {
			t.Fatal(err)
		}
		before := notificationCounts(t, f)
		if _, err = s.Enqueue(ctx, write); !errors.Is(err, ErrAudit) {
			t.Fatal("audit failure", err)
		}
		if notificationCounts(t, f) != before {
			t.Fatal("queue escaped audit rollback")
		}
		if _, err = f.owner.Exec(ctx, `DROP TRIGGER reject_management_audit ON framework.audit_log`); err != nil {
			t.Fatal(err)
		}
		trace := &invitationCommitLoss{}
		cfg := f.pool.Config()
		cfg.ConnConfig.Tracer = trace
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer pool.Close()
		policy, _ := NewAccessPolicyRepository(access.New(pool), f.repo.scope)
		connectors, _ := NewEmailConnectorService(policy, s.connectors.options)
		uncertain := NewNotificationManagement(policy, connectors, s.repository.communication)
		trace.armed.Store(true)
		if n, err := uncertain.Enqueue(ctx, write); !errors.Is(err, ErrCommitUncertain) || n.ID != "" || trace.commits.Load() != 1 {
			t.Fatal("uncertain write retried", err)
		}
		r, err := s.Receipt(ctx, write.Input.RequestID, 0, 20)
		if err != nil || r.JobCount != 1 {
			t.Fatal("uncertain request not inspectable", err)
		}
	})
}
func TestNotificationManagementOnboardingEligibilityAndCSVSelection(t *testing.T) {
	f, s := managementFixture(t)
	f.run(t, func(ctx context.Context) {
		input := managementInput(t, ctx, s, 31)
		input.Type = "reminder"
		pending, err := s.Onboarding(ctx, NotificationPageQuery{Category: "pending", Limit: 20})
		if err != nil || pending.Counts.Pending != 1 {
			t.Fatal("pending overview", err)
		}
		for _, tc := range []struct {
			subject          string
			active, approved bool
			want             string
		}{{"observed", true, true, "onboarded"}, {"unknown", true, true, ""}, {"inactive", false, false, "inactive_user"}, {"unapproved", true, false, "review_required"}} {
			u := policyUser(t, f, tc.subject, tc.subject+"@vopak.com", "Viewer", tc.active)
			p, err := s.Preview(ctx, input)
			if err != nil {
				t.Fatal(err)
			}
			if tc.approved {
				if _, err = s.repository.policy.SetApproval(ctx, p.Expected.invitation().PolicyExpectation, OIDCIdentityKey{f.identity.Issuer, tc.subject}, 0, "approved", "review exact onboarding identity"); err != nil {
					t.Fatal(err)
				}
			}
			if tc.subject == "observed" {
				identity := auth.Identity{Issuer: f.identity.Issuer, Subject: tc.subject, Provider: auth.OIDC, Email: tc.subject + "@vopak.com", EmailVerified: true}
				if err = f.store.OIDCAdmission(f.repo.scope.DeploymentID, f.repo.scope.Environment).Login(ctx, identity, auth.Binding{}, normalSessionWrite(identity)); err != nil {
					t.Fatal(err)
				}
			}
			userInput := input
			userInput.Targets = []string{"user:" + u.ID}
			p, err = s.Preview(ctx, userInput)
			if err != nil || p.Rows[0].Code != tc.want {
				t.Fatal("reminder eligibility", tc.subject, err, p.Rows)
			}
		}
		overview, err := s.Onboarding(ctx, NotificationPageQuery{Category: "unobserved", Limit: 20})
		if err != nil || overview.Counts.Onboarded != 1 || overview.Counts.Inactive != 1 || overview.Counts.Unobserved < 2 {
			t.Fatal("unknown history inferred as onboarded", err, overview.Counts)
		}
		for _, row := range overview.Items {
			if row.FirstLogin != nil || row.LastLogin != nil {
				t.Fatal("fabricated history")
			}
		}
		// CSV receipt filtering uses persisted references; CSV email input is never
		// accepted as an identity or an arbitrary notification recipient.
		p, err := s.Preview(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		csv := CSVPreviewRequest{CSV: "email,display_name\r\ncsv-notify@vopak.com,CSV Employee\r\n", ExpirationDays: 7, ImportExpectation: p.Expected}
		preview, err := s.repository.policy.PreviewInvitationCSV(ctx, csv)
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := s.repository.policy.ImportInvitationCSV(ctx, CSVImportRequest{CSVPreviewRequest: CSVPreviewRequest{CSV: csv.CSV, ExpirationDays: 7, ImportExpectation: preview.ImportExpectation, SelectedRows: preview.SelectedRows}, ImportID: operationID(), IdempotencyKey: operationID(), PreviewDigest: preview.PreviewDigest, PreviewExpiresAt: preview.ExpiresAt, Reason: "review CSV receipt notification targets", Confirm: true})
		if err != nil {
			t.Fatal(err)
		}
		csvPage, err := s.Onboarding(ctx, NotificationPageQuery{Category: "pending", ImportID: receipt.ID, Limit: 20})
		if err != nil || csvPage.Total != 1 || csvPage.Items[0].ImportID != receipt.ID {
			t.Fatal("CSV selection", err)
		}
	})
}
func TestNotificationManagementHistoryUncertaintyAndCancellation(t *testing.T) {
	f, s := managementFixture(t)
	f.run(t, func(ctx context.Context) {
		input := managementInput(t, ctx, s, 41)
		p, err := s.Preview(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.Enqueue(ctx, managementEnqueue(p)); err != nil {
			t.Fatal(err)
		}
		// Fake dispatch is isolated to this disposable test infrastructure. There
		// is no administrator API for simulated sending or changing job outcomes.
		leases, err := s.repository.Worker().Acquire(ctx, workerOne, 1, time.Minute)
		if err != nil || len(leases) != 1 {
			t.Fatal(err)
		}
		d, err := s.repository.Worker().Begin(ctx, leases[0])
		if err != nil {
			t.Fatal(err)
		}
		if err = s.repository.Worker().Complete(ctx, d.Lease, notifications.Result{Outcome: notifications.Uncertain, ErrorCode: "provider_uncertain"}); err != nil {
			t.Fatal(err)
		}
		h, err := s.History(ctx, NotificationPageQuery{Status: "needs_inspection", Limit: 1})
		if err != nil || h.Total != 1 || h.Items[0].AttemptOutcome != "uncertain" {
			t.Fatal("uncertain history", err)
		}
		job, err := s.Job(ctx, h.Items[0].ID)
		if err != nil || len(job.Attempts) != 1 || job.Attempts[0].Outcome != "uncertain" {
			t.Fatal("attempt inspection", err)
		}
		if err = s.repository.Cancel(ctx, job.Item.ID, job.Item.Generation, "cannot reset uncertain provider outcome"); !errors.Is(err, ErrConflict) {
			t.Fatal("uncertain job reset", err)
		}
		input = managementInput(t, ctx, s, 42)
		current, err := s.connectors.Read(ctx, sesConnector)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.owner.Exec(ctx, `UPDATE framework.notification_connector_readiness SET tested_at=clock_timestamp()-interval '1 minute',expires_at=clock_timestamp()+interval '1 minute',generation=generation+1 WHERE connector_id=$1`, sesConnector); err != nil {
			t.Fatal(err)
		}
		if _, err = s.connectors.Test(ctx, sesConnector, current.Generation, "refresh readiness after isolated uncertain outcome"); err != nil {
			t.Fatal(err)
		}
		p, err = s.Preview(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.Enqueue(ctx, managementEnqueue(p)); err != nil {
			t.Fatal(err)
		}
		r, err := s.Receipt(ctx, input.RequestID, 0, 20)
		if err != nil {
			t.Fatal(err)
		}
		if err = s.repository.Cancel(ctx, r.Jobs.Items[0].ID, r.Jobs.Items[0].Generation+1, "stale cancellation generation"); !errors.Is(err, ErrConflict) {
			t.Fatal("stale cancellation accepted", err)
		}
		if err = s.repository.Cancel(ctx, r.Jobs.Items[0].ID, r.Jobs.Items[0].Generation, "cancel queued employee notification"); err != nil {
			t.Fatal(err)
		}
	})
}
func TestNotificationManagementProtectedHTTP(t *testing.T) {
	f, s := managementFixture(t)
	mux := http.NewServeMux()
	RegisterNotificationManagement(mux, fixedAuth{f.identity}, f.store, s.connectors.options.Origin, s)
	request := func(method, path, body, origin string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		mux.ServeHTTP(w, r)
		return w
	}
	if w := request("GET", NotificationManagementPath+"/onboarding?category=pending&offset=0&limit=20", "", ""); w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("protected observations", w.Code)
	}
	for _, path := range []string{"/onboarding?category=pending&limit=101", "/history?status=pretend_sent", "/history?offset=%zz"} {
		if w := request("GET", NotificationManagementPath+path, "", ""); w.Code != 400 {
			t.Fatal("invalid bounded query", w.Code)
		}
	}
	f.run(t, func(ctx context.Context) {
		input := managementInput(t, ctx, s, 51)
		p, err := s.Preview(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		write := managementEnqueue(p)
		raw, _ := json.Marshal(write)
		if w := request("POST", NotificationManagementPath+"/enqueue", string(raw), "https://evil.test"); w.Code != 403 {
			t.Fatal("cross origin enqueue", w.Code)
		}
		if w := request("POST", NotificationManagementPath+"/enqueue", strings.Replace(string(raw), `"type":"invitation"`, `"type":"invitation","type":"reminder"`, 1), s.connectors.options.Origin); w.Code != 400 {
			t.Fatal("nested duplicate accepted", w.Code)
		}
		if w := request("POST", NotificationManagementPath+"/enqueue", string(raw), s.connectors.options.Origin); w.Code != 201 || !strings.Contains(w.Body.String(), `"outcome":"queued"`) {
			t.Fatal("queue HTTP", w.Code, w.Body.String())
		}
		for _, suffix := range []string{"/send", "/simulate", "/retry"} {
			if w := request("POST", NotificationManagementPath+suffix, "{}", s.connectors.options.Origin); w.Code != 404 {
				t.Fatal("public dispatch capability", w.Code)
			}
		}
	})
	if _, err := s.History(context.Background(), NotificationPageQuery{Limit: 20}); !errors.Is(err, ErrDenied) {
		t.Fatal("anonymous history", err)
	}
	localIdentity := f.identity
	localIdentity.Provider = auth.LocalDev
	localMux := http.NewServeMux()
	RegisterNotificationManagement(localMux, fixedAuth{localIdentity}, f.store, s.connectors.options.Origin, nil)
	localResponse := httptest.NewRecorder()
	localMux.ServeHTTP(localResponse, httptest.NewRequest("GET", NotificationManagementPath+"/history", nil))
	if localResponse.Code != 403 {
		t.Fatal("Local DEV administrator reached OIDC-only management availability", localResponse.Code)
	}
	other, _ := NewAccessPolicyRepository(f.store, Scope{"other-deployment", "development"})
	c, _ := NewEmailConnectorService(other, s.connectors.options)
	cross := NewNotificationManagement(other, c, s.repository.communication)
	f.run(t, func(ctx context.Context) {
		if _, err := cross.History(ctx, NotificationPageQuery{Limit: 20}); err == nil {
			t.Fatal("cross-deployment history")
		}
	})
}

func TestNotificationManagementBoundedBulkAndPolicyChange(t *testing.T) {
	f, s := managementFixture(t)
	f.run(t, func(ctx context.Context) {
		input := managementInput(t, ctx, s, 100)
		for n := 101; n < 200; n++ {
			other := managementInput(t, ctx, s, n)
			input.Targets = append(input.Targets, other.Targets...)
		}
		tooMany := input
		tooMany.Targets = append(append([]string{}, input.Targets...), input.Targets[0])
		if _, err := s.Preview(ctx, tooMany); !errors.Is(err, ErrInvalid) {
			t.Fatal("unbounded preview", err)
		}
		start := time.Now()
		p, err := s.Preview(ctx, input)
		if err != nil || p.Ready != 100 {
			t.Fatal("bounded preview", err, p.Ready)
		}
		t.Logf("100-recipient read-only preview: %s", time.Since(start))
		start = time.Now()
		if _, err = s.Enqueue(ctx, managementEnqueue(p)); err != nil {
			t.Fatal("bounded atomic enqueue", err)
		}
		t.Logf("100-recipient confirmation with preview revalidation, jobs and audit: %s", time.Since(start))
		receipt, err := s.Receipt(ctx, input.RequestID, 20, 20)
		if err != nil || receipt.JobCount != 100 || receipt.Jobs.Total != 100 || len(receipt.Jobs.Items) != 20 {
			t.Fatal("bounded receipt page", err)
		}
		input = managementInput(t, ctx, s, 201)
		p, err = s.Preview(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.repository.policy.Update(ctx, p.Expected.invitation().PolicyExpectation, AccessPolicySettings{"allow_all", []string{"vopak.com"}, "Viewer"}, "allow all optional onboarding communications"); err != nil {
			t.Fatal(err)
		}
		if _, err = s.Enqueue(ctx, managementEnqueue(p)); !errors.Is(err, ErrConflict) {
			t.Fatal("policy change ignored", err)
		}
		p, err = s.Preview(ctx, input)
		if err != nil || p.Ready != 1 {
			t.Fatal("Allow All invitation preview", err)
		}
		if _, err = s.Enqueue(ctx, managementEnqueue(p)); err != nil {
			t.Fatal("Allow All optional invitation queue", err)
		}
	})
}

func TestNotificationCommunicationConfiguration(t *testing.T) {
	for _, tc := range []struct {
		domains, hours string
		valid          bool
	}{{"vopak.com", "", true}, {"vopak.com, example.org", "720", true}, {"vopak.com", "71", false}, {"vopak.com", "721", false}, {"vopak.com", "oops", false}, {"*.vopak.com", "72", false}, {"", "72", false}} {
		p := NotificationCommunicationFromEnv("https://vgca.example.test", func(key string) string {
			if key == "NOTIFICATION_ALLOWED_DOMAINS" {
				return tc.domains
			}
			if key == "NOTIFICATION_COOLDOWN_HOURS" {
				return tc.hours
			}
			return ""
		})
		normal, err := normalizePolicy(AccessPolicySettings{"allow_all", p.AllowedDomains, "Viewer"})
		valid := err == nil && len(normal.AllowedEmailDomains) > 0
		if valid != tc.valid {
			t.Fatal("communication configuration", tc.domains, tc.hours)
		}
	}
}
