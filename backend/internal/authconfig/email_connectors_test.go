package authconfig

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/notifications"
	"github.com/jackc/pgx/v5"
)

type fakeConnectorSES struct {
	result           notifications.Readiness
	entered, release chan struct{}
	calls            int
}

func (f *fakeConnectorSES) Check(context.Context, notifications.Probe) notifications.Readiness {
	f.calls++
	if f.entered != nil {
		close(f.entered)
		<-f.release
	}
	return f.result
}

type fakeConnectorGmail struct {
	result               notifications.Readiness
	exchanges, refreshes int
}

func (f *fakeConnectorGmail) AuthorizationURL(state, verifier, mailbox string) string {
	return "https://accounts.google.com/o/oauth2/v2/auth?" + url.Values{"state": {state}, "code_challenge": {verifier}, "login_hint": {mailbox}}.Encode()
}
func (f *fakeConnectorGmail) Exchange(context.Context, string, string, string, string) (notifications.GmailCredential, notifications.Readiness) {
	f.exchanges++
	return notifications.GmailCredential{RefreshToken: "PRIVATE-REFRESH-TOKEN", Mailbox: "onboarding@vopak.com", Scopes: notifications.GmailScope + " " + notifications.GmailSenderScope}, f.result
}
func (f *fakeConnectorGmail) Refresh(_ context.Context, c notifications.GmailCredential, _ string) (notifications.GmailCredential, notifications.Readiness) {
	f.refreshes++
	return c, f.result
}
func emailServiceFixture(t *testing.T) (*fixture, *EmailConnectorService, *fakeConnectorGmail, *fakeConnectorSES) {
	t.Helper()
	f, r, _ := notificationFixture(t)
	s, err := NewEmailConnectorService(r.policy, EmailConnectorOptions{Origin: "https://vgca.example.test", GmailClientID: "fake-email-client"})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "email-key")
	if err = os.WriteFile(key, []byte(base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))), 0600); err != nil {
		t.Fatal(err)
	}
	s.credentials, err = notifications.NewFileCredentials(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	gmail := &fakeConnectorGmail{result: notifications.Readiness{Status: notifications.Ready, Code: "ready"}}
	ses := &fakeConnectorSES{result: notifications.Readiness{Status: notifications.Ready, Code: "ready", QuotaKnown: true, Remaining24Hours: 5000, MaxPerSecond: 5}}
	s.gmail, s.ses = gmail, ses
	return f, s, gmail, ses
}
func TestEmailConnectorReadinessConfigurationAndRedaction(t *testing.T) {
	f, s, _, ses := emailServiceFixture(t)
	f.run(t, func(ctx context.Context) {
		before := invitationState(t, f)
		ready, err := s.Test(ctx, sesConnector, 1, "inspect provider authorization")
		if err != nil || ready.Readiness.Status != notifications.Ready || ses.calls != 1 {
			t.Fatal("SES readiness", err)
		}
		configured, err := s.Configure(ctx, sesConnector, EmailConnectorUpdate{ExpectedGeneration: 1, Enabled: true, Default: true, PerMinute: 30, PerDay: 1500, Reason: "enable tested SES connector"})
		if err != nil || configured.Generation != 2 || !configured.Default {
			t.Fatal("configure tested connector", err)
		}
		if _, err = s.Configure(ctx, sesConnector, EmailConnectorUpdate{ExpectedGeneration: 1, Enabled: true, PerMinute: 30, PerDay: 1500, Reason: "stale configuration update"}); !errors.Is(err, ErrConflict) {
			t.Fatal("stale generation accepted", err)
		}
		rows, total, err := s.List(ctx, 0, 20)
		if err != nil || total != 2 || len(rows) != 2 {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(rows)
		for _, forbidden := range []string{"PRIVATE", "credential_reference", "credential_version", "state_hash", "fake-email-client"} {
			if strings.Contains(string(raw), forbidden) {
				t.Fatal("private connector data exposed")
			}
		}
		if invitationState(t, f) != before {
			t.Fatal("connection test modified authentication data")
		}
		c, err := s.Create(ctx, EmailConnectorCreate{ID: "99999999-1111-4111-8111-111111111111", Provider: "ses", Sender: "support@vopak.com", Region: "eu-west-1", PerMinute: 30, PerDay: 1500, Reason: "new disabled email connector"})
		if err != nil || c.Enabled || c.Readiness.Status != notifications.Configured {
			t.Fatal("new connector not disabled", err)
		}
		if _, err = s.Configure(ctx, c.ID, EmailConnectorUpdate{ExpectedGeneration: 1, Enabled: true, PerMinute: 30, PerDay: 1500, Reason: "cannot enable without a test"}); !errors.Is(err, ErrConflict) {
			t.Fatal("unproven connector enabled", err)
		}
	})
	if _, err := s.Read(context.Background(), sesConnector); !errors.Is(err, ErrDenied) {
		t.Fatal("anonymous read", err)
	}
}
func TestEmailConnectorOAuthReplayBrowserAndGenerationBinding(t *testing.T) {
	f, s, gmail, _ := emailServiceFixture(t)
	f.run(t, func(ctx context.Context) {
		input := GmailAuthorizationInput{ExpectedGeneration: 1, Mailbox: "onboarding@vopak.com", Reason: "authorize dedicated sender mailbox", ConfirmSenderSettings: true}
		first, err := s.BeginGmail(ctx, gmailConnector, input)
		if err != nil {
			t.Fatal(err)
		}
		parsed, _ := url.Parse(first.URL)
		state := parsed.Query().Get("state")
		if err = s.CompleteGmail(ctx, state, "wrong-cookie-value-of-invalid-length", "code", ""); err == nil || gmail.exchanges != 0 {
			t.Fatal("browser mismatch accepted")
		}
		second, err := s.BeginGmail(ctx, gmailConnector, input)
		if err != nil {
			t.Fatal(err)
		}
		if err = s.CompleteGmail(ctx, state, first.Browser, "fake-code", ""); err != nil || gmail.exchanges != 1 {
			t.Fatal("valid callback", err)
		}
		c, err := s.Read(ctx, gmailConnector)
		if err != nil || !c.HasAuthorization || c.Generation != 2 || c.Readiness.Status != notifications.Ready {
			t.Fatal("authorization not persisted", err)
		}
		if err = s.CompleteGmail(ctx, state, first.Browser, "fake-code", ""); err == nil || gmail.exchanges != 1 {
			t.Fatal("replay exchanged tokens")
		}
		parsed, _ = url.Parse(second.URL)
		if err = s.CompleteGmail(ctx, parsed.Query().Get("state"), second.Browser, "fake-code", ""); !errors.Is(err, ErrConflict) || gmail.exchanges != 1 {
			t.Fatal("stale flow activated", err)
		}
		// Cooldown applies to tests; advance only the disposable fixture's observation.
		if _, err = f.owner.Exec(ctx, `UPDATE framework.notification_connector_readiness SET tested_at=clock_timestamp()-interval '1 minute',expires_at=clock_timestamp()+interval '1 minute',generation=generation+1 WHERE connector_id=$1`, gmailConnector); err != nil {
			t.Fatal(err)
		}
		gmail.result = notifications.Readiness{Status: notifications.AuthenticationFailed, Code: "gmail_authentication_failed"}
		c, err = s.Test(ctx, gmailConnector, 2, "detect refresh token revocation")
		if err != nil || c.Readiness.Status != notifications.AuthenticationFailed || gmail.refreshes != 1 {
			t.Fatal("refresh failure hidden", err)
		}
		var secrets bool
		if err = f.owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM framework.notification_connector_oauth_flows f WHERE to_jsonb(f)::text LIKE '%PRIVATE-REFRESH%')`).Scan(&secrets); err != nil || secrets {
			t.Fatal("token reached PostgreSQL", err)
		}
	})
}
func TestEmailConnectorStaleTestAndConcurrentConfiguration(t *testing.T) {
	f, s, _, ses := emailServiceFixture(t)
	ses.entered = make(chan struct{})
	ses.release = make(chan struct{})
	f.run(t, func(ctx context.Context) {
		done := make(chan error, 1)
		go func() { _, err := s.Test(ctx, sesConnector, 1, "test while configuration changes"); done <- err }()
		<-ses.entered
		if _, err := s.Configure(ctx, sesConnector, EmailConnectorUpdate{ExpectedGeneration: 1, Enabled: false, PerMinute: 20, PerDay: 1000, Reason: "change limits during readiness test"}); err != nil {
			t.Fatal(err)
		}
		close(ses.release)
		if err := <-done; !errors.Is(err, ErrConflict) {
			t.Fatal("stale provider result committed", err)
		}
		var wg sync.WaitGroup
		var mu sync.Mutex
		successes := 0
		for range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := s.Configure(ctx, sesConnector, EmailConnectorUpdate{ExpectedGeneration: 2, Enabled: false, PerMinute: 20, PerDay: 1000, Reason: "concurrent configuration review"})
				mu.Lock()
				defer mu.Unlock()
				if err == nil {
					successes++
				} else if !errors.Is(err, ErrConflict) {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		if successes != 1 {
			t.Fatal("configuration race", successes)
		}
		other, _ := NewAccessPolicyRepository(f.store, Scope{"other-deployment", "development"})
		cross, _ := NewEmailConnectorService(other, s.options)
		if _, err := cross.Read(ctx, sesConnector); err == nil {
			t.Fatal("cross-deployment metadata read")
		}
	})
}
func TestEmailConnectorProtectedHTTPAndNoSendingEndpoint(t *testing.T) {
	f, s, _, _ := emailServiceFixture(t)
	mux := http.NewServeMux()
	RegisterEmailConnectors(mux, fixedAuth{f.identity}, f.store, s.options.Origin, s)
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
	w := request("GET", EmailConnectorsPath+"?offset=0&limit=20", "", "")
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || strings.Contains(w.Body.String(), "credential_reference") {
		t.Fatal("metadata contract", w.Code)
	}
	if w = request("GET", EmailConnectorsPath+"?offset=%ZZ", "", ""); w.Code != 400 {
		t.Fatal("malformed query accepted", w.Code)
	}
	for _, body := range []string{`{"expected_generation":1,"reason":"check sender only","recipient":"arbitrary@evil.test"}`, `{"expected_generation":1,"expected_generation":2,"reason":"duplicate key validation"}`} {
		if w = request("POST", EmailConnectorsPath+"/"+sesConnector+"/test", body, s.options.Origin); w.Code != 400 {
			t.Fatal("unsafe test body accepted", w.Code)
		}
	}
	if w = request("POST", EmailConnectorsPath+"/"+sesConnector+"/test", `{"expected_generation":1,"reason":"check sender only"}`, "https://evil.test"); w.Code != 403 {
		t.Fatal("cross-origin write", w.Code)
	}
	if w = request("POST", EmailConnectorsPath+"/"+sesConnector+"/send", `{}`, s.options.Origin); w.Code != 404 {
		t.Fatal("public sending endpoint exists", w.Code)
	}
	input := `{"expected_generation":1,"mailbox":"onboarding@vopak.com","reason":"authorize dedicated mailbox","confirm_sender_settings":true}`
	w = request("POST", EmailConnectorsPath+"/"+gmailConnector+"/gmail/authorize", input, s.options.Origin)
	if w.Code != 200 {
		t.Fatal("begin OAuth", w.Code)
	}
	var started struct {
		URL string `json:"authorization_url"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &started)
	u, _ := url.Parse(started.URL)
	callback := httptest.NewRequest("GET", GmailCallbackPath+"?"+url.Values{"state": {u.Query().Get("state")}, "code": {"private-code"}}.Encode(), nil)
	for _, c := range w.Result().Cookies() {
		if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode {
			t.Fatal("unsafe OAuth cookie")
		}
		callback.AddCookie(c)
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, callback)
	if w.Code != 303 || strings.Contains(w.Header().Get("Location"), "private-code") {
		t.Fatal("callback leaked authorization code", w.Code)
	}
}

func TestEmailConnectorAuditRollbackAndQuotaInvalidation(t *testing.T) {
	f, s, _, _ := emailServiceFixture(t)
	f.run(t, func(ctx context.Context) {
		if _, err := f.owner.Exec(ctx, `CREATE FUNCTION framework.reject_connector_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action IN ('notification.connector_created','notification.connector_test_completed') THEN RAISE EXCEPTION 'synthetic'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_connector_audit BEFORE INSERT ON framework.audit_log FOR EACH ROW EXECUTE FUNCTION framework.reject_connector_audit()`); err != nil {
			t.Fatal(err)
		}
		id := "99999999-1111-4111-8111-222222222222"
		if _, err := s.Create(ctx, EmailConnectorCreate{ID: id, Provider: "ses", Sender: "support@vopak.com", Region: "eu-west-1", PerMinute: 30, PerDay: 1500, Reason: "audit rollback verification"}); !errors.Is(err, ErrAudit) {
			t.Fatal("unaudited connector creation", err)
		}
		if _, err := s.Read(ctx, id); !errors.Is(err, ErrNotFound) {
			t.Fatal("connector escaped rollback", err)
		}
		if _, err := s.Test(ctx, sesConnector, 1, "audit rollback of test result"); !errors.Is(err, ErrAudit) {
			t.Fatal("unaudited test result", err)
		}
		c, err := s.Read(ctx, sesConnector)
		if err != nil || c.Readiness.Status != notifications.Configured {
			t.Fatal("ready escaped failed audit", err)
		}
		if _, err = f.owner.Exec(ctx, `DROP TRIGGER reject_connector_audit ON framework.audit_log; UPDATE framework.notification_connector_readiness SET tested_at=clock_timestamp()-interval '1 minute',expires_at=clock_timestamp()+interval '1 minute',generation=generation+1`); err != nil {
			t.Fatal(err)
		}
		if _, err = s.Test(ctx, sesConnector, 1, "inspect quota before limits change"); err != nil {
			t.Fatal(err)
		}
		c, err = s.Configure(ctx, sesConnector, EmailConnectorUpdate{ExpectedGeneration: 1, Enabled: false, PerMinute: 30, PerDay: 6000, Reason: "raise disabled connector daily budget"})
		if err != nil || c.Readiness.Status != notifications.Configured {
			t.Fatal("readiness retained beyond quota", err, c.Readiness)
		}
	})
}

func TestNotificationAdministratorCurrentPolicyEligibility(t *testing.T) {
	f, r, e := notificationFixture(t)
	f.run(t, func(ctx context.Context) {
		unapproved := policyUser(t, f, "unapproved-administrator", "other-admin@vopak.com", "Admin", true)
		if err := r.admin(ctx, func(ctx context.Context, tx pgx.Tx, _ access.User) error {
			b, err := r.policy.invitationContext(ctx, tx, nil)
			if err != nil {
				return err
			}
			ok, err := r.administratorEligible(ctx, tx, unapproved.ID, b)
			if err != nil {
				return err
			}
			if ok {
				t.Fatal("unapproved administrator eligible under Approved Users Only")
			}
			b.policy.Mode = "allow_all"
			ok, err = r.administratorEligible(ctx, tx, unapproved.ID, b)
			if err == nil && !ok {
				t.Fatal("Allow All required approval")
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		input := notificationInput(t, ctx, r, e, 71)
		if _, err := r.Enqueue(ctx, input); err != nil {
			t.Fatal(err)
		}
		leases, err := r.Worker().Acquire(ctx, workerOne, 1, time.Minute)
		if err != nil || len(leases) != 1 {
			t.Fatal(err)
		}
		// Synthetic change in the disposable database, without a policy-generation change.
		if _, err = f.owner.Exec(ctx, `UPDATE framework.users SET email='administrator@outside.test' WHERE issuer=$1 AND subject=$2`, f.identity.Issuer, f.identity.Subject); err != nil {
			t.Fatal(err)
		}
		if _, err = r.Worker().Begin(ctx, leases[0]); !errors.Is(err, ErrConflict) {
			t.Fatal("domain-ineligible administrator dispatched", err)
		}
		var status, code string
		if err = f.owner.QueryRow(ctx, `SELECT status,disposition_code FROM framework.notification_jobs WHERE id=$1`, leases[0].ID).Scan(&status, &code); err != nil || status != "cancelled" || code != "review_required" {
			t.Fatal("unsafe job state", status, code, err)
		}
	})
}
