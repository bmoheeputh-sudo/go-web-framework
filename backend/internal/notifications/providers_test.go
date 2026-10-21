package notifications

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
	"github.com/aws/smithy-go"
)

func privateStore(t *testing.T) *FileCredentials {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "notification-key")
	if err := os.WriteFile(key, []byte(base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := NewFileCredentials(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	return store
}
func TestGmailAuthorizationRefreshAndSenderReadiness(t *testing.T) {
	mode := "ready"
	sends := 0
	refreshes := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			_ = r.ParseForm()
			if r.Form.Get("client_secret") != "fake-notification-secret" {
				t.Error("missing confidential client proof")
			}
			if r.Form.Get("grant_type") == "refresh_token" {
				refreshes++
			}
			if mode == "revoked" {
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"PRIVATE SECRET"}`))
				return
			}
			scope := GmailScope + " " + GmailSenderScope
			if mode == "scope" {
				scope = GmailSenderScope
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fake-access", "refresh_token": "fake-rotated-refresh", "token_type": "Bearer", "expires_in": 3600, "scope": scope})
		case "/sender":
			if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer fake-access" {
				t.Error("invalid readiness request")
			}
			if mode == "denied" {
				w.WriteHeader(403)
				return
			}
			if mode == "unavailable" {
				w.WriteHeader(503)
				return
			}
			verified := "accepted"
			if mode == "sender" {
				verified = "pending"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"sendAs": []any{map[string]any{"sendAsEmail": "mailbox@example.test", "isPrimary": true, "verificationStatus": "accepted"}, map[string]any{"sendAsEmail": "onboarding@example.test", "verificationStatus": verified}}})
		default:
			sends++
			w.WriteHeader(500)
		}
	}))
	defer server.Close()
	g := NewGmail("fake-client", "fake-notification-secret", "https://app.example.test/callback")
	g.config.Endpoint.TokenURL = server.URL + "/token"
	g.sendAsURL = server.URL + "/sender"
	g.client = server.Client()
	url := g.AuthorizationURL("state", "verifier", "mailbox@example.test")
	for _, expected := range []string{"access_type=offline", "code_challenge_method=S256", "gmail.send", "gmail.settings.basic", "prompt=consent"} {
		if !strings.Contains(url, expected) {
			t.Fatal("missing OAuth requirement", expected)
		}
	}
	credential, result := g.Exchange(context.Background(), "fake-code", "verifier", "mailbox@example.test", "onboarding@example.test")
	if result.Status != Ready || credential.RefreshToken == "" {
		t.Fatal("valid authorization rejected", result)
	}
	if _, err := json.Marshal(credential); err == nil || strings.Contains(fmt.Sprint(credential), "fake-rotated") {
		t.Fatal("credential printable")
	}
	for _, tc := range []struct {
		mode string
		want ReadinessStatus
	}{{"ready", Ready}, {"sender", SenderNotVerified}, {"denied", PermissionDenied}, {"unavailable", ProviderUnavailable}, {"revoked", AuthenticationFailed}, {"scope", PermissionDenied}} {
		mode = tc.mode
		_, result = g.Refresh(context.Background(), credential, "onboarding@example.test")
		if result.Status != tc.want {
			t.Fatal(mode, result)
		}
	}
	if sends != 0 || refreshes != 6 {
		t.Fatal("connection test attempted sending or skipped refresh", sends, refreshes)
	}
}
func TestNotificationCredentialStoreIsolationAndConcurrentRefresh(t *testing.T) {
	store := privateStore(t)
	binding := CredentialBinding{"installation", "test", "connector", "version", "onboarding@example.test"}
	credential := GmailCredential{RefreshToken: "fake-refresh", Mailbox: "mailbox@example.test", Scopes: GmailScope + " " + GmailSenderScope}
	if err := store.Save(context.Background(), binding, credential); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*CredentialBinding){func(b *CredentialBinding) { b.Deployment = "different" }, func(b *CredentialBinding) { b.Sender = "other@example.test" }, func(b *CredentialBinding) { b.Version = "other-version" }} {
		other := binding
		change(&other)
		if _, err := store.Update(context.Background(), other, func(c GmailCredential) (GmailCredential, Readiness) {
			t.Error("cross-binding credential revealed")
			return c, Readiness{Status: Ready, Code: "ready"}
		}); err == nil {
			t.Fatal("cross-binding accepted")
		}
	}
	var wg sync.WaitGroup
	var calls atomic.Int32
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			separate, _ := NewFileCredentials(store.directory, store.keyFile)
			_, err := separate.Update(context.Background(), binding, func(c GmailCredential) (GmailCredential, Readiness) {
				calls.Add(1)
				return c, Readiness{Status: Ready, Code: "ready"}
			})
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 4 {
		t.Fatal("credential lock lost updates")
	}
	files, err := os.ReadDir(store.directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".enc") {
			raw, _ := os.ReadFile(filepath.Join(store.directory, f.Name()))
			if strings.Contains(string(raw), "fake-refresh") {
				t.Fatal("plaintext token persisted")
			}
		}
	}
}

type fakeSESClient struct {
	account    *sesv2.GetAccountOutput
	identity   *sesv2.GetEmailIdentityOutput
	err        error
	sent       int
	identities []string
	sendErr    error
	messageID  string
}

func (f *fakeSESClient) GetAccount(context.Context, *sesv2.GetAccountInput, ...func(*sesv2.Options)) (*sesv2.GetAccountOutput, error) {
	return f.account, f.err
}
func (f *fakeSESClient) GetEmailIdentity(_ context.Context, input *sesv2.GetEmailIdentityInput, _ ...func(*sesv2.Options)) (*sesv2.GetEmailIdentityOutput, error) {
	f.identities = append(f.identities, *input.EmailIdentity)
	return f.identity, f.err
}
func (f *fakeSESClient) SendEmail(context.Context, *sesv2.SendEmailInput, ...func(*sesv2.Options)) (*sesv2.SendEmailOutput, error) {
	f.sent++
	return &sesv2.SendEmailOutput{MessageId: aws.String(f.messageID)}, f.sendErr
}
func TestSESConnectionReadinessWithoutSending(t *testing.T) {
	f := &fakeSESClient{account: &sesv2.GetAccountOutput{SendingEnabled: true, ProductionAccessEnabled: true, SendQuota: &types.SendQuota{Max24HourSend: 2000, SentLast24Hours: 100, MaxSendRate: 2}}, identity: &sesv2.GetEmailIdentityOutput{VerifiedForSendingStatus: true}}
	ses := &SES{load: func(_ context.Context, region string) (SESClient, error) {
		if region != "eu-west-1" {
			t.Error("wrong region")
		}
		return f, nil
	}}
	probe := Probe{Sender: "onboarding@example.test", Region: "eu-west-1", PerMinute: 30, PerDay: 1500}
	if r := ses.Check(context.Background(), probe); r.Status != Ready || !r.QuotaKnown || r.Remaining24Hours != 1900 {
		t.Fatal(r)
	}
	f.identity.VerifiedForSendingStatus = false
	if r := ses.Check(context.Background(), probe); r.Status != SenderNotVerified {
		t.Fatal(r)
	}
	f.identity.VerifiedForSendingStatus = true
	f.account.SendQuota.MaxSendRate = 0
	if r := ses.Check(context.Background(), probe); r.Status != QuotaUnavailable {
		t.Fatal(r)
	}
	f.account.SendQuota.MaxSendRate = 2
	f.account.ProductionAccessEnabled = false
	if r := ses.Check(context.Background(), probe); r.Code != "ses_sandbox" {
		t.Fatal(r)
	}
	f.account.ProductionAccessEnabled = true
	f.err = &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "PRIVATE AWS DETAILS"}
	if r := ses.Check(context.Background(), probe); r.Status != PermissionDenied || strings.Contains(fmt.Sprint(r), "PRIVATE") {
		t.Fatal(r)
	}
	f.err = &smithy.GenericAPIError{Code: "ExpiredTokenException"}
	if r := ses.Check(context.Background(), probe); r.Status != AuthenticationFailed {
		t.Fatal(r)
	}
	f.err = nil
	ses.load = func(context.Context, string) (SESClient, error) { return nil, errSESCredentials }
	if r := ses.Check(context.Background(), probe); r.Status != AuthenticationFailed {
		t.Fatal("missing credentials misclassified", r)
	}
	if f.sent != 0 {
		t.Fatal("test connection sent email")
	}
	for _, identity := range f.identities {
		if identity != probe.Sender {
			t.Fatal("test used an arbitrary identity")
		}
	}
}

func TestSESAdapterSingleAttemptAndUncertainty(t *testing.T) {
	f := &fakeSESClient{account: &sesv2.GetAccountOutput{SendingEnabled: true, ProductionAccessEnabled: true, SendQuota: &types.SendQuota{Max24HourSend: 2000, MaxSendRate: 2}}, identity: &sesv2.GetEmailIdentityOutput{VerifiedForSendingStatus: true}}
	adapter := &SESAdapter{SES: &SES{load: func(context.Context, string) (SESClient, error) { return f, nil }}, Probe: Probe{Sender: "onboarding@example.test", Region: "eu-west-1", PerMinute: 30, PerDay: 1500}}
	m := Message{sender: adapter.Probe.Sender, recipient: "employee@example.test", subject: "Invitation", text: "Hello", reference: "vgca.12345678-1234-4234-8234-123456789abc"}
	for _, tc := range []struct {
		err  error
		id   string
		want Outcome
	}{
		{nil, "safe-provider-id", Accepted}, {&smithy.GenericAPIError{Code: "MessageRejected", Message: "PRIVATE"}, "", Rejected}, {errors.New("network lost PRIVATE"), "", Uncertain}, {nil, "", Uncertain},
	} {
		f.sendErr, f.messageID = tc.err, tc.id
		before := f.sent
		result := adapter.Send(context.Background(), m)
		if result.Outcome != tc.want || f.sent != before+1 || strings.Contains(fmt.Sprint(result), "PRIVATE") {
			t.Fatal("unsafe SES attempt", result, f.sent)
		}
	}
	m.sender = "arbitrary@example.test"
	before := f.sent
	if result := adapter.Send(context.Background(), m); result.Outcome != Rejected || f.sent != before {
		t.Fatal("sender binding bypass")
	}
}

func TestGmailAdapterSingleAttemptAndUncertainty(t *testing.T) {
	status, sends := 200, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			_, _ = w.Write([]byte(`{"access_token":"synthetic","expires_in":3600,"token_type":"Bearer"}`))
		case "/sender":
			_, _ = w.Write([]byte(`{"sendAs":[{"sendAsEmail":"onboarding@example.test","isPrimary":true,"verificationStatus":"accepted"}]}`))
		case "/send":
			sends++
			var body struct {
				Raw string `json:"raw"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				t.Error("invalid MIME envelope")
			}
			raw, _ := base64.RawURLEncoding.DecodeString(body.Raw)
			for _, line := range strings.Split(string(raw), "\r\n") {
				if len(line) > 998 {
					t.Error("invalid MIME line length")
				}
			}
			w.WriteHeader(status)
			if status == 200 {
				_, _ = w.Write([]byte(`{"id":"safe-provider-id"}`))
			}
		default:
			t.Error("unexpected provider request")
		}
	}))
	defer server.Close()
	g := NewGmail("synthetic-client", "synthetic-secret", "https://app.example.test/callback")
	g.config.Endpoint.TokenURL, g.sendAsURL, g.sendURL = server.URL+"/token", server.URL+"/sender", server.URL+"/send"
	g.client = server.Client()
	store := privateStore(t)
	binding := CredentialBinding{"installation", "test", "connector", "version", "onboarding@example.test"}
	credential := GmailCredential{RefreshToken: "synthetic-refresh", Mailbox: binding.Sender, Scopes: GmailScope + " " + GmailSenderScope}
	if err := store.Save(context.Background(), binding, credential); err != nil {
		t.Fatal(err)
	}
	adapter := &GmailAdapter{Gmail: g, Store: store, Binding: binding}
	m := Message{sender: binding.Sender, recipient: "employee@example.test", subject: "Invitation", text: strings.Repeat("Hello ", 500), reference: "vgca.12345678-1234-4234-8234-123456789abc"}
	for _, tc := range []struct {
		status int
		want   Outcome
	}{{200, Accepted}, {403, Rejected}, {503, Uncertain}, {408, Uncertain}} {
		status = tc.status
		before := sends
		if result := adapter.Send(context.Background(), m); result.Outcome != tc.want || sends != before+1 {
			t.Fatal("unsafe Gmail attempt", result, sends)
		}
	}
	m.sender = "arbitrary@example.test"
	before := sends
	if result := adapter.Send(context.Background(), m); result.Outcome != Rejected || sends != before {
		t.Fatal("sender binding bypass")
	}
	credential.RefreshExpiresAt = time.Now().Add(-time.Hour)
	if _, result := g.Refresh(context.Background(), credential, binding.Sender); result.Status != AuthenticationFailed {
		t.Fatal("expired credential accepted")
	}
}
