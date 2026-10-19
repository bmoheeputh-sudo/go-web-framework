package authconfig

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
)

const settingsPath = "/api/admin/auth/settings"
const statusPath = "/api/admin/auth/status"
const apiOrigin = "https://app.example.test"
const apiSecret = "fake-api-secret-not-a-real-credential"

func configHandler(f *fixture, repo *Repository, provider auth.Authenticator) http.Handler {
	mux := http.NewServeMux()
	// Repository authorization uses the fixture's verified synthetic identity;
	// runtime status uses the real request-capture path, never database revisions.
	local, err := auth.NewLocalDev("development", auth.LocalDevConfig{
		Subject: "status-only", Email: "status@example.invalid", DisplayName: "Status Fixture",
	})
	if err != nil {
		panic(err)
	}
	runtime, err := auth.NewEnvironmentRuntime(local, "installation-a", "development")
	if err != nil {
		panic(err)
	}
	Register(mux, provider, f.store, apiOrigin, repo, runtime.Status)
	return runtime.Capture(mux)
}
func apiRequest(t *testing.T, handler http.Handler, method, path string, body any, want int) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	switch value := body.(type) {
	case string:
		reader = strings.NewReader(value)
	case io.Reader:
		reader = value
	default:
		if value != nil {
			data, err := json.Marshal(value)
			if err != nil {
				t.Fatal("test request encoding failed")
			}
			reader = bytes.NewReader(data)
		}
	}
	request := httptest.NewRequest(method, path, reader)
	request.Header.Set("Origin", apiOrigin)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	checkAPIResponse(t, response, want)
	return response
}
func checkAPIResponse(t *testing.T, response *httptest.ResponseRecorder, want int) {
	t.Helper()
	if strings.Contains(response.Body.String(), apiSecret) || strings.Contains(response.Body.String(), `"client_secret"`) || strings.Contains(response.Body.String(), `"secret_ciphertext"`) || strings.Contains(response.Body.String(), `"secret_nonce"`) {
		t.Fatal("response exposed secret material")
	}
	if response.Code != want {
		t.Fatalf("status %d, want %d", response.Code, want)
	}
	if response.Header().Get("Content-Type") != "application/json" || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("missing JSON or no-store headers")
	}
	var value any
	if json.Unmarshal(response.Body.Bytes(), &value) != nil {
		t.Fatal("invalid response JSON")
	}
	if want >= 400 {
		var failure map[string]string
		if json.Unmarshal(response.Body.Bytes(), &failure) != nil || len(failure) != 1 || failure["error"] == "" {
			t.Fatal("invalid error envelope")
		}
		for _, internal := range []string{"postgres", "SQL", "cipher", "password", "connection", "23505"} {
			if strings.Contains(failure["error"], internal) {
				t.Fatal("internal error leaked")
			}
		}
	}
}
func oidcDraft(version int64) map[string]any {
	return map[string]any{"expected_latest_version": version, "provider": "oidc", "issuer_url": "https://offline-idp.example.invalid", "client_id": "test-client", "client_secret": apiSecret, "redirect_uri": apiOrigin + "/api/auth/callback"}
}
func metadataResponse(t *testing.T, response *httptest.ResponseRecorder) Metadata {
	t.Helper()
	var m Metadata
	if json.Unmarshal(response.Body.Bytes(), &m) != nil || m.ID == "" {
		t.Fatal("invalid metadata")
	}
	return m
}

type denyHTTP struct{ calls atomic.Int64 }

func (d *denyHTTP) RoundTrip(*http.Request) (*http.Response, error) {
	d.calls.Add(1)
	return nil, errors.New("network forbidden during configuration management")
}

func TestAuthConfigurationHTTPWorkflow(t *testing.T) {
	transport := &denyHTTP{}
	original := http.DefaultTransport
	http.DefaultTransport = transport
	defer func() {
		http.DefaultTransport = original
		if transport.calls.Load() != 0 {
			t.Error("configuration management attempted network access")
		}
	}()
	f := newFixture(t)
	handler := configHandler(f, f.repo, fixedAuth{f.identity})
	response := apiRequest(t, handler, "GET", statusPath, nil, 200)
	var status struct {
		RuntimeProvider auth.Provider `json:"runtime_provider"`
		RuntimeSource   string        `json:"runtime_source"`
		ManagementOnly  bool          `json:"management_only"`
		ValidationMode  string        `json:"validation_mode"`
		Latest          *Metadata     `json:"latest_revision"`
		Active          *Metadata     `json:"database_active_revision"`
	}
	if json.Unmarshal(response.Body.Bytes(), &status) != nil || status.RuntimeProvider != auth.LocalDev || status.RuntimeSource != "environment" || !status.ManagementOnly || status.ValidationMode != "offline_static" || status.Latest != nil || status.Active != nil {
		t.Fatal("incorrect initial runtime/database status")
	}
	response = apiRequest(t, handler, "POST", settingsPath, oidcDraft(0), 201)
	m := metadataResponse(t, response)
	if !m.HasSecret || m.Version != 1 || m.Generation != 1 || m.Status != Draft || response.Header().Get("Location") != settingsPath+"/"+m.ID {
		t.Fatal("incorrect created revision")
	}
	var ciphertext []byte
	if err := f.owner.QueryRow(context.Background(), `SELECT secret_ciphertext FROM framework.auth_config_revisions WHERE id=$1`, m.ID).Scan(&ciphertext); err != nil || len(ciphertext) <= 16 || bytes.Contains(ciphertext, []byte(apiSecret)) {
		t.Fatal("secret not encrypted at rest")
	}
	read := metadataResponse(t, apiRequest(t, handler, "GET", settingsPath+"/"+m.ID, nil, 200))
	if read.ID != m.ID || !read.HasSecret {
		t.Fatal("wrong metadata")
	}
	response = apiRequest(t, handler, "GET", settingsPath+"?limit=1", nil, 200)
	var list struct {
		Revisions []Metadata `json:"revisions"`
		Next      int64      `json:"next_before_version"`
	}
	if json.Unmarshal(response.Body.Bytes(), &list) != nil || len(list.Revisions) != 1 || list.Revisions[0].ID != m.ID || list.Next != 1 {
		t.Fatal("incorrect list")
	}
	response = apiRequest(t, handler, "GET", settingsPath+"?before_version=1", nil, 200)
	if json.Unmarshal(response.Body.Bytes(), &list) != nil || len(list.Revisions) != 0 || list.Next != 0 {
		t.Fatal("incorrect pagination")
	}
	apiRequest(t, handler, "POST", settingsPath, oidcDraft(0), 409)
	path := settingsPath + "/" + m.ID
	apiRequest(t, handler, "POST", path+"/approve", map[string]int{"expected_generation": 1}, 400)
	validated := metadataResponse(t, apiRequest(t, handler, "POST", path+"/validate", map[string]int{"expected_generation": 1}, 200))
	if validated.Status != Validated || validated.Generation != 2 || validated.Validation.Check != "static" || validated.Validation.Version != 1 {
		t.Fatal("incorrect offline validation")
	}
	apiRequest(t, handler, "POST", path+"/validate", map[string]int{"expected_generation": 1}, 409)
	approved := metadataResponse(t, apiRequest(t, handler, "POST", path+"/approve", map[string]int{"expected_generation": 2}, 200))
	if approved.Status != Approved || approved.Generation != 3 {
		t.Fatal("incorrect approval")
	}
	apiRequest(t, handler, "POST", path+"/approve", map[string]int{"expected_generation": 2}, 409)
	response = apiRequest(t, handler, "GET", statusPath, nil, 200)
	if json.Unmarshal(response.Body.Bytes(), &status) != nil || status.Latest == nil || status.Latest.Status != Approved || status.Active != nil || status.RuntimeProvider != auth.LocalDev {
		t.Fatal("approval implied runtime activation")
	}
	var actions []string
	rows, err := f.owner.Query(context.Background(), `SELECT action,actor_user_id::text,details::text FROM framework.audit_log WHERE target_id=$1 ORDER BY id`, m.ID)
	if err != nil {
		t.Fatal("audit query failed")
	}
	defer rows.Close()
	for rows.Next() {
		var action, actor, details string
		if rows.Scan(&action, &actor, &details) != nil || actor != m.CreatedBy || strings.Contains(details, apiSecret) {
			t.Fatal("unsafe audit")
		}
		actions = append(actions, action)
	}
	if rows.Err() != nil || strings.Join(actions, ",") != "auth_config.draft_created,auth_config.validated,auth_config.approved" {
		t.Fatal("missing lifecycle audits")
	}
	// Existing active database state still must not be reported as the runtime source.
	if _, err := f.owner.Exec(context.Background(), `UPDATE framework.auth_config_lifecycle SET status='active',generation=generation+1 WHERE revision_id=$1`, m.ID); err != nil {
		t.Fatal(err)
	}
	response = apiRequest(t, handler, "GET", statusPath, nil, 200)
	if json.Unmarshal(response.Body.Bytes(), &status) != nil || status.Active == nil || status.Active.ID != m.ID || status.RuntimeProvider != auth.LocalDev || status.RuntimeSource != "environment" || !status.ManagementOnly {
		t.Fatal("database active state confused with runtime")
	}
	for version, body := range []map[string]any{
		{"expected_latest_version": 1, "provider": "google_iap", "iap_audience": "/projects/123/global/backendServices/456"},
		{"expected_latest_version": 2, "provider": "local_dev"},
	} {
		added := metadataResponse(t, apiRequest(t, handler, "POST", settingsPath, body, 201))
		if added.HasSecret || added.Version != int64(version+2) {
			t.Fatal("incorrect non-OIDC draft")
		}
	}
}

func TestAuthConfigurationHTTPAuthorizationAndIsolation(t *testing.T) {
	f := newFixture(t)
	m := f.draft(t, 0)
	paths := []struct{ method, path string }{{"GET", settingsPath}, {"GET", settingsPath + "/" + m.ID}, {"POST", settingsPath}, {"POST", settingsPath + "/" + m.ID + "/validate"}, {"POST", settingsPath + "/" + m.ID + "/approve"}, {"GET", statusPath}}
	for _, role := range []string{"User", "Viewer", "None", "Unauthenticated"} {
		t.Run(role, func(t *testing.T) {
			var provider auth.Authenticator
			want := 401
			if role != "Unauthenticated" {
				identity := auth.Identity{Issuer: f.identity.Issuer, Subject: "api-" + role, Provider: auth.OIDC}
				user, err := f.store.Resolve(context.Background(), identity)
				if err != nil {
					t.Fatal(err)
				}
				if role != "None" {
					if _, err = f.owner.Exec(context.Background(), `INSERT INTO framework.user_roles(user_id,role) VALUES($1,$2)`, user.ID, role); err != nil {
						t.Fatal(err)
					}
				}
				provider = fixedAuth{identity}
				want = 403
			}
			handler := configHandler(f, f.repo, provider)
			before := f.counts(t)
			for _, route := range paths {
				apiRequest(t, handler, route.method, route.path, `{}`, want)
			}
			if f.counts(t) != before {
				t.Fatal("denied access changed configuration")
			}
		})
	}
	handler := configHandler(f, f.repo, fixedAuth{f.identity})
	for _, scope := range []Scope{{"other", "development"}, {"installation-a", "test"}, {"installation-a", "production"}} {
		other, err := NewRepository(f.store, scope, f.repo.cipher)
		if err != nil {
			t.Fatal(err)
		}
		h := configHandler(f, other, fixedAuth{f.identity})
		apiRequest(t, h, "GET", settingsPath+"/"+m.ID, nil, 404)
		apiRequest(t, h, "POST", settingsPath+"/"+m.ID+"/validate", map[string]int{"expected_generation": 1}, 404)
		apiRequest(t, h, "POST", settingsPath+"/"+m.ID+"/approve", map[string]int{"expected_generation": 1}, 404)
		response := apiRequest(t, h, "GET", settingsPath, nil, 200)
		if strings.Contains(response.Body.String(), m.ID) {
			t.Fatal("cross-scope list")
		}
		apiRequest(t, h, "POST", settingsPath, oidcDraft(0), 201)
		if scope.Environment != "development" {
			apiRequest(t, h, "POST", settingsPath, map[string]any{"expected_latest_version": 1, "provider": "local_dev"}, 400)
			body := oidcDraft(1)
			body["allow_http_development"] = true
			body["redirect_uri"] = "http://localhost/api/auth/callback"
			apiRequest(t, h, "POST", settingsPath, body, 400)
		}
	}
	apiRequest(t, handler, "GET", settingsPath+"/11111111-1111-4111-8111-111111111111", nil, 404)
	if _, err := f.owner.Exec(context.Background(), `UPDATE framework.users SET active=false WHERE subject='config-admin'`); err != nil {
		t.Fatal(err)
	}
	for _, route := range paths {
		apiRequest(t, handler, route.method, route.path, `{}`, 403)
	}
}

func TestAuthConfigurationHTTPInvalidRequestsAndAvailability(t *testing.T) {
	f := newFixture(t)
	handler := configHandler(f, f.repo, fixedAuth{f.identity})
	m := f.draft(t, 0)
	before := f.counts(t)
	for _, body := range []any{`null`, `{}`, `[]`, `{`, `{} {}`, strings.Repeat(" ", 16*1024) + `{}`, map[string]any{"provider": "local_dev"}, map[string]any{"provider": "local_dev", "expected_latest_version": nil}} {
		apiRequest(t, handler, "POST", settingsPath, body, 400)
	}
	for _, field := range []string{"actor", "created_by", "deployment_id", "environment", "status", "encryption_key_id", "configuration_version"} {
		body := oidcDraft(1)
		body[field] = "forged"
		apiRequest(t, handler, "POST", settingsPath, body, 400)
	}
	for _, change := range []map[string]any{{"provider": "unknown"}, {"client_secret": ""}, {"issuer_url": "http://idp.test"}, {"redirect_uri": "https://app.test/not-callback"}, {"expected_latest_version": -1}, {"expected_latest_version": "1"}, {"iap_audience": "mixed"}} {
		body := oidcDraft(1)
		for k, v := range change {
			body[k] = v
		}
		apiRequest(t, handler, "POST", settingsPath, body, 400)
	}
	for _, suffix := range []string{"?limit=0", "?limit=101", "?before_version=-1", "?limit=1&limit=2", "?limit=no", "?deployment_id=other", "?bad=%zz"} {
		apiRequest(t, handler, "GET", settingsPath+suffix, nil, 400)
	}
	apiRequest(t, handler, "GET", settingsPath+"/malformed", nil, 400)
	for _, body := range []string{`null`, `{}`, `{"expected_generation":null}`, `{"expected_generation":0}`, `{"expected_generation":1,"actor":"forged"}`} {
		for _, action := range []string{"validate", "approve"} {
			apiRequest(t, handler, "POST", settingsPath+"/"+m.ID+"/"+action, body, 400)
		}
	}
	for _, path := range []string{settingsPath, settingsPath + "/" + m.ID + "/validate", settingsPath + "/" + m.ID + "/approve"} {
		for _, headers := range []http.Header{{}, {"Origin": {apiOrigin}}, {"Origin": {"https://evil.test"}, "Content-Type": {"application/json"}}, {"Origin": {apiOrigin, apiOrigin}, "Content-Type": {"application/json"}}, {"Origin": {apiOrigin}, "Content-Type": {"text/plain"}}} {
			r := httptest.NewRequest("POST", path, strings.NewReader(`{}`))
			r.Header = headers
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			checkAPIResponse(t, w, 403)
		}
	}
	if before != f.counts(t) {
		t.Fatal("invalid requests changed database")
	}
	for _, path := range []string{settingsPath, statusPath} {
		apiRequest(t, configHandler(f, nil, fixedAuth{f.identity}), "GET", path, nil, 503)
	}
	// A lost/wrong key must never be replaced automatically or leak crypto details.
	wrong, err := NewRepository(f.store, f.repo.scope, testCipher(t, "other-key"))
	if err != nil {
		t.Fatal(err)
	}
	apiRequest(t, configHandler(f, wrong, fixedAuth{f.identity}), "POST", settingsPath+"/"+m.ID+"/validate", map[string]int{"expected_generation": 1}, 503)
	f.pool.Close()
	apiRequest(t, handler, "GET", settingsPath, nil, 503)
}

// Revocation occurs during body decoding: after HTTP authorization, before the
// repository obtains its lock and rechecks the verified principal.
type revokingReader struct {
	io.Reader
	once   sync.Once
	revoke func()
}

func (r *revokingReader) Read(p []byte) (int, error) { r.once.Do(r.revoke); return r.Reader.Read(p) }
func TestAuthConfigurationHTTPAtomicityAndRecheck(t *testing.T) {
	f := newFixture(t)
	handler := configHandler(f, f.repo, fixedAuth{f.identity})
	pending := f.draft(t, 0)
	validated := f.draft(t, 1)
	apiRequest(t, handler, "POST", settingsPath+"/"+validated.ID+"/validate", map[string]int{"expected_generation": 1}, 200)
	if _, err := f.owner.Exec(context.Background(), `REVOKE INSERT ON framework.audit_log FROM go_web_app`); err != nil {
		t.Fatal(err)
	}
	before := f.counts(t)
	apiRequest(t, handler, "POST", settingsPath, oidcDraft(2), 503)
	apiRequest(t, handler, "POST", settingsPath+"/"+pending.ID+"/validate", map[string]int{"expected_generation": 1}, 503)
	apiRequest(t, handler, "POST", settingsPath+"/"+validated.ID+"/approve", map[string]int{"expected_generation": 2}, 503)
	if before != f.counts(t) {
		t.Fatal("audit failure committed partial changes")
	}
	if _, err := f.owner.Exec(context.Background(), `GRANT INSERT ON framework.audit_log TO go_web_app`); err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{`DELETE FROM framework.user_roles WHERE role='Admin'`, `UPDATE framework.users SET active=false WHERE subject='config-admin'`} {
		body, _ := json.Marshal(oidcDraft(2))
		reader := &revokingReader{Reader: bytes.NewReader(body), revoke: func() {
			if _, err := f.owner.Exec(context.Background(), sql); err != nil {
				t.Fatal(err)
			}
		}}
		apiRequest(t, handler, "POST", settingsPath, reader, 403)
		if before != f.counts(t) {
			t.Fatal("revoked principal committed changes")
		}
		if _, err := f.owner.Exec(context.Background(), `UPDATE framework.users SET active=true WHERE subject='config-admin'; INSERT INTO framework.user_roles(user_id,role) SELECT id,'Admin' FROM framework.users WHERE subject='config-admin' ON CONFLICT DO NOTHING`); err != nil {
			t.Fatal(err)
		}
	}
}
func TestAuthConfigurationHTTPConcurrentDrafts(t *testing.T) {
	f := newFixture(t)
	handler := configHandler(f, f.repo, fixedAuth{f.identity})
	var wg sync.WaitGroup
	statuses := make(chan int, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body, _ := json.Marshal(oidcDraft(0))
			r := httptest.NewRequest("POST", settingsPath, bytes.NewReader(body))
			r.Header.Set("Origin", apiOrigin)
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			statuses <- w.Code
		}()
	}
	wg.Wait()
	close(statuses)
	counts := map[int]int{}
	for status := range statuses {
		counts[status]++
	}
	if counts[201] != 1 || counts[409] != 1 {
		t.Fatal("concurrent create did not detect conflict")
	}
	response := apiRequest(t, handler, "GET", settingsPath, nil, 200)
	var list struct {
		Revisions []Metadata `json:"revisions"`
	}
	if json.Unmarshal(response.Body.Bytes(), &list) != nil || len(list.Revisions) != 1 {
		t.Fatal("conflicting revision persisted")
	}
	apiRequest(t, handler, "GET", settingsPath+"?before_version="+strconv.FormatInt(list.Revisions[0].Version, 10), nil, 200)
}
func TestRepositoryFromEnvUnavailable(t *testing.T) {
	for _, values := range []map[string]string{{}, {"AUTH_CONFIG_DEPLOYMENT": "test", "APP_ENV": "development"}, {"AUTH_CONFIG_DEPLOYMENT": "test", "APP_ENV": "development", "AUTH_ENCRYPTION_KEY": "invalid", "AUTH_ENCRYPTION_KEY_ID": "key-v1"}} {
		if repo, err := RepositoryFromEnv(nil, func(k string) string { return values[k] }); repo != nil || err == nil {
			t.Fatal("unconfigured management service accepted")
		}
	}
}

func TestRepositoryFromEnvConfiguration(t *testing.T) {
	f := newFixture(t)
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal("test key unavailable")
	}
	values := map[string]string{"AUTH_CONFIG_DEPLOYMENT": "test-installation", "APP_ENV": "TEST", "AUTH_ENCRYPTION_KEY_ID": "test-key", "AUTH_ENCRYPTION_KEY": base64.StdEncoding.EncodeToString(key[:])}
	clear(key[:])
	repo, err := RepositoryFromEnv(f.store, func(k string) string { return values[k] })
	if err != nil || repo.scope != (Scope{"test-installation", "test"}) || repo.cipher.keyID != "test-key" {
		t.Fatal("management scope/key configuration not loaded")
	}
	for _, field := range []string{"AUTH_CONFIG_DEPLOYMENT", "APP_ENV", "AUTH_ENCRYPTION_KEY_ID", "AUTH_ENCRYPTION_KEY"} {
		original := values[field]
		values[field] = ""
		if repo, err := RepositoryFromEnv(f.store, func(k string) string { return values[k] }); err == nil || repo != nil {
			t.Fatal("missing management configuration accepted")
		}
		values[field] = original
	}
}

func TestAuthConfigurationHTTPStatusLocalDevWithoutDatabaseConfiguration(t *testing.T) {
	f := newFixture(t)
	provider, err := auth.NewLocalDev("development", auth.LocalDevConfig{
		Subject: "status-local-admin", Email: "status-admin@example.invalid", DisplayName: "Status Test Admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	verifiedRequest := httptest.NewRequest("GET", statusPath, nil)
	verifiedRequest.RemoteAddr = "127.0.0.1:4321"
	identity, err := provider.Authenticate(verifiedRequest)
	if err != nil {
		t.Fatal(err)
	}
	user, err := f.store.Resolve(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	// Explicit fixture grant only; Local DEV never gains Admin automatically.
	if _, err := f.owner.Exec(context.Background(), `INSERT INTO framework.user_roles(user_id,role) VALUES($1,'Admin')`, user.ID); err != nil {
		t.Fatal(err)
	}
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal("test key unavailable")
	}
	values := map[string]string{
		"APP_ENV": "development", "AUTH_PROVIDER": "local_dev", "AUTH_CONFIG_DEPLOYMENT": "local-dev",
		"AUTH_ENCRYPTION_KEY_ID": "key-v1", "AUTH_ENCRYPTION_KEY": base64.StdEncoding.EncodeToString(key[:]),
	}
	clear(key[:])
	repo, err := RepositoryFromEnv(f.store, func(name string) string { return values[name] })
	if err != nil {
		t.Fatal("test management initialization failed")
	}
	handler := configHandler(f, repo, provider)
	before := f.counts(t)
	var revisions int
	if err := f.owner.QueryRow(context.Background(), `SELECT count(*) FROM framework.auth_config_revisions`).Scan(&revisions); err != nil || revisions != 0 {
		t.Fatal("expected no database authentication configuration")
	}
	request := httptest.NewRequest("GET", statusPath, nil)
	request.RemoteAddr = "127.0.0.1:4321"
	request.Header.Set("Cache-Control", "no-cache")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	checkAPIResponse(t, response, http.StatusOK)
	var result struct {
		RuntimeProvider auth.Provider `json:"runtime_provider"`
		RuntimeSource   string        `json:"runtime_source"`
		ManagementOnly  bool          `json:"management_only"`
		Latest          *Metadata     `json:"latest_revision"`
		Active          *Metadata     `json:"database_active_revision"`
	}
	if json.Unmarshal(response.Body.Bytes(), &result) != nil || result.RuntimeProvider != auth.LocalDev || result.RuntimeSource != "environment" || !result.ManagementOnly || result.Latest != nil || result.Active != nil {
		t.Fatal("empty database configuration rejected or confused with runtime authentication")
	}
	// Status takes no query parameters. A caller-supplied scope or cache-buster
	// reproduces the generic invalid-request response, independently of settings.
	for _, query := range []string{"_=1", "deployment_id=local-dev", "environment=development"} {
		withQuery := request.Clone(request.Context())
		withQuery.URL.RawQuery = query
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, withQuery)
		checkAPIResponse(t, response, http.StatusBadRequest)
		var failure map[string]string
		if json.Unmarshal(response.Body.Bytes(), &failure) != nil || failure["error"] != "auth_config_invalid" {
			t.Fatal("unexpected status query rejection")
		}
	}
	if before != f.counts(t) {
		t.Fatal("status request changed database configuration or audit records")
	}
	// Preserve the real provider's loopback restriction and framework authorization.
	request.RemoteAddr = "192.0.2.1:4321"
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	checkAPIResponse(t, response, http.StatusUnauthorized)
	request.RemoteAddr = "127.0.0.1:4321"
	if _, err := f.owner.Exec(context.Background(), `UPDATE framework.users SET active=false WHERE id=$1`, user.ID); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	checkAPIResponse(t, response, http.StatusForbidden)
}
