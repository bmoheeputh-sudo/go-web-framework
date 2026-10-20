package authconfig

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
)

func activationAPIHandler(t *testing.T, f *fixture, service *ActivationService, provider auth.Authenticator) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	service.runtime.RegisterRoutes(mux)
	closeManagement := Register(mux, provider, f.store, apiOrigin, f.repo, service, service.runtime.Status)
	t.Cleanup(closeManagement)
	return service.runtime.Capture(mux)
}

func prepareThroughAPI(t *testing.T, h http.Handler, m Metadata, generation int64) preparationResponse {
	t.Helper()
	w := apiRequest(t, h, http.MethodPost, settingsPath+"/"+m.ID+"/activation/prepare", map[string]any{
		"expected_revision_generation":   m.Generation,
		"expected_activation_generation": generation,
	}, http.StatusCreated)
	var result preparationResponse
	if json.Unmarshal(w.Body.Bytes(), &result) != nil || result.ID == "" || result.RevisionID != m.ID {
		t.Fatal("invalid activation preparation response")
	}
	return result
}

func TestActivationHTTPNormalCallbackAndFirstCutover(t *testing.T) {
	f, service, issuer, revision := activationServiceFixture(t)
	issuer.callback = apiOrigin + "/api/auth/callback"
	issuer.claims = func(claims map[string]any) { claims["sub"] = "enrolled-admin" }
	h := activationAPIHandler(t, f, service, fixedAuth{f.identity})
	request, enrolledUser := activationReadiness(t, f, revision, "")
	statusResponse := apiRequest(t, h, http.MethodGet, statusPath, nil, http.StatusOK)
	var managementStatus struct {
		ManagementOnly      bool `json:"management_only"`
		ActivationAvailable bool `json:"activation_api_available"`
	}
	if json.Unmarshal(statusResponse.Body.Bytes(), &managementStatus) != nil || managementStatus.ManagementOnly || !managementStatus.ActivationAvailable {
		t.Fatal("status did not report activation API availability")
	}
	apiRequest(t, h, http.MethodPost, settingsPath+"/"+revision.ID+"/activation/prepare", map[string]any{
		"expected_revision_generation": revision.Generation, "expected_activation_generation": 0, "actor": "forged",
	}, http.StatusBadRequest)

	prepared := prepareThroughAPI(t, h, revision, 0)
	if !prepared.RequiresReauthentication || prepared.MaximumTransitionSeconds != 0 || prepared.Warning != "immediate_reauthentication_required" || prepared.TargetGeneration != 1 {
		t.Fatal("first cutover did not disclose immediate reauthentication")
	}
	apiRequest(t, h, http.MethodPost, "/api/admin/auth/activation-preparations/"+prepared.ID+"/activate", map[string]any{
		"revision_id": revision.ID, "expected_revision_generation": revision.Generation,
		"expected_activation_generation": 0, "isolated_evidence_id": request.IsolatedEvidenceID,
		"normal_evidence_id": request.NormalEvidenceID, "enrolled_user_id": enrolledUser,
		"transition_seconds": 1, "acknowledge_reauthentication": true, "confirm": true,
		"reason": "approved first cutover",
	}, http.StatusBadRequest)

	w := apiRequest(t, h, http.MethodPost, "/api/admin/auth/activation-preparations/"+prepared.ID+"/readiness", map[string]any{}, http.StatusCreated)
	var started struct {
		Status           string `json:"status"`
		AuthorizationURL string `json:"authorization_url"`
		CallbackURL      string `json:"callback_url"`
	}
	if json.Unmarshal(w.Body.Bytes(), &started) != nil || started.Status != "pending" || started.CallbackURL != apiOrigin+"/api/auth/callback" {
		t.Fatal("invalid normal callback readiness response")
	}
	authorization, err := url.Parse(started.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	query := authorization.Query()
	if query.Get("redirect_uri") != apiOrigin+"/api/auth/callback" || query.Get("code_challenge_method") != "S256" {
		t.Fatal("readiness did not use the normal PKCE callback")
	}
	issuer.mu.Lock()
	issuer.nonce = query.Get("nonce")
	issuer.challenge = query.Get("code_challenge")
	issuer.mu.Unlock()
	var readinessCookie *http.Cookie
	for _, cookie := range w.Result().Cookies() {
		if strings.Contains(cookie.Name, "oidc_readiness") {
			readinessCookie = cookie
		}
	}
	if readinessCookie == nil || !readinessCookie.HttpOnly || !readinessCookie.Secure {
		t.Fatal("missing secure readiness cookie")
	}
	callback := httptest.NewRequest(http.MethodGet, "/api/auth/callback?"+url.Values{
		"state": {query.Get("state")}, "code": {"synthetic-code"},
	}.Encode(), nil)
	callback.AddCookie(readinessCookie)
	callbackResponse := httptest.NewRecorder()
	h.ServeHTTP(callbackResponse, callback)
	if callbackResponse.Code != http.StatusSeeOther || callbackResponse.Header().Get("Location") != apiOrigin+"/?auth_test=completed" {
		t.Fatal("normal callback readiness failed")
	}
	var sessionCount int
	if err := f.owner.QueryRow(context.Background(), `SELECT count(*) FROM framework.sessions`).Scan(&sessionCount); err != nil || sessionCount != 0 {
		t.Fatal("readiness callback created an application session")
	}
	statusResponse = apiRequest(t, h, http.MethodGet, "/api/admin/auth/activation-preparations/"+prepared.ID, nil, http.StatusOK)
	var status preparationResponse
	if json.Unmarshal(statusResponse.Body.Bytes(), &status) != nil || status.NormalCallbackStatus != "succeeded" || status.NormalEvidenceID == "" {
		t.Fatal("normal callback evidence was not reported")
	}

	activationResponse := apiRequest(t, h, http.MethodPost, "/api/admin/auth/activation-preparations/"+prepared.ID+"/activate", map[string]any{
		"revision_id": revision.ID, "expected_revision_generation": revision.Generation,
		"expected_activation_generation": 0, "isolated_evidence_id": request.IsolatedEvidenceID,
		"normal_evidence_id": status.NormalEvidenceID, "enrolled_user_id": enrolledUser,
		"transition_seconds": 0, "acknowledge_reauthentication": true, "confirm": true,
		"reason": "approved first cutover",
	}, http.StatusOK)
	var result ActivationResult
	if json.Unmarshal(activationResponse.Body.Bytes(), &result) != nil || !result.Committed || !result.Applied || result.DesiredGeneration != 1 || result.AppliedGeneration != 1 {
		t.Fatal("activation result did not report desired and applied state")
	}
	apiRequest(t, h, http.MethodPost, "/api/admin/auth/activation-preparations/"+prepared.ID+"/activate", map[string]any{
		"revision_id": revision.ID, "expected_revision_generation": revision.Generation,
		"expected_activation_generation": 0, "transition_seconds": 0, "confirm": true,
		"reason": "duplicate activation attempt",
	}, http.StatusNotFound)
}

func TestActivationHTTPRecoveryCreatesImmutableDraftOnly(t *testing.T) {
	f, service, _, historical := activationServiceFixture(t)
	h := activationAPIHandler(t, f, service, fixedAuth{f.identity})
	if _, err := f.owner.Exec(context.Background(), `UPDATE framework.auth_config_lifecycle SET status='active',generation=generation+1 WHERE revision_id=$1`, historical.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.Exec(context.Background(), `UPDATE framework.auth_config_lifecycle SET status='superseded',generation=generation+1 WHERE revision_id=$1`, historical.ID); err != nil {
		t.Fatal(err)
	}
	w := apiRequest(t, h, http.MethodPost, settingsPath+"/"+historical.ID+"/rollback", map[string]any{
		"expected_latest_version": historical.Version,
		"confirm":                 true,
		"reason":                  "restore last verified provider settings",
	}, http.StatusCreated)
	var result struct {
		Revision           Metadata `json:"revision"`
		ActivationRequired bool     `json:"activation_required"`
	}
	if json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Revision.ID == historical.ID || result.Revision.Status != Draft || !result.ActivationRequired {
		t.Fatal("rollback did not create a new immutable recovery draft")
	}
	var activeCount int
	var details string
	if err := f.owner.QueryRow(context.Background(), `SELECT count(*) FROM framework.auth_config_lifecycle WHERE status='active'`).Scan(&activeCount); err != nil || activeCount != 0 {
		t.Fatal("recovery draft changed active authentication")
	}
	if err := f.owner.QueryRow(context.Background(), `SELECT details::text FROM framework.audit_log WHERE action='auth_config.recovery_draft' AND target_id=$1`, result.Revision.ID).Scan(&details); err != nil || !strings.Contains(details, historical.ID) || !strings.Contains(details, "restore last verified") {
		t.Fatal("recovery draft lacked atomic provenance and reason")
	}
	apiRequest(t, h, http.MethodPost, settingsPath+"/"+historical.ID+"/rollback", map[string]any{
		"expected_latest_version": historical.Version, "confirm": true, "reason": "stale recovery request",
	}, http.StatusConflict)
}

func TestActivationHTTPSubsequentCutoverBoundsGrace(t *testing.T) {
	f, service, _, first := activationServiceFixture(t)
	request, userID := activationReadiness(t, f, first, "")
	p := prepareActivation(t, f, service, first, 0)
	f.run(t, func(ctx context.Context) {
		if _, err := service.Activate(ctx, p, request); err != nil {
			t.Fatal(err)
		}
	})
	var second Metadata
	f.run(t, func(ctx context.Context) {
		var err error
		second, err = f.repo.CreateDraft(ctx, first.Version, first.Settings, NewSecret([]byte(apiSecret)))
		if err == nil {
			second, err = f.repo.Transition(ctx, second.ID, second.Generation, Validated)
		}
		if err == nil {
			second, err = f.repo.Transition(ctx, second.ID, second.Generation, Approved)
		}
		if err != nil {
			t.Fatal(err)
		}
	})
	h := activationAPIHandler(t, f, service, fixedAuth{f.identity})
	prepared := prepareThroughAPI(t, h, second, 1)
	if prepared.RequiresReauthentication || prepared.MaximumTransitionSeconds != 1800 || prepared.CurrentSource != "database" {
		t.Fatal("database OIDC transition did not report the bounded grace policy")
	}
	apiRequest(t, h, http.MethodPost, "/api/admin/auth/activation-preparations/"+prepared.ID+"/activate", map[string]any{
		"revision_id": second.ID, "expected_revision_generation": second.Generation,
		"expected_activation_generation": 1, "transition_seconds": 1801,
		"isolated_evidence_id": request.IsolatedEvidenceID, "normal_evidence_id": request.NormalEvidenceID,
		"enrolled_user_id": userID, "confirm": true, "reason": "transition exceeds approved grace",
	}, http.StatusBadRequest)
	apiRequest(t, h, http.MethodGet, "/api/admin/auth/activation-preparations/"+prepared.ID, nil, http.StatusOK)
}

func TestActivationHTTPStrictWritesAndUnavailableService(t *testing.T) {
	f := newFixture(t)
	h := configHandler(f, f.repo, fixedAuth{f.identity})
	path := settingsPath + "/11111111-1111-4111-8111-111111111111/activation/prepare"
	apiRequest(t, h, http.MethodPost, path, map[string]int64{"expected_revision_generation": 1, "expected_activation_generation": 0}, http.StatusServiceUnavailable)
	for _, body := range []any{map[string]any{}, map[string]any{"expected_revision_generation": 1, "expected_activation_generation": 0, "actor": "forged"}, strings.Repeat("x", 17*1024)} {
		request := httptest.NewRequest(http.MethodPost, path, nil)
		if encoded, ok := body.(map[string]any); ok {
			data, _ := json.Marshal(encoded)
			request = httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(data)))
		} else {
			request = httptest.NewRequest(http.MethodPost, path, strings.NewReader(body.(string)))
		}
		request.Header.Set("Origin", apiOrigin)
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		h.ServeHTTP(response, request)
		// The unavailable service is checked before parsing; it still fails closed.
		checkAPIResponse(t, response, http.StatusServiceUnavailable)
	}
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
	request.Header.Set("Origin", "https://evil.example")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	checkAPIResponse(t, response, http.StatusForbidden)
}
