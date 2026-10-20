package authconfig

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/jackc/pgx/v5"
)

func activationAPIHandler(t *testing.T, f *fixture, service *ActivationService, provider auth.Authenticator) http.Handler {
	return activationAPIHandlerWithOperations(t, f, service, provider, ActivationOperations{Affinity: ActivationAffinity{Mode: "single_instance"}})
}

func activationAPIHandlerWithOperations(t *testing.T, f *fixture, service *ActivationService, provider auth.Authenticator, operations ActivationOperations) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	service.runtime.RegisterRoutes(mux)
	closeManagement := Register(mux, provider, f.store, apiOrigin, f.repo, service, operations, service.runtime.Status)
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
	if !prepared.RequiresReauthentication || prepared.MaximumTransitionSeconds != 0 || prepared.Warning != "immediate_reauthentication_required" || !prepared.EmergencyRecoveryRequired || prepared.OfflineRecoveryProcedure != "auth-recovery-cli" || prepared.TargetGeneration != 1 {
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
		"acknowledge_emergency_recovery": true,
		"reason":                         "approved first cutover",
	}, http.StatusOK)
	var result ActivationResult
	if json.Unmarshal(activationResponse.Body.Bytes(), &result) != nil || result.CommitPersisted == nil || !*result.CommitPersisted || result.Outcome != ActivationCommittedApplied || !result.Applied || result.DesiredGeneration != 1 || result.AppliedGeneration != 1 || result.AutomaticRetryAllowed {
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

func TestRecoveryReadinessAndProviderOutage(t *testing.T) {
	f, service, _, historical := activationServiceFixture(t)
	if _, err := f.owner.Exec(context.Background(), `UPDATE framework.auth_config_lifecycle SET status='active',generation=generation+1 WHERE revision_id=$1`, historical.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.Exec(context.Background(), `UPDATE framework.auth_config_lifecycle SET status='superseded',generation=generation+1 WHERE revision_id=$1`, historical.ID); err != nil {
		t.Fatal(err)
	}
	var recovery Metadata
	f.run(t, func(ctx context.Context) {
		var err error
		recovery, err = f.repo.PrepareRecoveryDraftWithReason(ctx, historical.ID, historical.Version, "pre-stage the approved recovery provider")
		if err == nil {
			recovery, err = f.repo.Transition(ctx, recovery.ID, recovery.Generation, Validated)
		}
		if err == nil {
			recovery, err = f.repo.Transition(ctx, recovery.ID, recovery.Generation, Approved)
		}
		if err != nil {
			t.Fatal(err)
		}
	})
	activationReadiness(t, f, recovery, "")
	h := activationAPIHandler(t, f, service, fixedAuth{f.identity})
	w := apiRequest(t, h, http.MethodGet, settingsPath+"/"+recovery.ID+"/recovery-readiness", nil, http.StatusOK)
	var readiness RecoveryReadiness
	if json.Unmarshal(w.Body.Bytes(), &readiness) != nil || !readiness.ConfigurationPreStaged || !readiness.EnrolledAdministratorReady || !readiness.FreshIsolatedEvidence || !readiness.FreshNormalCallbackEvidence || !readiness.ReadyForPortalActivation || !readiness.LiveProviderRequired || readiness.OfflineRecoveryProcedure != "auth-recovery-cli" {
		t.Fatal("recovery readiness did not distinguish durable staging from live proof", readiness)
	}
	service.client = func(context.Context, string) (*http.Client, error) {
		return nil, errors.New("synthetic provider outage")
	}
	w = apiRequest(t, h, http.MethodPost, settingsPath+"/"+recovery.ID+"/activation/prepare", map[string]any{
		"expected_revision_generation": recovery.Generation, "expected_activation_generation": 0,
	}, http.StatusServiceUnavailable)
	var failure map[string]any
	if json.Unmarshal(w.Body.Bytes(), &failure) != nil || failure["error"] != "recovery_provider_unavailable" || failure["offline_recovery_procedure"] != "auth-recovery-cli" || failure["recovery_provider_must_be_available"] != true || failure["automatic_retry_allowed"] != false {
		t.Fatal("provider outage did not return safe recovery guidance", failure)
	}
}

func TestActivationPreparationRequiresExplicitAffinityAndOriginatingInstance(t *testing.T) {
	f, service, _, revision := activationServiceFixture(t)
	withoutAffinity := activationAPIHandlerWithOperations(t, f, service, fixedAuth{f.identity}, ActivationOperations{})
	w := apiRequest(t, withoutAffinity, http.MethodPost, settingsPath+"/"+revision.ID+"/activation/prepare", map[string]any{
		"expected_revision_generation": revision.Generation, "expected_activation_generation": 0,
	}, http.StatusServiceUnavailable)
	var failure map[string]any
	if json.Unmarshal(w.Body.Bytes(), &failure) != nil || failure["error"] != "activation_affinity_required" || failure["required_configuration"] != "AUTH_ACTIVATION_AFFINITY_MODE" || failure["automatic_retry_allowed"] != false {
		t.Fatal("missing affinity was not actionable", failure)
	}

	first := activationAPIHandler(t, f, service, fixedAuth{f.identity})
	second := activationAPIHandler(t, f, service, fixedAuth{f.identity})
	prepared := prepareThroughAPI(t, first, revision, 0)
	w = apiRequest(t, second, http.MethodGet, "/api/admin/auth/activation-preparations/"+prepared.ID, nil, http.StatusServiceUnavailable)
	if json.Unmarshal(w.Body.Bytes(), &failure) != nil || failure["error"] != "activation_preparation_wrong_instance" {
		t.Fatal("cross-instance preparation was not identified", failure)
	}
	apiRequest(t, first, http.MethodGet, "/api/admin/auth/activation-preparations/"+prepared.ID, nil, http.StatusOK)
}

func TestActivationAffinityConfigurationIsStrict(t *testing.T) {
	for value, want := range map[string]string{"": "", "single_instance": "single_instance", "session_affinity": "session_affinity"} {
		affinity, err := ActivationAffinityFromEnv(func(string) string { return value })
		if err != nil || affinity.Mode != want {
			t.Fatalf("affinity %q: got %+v, %v", value, affinity, err)
		}
	}
	for _, value := range []string{"round_robin", "sticky", " SINGLE_INSTANCE "} {
		if _, err := ActivationAffinityFromEnv(func(string) string { return value }); !errors.Is(err, ErrInvalid) {
			t.Fatalf("unsafe affinity mode %q accepted", value)
		}
	}
}

func TestNormalCallbackReadinessRejectsAnotherInstanceWithoutConsumingFlow(t *testing.T) {
	f, firstService, issuer, revision := activationServiceFixture(t)
	issuer.callback = apiOrigin + "/api/auth/callback"
	first := activationAPIHandler(t, f, firstService, fixedAuth{f.identity})
	prepared := prepareThroughAPI(t, first, revision, 0)
	w := apiRequest(t, first, http.MethodPost, "/api/admin/auth/activation-preparations/"+prepared.ID+"/readiness", map[string]any{}, http.StatusCreated)
	var started struct {
		Authorization string `json:"authorization_url"`
	}
	if json.Unmarshal(w.Body.Bytes(), &started) != nil {
		t.Fatal("invalid readiness response")
	}
	authorization, err := url.Parse(started.Authorization)
	if err != nil {
		t.Fatal(err)
	}
	query := authorization.Query()
	issuer.mu.Lock()
	issuer.nonce = query.Get("nonce")
	issuer.challenge = query.Get("code_challenge")
	issuer.mu.Unlock()
	var cookie *http.Cookie
	for _, candidate := range w.Result().Cookies() {
		if strings.Contains(candidate.Name, "oidc_readiness") {
			cookie = candidate
		}
	}
	if cookie == nil {
		t.Fatal("missing readiness cookie")
	}

	local, err := auth.NewLocalDev("development", auth.LocalDevConfig{Subject: "second", Email: "second@example.test", DisplayName: "Second"})
	if err != nil {
		t.Fatal(err)
	}
	secondRuntime, err := auth.NewEnvironmentRuntime(local, f.repo.scope.DeploymentID, f.repo.scope.Environment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(secondRuntime.Close)
	secondService, err := NewActivationService(f.repo, secondRuntime, firstService.store, firstService.sessions, firstService.callback)
	if err != nil {
		t.Fatal(err)
	}
	secondService.client = firstService.client
	second := activationAPIHandler(t, f, secondService, fixedAuth{f.identity})
	callbackPath := "/api/auth/callback?" + url.Values{"state": {query.Get("state")}, "code": {"synthetic-code"}}.Encode()
	request := httptest.NewRequest(http.MethodGet, callbackPath, nil)
	request.AddCookie(cookie)
	misrouted := httptest.NewRecorder()
	second.ServeHTTP(misrouted, request)
	if misrouted.Code != http.StatusServiceUnavailable || !strings.Contains(misrouted.Body.String(), "originating instance") {
		t.Fatal("misrouted callback did not fail with affinity guidance", misrouted.Code, misrouted.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, callbackPath, nil)
	request.AddCookie(cookie)
	origin := httptest.NewRecorder()
	first.ServeHTTP(origin, request)
	if origin.Code != http.StatusSeeOther {
		t.Fatal("misrouting consumed the one-time flow", origin.Code, origin.Body.String())
	}
}

func TestActivationAmbiguousCommitCanBeAuthoritativelyReconciledWithoutRetry(t *testing.T) {
	f, service, issuer, revision := activationServiceFixture(t)
	request, userID := activationReadiness(t, f, revision, "")
	original := service.transaction
	service.transaction = func(ctx context.Context, fn func(context.Context, pgx.Tx, access.User) error) error {
		if err := original(ctx, fn); err != nil {
			return err
		}
		return ErrCommitUncertain
	}
	first := activationAPIHandler(t, f, service, fixedAuth{f.identity})
	prepared := prepareThroughAPI(t, first, revision, 0)
	w := apiRequest(t, first, http.MethodPost, "/api/admin/auth/activation-preparations/"+prepared.ID+"/activate", map[string]any{
		"revision_id": revision.ID, "expected_revision_generation": revision.Generation,
		"expected_activation_generation": 0, "isolated_evidence_id": request.IsolatedEvidenceID,
		"normal_evidence_id": request.NormalEvidenceID, "enrolled_user_id": userID,
		"transition_seconds": 0, "acknowledge_reauthentication": true,
		"acknowledge_emergency_recovery": true, "confirm": true,
		"reason": "ambiguous transport after commit",
	}, http.StatusServiceUnavailable)
	var failure struct {
		Error string `json:"error"`
		ActivationResult
	}
	if json.Unmarshal(w.Body.Bytes(), &failure) != nil || failure.Error != "activation_commit_uncertain" || failure.Outcome != ActivationCommitUncertain || failure.CommitPersisted != nil || !failure.CommitUncertain || !failure.ReconciliationRequired || failure.AutomaticRetryAllowed || !failure.AuthoritativeStateKnown || failure.AuthoritativeGeneration != 1 || failure.AuthoritativeRevisionID != revision.ID {
		t.Fatal("ambiguous response contract was unsafe", failure)
	}

	syncer, secondRuntime := subscriberFixture(t, f, service, issuer)
	secondService, err := NewActivationService(f.repo, secondRuntime, service.store, service.sessions, service.callback)
	if err != nil {
		t.Fatal(err)
	}
	secondService.client = service.client
	second := activationAPIHandlerWithOperations(t, f, secondService, fixedAuth{f.identity}, ActivationOperations{
		Affinity: ActivationAffinity{Mode: "session_affinity"}, SynchronizationStatus: syncer.Status, Reconcile: syncer.Reconcile,
	})
	w = apiRequest(t, second, http.MethodGet, "/api/admin/auth/activation/status", nil, http.StatusOK)
	var status ActivationOperationalStatus
	if json.Unmarshal(w.Body.Bytes(), &status) != nil || status.AuthoritativeGeneration != 1 || status.LocalAppliedGeneration != 0 || !status.ReconciliationRequired || status.AutomaticActivationRetry {
		t.Fatal("authoritative mismatch was hidden", status)
	}
	w = apiRequest(t, second, http.MethodPost, "/api/admin/auth/activation/reconcile", map[string]any{
		"expected_desired_generation": 1, "confirm": true,
	}, http.StatusOK)
	if json.Unmarshal(w.Body.Bytes(), &status) != nil || !status.Reconciled || status.ReconciliationRequired || status.LocalAppliedGeneration != 1 || status.AuthoritativeGeneration != 1 || status.AutomaticActivationRetry {
		t.Fatal("reconciliation did not converge without activation retry", status)
	}
}

func TestActivationFailureJSONOutcomes(t *testing.T) {
	tests := []struct {
		name      string
		result    ActivationResult
		errorCode string
		persisted *bool
	}{
		{"committed but not applied", ActivationResult{Outcome: ActivationCommittedNotApplied, CommitPersisted: commitKnown(true), ReconciliationRequired: true}, "activation_committed_not_applied", commitKnown(true)},
		{"commit uncertain", ActivationResult{Outcome: ActivationCommitUncertain, CommitUncertain: true, ReconciliationRequired: true}, "activation_commit_uncertain", nil},
		{"definitely not committed", ActivationResult{Outcome: ActivationNotCommitted, CommitPersisted: commitKnown(false)}, "auth_config_invalid", commitKnown(false)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			err := ErrInvalid
			if test.result.Outcome != ActivationNotCommitted {
				err = auth.ErrRuntimeMismatch
			}
			activationFailure(w, err, test.result)
			var got struct {
				Error string `json:"error"`
				ActivationResult
			}
			if json.Unmarshal(w.Body.Bytes(), &got) != nil || got.Error != test.errorCode || got.Outcome != test.result.Outcome || got.AutomaticRetryAllowed {
				t.Fatal("unstable activation outcome contract", got)
			}
			if (got.CommitPersisted == nil) != (test.persisted == nil) || got.CommitPersisted != nil && *got.CommitPersisted != *test.persisted {
				t.Fatal("commit certainty was misrepresented", got.CommitPersisted)
			}
		})
	}
}
