package authconfig

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"golang.org/x/oauth2"
)

const maximumPreparations = 16

type activationPreparation struct {
	id       string
	actor    string
	prepared *PreparedActivation
	normal   *NormalCallbackResult
	claimed  bool
}

type activationHTTP struct {
	mu         sync.Mutex
	service    *ActivationService
	operations ActivationOperations
	instance   string
	items      map[string]*activationPreparation
	closed     bool
}

func newActivationHTTP(service *ActivationService, operations ActivationOperations) *activationHTTP {
	return &activationHTTP{service: service, operations: operations, instance: oauth2.GenerateVerifier(), items: make(map[string]*activationPreparation)}
}

func (h *activationHTTP) close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	for id, item := range h.items {
		item.prepared.Close()
		delete(h.items, id)
	}
}

func (h *activationHTTP) pruneLocked(now time.Time) {
	for id, item := range h.items {
		if item.claimed || !now.Before(item.prepared.expires) {
			item.prepared.Close()
			delete(h.items, id)
		}
	}
}

func (h *activationHTTP) add(item *activationPreparation) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pruneLocked(time.Now())
	if h.closed || len(h.items) >= maximumPreparations {
		return ErrUnavailable
	}
	for _, existing := range h.items {
		if existing.actor == item.actor {
			return ErrConflict
		}
	}
	h.items[item.id] = item
	return nil
}

func (h *activationHTTP) get(ctx context.Context, id string) (*activationPreparation, error) {
	actor, ok := access.Principal(ctx)
	if !ok {
		return nil, ErrDenied
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pruneLocked(time.Now())
	if prefix, _, found := strings.Cut(id, "."); found && prefix != h.instance {
		return nil, ErrPreparationWrongInstance
	}
	item := h.items[id]
	if item == nil || item.actor != actor.ID || item.claimed {
		return nil, ErrNotFound
	}
	return item, nil
}

func (h *activationHTTP) claim(ctx context.Context, id string) (*activationPreparation, error) {
	actor, ok := access.Principal(ctx)
	if !ok {
		return nil, ErrDenied
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pruneLocked(time.Now())
	if prefix, _, found := strings.Cut(id, "."); found && prefix != h.instance {
		return nil, ErrPreparationWrongInstance
	}
	item := h.items[id]
	if item == nil || item.actor != actor.ID || item.claimed {
		return nil, ErrNotFound
	}
	item.claimed = true
	delete(h.items, id)
	return item, nil
}

type preparationResponse struct {
	ID                        string        `json:"preparation_id"`
	RevisionID                string        `json:"revision_id"`
	RevisionGeneration        int64         `json:"revision_generation"`
	ExpectedGeneration        int64         `json:"expected_activation_generation"`
	TargetGeneration          int64         `json:"target_activation_generation"`
	ExpiresAt                 time.Time     `json:"expires_at"`
	CurrentProvider           auth.Provider `json:"current_provider"`
	CurrentSource             string        `json:"current_source"`
	RequiresReauthentication  bool          `json:"requires_reauthentication"`
	MaximumTransitionSeconds  int64         `json:"maximum_transition_seconds"`
	Warning                   string        `json:"warning,omitempty"`
	EmergencyRecoveryRequired bool          `json:"emergency_recovery_required"`
	OfflineRecoveryProcedure  string        `json:"offline_recovery_procedure,omitempty"`
	NormalCallbackStatus      string        `json:"normal_callback_status"`
	NormalEvidenceID          string        `json:"normal_evidence_id,omitempty"`
	NormalEvidenceExpiresAt   *time.Time    `json:"normal_evidence_expires_at,omitempty"`
}

func responseForPreparation(item *activationPreparation) preparationResponse {
	p, readiness := item.prepared, item.prepared.readiness
	result := preparationResponse{ID: item.id, RevisionID: p.metadata.ID,
		RevisionGeneration: p.metadata.Generation, ExpectedGeneration: p.expected,
		TargetGeneration: p.expected + 1, ExpiresAt: p.expires,
		CurrentProvider: readiness.CurrentProvider, CurrentSource: readiness.CurrentSource,
		RequiresReauthentication: readiness.RequiresReauthentication,
		MaximumTransitionSeconds: int64(readiness.MaximumSessionGrace / time.Second),
		NormalCallbackStatus:     "not_started"}
	if readiness.RequiresReauthentication {
		result.Warning = "immediate_reauthentication_required"
		result.EmergencyRecoveryRequired = true
		result.OfflineRecoveryProcedure = "auth-recovery-cli"
	}
	if item.normal != nil {
		status, evidence, expires := item.normal.Status()
		result.NormalCallbackStatus = status
		if evidence.ID != "" {
			result.NormalEvidenceID = evidence.ID
			result.NormalEvidenceExpiresAt = &evidence.ExpiresAt
		} else if !expires.IsZero() {
			result.NormalEvidenceExpiresAt = &expires
		}
	}
	return result
}

type capturedRedirect struct {
	header http.Header
	status int
}

func (w *capturedRedirect) Header() http.Header    { return w.header }
func (w *capturedRedirect) WriteHeader(status int) { w.status = status }
func (w *capturedRedirect) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return len(body), nil
}

func safeReason(reason string) (string, bool) {
	reason = strings.TrimSpace(reason)
	return reason, len(reason) >= 8 && len(reason) <= 512 && !strings.ContainsAny(reason, "\r\n\x00")
}

func (h *activationHTTP) requirePreparation(w http.ResponseWriter) bool {
	if h.service == nil {
		httpError(w, ErrUnavailable)
		return false
	}
	if !h.operations.Affinity.configured() {
		reply(w, http.StatusServiceUnavailable, map[string]any{
			"error": "activation_affinity_required", "required_configuration": "AUTH_ACTIVATION_AFFINITY_MODE",
			"automatic_retry_allowed": false,
		})
		return false
	}
	return true
}

func activationErrorCode(err error) (int, string) {
	switch {
	case errors.Is(err, ErrInvalid):
		return http.StatusBadRequest, "auth_config_invalid"
	case errors.Is(err, ErrDenied):
		return http.StatusForbidden, "access_denied"
	case errors.Is(err, ErrNotFound):
		return http.StatusNotFound, "auth_config_not_found"
	case errors.Is(err, ErrConflict):
		return http.StatusConflict, "auth_config_conflict"
	case errors.Is(err, ErrPreparationWrongInstance):
		return http.StatusServiceUnavailable, "activation_preparation_wrong_instance"
	default:
		return http.StatusServiceUnavailable, "auth_config_unavailable"
	}
}

func activationFailure(w http.ResponseWriter, err error, result ActivationResult) {
	status, code := activationErrorCode(err)
	if errors.Is(err, auth.ErrRuntimeMismatch) {
		status = http.StatusServiceUnavailable
		if result.Outcome == ActivationCommitUncertain {
			code = "activation_commit_uncertain"
		} else {
			code = "activation_committed_not_applied"
		}
	}
	reply(w, status, struct {
		Error string `json:"error"`
		ActivationResult
	}{code, result})
}

func (h *activationHTTP) withAuthoritativeState(ctx context.Context, result ActivationResult) ActivationResult {
	if h.service == nil {
		return result
	}
	if head, err := h.service.repo.activationHeadAuthorized(ctx); err == nil {
		result.AuthoritativeStateKnown = true
		result.AuthoritativeGeneration = head.Generation
		result.AuthoritativeRevisionID = head.ActiveRevisionID
	}
	return result
}

func (h *activationHTTP) register(route func(string, http.HandlerFunc)) {
	route("POST /api/admin/auth/settings/{id}/activation/prepare", h.prepare)
	route("GET /api/admin/auth/activation-preparations/{preparation}", h.status)
	route("POST /api/admin/auth/activation-preparations/{preparation}/cancel", h.cancel)
	route("POST /api/admin/auth/activation-preparations/current/cancel", h.cancelCurrent)
	route("POST /api/admin/auth/activation-preparations/{preparation}/readiness", h.readiness)
	route("POST /api/admin/auth/activation-preparations/{preparation}/activate", h.activate)
	route("POST /api/admin/auth/settings/{id}/rollback", h.rollback)
	route("GET /api/admin/auth/settings/{id}/recovery-readiness", h.recoveryReadiness)
	route("GET /api/admin/auth/activation/status", h.activationStatus)
	route("POST /api/admin/auth/activation/reconcile", h.reconcile)
}

func (h *activationHTTP) prepare(w http.ResponseWriter, r *http.Request) {
	if !h.requirePreparation(w) {
		return
	}
	var body struct {
		RevisionGeneration   *int64 `json:"expected_revision_generation"`
		ActivationGeneration *int64 `json:"expected_activation_generation"`
	}
	if !access.DecodeJSON(w, r, &body) {
		return
	}
	if body.RevisionGeneration == nil || body.ActivationGeneration == nil {
		httpError(w, ErrInvalid)
		return
	}
	p, err := h.service.Prepare(r.Context(), r.PathValue("id"), *body.RevisionGeneration, *body.ActivationGeneration)
	if err != nil {
		if errors.Is(err, ErrRecoveryProviderUnavailable) {
			reply(w, http.StatusServiceUnavailable, map[string]any{
				"error": "recovery_provider_unavailable", "offline_recovery_procedure": "auth-recovery-cli",
				"recovery_provider_must_be_available": true, "automatic_retry_allowed": false,
			})
			return
		}
		httpError(w, err)
		return
	}
	actor, _ := access.Principal(r.Context())
	item := &activationPreparation{id: h.instance + "." + oauth2.GenerateVerifier(), actor: actor.ID, prepared: p}
	if err := h.add(item); err != nil {
		p.Close()
		if errors.Is(err, ErrConflict) {
			reply(w, http.StatusConflict, map[string]string{"error": "activation_preparation_conflict"})
			return
		}
		httpError(w, err)
		return
	}
	reply(w, http.StatusCreated, responseForPreparation(item))
}

func (h *activationHTTP) status(w http.ResponseWriter, r *http.Request) {
	if !h.requirePreparation(w) {
		return
	}
	item, err := h.get(r.Context(), r.PathValue("preparation"))
	if err != nil {
		httpError(w, err)
		return
	}
	// Recheck administrator and revision authorization on every status read.
	if _, err = h.service.repo.testTransaction(r.Context(), item.prepared.metadata.ID, item.prepared.metadata.Generation, "", "", "", nil, nil); err != nil {
		httpError(w, err)
		return
	}
	h.mu.Lock()
	h.pruneLocked(time.Now())
	if h.items[item.id] != item || item.claimed {
		h.mu.Unlock()
		httpError(w, ErrNotFound)
		return
	}
	response := responseForPreparation(item)
	h.mu.Unlock()
	reply(w, http.StatusOK, response)
}

// Cancel only releases an unclaimed, process-local preparation owned by this
// verified administrator. A claimed activation is removed before its database
// transaction begins, so cancellation can never interrupt an uncertain commit.
func (h *activationHTTP) cancel(w http.ResponseWriter, r *http.Request) {
	h.cancelOwned(w, r, r.PathValue("preparation"))
}

func (h *activationHTTP) cancelCurrent(w http.ResponseWriter, r *http.Request) {
	h.cancelOwned(w, r, "")
}

func (h *activationHTTP) cancelOwned(w http.ResponseWriter, r *http.Request, id string) {
	if !h.requirePreparation(w) {
		return
	}
	var body struct{}
	if !access.DecodeJSON(w, r, &body) {
		return
	}
	actor, ok := access.Principal(r.Context())
	if !ok {
		httpError(w, ErrDenied)
		return
	}
	h.mu.Lock()
	h.pruneLocked(time.Now())
	if prefix, _, found := strings.Cut(id, "."); id != "" && found && prefix != h.instance {
		h.mu.Unlock()
		httpError(w, ErrPreparationWrongInstance)
		return
	}
	if id == "" {
		for candidate, existing := range h.items {
			if existing.actor == actor.ID && !existing.claimed {
				id = candidate
				break
			}
		}
	}
	item := h.items[id]
	if item == nil || item.actor != actor.ID || item.claimed {
		h.mu.Unlock()
		httpError(w, ErrNotFound)
		return
	}
	delete(h.items, id)
	h.mu.Unlock()
	item.prepared.Close()
	reply(w, http.StatusOK, map[string]string{"status": "cancelled"})
}

func (h *activationHTTP) readiness(w http.ResponseWriter, r *http.Request) {
	if !h.requirePreparation(w) {
		return
	}
	var body struct{}
	if !access.DecodeJSON(w, r, &body) {
		return
	}
	item, err := h.get(r.Context(), r.PathValue("preparation"))
	if err != nil {
		httpError(w, err)
		return
	}
	h.mu.Lock()
	if h.items[item.id] != item || item.claimed {
		h.mu.Unlock()
		httpError(w, ErrNotFound)
		return
	}
	if item.normal != nil {
		h.mu.Unlock()
		httpError(w, ErrConflict)
		return
	}
	capture := &capturedRedirect{header: make(http.Header)}
	result, err := h.service.BeginNormalCallbackTest(item.prepared, capture, r)
	if err == nil {
		item.normal = result
	}
	h.mu.Unlock()
	if err != nil {
		httpError(w, err)
		return
	}
	if capture.status != http.StatusFound || capture.header.Get("Location") == "" {
		httpError(w, ErrUnavailable)
		return
	}
	for _, cookie := range capture.header.Values("Set-Cookie") {
		w.Header().Add("Set-Cookie", cookie)
	}
	status, _, expires := result.Status()
	reply(w, http.StatusCreated, struct {
		PreparationID string    `json:"preparation_id"`
		Status        string    `json:"status"`
		Authorization string    `json:"authorization_url"`
		CallbackURL   string    `json:"callback_url"`
		ExpiresAt     time.Time `json:"expires_at"`
	}{item.id, status, capture.header.Get("Location"), h.service.callback, expires})
}

func (h *activationHTTP) activate(w http.ResponseWriter, r *http.Request) {
	if !h.requirePreparation(w) {
		return
	}
	var body struct {
		RevisionID                   string `json:"revision_id"`
		RevisionGeneration           *int64 `json:"expected_revision_generation"`
		ActivationGeneration         *int64 `json:"expected_activation_generation"`
		IsolatedEvidenceID           string `json:"isolated_evidence_id"`
		NormalEvidenceID             string `json:"normal_evidence_id"`
		EnrolledUserID               string `json:"enrolled_user_id"`
		TransitionSeconds            *int64 `json:"transition_seconds"`
		AcknowledgeReauthentication  bool   `json:"acknowledge_reauthentication"`
		AcknowledgeEmergencyRecovery bool   `json:"acknowledge_emergency_recovery"`
		Confirm                      bool   `json:"confirm"`
		Reason                       string `json:"reason"`
	}
	if !access.DecodeJSON(w, r, &body) {
		return
	}
	reason, validReason := safeReason(body.Reason)
	if !body.Confirm || !validReason || body.RevisionGeneration == nil || body.ActivationGeneration == nil || body.TransitionSeconds == nil || *body.TransitionSeconds < 0 || *body.TransitionSeconds > 1800 {
		activationFailure(w, ErrInvalid, activationNotCommitted(nil))
		return
	}
	item, err := h.get(r.Context(), r.PathValue("preparation"))
	if err != nil {
		activationFailure(w, err, activationNotCommitted(nil))
		return
	}
	if body.RevisionID != item.prepared.metadata.ID || *body.RevisionGeneration != item.prepared.metadata.Generation || *body.ActivationGeneration != item.prepared.expected {
		activationFailure(w, ErrConflict, h.withAuthoritativeState(r.Context(), activationNotCommitted(item.prepared)))
		return
	}
	if item.prepared.readiness.RequiresReauthentication && (!body.AcknowledgeReauthentication || *body.TransitionSeconds != 0) {
		activationFailure(w, ErrInvalid, h.withAuthoritativeState(r.Context(), activationNotCommitted(item.prepared)))
		return
	}
	if item.prepared.readiness.RequiresReauthentication && !body.AcknowledgeEmergencyRecovery {
		activationFailure(w, ErrInvalid, h.withAuthoritativeState(r.Context(), activationNotCommitted(item.prepared)))
		return
	}
	item, err = h.claim(r.Context(), item.id)
	if err != nil {
		activationFailure(w, err, activationNotCommitted(nil))
		return
	}
	defer item.prepared.Close()
	result, err := h.service.Activate(r.Context(), item.prepared, ActivationRequest{
		AcknowledgeReauthentication:  body.AcknowledgeReauthentication,
		AcknowledgeEmergencyRecovery: body.AcknowledgeEmergencyRecovery,
		IsolatedEvidenceID:           body.IsolatedEvidenceID, NormalEvidenceID: body.NormalEvidenceID,
		EnrolledUserID: body.EnrolledUserID, Transition: time.Duration(*body.TransitionSeconds) * time.Second,
		Reason: reason,
	})
	result = h.withAuthoritativeState(r.Context(), result)
	if err != nil {
		if errors.Is(err, auth.ErrRuntimeMismatch) {
			activationFailure(w, err, result)
			return
		}
		activationFailure(w, err, result)
		return
	}
	reply(w, http.StatusOK, result)
}

func (h *activationHTTP) recoveryReadiness(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		httpError(w, ErrUnavailable)
		return
	}
	result, err := h.service.repo.RecoveryReadiness(r.Context(), r.PathValue("id"), h.service.callback)
	if err != nil {
		httpError(w, err)
		return
	}
	reply(w, http.StatusOK, result)
}

func (h *activationHTTP) activationStatus(w http.ResponseWriter, r *http.Request) {
	status, err := h.operationalStatus(r.Context())
	if err != nil {
		httpError(w, err)
		return
	}
	reply(w, http.StatusOK, status)
}

func (h *activationHTTP) reconcile(w http.ResponseWriter, r *http.Request) {
	if h.service == nil || h.operations.Reconcile == nil {
		httpError(w, ErrUnavailable)
		return
	}
	var body struct {
		ExpectedDesiredGeneration *int64 `json:"expected_desired_generation"`
		Confirm                   bool   `json:"confirm"`
	}
	if !access.DecodeJSON(w, r, &body) {
		return
	}
	if body.ExpectedDesiredGeneration == nil || *body.ExpectedDesiredGeneration < 0 || !body.Confirm {
		httpError(w, ErrInvalid)
		return
	}
	before, err := h.operationalStatus(r.Context())
	if err != nil {
		httpError(w, err)
		return
	}
	if before.AuthoritativeGeneration != *body.ExpectedDesiredGeneration {
		httpError(w, ErrConflict)
		return
	}
	if err = h.operations.Reconcile(r.Context()); err != nil {
		httpError(w, err)
		return
	}
	after, err := h.operationalStatus(r.Context())
	if err != nil {
		httpError(w, err)
		return
	}
	reply(w, http.StatusOK, after)
}

func (h *activationHTTP) rollback(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		httpError(w, ErrUnavailable)
		return
	}
	var body struct {
		ExpectedLatestVersion *int64 `json:"expected_latest_version"`
		Confirm               bool   `json:"confirm"`
		Reason                string `json:"reason"`
	}
	if !access.DecodeJSON(w, r, &body) {
		return
	}
	reason, ok := safeReason(body.Reason)
	if !body.Confirm || !ok || body.ExpectedLatestVersion == nil {
		httpError(w, ErrInvalid)
		return
	}
	m, err := h.service.repo.PrepareRecoveryDraftWithReason(r.Context(), r.PathValue("id"), *body.ExpectedLatestVersion, reason)
	if err != nil {
		httpError(w, err)
		return
	}
	w.Header().Set("Location", "/api/admin/auth/settings/"+m.ID)
	reply(w, http.StatusCreated, struct {
		Revision           Metadata `json:"revision"`
		ActivationRequired bool     `json:"activation_required"`
	}{m, true})
}
