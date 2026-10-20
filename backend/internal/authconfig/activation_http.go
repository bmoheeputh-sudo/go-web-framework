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
	mu      sync.Mutex
	service *ActivationService
	items   map[string]*activationPreparation
	closed  bool
}

func newActivationHTTP(service *ActivationService) *activationHTTP {
	return &activationHTTP{service: service, items: make(map[string]*activationPreparation)}
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
	item := h.items[id]
	if item == nil || item.actor != actor.ID || item.claimed {
		return nil, ErrNotFound
	}
	item.claimed = true
	delete(h.items, id)
	return item, nil
}

type preparationResponse struct {
	ID                       string        `json:"preparation_id"`
	RevisionID               string        `json:"revision_id"`
	RevisionGeneration       int64         `json:"revision_generation"`
	ExpectedGeneration       int64         `json:"expected_activation_generation"`
	TargetGeneration         int64         `json:"target_activation_generation"`
	ExpiresAt                time.Time     `json:"expires_at"`
	CurrentProvider          auth.Provider `json:"current_provider"`
	CurrentSource            string        `json:"current_source"`
	RequiresReauthentication bool          `json:"requires_reauthentication"`
	MaximumTransitionSeconds int64         `json:"maximum_transition_seconds"`
	Warning                  string        `json:"warning,omitempty"`
	NormalCallbackStatus     string        `json:"normal_callback_status"`
	NormalEvidenceID         string        `json:"normal_evidence_id,omitempty"`
	NormalEvidenceExpiresAt  *time.Time    `json:"normal_evidence_expires_at,omitempty"`
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

func (h *activationHTTP) register(route func(string, http.HandlerFunc)) {
	route("POST /api/admin/auth/settings/{id}/activation/prepare", h.prepare)
	route("GET /api/admin/auth/activation-preparations/{preparation}", h.status)
	route("POST /api/admin/auth/activation-preparations/{preparation}/readiness", h.readiness)
	route("POST /api/admin/auth/activation-preparations/{preparation}/activate", h.activate)
	route("POST /api/admin/auth/settings/{id}/rollback", h.rollback)
}

func (h *activationHTTP) prepare(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		httpError(w, ErrUnavailable)
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
		httpError(w, err)
		return
	}
	actor, _ := access.Principal(r.Context())
	item := &activationPreparation{id: oauth2.GenerateVerifier(), actor: actor.ID, prepared: p}
	if err := h.add(item); err != nil {
		p.Close()
		httpError(w, err)
		return
	}
	reply(w, http.StatusCreated, responseForPreparation(item))
}

func (h *activationHTTP) status(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		httpError(w, ErrUnavailable)
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

func (h *activationHTTP) readiness(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		httpError(w, ErrUnavailable)
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
	if h.service == nil {
		httpError(w, ErrUnavailable)
		return
	}
	var body struct {
		RevisionID                  string `json:"revision_id"`
		RevisionGeneration          *int64 `json:"expected_revision_generation"`
		ActivationGeneration        *int64 `json:"expected_activation_generation"`
		IsolatedEvidenceID          string `json:"isolated_evidence_id"`
		NormalEvidenceID            string `json:"normal_evidence_id"`
		EnrolledUserID              string `json:"enrolled_user_id"`
		TransitionSeconds           *int64 `json:"transition_seconds"`
		AcknowledgeReauthentication bool   `json:"acknowledge_reauthentication"`
		Confirm                     bool   `json:"confirm"`
		Reason                      string `json:"reason"`
	}
	if !access.DecodeJSON(w, r, &body) {
		return
	}
	reason, validReason := safeReason(body.Reason)
	if !body.Confirm || !validReason || body.RevisionGeneration == nil || body.ActivationGeneration == nil || body.TransitionSeconds == nil || *body.TransitionSeconds < 0 || *body.TransitionSeconds > 1800 {
		httpError(w, ErrInvalid)
		return
	}
	item, err := h.get(r.Context(), r.PathValue("preparation"))
	if err != nil {
		httpError(w, err)
		return
	}
	if body.RevisionID != item.prepared.metadata.ID || *body.RevisionGeneration != item.prepared.metadata.Generation || *body.ActivationGeneration != item.prepared.expected {
		httpError(w, ErrConflict)
		return
	}
	if item.prepared.readiness.RequiresReauthentication && (!body.AcknowledgeReauthentication || *body.TransitionSeconds != 0) {
		httpError(w, ErrInvalid)
		return
	}
	item, err = h.claim(r.Context(), item.id)
	if err != nil {
		httpError(w, err)
		return
	}
	defer item.prepared.Close()
	result, err := h.service.Activate(r.Context(), item.prepared, ActivationRequest{
		AcknowledgeReauthentication: body.AcknowledgeReauthentication,
		IsolatedEvidenceID:          body.IsolatedEvidenceID, NormalEvidenceID: body.NormalEvidenceID,
		EnrolledUserID: body.EnrolledUserID, Transition: time.Duration(*body.TransitionSeconds) * time.Second,
		Reason: reason,
	})
	if err != nil {
		if errors.Is(err, auth.ErrRuntimeMismatch) {
			reply(w, http.StatusServiceUnavailable, struct {
				Error string `json:"error"`
				ActivationResult
			}{"auth_runtime_mismatch", result})
			return
		}
		httpError(w, err)
		return
	}
	reply(w, http.StatusOK, result)
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
