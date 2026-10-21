package authconfig

import (
	"errors"
	"net/http"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
)

type invitationWrite struct {
	InvitationInput
	PolicyGeneration     *int64 `json:"expected_policy_generation"`
	ActivationGeneration *int64 `json:"expected_activation_generation"`
	RevisionID           string `json:"revision_id"`
	RevisionGeneration   *int64 `json:"expected_revision_generation"`
}

func (b invitationWrite) expectation() (InvitationExpectation, bool) {
	if b.PolicyGeneration == nil || b.ActivationGeneration == nil || b.RevisionGeneration == nil {
		return InvitationExpectation{}, false
	}
	e := InvitationExpectation{PolicyExpectation{*b.PolicyGeneration, *b.ActivationGeneration}, b.RevisionID, *b.RevisionGeneration}
	return e, e.valid()
}
func invitationError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrNotFound) {
		reply(w, 404, map[string]string{"error": "oidc_invitation_not_found_or_policy_uninitialized"})
		return
	}
	if errors.Is(err, ErrCommitUncertain) {
		reply(w, 503, map[string]any{"error": "oidc_invitation_commit_uncertain", "automatic_retry_allowed": false, "inspection_required": true})
		return
	}
	accessPolicyError(w, err)
}

// Routes reuse precisely the same authentication, administrator and Origin/JSON
// middleware as policy management. There is intentionally no claim endpoint.
func registerInvitationRoutes(route func(string, http.HandlerFunc), repo *AccessPolicyRepository) {
	base := accessPolicyPath + "/invitations"
	route("GET "+base, func(w http.ResponseWriter, r *http.Request) {
		search, status, offset, limit, err := accessListQuery(r.URL.RawQuery)
		if err != nil {
			invitationError(w, err)
			return
		}
		result, err := repo.ListInvitations(r.Context(), search, status, offset, limit)
		if err != nil {
			invitationError(w, err)
			return
		}
		reply(w, 200, result)
	})
	route("GET "+base+"/{id}", func(w http.ResponseWriter, r *http.Request) {
		result, err := repo.ReadInvitation(r.Context(), r.PathValue("id"))
		if err != nil {
			invitationError(w, err)
			return
		}
		reply(w, 200, result)
	})
	route("POST "+base, func(w http.ResponseWriter, r *http.Request) {
		var body invitationWrite
		if !access.DecodeJSON(w, r, &body) {
			return
		}
		expected, ok := body.expectation()
		if !ok {
			invitationError(w, ErrInvalid)
			return
		}
		result, err := repo.CreateInvitation(r.Context(), expected, body.InvitationInput)
		if err != nil {
			invitationError(w, err)
			return
		}
		reply(w, 201, result)
	})
	route("POST "+base+"/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			PolicyGeneration     *int64 `json:"expected_policy_generation"`
			ActivationGeneration *int64 `json:"expected_activation_generation"`
			RevisionID           string `json:"revision_id"`
			RevisionGeneration   *int64 `json:"expected_revision_generation"`
			InvitationGeneration *int64 `json:"expected_invitation_generation"`
			Reason               string `json:"reason"`
		}
		if !access.DecodeJSON(w, r, &body) {
			return
		}
		if body.PolicyGeneration == nil || body.ActivationGeneration == nil || body.RevisionGeneration == nil || body.InvitationGeneration == nil {
			invitationError(w, ErrInvalid)
			return
		}
		expected := InvitationExpectation{PolicyExpectation{*body.PolicyGeneration, *body.ActivationGeneration}, body.RevisionID, *body.RevisionGeneration}
		result, err := repo.RevokeInvitation(r.Context(), expected, r.PathValue("id"), *body.InvitationGeneration, body.Reason)
		if err != nil {
			invitationError(w, err)
			return
		}
		reply(w, 200, result)
	})
}
