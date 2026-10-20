package authconfig

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
)

const accessPolicyPath = "/api/admin/auth/access-policy"

func accessPolicyError(w http.ResponseWriter, err error) {
	code, status := "access_policy_unavailable", http.StatusServiceUnavailable
	switch {
	case errors.Is(err, ErrNotFound):
		code, status = "access_policy_setup_required", http.StatusNotFound
	case errors.Is(err, ErrInvalid):
		code, status = "access_policy_invalid", http.StatusBadRequest
	case errors.Is(err, ErrConflict):
		code, status = "access_policy_conflict", http.StatusConflict
	case errors.Is(err, ErrLastOIDCAdministrator):
		code, status = "access_policy_last_oidc_administrator", http.StatusConflict
	case errors.Is(err, ErrSelfAccessLoss):
		code, status = "access_policy_self_access_loss_confirmation_required", http.StatusConflict
	case errors.Is(err, ErrDenied):
		code, status = "access_policy_denied", http.StatusForbidden
	case errors.Is(err, ErrCommitUncertain):
		code = "access_policy_commit_uncertain"
	}
	reply(w, status, map[string]string{"error": code})
}

type accessPolicyChange struct {
	AccessPolicySettings
	PolicyGeneration     *int64 `json:"expected_policy_generation"`
	ActivationGeneration *int64 `json:"expected_activation_generation"`
	Reason               string `json:"reason"`
	ConfirmAccessLoss    bool   `json:"confirm_access_loss"`
}

func (b accessPolicyChange) expectation() (PolicyExpectation, bool) {
	if b.PolicyGeneration == nil || b.ActivationGeneration == nil {
		return PolicyExpectation{}, false
	}
	return PolicyExpectation{*b.PolicyGeneration, *b.ActivationGeneration}, true
}

// Registered independently of encrypted configuration management: policy reads
// and edits do not require a client-secret encryption key. No bootstrap route.
func RegisterAccessPolicy(mux *http.ServeMux, provider auth.Authenticator, store *access.Store, origin string, repo *AccessPolicyRepository) {
	route := func(pattern string, h http.HandlerFunc) {
		handler := auth.Require(provider, access.ProtectWrites(origin, store.Require(access.AdminManage, "", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if repo == nil {
				accessPolicyError(w, ErrUnavailable)
				return
			}
			if pattern != "GET "+accessPolicyPath+"/approvals" && r.URL.RawQuery != "" {
				accessPolicyError(w, ErrInvalid)
				return
			}
			h(w, r)
		}))))
		mux.Handle(pattern, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			handler.ServeHTTP(w, r)
		}))
	}
	route("GET "+accessPolicyPath, func(w http.ResponseWriter, r *http.Request) {
		s, err := repo.Snapshot(r.Context())
		if err != nil {
			accessPolicyError(w, err)
			return
		}
		reply(w, 200, s)
	})
	route("GET "+accessPolicyPath+"/overview", func(w http.ResponseWriter, r *http.Request) {
		s, err := repo.Snapshot(r.Context())
		if err != nil {
			accessPolicyError(w, err)
			return
		}
		reply(w, 200, s)
	})
	route("POST "+accessPolicyPath+"/preview", func(w http.ResponseWriter, r *http.Request) {
		var body accessPolicyChange
		if !access.DecodeJSON(w, r, &body) {
			return
		}
		expected, ok := body.expectation()
		if !ok {
			accessPolicyError(w, ErrInvalid)
			return
		}
		p, err := repo.Preview(r.Context(), expected, body.AccessPolicySettings)
		if err != nil {
			accessPolicyError(w, err)
			return
		}
		reply(w, 200, p)
	})
	route("PUT "+accessPolicyPath, func(w http.ResponseWriter, r *http.Request) {
		var body accessPolicyChange
		if !access.DecodeJSON(w, r, &body) {
			return
		}
		expected, ok := body.expectation()
		if !ok {
			accessPolicyError(w, ErrInvalid)
			return
		}
		p, err := repo.UpdateReviewed(r.Context(), expected, body.AccessPolicySettings, body.Reason, body.ConfirmAccessLoss)
		if err != nil {
			accessPolicyError(w, err)
			return
		}
		reply(w, 200, p)
	})
	route("GET "+accessPolicyPath+"/approvals", func(w http.ResponseWriter, r *http.Request) {
		search, status, offset, limit, err := accessListQuery(r.URL.RawQuery)
		if err != nil {
			accessPolicyError(w, err)
			return
		}
		items, err := repo.Identities(r.Context(), search, status, offset, limit)
		if err != nil {
			accessPolicyError(w, err)
			return
		}
		reply(w, 200, items)
	})
	route("GET "+accessPolicyPath+"/approvals/{user}", func(w http.ResponseWriter, r *http.Request) {
		item, err := repo.Identity(r.Context(), r.PathValue("user"))
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				reply(w, 404, map[string]string{"error": "access_policy_identity_not_found"})
				return
			}
			accessPolicyError(w, err)
			return
		}
		reply(w, 200, item)
	})
	for _, state := range []string{"approved", "revoked"} {
		action := "approve"
		if state == "revoked" {
			action = "revoke"
		}
		route("POST "+accessPolicyPath+"/approvals/{user}/"+action, func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				PolicyGeneration     *int64 `json:"expected_policy_generation"`
				ActivationGeneration *int64 `json:"expected_activation_generation"`
				ApprovalGeneration   *int64 `json:"expected_approval_generation"`
				Reason               string `json:"reason"`
			}
			if !access.DecodeJSON(w, r, &body) {
				return
			}
			if body.PolicyGeneration == nil || body.ActivationGeneration == nil || body.ApprovalGeneration == nil {
				accessPolicyError(w, ErrInvalid)
				return
			}
			result, err := repo.SetUserApproval(r.Context(), PolicyExpectation{*body.PolicyGeneration, *body.ActivationGeneration}, r.PathValue("user"), *body.ApprovalGeneration, state, body.Reason)
			if err != nil {
				if errors.Is(err, ErrNotFound) {
					reply(w, 404, map[string]string{"error": "access_policy_identity_not_found"})
					return
				}
				accessPolicyError(w, err)
				return
			}
			reply(w, 200, result)
		})
	}
}
func accessListQuery(raw string) (string, string, int, int, error) {
	values, err := url.ParseQuery(raw)
	if err != nil {
		return "", "", 0, 0, ErrInvalid
	}
	offset, limit := 0, 20
	for key, v := range values {
		if len(v) != 1 {
			return "", "", 0, 0, ErrInvalid
		}
		switch key {
		case "search", "status":
		case "offset", "limit":
			n, err := strconv.Atoi(v[0])
			if err != nil {
				return "", "", 0, 0, ErrInvalid
			}
			if key == "offset" {
				offset = n
			} else {
				limit = n
			}
		default:
			return "", "", 0, 0, ErrInvalid
		}
	}
	return values.Get("search"), values.Get("status"), offset, limit, nil
}
