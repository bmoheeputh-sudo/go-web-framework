package authconfig

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
)

// RepositoryFromEnv loads only management configuration, never runtime providers.
// A missing/invalid key or scope leaves the management service unavailable.
func RepositoryFromEnv(store *access.Store, getenv func(string) string) (*Repository, error) {
	scope, err := ScopeFromEnv(getenv)
	if err != nil {
		return nil, err
	}
	cipher, err := CipherFromEnv(getenv)
	if err != nil {
		return nil, err
	}
	return NewRepository(store, scope, cipher)
}

func reply(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func httpError(w http.ResponseWriter, err error) {
	status, code := http.StatusServiceUnavailable, "auth_config_unavailable"
	switch {
	case errors.Is(err, ErrInvalid):
		status, code = http.StatusBadRequest, "auth_config_invalid"
	case errors.Is(err, ErrDenied):
		status, code = http.StatusForbidden, "access denied"
	case errors.Is(err, ErrNotFound):
		status, code = http.StatusNotFound, "auth_config_not_found"
	case errors.Is(err, ErrConflict):
		status, code = http.StatusConflict, "auth_config_conflict"
	}
	reply(w, status, map[string]string{"error": code})
}

// Register accepts server-owned scope/repository and a request-snapshot status reader.
// Every repository call rechecks administrator authorization inside AdminTransaction.
// There is deliberately no HTTP path to ReadSecretPrivileged or activation.
func Register(mux *http.ServeMux, provider auth.Authenticator, store *access.Store, origin string, repo *Repository, runtimeStatus func(context.Context) (auth.RuntimeStatus, bool)) {
	route := func(pattern string, h http.HandlerFunc) {
		available := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if repo == nil {
				httpError(w, ErrUnavailable)
				return
			}
			if pattern != "GET /api/admin/auth/settings" && r.URL.RawQuery != "" {
				httpError(w, ErrInvalid)
				return
			}
			h(w, r)
		})
		mux.Handle(pattern, auth.Require(provider, access.ProtectWrites(origin, store.Require(access.AdminManage, "", available))))
	}
	newConnectionTests(repo, origin).register(mux, route)
	route("POST /api/admin/auth/settings/{id}/enroll", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			EvidenceID string `json:"evidence_id"`
			Generation int64  `json:"expected_generation"`
			Role       string `json:"role"`
			Confirm    bool   `json:"confirm"`
		}
		if !access.DecodeJSON(w, r, &body) {
			return
		}
		if !body.Confirm {
			httpError(w, ErrInvalid)
			return
		}
		user, err := repo.EnrollIdentity(r.Context(), r.PathValue("id"), body.EvidenceID, body.Generation, body.Role)
		if err != nil {
			httpError(w, err)
			return
		}
		reply(w, http.StatusOK, user)
	})
	route("GET /api/admin/auth/settings", func(w http.ResponseWriter, r *http.Request) {
		before, limit, err := pagination(r.URL.RawQuery)
		if err != nil {
			httpError(w, err)
			return
		}
		revisions, err := repo.List(r.Context(), before, limit)
		if err != nil {
			httpError(w, err)
			return
		}
		var next int64
		if len(revisions) == limit {
			next = revisions[len(revisions)-1].Version
		}
		reply(w, http.StatusOK, struct {
			Revisions []Metadata `json:"revisions"`
			Next      int64      `json:"next_before_version"`
		}{revisions, next})
	})
	route("GET /api/admin/auth/settings/{id}", func(w http.ResponseWriter, r *http.Request) {
		m, err := repo.Read(r.Context(), r.PathValue("id"))
		if err != nil {
			httpError(w, err)
			return
		}
		reply(w, http.StatusOK, m)
	})
	route("POST /api/admin/auth/settings", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Settings
			ExpectedLatestVersion *int64 `json:"expected_latest_version"`
			ClientSecret          string `json:"client_secret"`
		}
		if !access.DecodeJSON(w, r, &body) {
			return
		}
		if body.ExpectedLatestVersion == nil {
			httpError(w, ErrInvalid)
			return
		}
		secret := NewSecret([]byte(body.ClientSecret))
		body.ClientSecret = ""
		defer clear(secret.value)
		m, err := repo.CreateDraft(r.Context(), *body.ExpectedLatestVersion, body.Settings, secret)
		if err != nil {
			httpError(w, err)
			return
		}
		w.Header().Set("Location", "/api/admin/auth/settings/"+m.ID)
		reply(w, http.StatusCreated, m)
	})
	for _, transition := range []struct {
		path   string
		status Status
	}{{"validate", Validated}, {"approve", Approved}} {
		route("POST /api/admin/auth/settings/{id}/"+transition.path, func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				ExpectedGeneration *int64 `json:"expected_generation"`
			}
			if !access.DecodeJSON(w, r, &body) {
				return
			}
			if body.ExpectedGeneration == nil {
				httpError(w, ErrInvalid)
				return
			}
			m, err := repo.Transition(r.Context(), r.PathValue("id"), *body.ExpectedGeneration, transition.status)
			if err != nil {
				httpError(w, err)
				return
			}
			reply(w, http.StatusOK, m)
		})
	}
	route("GET /api/admin/auth/status", func(w http.ResponseWriter, r *http.Request) {
		status, ok := runtimeStatus(r.Context())
		if !ok {
			httpError(w, ErrUnavailable)
			return
		}
		latest, err := repo.List(r.Context(), 0, 1)
		if err != nil {
			httpError(w, err)
			return
		}
		active, err := repo.CurrentActive(r.Context())
		if err != nil && !errors.Is(err, ErrNotFound) {
			httpError(w, err)
			return
		}
		var latestRevision, activeRevision *Metadata
		if len(latest) != 0 {
			latestRevision = &latest[0]
		}
		if err == nil {
			activeRevision = &active
		}
		reply(w, http.StatusOK, struct {
			RuntimeProvider auth.Provider `json:"runtime_provider"`
			RuntimeSource   string        `json:"runtime_source"`
			ManagementOnly  bool          `json:"management_only"`
			ValidationMode  string        `json:"validation_mode"`
			LatestRevision  *Metadata     `json:"latest_revision"`
			ActiveRevision  *Metadata     `json:"database_active_revision"`
		}{status.Provider, status.Source, true, "offline_static", latestRevision, activeRevision})
	})
}

func pagination(raw string) (int64, int, error) {
	values, err := url.ParseQuery(raw)
	if err != nil {
		return 0, 0, ErrInvalid
	}
	before, limit := int64(0), int64(50)
	for key, values := range values {
		if len(values) != 1 {
			return 0, 0, ErrInvalid
		}
		n, err := strconv.ParseInt(values[0], 10, 64)
		if err != nil {
			return 0, 0, ErrInvalid
		}
		switch key {
		case "before_version":
			before = n
		case "limit":
			limit = n
		default:
			return 0, 0, ErrInvalid
		}
	}
	if before < 0 || limit < 1 || limit > 100 {
		return 0, 0, ErrInvalid
	}
	return before, int(limit), nil
}
