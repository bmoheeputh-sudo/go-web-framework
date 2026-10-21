package authconfig

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
)

func notificationError(w http.ResponseWriter, err error) {
	status, code := 503, "notification_unavailable"
	switch {
	case errors.Is(err, ErrInvalid):
		status, code = 400, "notification_invalid"
	case errors.Is(err, ErrDenied):
		status, code = 403, "notification_denied"
	case errors.Is(err, ErrNotFound):
		status, code = 404, "notification_not_found"
	case errors.Is(err, ErrConflict):
		status, code = 409, "notification_conflict"
	case errors.Is(err, ErrCommitUncertain):
		code = "notification_commit_uncertain"
	}
	reply(w, status, map[string]any{"error": code, "inspection_required": errors.Is(err, ErrCommitUncertain), "automatic_retry_allowed": false})
}
func notificationQuery(r *http.Request, allowed ...string) (url.Values, error) {
	if len(r.URL.RawQuery) > 4096 {
		return nil, ErrInvalid
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, ErrInvalid
	}
	for key, values := range q {
		ok := false
		for _, name := range allowed {
			if key == name {
				ok = true
			}
		}
		if !ok || len(values) != 1 {
			return nil, ErrInvalid
		}
	}
	return q, nil
}
func notificationPageQuery(q url.Values) (NotificationPageQuery, error) {
	p := NotificationPageQuery{Search: q.Get("search"), Category: q.Get("category"), ImportID: q.Get("import_id"), Status: q.Get("status"), RequestID: q.Get("request_id"), Limit: 20}
	var err error
	if q.Has("offset") {
		p.Offset, err = strconv.Atoi(q.Get("offset"))
		if err != nil {
			return p, ErrInvalid
		}
	}
	if q.Has("limit") {
		p.Limit, err = strconv.Atoi(q.Get("limit"))
		if err != nil {
			return p, ErrInvalid
		}
	}
	if !p.valid() {
		return p, ErrInvalid
	}
	return p, nil
}

func RegisterNotificationManagement(mux *http.ServeMux, provider auth.Authenticator, store *access.Store, origin string, s *NotificationManagement) {
	route := func(pattern string, h http.HandlerFunc) {
		guard := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := requireImportOIDC(r.Context()); err != nil {
				notificationError(w, err)
				return
			}
			if s == nil {
				notificationError(w, ErrUnavailable)
				return
			}
			if len(r.URL.RawQuery) > 4096 || r.Method == "POST" && r.URL.RawQuery != "" {
				notificationError(w, ErrInvalid)
				return
			}
			h(w, r)
		})
		protected := auth.Require(provider, access.ProtectWrites(origin, store.Require(access.AdminManage, "", guard)))
		mux.Handle(pattern, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Referrer-Policy", "no-referrer")
			protected.ServeHTTP(w, r)
		}))
	}
	route("GET "+NotificationManagementPath+"/onboarding", func(w http.ResponseWriter, r *http.Request) {
		q, err := notificationQuery(r, "search", "category", "import_id", "offset", "limit")
		if err != nil {
			notificationError(w, err)
			return
		}
		p, err := notificationPageQuery(q)
		if err != nil {
			notificationError(w, err)
			return
		}
		result, err := s.Onboarding(r.Context(), p)
		if err != nil {
			notificationError(w, err)
			return
		}
		reply(w, 200, result)
	})
	route("POST "+NotificationManagementPath+"/preview", func(w http.ResponseWriter, r *http.Request) {
		var input NotificationPreviewInput
		if !decodeNotificationAdminJSON(w, r, &input, notificationError) {
			return
		}
		result, err := s.Preview(r.Context(), input)
		if err != nil {
			notificationError(w, err)
			return
		}
		reply(w, 200, result)
	})
	route("POST "+NotificationManagementPath+"/enqueue", func(w http.ResponseWriter, r *http.Request) {
		var input NotificationEnqueueInput
		if !decodeNotificationAdminJSON(w, r, &input, notificationError) {
			return
		}
		result, err := s.Enqueue(r.Context(), input)
		if err != nil {
			notificationError(w, err)
			return
		}
		reply(w, 201, map[string]any{"request_id": result.ID, "job_count": result.JobCount, "outcome": "queued", "delivery_enabled": false})
	})
	route("GET "+NotificationManagementPath+"/history", func(w http.ResponseWriter, r *http.Request) {
		q, err := notificationQuery(r, "search", "status", "request_id", "offset", "limit")
		if err != nil {
			notificationError(w, err)
			return
		}
		p, err := notificationPageQuery(q)
		if err != nil {
			notificationError(w, err)
			return
		}
		result, err := s.History(r.Context(), p)
		if err != nil {
			notificationError(w, err)
			return
		}
		reply(w, 200, result)
	})
	route("GET "+NotificationManagementPath+"/requests/{id}", func(w http.ResponseWriter, r *http.Request) {
		q, err := notificationQuery(r, "offset", "limit")
		if err != nil {
			notificationError(w, err)
			return
		}
		p, err := notificationPageQuery(q)
		if err != nil {
			notificationError(w, err)
			return
		}
		result, err := s.Receipt(r.Context(), r.PathValue("id"), p.Offset, p.Limit)
		if err != nil {
			notificationError(w, err)
			return
		}
		reply(w, 200, result)
	})
	job := func(attempts bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if _, err := notificationQuery(r); err != nil {
				notificationError(w, err)
				return
			}
			result, err := s.Job(r.Context(), r.PathValue("id"))
			if err != nil {
				notificationError(w, err)
				return
			}
			if attempts {
				reply(w, 200, map[string]any{"job_id": result.Item.ID, "items": result.Attempts, "delivery_enabled": false})
			} else {
				reply(w, 200, result)
			}
		}
	}
	route("GET "+NotificationManagementPath+"/jobs/{id}", job(false))
	route("GET "+NotificationManagementPath+"/jobs/{id}/attempts", job(true))
	route("POST "+NotificationManagementPath+"/jobs/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			ExpectedGeneration int64  `json:"expected_generation"`
			Reason             string `json:"reason"`
		}
		if !decodeNotificationAdminJSON(w, r, &input, notificationError) {
			return
		}
		if err := s.repository.Cancel(r.Context(), r.PathValue("id"), input.ExpectedGeneration, input.Reason); err != nil {
			notificationError(w, err)
			return
		}
		reply(w, 200, map[string]string{"id": r.PathValue("id"), "outcome": "cancelled"})
	})
	route("GET "+NotificationManagementPath+"/suppressions", func(w http.ResponseWriter, r *http.Request) {
		q, err := notificationQuery(r, "target")
		if err != nil {
			notificationError(w, err)
			return
		}
		result, err := s.Suppression(r.Context(), q.Get("target"))
		if err != nil {
			notificationError(w, err)
			return
		}
		reply(w, 200, result)
	})
	route("POST "+NotificationManagementPath+"/suppressions", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Target             string `json:"target"`
			ExpectedGeneration int64  `json:"expected_generation"`
			Active             bool   `json:"active"`
			Reason             string `json:"reason"`
		}
		if !decodeNotificationAdminJSON(w, r, &input, notificationError) {
			return
		}
		t, err := notificationTarget(input.Target)
		if err != nil {
			notificationError(w, err)
			return
		}
		result, err := s.repository.SetSuppression(r.Context(), SuppressionTarget{NotificationTarget: t}, input.ExpectedGeneration, input.Active, input.Reason)
		if err != nil {
			notificationError(w, err)
			return
		}
		reply(w, 200, NotificationSuppressionDTO{input.Target, result.Active, result.Generation, result.Reason})
	})
}
