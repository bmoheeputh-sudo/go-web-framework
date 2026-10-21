package authconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/notifications"
)

func connectorError(w http.ResponseWriter, err error) {
	status, code := 503, "email_connector_unavailable"
	switch {
	case errors.Is(err, ErrInvalid):
		status, code = 400, "email_connector_invalid"
	case errors.Is(err, ErrDenied):
		status, code = 403, "email_connector_denied"
	case errors.Is(err, ErrNotFound):
		status, code = 404, "email_connector_not_found"
	case errors.Is(err, ErrConflict):
		status, code = 409, "email_connector_conflict"
	case errors.Is(err, ErrCommitUncertain):
		code = "email_connector_commit_uncertain"
	}
	reply(w, status, map[string]any{"error": code, "inspection_required": errors.Is(err, ErrCommitUncertain), "automatic_retry_allowed": false})
}
func decodeConnector(w http.ResponseWriter, r *http.Request, out any) bool {
	return decodeNotificationAdminJSON(w, r, out, connectorError)
}
func decodeNotificationAdminJSON(w http.ResponseWriter, r *http.Request, out any, failure func(http.ResponseWriter, error)) bool {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<10))
	if err != nil || !validJSONUnicode(data) {
		failure(w, ErrInvalid)
		return false
	}
	allowed := map[string]bool{}
	t := reflect.TypeOf(out).Elem()
	for i := 0; i < t.NumField(); i++ {
		allowed[strings.Split(t.Field(i).Tag.Get("json"), ",")[0]] = true
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		failure(w, ErrInvalid)
		return false
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err = decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] || !allowed[key] {
			failure(w, ErrInvalid)
			return false
		}
		seen[key] = true
		var raw json.RawMessage
		if decoder.Decode(&raw) != nil {
			failure(w, ErrInvalid)
			return false
		}
	}
	if _, err = decoder.Token(); err != nil || decoder.Decode(new(any)) != io.EOF {
		failure(w, ErrInvalid)
		return false
	}
	if !uniqueJSONKeys(json.NewDecoder(bytes.NewReader(data))) {
		failure(w, ErrInvalid)
		return false
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil {
		failure(w, ErrInvalid)
		return false
	}
	return true
}

// DisallowUnknownFields handles schemas; this walk also rejects ambiguous keys
// inside nested preview/input/expectation objects, not only at the top level.
func uniqueJSONKeys(d *json.Decoder) bool {
	token, err := d.Token()
	if err != nil {
		return false
	}
	switch token {
	case json.Delim('{'):
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			name, ok := key.(string)
			if err != nil || !ok || seen[name] {
				return false
			}
			seen[name] = true
			if !uniqueJSONKeys(d) {
				return false
			}
		}
		end, err := d.Token()
		return err == nil && end == json.Delim('}')
	case json.Delim('['):
		for d.More() {
			if !uniqueJSONKeys(d) {
				return false
			}
		}
		end, err := d.Token()
		return err == nil && end == json.Delim(']')
	}
	return true
}
func gmailCookieName(flow string, secure bool) string {
	prefix := "vgca_gmail_"
	if secure {
		prefix = "__Secure-" + prefix
	}
	return prefix + flow
}
func RegisterEmailConnectors(mux *http.ServeMux, provider auth.Authenticator, store *access.Store, origin string, service *EmailConnectorService) {
	route := func(pattern string, allowQuery bool, h http.HandlerFunc) {
		wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if service == nil {
				connectorError(w, ErrUnavailable)
				return
			}
			if len(r.URL.RawQuery) > 8192 || (!allowQuery && r.URL.RawQuery != "") {
				connectorError(w, ErrInvalid)
				return
			}
			h(w, r)
		})
		protected := auth.Require(provider, access.ProtectWrites(origin, store.Require(access.AdminManage, "", wrapped)))
		mux.Handle(pattern, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Referrer-Policy", "no-referrer")
			protected.ServeHTTP(w, r)
		}))
	}
	route("GET "+EmailConnectorsPath, true, func(w http.ResponseWriter, r *http.Request) {
		values, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			connectorError(w, ErrInvalid)
			return
		}
		for key, entries := range values {
			if (key != "offset" && key != "limit") || len(entries) != 1 {
				connectorError(w, ErrInvalid)
				return
			}
		}
		offset, limit := 0, 20
		if values.Has("offset") {
			offset, err = strconv.Atoi(values.Get("offset"))
			if err != nil {
				connectorError(w, ErrInvalid)
				return
			}
		}
		if values.Has("limit") {
			limit, err = strconv.Atoi(values.Get("limit"))
			if err != nil {
				connectorError(w, ErrInvalid)
				return
			}
		}
		items, total, err := service.List(r.Context(), offset, limit)
		if err != nil {
			connectorError(w, err)
			return
		}
		reply(w, 200, map[string]any{"items": items, "total": total, "offset": offset, "limit": limit, "gmail_authorization_available": service.credentials != nil, "gmail_callback_url": origin + GmailCallbackPath, "gmail_scopes": []string{notifications.GmailScope, notifications.GmailSenderScope}})
	})
	route("POST "+EmailConnectorsPath, false, func(w http.ResponseWriter, r *http.Request) {
		var input EmailConnectorCreate
		if !decodeConnector(w, r, &input) {
			return
		}
		c, err := service.Create(r.Context(), input)
		if err != nil {
			connectorError(w, err)
			return
		}
		reply(w, 201, c)
	})
	route("GET "+EmailConnectorsPath+"/{id}", false, func(w http.ResponseWriter, r *http.Request) {
		c, err := service.Read(r.Context(), r.PathValue("id"))
		if err != nil {
			connectorError(w, err)
			return
		}
		reply(w, 200, c)
	})
	route("POST "+EmailConnectorsPath+"/{id}/configure", false, func(w http.ResponseWriter, r *http.Request) {
		var input EmailConnectorUpdate
		if !decodeConnector(w, r, &input) {
			return
		}
		c, err := service.Configure(r.Context(), r.PathValue("id"), input)
		if err != nil {
			connectorError(w, err)
			return
		}
		reply(w, 200, c)
	})
	route("POST "+EmailConnectorsPath+"/{id}/test", false, func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			ExpectedGeneration int64  `json:"expected_generation"`
			Reason             string `json:"reason"`
		}
		if !decodeConnector(w, r, &input) {
			return
		}
		c, err := service.Test(r.Context(), r.PathValue("id"), input.ExpectedGeneration, input.Reason)
		if err != nil {
			connectorError(w, err)
			return
		}
		reply(w, 200, c)
	})
	route("POST "+EmailConnectorsPath+"/{id}/gmail/authorize", false, func(w http.ResponseWriter, r *http.Request) {
		var input GmailAuthorizationInput
		if !decodeConnector(w, r, &input) {
			return
		}
		started, err := service.BeginGmail(r.Context(), r.PathValue("id"), input)
		if err != nil {
			connectorError(w, err)
			return
		}
		secure := strings.HasPrefix(origin, "https://")
		http.SetCookie(w, &http.Cookie{Name: gmailCookieName(started.FlowID, secure), Value: started.Browser, Path: GmailCallbackPath, HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode, Expires: started.ExpiresAt, MaxAge: 300})
		reply(w, 200, map[string]string{"authorization_url": started.URL})
	})
	route("GET "+GmailCallbackPath, true, func(w http.ResponseWriter, r *http.Request) {
		q, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			connectorError(w, ErrInvalid)
			return
		}
		for key, entries := range q {
			if len(entries) != 1 || !slices.Contains([]string{"state", "code", "error", "scope", "authuser", "prompt", "hd", "iss"}, key) {
				connectorError(w, ErrInvalid)
				return
			}
		}
		if q.Has("iss") && q.Get("iss") != "https://accounts.google.com" {
			connectorError(w, ErrInvalid)
			return
		}
		state := q.Get("state")
		parts := strings.Split(state, ".")
		if len(parts) != 2 || !validID(parts[0]) {
			connectorError(w, ErrInvalid)
			return
		}
		secure := strings.HasPrefix(origin, "https://")
		name := gmailCookieName(parts[0], secure)
		cookie, err := r.Cookie(name)
		if err != nil {
			connectorError(w, ErrDenied)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: name, Path: GmailCallbackPath, HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode, Expires: time.Unix(1, 0), MaxAge: -1})
		result := "completed"
		if err = service.CompleteGmail(r.Context(), state, cookie.Value, q.Get("code"), q.Get("error")); err != nil {
			result = "failed"
		}
		// No authorization code/state/token or provider text reaches the SPA.
		http.Redirect(w, r, "/settings?tab=notifications&gmail_result="+result, http.StatusSeeOther)
	})
}
