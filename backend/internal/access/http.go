package access

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
)

type principalKey struct{}

func Principal(ctx context.Context) (User, bool) {
	u, ok := ctx.Value(principalKey{}).(User)
	return u, ok
}
func ValidateOrigin(origin, environment string) error {
	u, err := url.Parse(origin)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return errors.New("APP_ORIGIN must be an exact origin without path, credentials, query or fragment")
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && environment == "development" && (u.Hostname() == "localhost" || net.ParseIP(u.Hostname()).IsLoopback()) {
		return nil
	}
	return errors.New("APP_ORIGIN requires HTTPS, except loopback HTTP in development")
}
func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func failure(w http.ResponseWriter, err error) {
	status := http.StatusServiceUnavailable
	message := "authorization temporarily unavailable"
	switch {
	case errors.Is(err, ErrDenied):
		status = http.StatusForbidden
		message = "access denied"
	case errors.Is(err, ErrInvalid):
		status = http.StatusBadRequest
		message = "invalid request"
	case errors.Is(err, ErrConflict):
		status = http.StatusConflict
		message = "change conflicts with current state"
	}
	respond(w, status, map[string]string{"error": message})
}

// Require is deny-by-default, and must run inside auth.Require. accountParameter
// names a route path parameter whose account must be explicitly linked and active.
func (s *Store) Require(permission, accountParameter string, next http.Handler) http.Handler {
	return s.identify(false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, _ := Principal(r.Context())
		accountID := ""
		if accountParameter != "" {
			accountID = r.PathValue(accountParameter)
			if !validID(accountID) {
				failure(w, ErrDenied)
				return
			}
		}
		if err := s.Allowed(r.Context(), u.ID, permission, accountID); err != nil {
			failure(w, err)
			return
		}
		next.ServeHTTP(w, r)
	}))
}
func (s *Store) identify(register bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := auth.IdentityFromContext(r.Context())
		if !ok {
			failure(w, ErrDenied)
			return
		}
		if s == nil {
			failure(w, ErrUnavailable)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		var u User
		var err error
		if register {
			u, err = s.Resolve(ctx, identity)
		} else {
			u, err = s.lookup(ctx, identity)
		}
		if err != nil {
			failure(w, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, principalKey{}, u)))
	})
}

// ProtectWrites applies the same origin and JSON checks to core and module writes.
func ProtectWrites(origin string, next http.Handler) http.Handler {
	return protectWrites(origin, next)
}

func protectWrites(origin string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "HEAD" {
			origins := r.Header.Values("Origin")
			kind, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if len(origins) != 1 || origin == "" || origins[0] != origin || err != nil || kind != "application/json" {
				failure(w, ErrDenied)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
func decode(w http.ResponseWriter, r *http.Request, value any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(value) != nil {
		failure(w, ErrInvalid)
		return false
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		failure(w, ErrInvalid)
		return false
	}
	return true
}
func offset(r *http.Request) (int, error) {
	value := r.URL.Query().Get("offset")
	if value == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 0 || n > 1000000 {
		return 0, ErrInvalid
	}
	return n, nil
}

// Register keeps all RBAC/account routes behind both authentication and Go-side
// authorization. A nil store exposes no RBAC data or mutations (503).
func Register(mux *http.ServeMux, provider auth.Authenticator, s *Store, origin string) {
	route := func(pattern, permission, accountParameter string, h http.HandlerFunc) {
		var handler http.Handler
		if permission == "self" {
			handler = s.identify(true, h)
		} else {
			handler = s.Require(permission, accountParameter, h)
		}
		mux.Handle(pattern, auth.Require(provider, ProtectWrites(origin, handler)))
	}
	route("GET /api/access/me", "self", "", func(w http.ResponseWriter, r *http.Request) { u, _ := Principal(r.Context()); respond(w, 200, u) })
	route("GET /api/admin/users", AdminManage, "", func(w http.ResponseWriter, r *http.Request) {
		n, err := offset(r)
		if err != nil {
			failure(w, err)
			return
		}
		result, err := s.Users(r.Context(), n)
		if err != nil {
			failure(w, err)
			return
		}
		respond(w, 200, result)
	})
	route("GET /api/admin/roles", AdminManage, "", func(w http.ResponseWriter, r *http.Request) {
		result, err := s.Roles(r.Context())
		if err != nil {
			failure(w, err)
			return
		}
		respond(w, 200, result)
	})
	route("GET /api/admin/audit", AdminManage, "", func(w http.ResponseWriter, r *http.Request) {
		n, err := offset(r)
		if err != nil {
			failure(w, err)
			return
		}
		result, err := s.Audit(r.Context(), n)
		if err != nil {
			failure(w, err)
			return
		}
		respond(w, 200, result)
	})
	route("PUT /api/admin/users/{user}/roles", AdminManage, "", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Roles *[]string `json:"roles"`
		}
		if !decode(w, r, &body) {
			return
		}
		if body.Roles == nil {
			failure(w, ErrInvalid)
			return
		}
		u, _ := Principal(r.Context())
		if err := s.SetRoles(r.Context(), u.ID, r.PathValue("user"), *body.Roles); err != nil {
			failure(w, err)
			return
		}
		w.WriteHeader(204)
	})
	route("PUT /api/admin/users/{user}", AdminManage, "", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Active *bool `json:"active"`
		}
		if !decode(w, r, &body) {
			return
		}
		if body.Active == nil {
			failure(w, ErrInvalid)
			return
		}
		u, _ := Principal(r.Context())
		if err := s.SetActive(r.Context(), u.ID, r.PathValue("user"), *body.Active); err != nil {
			failure(w, err)
			return
		}
		w.WriteHeader(204)
	})
	route("PUT /api/admin/users/{user}/accounts", AdminManage, "", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			IDs *[]string `json:"account_ids"`
		}
		if !decode(w, r, &body) {
			return
		}
		if body.IDs == nil {
			failure(w, ErrInvalid)
			return
		}
		u, _ := Principal(r.Context())
		if err := s.SetAccounts(r.Context(), u.ID, r.PathValue("user"), *body.IDs); err != nil {
			failure(w, err)
			return
		}
		w.WriteHeader(204)
	})
	route("GET /api/admin/accounts", AdminManage, "", func(w http.ResponseWriter, r *http.Request) {
		n, err := offset(r)
		if err != nil {
			failure(w, err)
			return
		}
		result, err := s.Accounts(r.Context(), "", n)
		if err != nil {
			failure(w, err)
			return
		}
		respond(w, 200, result)
	})
	save := func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Name   string `json:"name"`
			Active *bool  `json:"active"`
		}
		if !decode(w, r, &body) {
			return
		}
		active := true
		if body.Active != nil {
			active = *body.Active
		} else if r.Method == "PUT" {
			failure(w, ErrInvalid)
			return
		}
		u, _ := Principal(r.Context())
		a, err := s.SaveAccount(r.Context(), u.ID, r.PathValue("account"), body.Name, active)
		if err != nil {
			failure(w, err)
			return
		}
		status := 200
		if r.Method == "POST" {
			status = 201
		}
		respond(w, status, a)
	}
	route("POST /api/admin/accounts", AdminManage, "", save)
	route("PUT /api/admin/accounts/{account}", AdminManage, "", save)
	route("GET /api/accounts", AccountRead, "", func(w http.ResponseWriter, r *http.Request) {
		u, _ := Principal(r.Context())
		n, err := offset(r)
		if err != nil {
			failure(w, err)
			return
		}
		result, err := s.Accounts(r.Context(), u.ID, n)
		if err != nil {
			failure(w, err)
			return
		}
		respond(w, 200, result)
	})
	route("GET /api/accounts/{account}", AccountRead, "account", func(w http.ResponseWriter, r *http.Request) {
		a, err := s.Account(r.Context(), r.PathValue("account"))
		if err != nil {
			failure(w, err)
			return
		}
		respond(w, 200, a)
	})
	route("PATCH /api/accounts/{account}", AccountWrite, "account", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Name string `json:"name"`
		}
		if !decode(w, r, &body) {
			return
		}
		u, _ := Principal(r.Context())
		if err := s.RenameAccount(r.Context(), u.ID, r.PathValue("account"), body.Name); err != nil {
			failure(w, err)
			return
		}
		w.WriteHeader(204)
	})
}
