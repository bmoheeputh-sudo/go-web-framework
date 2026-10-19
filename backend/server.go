package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
)

// newServer validates configuration before opening a listener. Unset authentication
// preserves public health checks but grants no identity or protected-route access.
func newServer(getenv func(string) string) (*http.Server, error) {
	address := getenv("HTTP_ADDR")
	if address == "" {
		address = "127.0.0.1:8080"
	}
	var provider auth.Authenticator
	switch auth.Provider(getenv("AUTH_PROVIDER")) {
	case "":
	case auth.LocalDev:
		local, err := auth.NewLocalDev(getenv("APP_ENV"), auth.LocalDevConfig{
			Subject: getenv("LOCAL_DEV_SUBJECT"), Email: getenv("LOCAL_DEV_EMAIL"),
			DisplayName: getenv("LOCAL_DEV_DISPLAY_NAME"),
		})
		if err != nil {
			return nil, err
		}
		host, port, err := net.SplitHostPort(address)
		if err != nil || !net.ParseIP(host).IsLoopback() {
			return nil, errors.New("local_dev requires HTTP_ADDR with a literal loopback IP (for example 127.0.0.1:8080)")
		}
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return nil, errors.New("HTTP_ADDR requires a port between 1 and 65535")
		}
		provider = local
	case auth.OIDC, auth.GoogleIAP:
		return nil, errors.New("selected AUTH_PROVIDER is not implemented in Phase 1")
	default:
		return nil, errors.New("unsupported AUTH_PROVIDER; use local_dev for development or leave unset for public health only")
	}
	return &http.Server{
		Addr: address, Handler: newHandler(provider),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second, WriteTimeout: 10 * time.Second,
		IdleTimeout: 60 * time.Second,
	}, nil
}

func newHandler(provider auth.Authenticator) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "ok", "service": "go-web-framework",
		})
	})
	mux.Handle("GET /api/auth/me", auth.Require(provider, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := auth.IdentityFromContext(r.Context())
		if !ok {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(identity)
	})))
	return mux
}
