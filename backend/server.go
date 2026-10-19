package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/apps/example"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/authconfig"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/database"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/modules"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/module"
	"github.com/jackc/pgx/v5/pgxpool"
)

type application struct {
	*http.Server
	closeResources func()
}

// newServer validates configuration before opening a listener. Unset authentication
// preserves public health checks but grants no identity or protected-route access.
func newServer(getenv func(string) string) (*application, error) {
	rbacEnabled := false
	if value := getenv("RBAC_ENABLED"); value != "" {
		var err error
		rbacEnabled, err = strconv.ParseBool(value)
		if err != nil {
			return nil, errors.New("RBAC_ENABLED must be true or false")
		}
	}
	// Explicit compile-time catalog: no init hooks, filesystem discovery or plugins.
	registry, err := modules.New([]module.Module{example.Module{}}, getenv("ENABLED_MODULES"))
	if err != nil {
		return nil, err
	}
	if len(registry.Enabled()) != 0 && !rbacEnabled {
		return nil, errors.New("ENABLED_MODULES requires RBAC_ENABLED=true")
	}
	origin := getenv("APP_ORIGIN")
	if rbacEnabled {
		if err := access.ValidateOrigin(origin, getenv("APP_ENV")); err != nil {
			return nil, err
		}
	}
	var pool *pgxpool.Pool
	address := getenv("HTTP_ADDR")
	if address == "" {
		address = "127.0.0.1:8080"
	}
	var provider auth.Authenticator
	closeResources := func() {}
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
	case auth.OIDC:
		sessions, err := auth.SessionConfigFromEnv(getenv)
		if err != nil {
			return nil, err
		}
		allowHTTP := false
		if value := getenv("OIDC_ALLOW_HTTP_DEVELOPMENT"); value != "" {
			allowHTTP, err = strconv.ParseBool(value)
			if err != nil {
				return nil, errors.New("OIDC_ALLOW_HTTP_DEVELOPMENT must be true or false")
			}
		}
		config := auth.OIDCConfig{
			AppEnv: getenv("APP_ENV"), Issuer: getenv("OIDC_ISSUER_URL"),
			ClientID: getenv("OIDC_CLIENT_ID"), ClientSecret: getenv("OIDC_CLIENT_SECRET"),
			RedirectURI: getenv("OIDC_REDIRECT_URI"),
			Sessions:    sessions, AllowHTTPDevelopment: allowHTTP,
		}
		if err := config.Validate(); err != nil {
			return nil, err
		}
		if allowHTTP {
			host, _, err := net.SplitHostPort(address)
			if err != nil || !net.ParseIP(host).IsLoopback() {
				return nil, errors.New("HTTP development requires a loopback HTTP_ADDR")
			}
		}
		pool, err = database.Open(context.Background(), getenv)
		if err != nil {
			return nil, err
		}
		store, err := auth.NewPostgresStore(pool, sessions)
		if err != nil {
			pool.Close()
			return nil, err
		}
		oidcProvider, err := auth.NewOIDC(context.Background(), config, store)
		if err != nil {
			pool.Close()
			return nil, err
		}
		closeResources = pool.Close
		provider = oidcProvider
	case auth.GoogleIAP:
		iap, err := auth.NewGoogleIAP(getenv("IAP_AUDIENCE"))
		if err != nil {
			return nil, err
		}
		provider = iap
	default:
		return nil, errors.New("unsupported AUTH_PROVIDER; use oidc, google_iap or local_dev, or leave unset for public health only")
	}
	var authorization *access.Store
	if rbacEnabled {
		if provider == nil {
			return nil, errors.New("RBAC_ENABLED requires an explicit AUTH_PROVIDER")
		}
		if pool == nil {
			var err error
			pool, err = database.Open(context.Background(), getenv)
			if err != nil {
				return nil, err
			}
			closeResources = pool.Close
		}
		authorization = access.New(pool)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := authorization.Check(ctx); err != nil {
			closeResources()
			return nil, errors.New("RBAC schema unavailable; apply migration 000004 manually before enabling RBAC")
		}
	}
	if err := registry.CheckMigrations(context.Background(), pool); err != nil {
		closeResources()
		return nil, err
	}
	handler, err := newHandlerWithModules(provider, authorization, origin, registry)
	if err != nil {
		closeResources()
		return nil, err
	}
	// Management is optional and never supplies runtime authentication settings.
	// Missing/invalid management configuration yields protected 503 responses;
	// it must not disable the existing environment-configured login provider.
	configRepository, _ := authconfig.RepositoryFromEnv(authorization, getenv)
	authconfig.Register(handler, provider, authorization, origin, configRepository, auth.Provider(getenv("AUTH_PROVIDER")))
	return &application{closeResources: closeResources, Server: &http.Server{
		Addr: address, Handler: handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second, WriteTimeout: 30 * time.Second,
		IdleTimeout: 60 * time.Second,
	}}, nil
}

func newHandler(provider auth.Authenticator) http.Handler {
	return newHandlerWithAccess(provider, nil, "")
}

func newHandlerWithAccess(provider auth.Authenticator, authorization *access.Store, origin string) *http.ServeMux {
	mux := http.NewServeMux()
	access.Register(mux, provider, authorization, origin)
	var providerName auth.Provider
	switch selected := provider.(type) {
	case *auth.OIDCAuthenticator:
		providerName = auth.OIDC
		mux.HandleFunc("GET /api/auth/login", selected.Login)
		mux.HandleFunc("GET /api/auth/callback", selected.Callback)
		mux.HandleFunc("POST /api/auth/logout", selected.Logout)
	case *auth.LocalDevAuthenticator:
		providerName = auth.LocalDev
	case *auth.IAPAuthenticator:
		providerName = auth.GoogleIAP
	}
	// Only the provider name is public; no issuer, client configuration or tokens.
	mux.HandleFunc("GET /api/auth/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]auth.Provider{"provider": providerName})
	})
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

// The core composition root owns both namespaces; modules never receive this mux.
func newHandlerWithModules(provider auth.Authenticator, authorization *access.Store, origin string, registry *modules.Registry) (*http.ServeMux, error) {
	if authorization != nil {
		var err error
		authorization, err = authorization.WithPermissionDefinitions(registry.PermissionDefinitions())
		if err != nil {
			return nil, err
		}
	}
	moduleHandler, err := registry.Handler(provider, authorization, origin)
	if err != nil {
		return nil, err
	}
	handler := newHandlerWithAccess(provider, authorization, origin)
	handler.Handle("/api/modules", moduleHandler)
	handler.Handle("/api/modules/", moduleHandler)
	return handler, nil
}
