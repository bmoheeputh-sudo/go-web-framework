package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
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
	authProvider   auth.Provider
}

// newServer validates configuration before opening a listener. Unset authentication
// preserves public health checks but grants no identity or protected-route access.
func newServer(getenv func(string) string) (*application, error) {
	return newServerWithPolicy(getenv, openStartupPolicy)
}

// The dependency seam is internal and used only by provider unit tests. Production
// always opens and validates the authoritative policy before preparing a provider.
func newServerWithPolicy(getenv func(string) string, policy func(func(string) string) (*pgxpool.Pool, error)) (result *application, resultErr error) {
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
	pool, err := policy(getenv)
	if err != nil {
		return nil, err
	}
	var runtime *auth.Runtime
	defer func() {
		if result == nil && runtime != nil {
			runtime.Close()
		}
		if result == nil && pool != nil {
			pool.Close()
		}
	}()
	address := getenv("HTTP_ADDR")
	if address == "" {
		address = "127.0.0.1:8080"
	}
	var provider auth.Authenticator
	closeResources := func() {}
	if pool != nil {
		closeResources = pool.Close
	}
	if pool != nil {
		scope, err := authconfig.ScopeFromEnv(getenv)
		if err != nil {
			return nil, err
		}
		reader, err := authconfig.NewActivationReader(pool, scope)
		if err != nil {
			return nil, err
		}
		runtime, err = authconfig.StartupRuntimeFromEnv(context.Background(), reader, getenv)
		if err != nil {
			return nil, errors.New("authentication runtime startup failed; verify authoritative policy, credentials and provider availability")
		}
		if runtime != nil {
			if err := access.ValidateOrigin(origin, getenv("APP_ENV")); err != nil {
				return nil, err
			}
			if strings.HasPrefix(origin, "http://") {
				host, _, err := net.SplitHostPort(address)
				if err != nil || !net.ParseIP(host).IsLoopback() {
					return nil, errors.New("HTTP development requires a loopback HTTP_ADDR")
				}
			}
		}
	}
	if runtime == nil {
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
			if pool == nil {
				pool, err = database.Open(context.Background(), getenv)
				if err != nil {
					return nil, err
				}
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
	}
	var authorization *access.Store
	if rbacEnabled {
		if provider == nil && runtime == nil {
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
	if runtime == nil {
		runtime, err = auth.NewEnvironmentRuntime(provider, getenv("AUTH_CONFIG_DEPLOYMENT"), getenv("APP_ENV"))
		if err != nil {
			closeResources()
			return nil, err
		}
	}
	status, _, _ := runtime.ControlStatus()
	if pool != nil && status.Source == "environment" {
		scope, err := authconfig.ScopeFromEnv(getenv)
		if err != nil {
			return nil, err
		}
		reader, err := authconfig.NewActivationReader(pool, scope)
		if err != nil {
			return nil, err
		}
		if err = reader.RequireEnvironmentStartup(context.Background()); err != nil {
			return nil, err
		}
	}
	handler, err := newHandlerWithModules(runtime, authorization, origin, registry)
	if err != nil {
		closeResources()
		return nil, err
	}
	// Management APIs remain separate from the read-only startup loader.
	// Missing/invalid management configuration yields protected 503 responses;
	// it must not disable the existing environment-configured login provider.
	configRepository, _ := authconfig.RepositoryFromEnv(authorization, getenv)
	authconfig.Register(handler.ServeMux, runtime, authorization, origin, configRepository, runtime.Status)
	return &application{authProvider: status.Provider, closeResources: func() { runtime.Close(); closeResources() }, Server: &http.Server{
		Addr: address, Handler: handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second, WriteTimeout: 30 * time.Second,
		IdleTimeout: 60 * time.Second,
	}}, nil
}

// The outer wrapper captures authentication once, before any router/middleware.
// Embedding the mux lets the composition root register management routes too.
type applicationRouter struct {
	*http.ServeMux
	captured http.Handler
}

func (r *applicationRouter) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	r.captured.ServeHTTP(w, request)
}

func newHandlerWithAccess(runtime *auth.Runtime, authorization *access.Store, origin string) *applicationRouter {
	mux := http.NewServeMux()
	access.Register(mux, runtime, authorization, origin)
	runtime.RegisterRoutes(mux)
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "ok", "service": "go-web-framework",
		})
	})
	return &applicationRouter{ServeMux: mux, captured: runtime.Capture(mux)}
}

// The core composition root owns both namespaces; modules never receive this mux.
func newHandlerWithModules(runtime *auth.Runtime, authorization *access.Store, origin string, registry *modules.Registry) (*applicationRouter, error) {
	if authorization != nil {
		var err error
		authorization, err = authorization.WithPermissionDefinitions(registry.PermissionDefinitions())
		if err != nil {
			return nil, err
		}
	}
	moduleHandler, err := registry.Handler(runtime, authorization, origin)
	if err != nil {
		return nil, err
	}
	handler := newHandlerWithAccess(runtime, authorization, origin)
	handler.Handle("/api/modules", moduleHandler)
	handler.Handle("/api/modules/", moduleHandler)
	return handler, nil
}

func openStartupPolicy(getenv func(string) string) (*pgxpool.Pool, error) {
	scope, err := authconfig.ScopeFromEnv(getenv)
	if err != nil {
		return nil, errors.New("authentication startup requires a valid deployment and environment scope")
	}
	pool, err := database.Open(context.Background(), getenv)
	if err != nil {
		return nil, errors.New("authentication startup policy unavailable; verify PostgreSQL configuration and schema")
	}
	reader, err := authconfig.NewActivationReader(pool, scope)
	if err == nil {
		err = reader.RequireEnvironmentStartup(context.Background())
	}
	if err != nil && !errors.Is(err, authconfig.ErrDatabaseRuntimeRequired) {
		pool.Close()
		return nil, err
	}
	return pool, nil
}
