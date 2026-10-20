package main

import (
	"context"
	"errors"
	"net"
	"net/http/httptest"
	"testing"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/authconfig"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/testdb"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestStartupPolicyPreservesLocalDevWithIsolatedDatabase(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		name := "no head"
		if explicit {
			name = "explicit environment"
		}
		t.Run(name, func(t *testing.T) {
			pool, _ := testdb.New(t)
			testdb.Migrations(t, pool, "up")
			env := developmentEnvironment()
			env["AUTH_CONFIG_DEPLOYMENT"] = "test-installation"
			if explicit {
				if _, err := pool.Exec(context.Background(), `INSERT INTO framework.auth_activation_heads(deployment_id,environment) VALUES('test-installation','development')`); err != nil {
					t.Fatal(err)
				}
			}
			// Substitute only connection establishment (the harness uses a private
			// Unix socket). Production scope parsing and policy queries run unchanged.
			app, err := newServerWithPolicy(envReader(env), func(getenv func(string) string) (*pgxpool.Pool, error) {
				scope, err := authconfig.ScopeFromEnv(getenv)
				if err != nil {
					return nil, err
				}
				reader, err := authconfig.NewActivationReader(pool, scope)
				if err != nil {
					return nil, err
				}
				if err := reader.RequireEnvironmentStartup(context.Background()); err != nil {
					return nil, err
				}
				return pool, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer app.closeResources()
			for _, path := range []string{"/api/health", "/api/auth/me", "/api/auth/config"} {
				r := httptest.NewRequest("GET", path, nil)
				r.RemoteAddr = "127.0.0.1:1234"
				w := httptest.NewRecorder()
				app.Handler.ServeHTTP(w, r)
				if w.Code != 200 {
					t.Fatal("existing Local DEV route changed", path, w.Code)
				}
			}
			var events int
			if err := pool.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM framework.auth_activation_history)+(SELECT count(*) FROM framework.sessions)+(SELECT count(*) FROM framework.users)`).Scan(&events); err != nil || events != 0 {
				t.Fatal("startup or Local DEV created records", err)
			}
		})
	}
}

func TestStartupPolicyBlocksBeforeAnyEnvironmentProvider(t *testing.T) {
	for _, provider := range []string{"local_dev", "oidc", ""} {
		for _, failure := range []error{authconfig.ErrDatabaseRuntimeRequired, authconfig.ErrUnavailable} {
			env := developmentEnvironment()
			env["AUTH_PROVIDER"] = provider
			called := false
			server, err := newServerWithPolicy(envReader(env), func(func(string) string) (*pgxpool.Pool, error) { called = true; return nil, failure })
			if !called || server != nil || !errors.Is(err, failure) {
				t.Fatal("startup bypassed policy", provider, err)
			}
		}
	}
}

func TestStartupRequiresScopeAndReadableDatabase(t *testing.T) {
	for _, deployment := range []string{"", "../invalid", "valid-scope"} {
		env := developmentEnvironment()
		env["AUTH_CONFIG_DEPLOYMENT"] = deployment
		env["DB_PORT"] = "invalid" // no network or development DB access
		server, err := newServer(envReader(env))
		if err == nil || server != nil {
			t.Fatal("missing policy permitted Local DEV fallback")
		}
	}
}

func TestStartupDatabaseConnectionFailureNeverSelectsLocalDev(t *testing.T) {
	// A synthetic non-PostgreSQL listener fails connection establishment. Never
	// read DB_* from the environment or attempt the development database port.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	defer func() { listener.Close(); <-done }()
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	env := developmentEnvironment()
	for key, value := range map[string]string{"AUTH_CONFIG_DEPLOYMENT": "test-installation", "DB_HOST": host, "DB_PORT": port, "DB_NAME": "synthetic", "DB_USER": "go_web_app", "DB_PASSWORD": "synthetic-test-only", "DB_SSLMODE": "disable"} {
		env[key] = value
	}
	app, err := newServer(envReader(env))
	if app != nil || err == nil || err.Error() != "authentication startup policy unavailable; verify PostgreSQL configuration and schema" {
		t.Fatal("unreadable database permitted startup or leaked connection detail")
	}
}
