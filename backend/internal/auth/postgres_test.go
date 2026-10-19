package auth

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/database"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/testdb"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/oauth2"
)

func TestPostgresSessions(t *testing.T) {
	pool, connection := testdb.New(t)
	ctx := context.Background()
	if database.CheckSchema(ctx, pool) == nil {
		t.Fatal("missing migrations were accepted")
	}
	testdb.Migrations(t, pool, "up")
	if err := database.CheckSchema(ctx, pool); err != nil {
		t.Fatal(err)
	}
	// Exercise all store operations as the unprivileged application role, with no
	// framework entry in search_path. Admin-only test fixtures still use pool.
	runtimeConfig, err := pgxpool.ParseConfig(connection)
	if err != nil {
		t.Fatal(err)
	}
	runtimeConfig.ConnConfig.User = "go_web_app"
	runtimeConfig.ConnConfig.RuntimeParams["search_path"] = "pg_catalog"
	runtimePool, err := pgxpool.NewWithConfig(ctx, runtimeConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer runtimePool.Close()
	if err := database.CheckSchema(ctx, runtimePool); err != nil {
		t.Fatal(err)
	}
	config := testSessionConfig()
	store, err := NewPostgresStore(runtimePool, config)
	if err != nil {
		t.Fatal(err)
	}
	identity := Identity{Issuer: "https://issuer.example.invalid", Subject: "user", Email: "user@example.invalid",
		EmailVerified: true, DisplayName: "User", Provider: OIDC}
	create := func() string {
		t.Helper()
		token, err := store.addSession(ctx, identity, time.Now().Add(time.Hour), "")
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	t.Run("creation hashes and lookup", func(t *testing.T) {
		token := create()
		var hash []byte
		var row, timestampType string
		if err := pool.QueryRow(ctx, `SELECT token_hash, row_to_json(s)::text, pg_typeof(expires_at)::text
		 FROM framework.sessions s WHERE token_hash=$1`, tokenHash(token)).Scan(&hash, &row, &timestampType); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(hash, tokenHash(token)) || bytes.Contains(hash, []byte(token)) || strings.Contains(row, token) {
			t.Fatal("raw session token stored")
		}
		if timestampType != "timestamp with time zone" {
			t.Fatal("timestamp is not TIMESTAMPTZ")
		}
		got, err := store.identity(ctx, token)
		if err != nil || got != identity {
			t.Fatalf("identity lookup failed: %v", err)
		}
		// An independently constructed pool/store resolves the same persistent session.
		otherPool, err := pgxpool.New(ctx, connection)
		if err != nil {
			t.Fatal(err)
		}
		defer otherPool.Close()
		other, _ := NewPostgresStore(otherPool, config)
		if got, err := other.identity(ctx, token); err != nil || got != identity {
			t.Fatal("session not shared between pools")
		}
	})
	t.Run("absolute and idle expiration", func(t *testing.T) {
		for _, absolute := range []bool{true, false} {
			token := create()
			query := `UPDATE framework.sessions SET created_at=now()-interval '2 hours', last_activity_at=now()-interval '1 hour' WHERE token_hash=$1`
			if absolute {
				query = `UPDATE framework.sessions SET created_at=now()-interval '2 hours', expires_at=now()-interval '1 minute' WHERE token_hash=$1`
			}
			if _, err := pool.Exec(ctx, query, tokenHash(token)); err != nil {
				t.Fatal(err)
			}
			if _, err := store.identity(ctx, token); !errors.Is(err, ErrUnauthenticated) {
				t.Fatal("expired session accepted")
			}
		}
	})
	t.Run("activity refresh does not extend absolute expiry", func(t *testing.T) {
		token := create()
		_, err := pool.Exec(ctx, `UPDATE framework.sessions SET created_at=now()-interval '10 minutes', last_activity_at=now()-interval '5 minutes' WHERE token_hash=$1`, tokenHash(token))
		if err != nil {
			t.Fatal(err)
		}
		var before, after, expiresBefore, expiresAfter time.Time
		_ = pool.QueryRow(ctx, `SELECT last_activity_at, expires_at FROM framework.sessions WHERE token_hash=$1`, tokenHash(token)).Scan(&before, &expiresBefore)
		if _, err := store.identity(ctx, token); err != nil {
			t.Fatal(err)
		}
		_ = pool.QueryRow(ctx, `SELECT last_activity_at, expires_at FROM framework.sessions WHERE token_hash=$1`, tokenHash(token)).Scan(&after, &expiresAfter)
		if !after.After(before) || !expiresBefore.Equal(expiresAfter) {
			t.Fatal("incorrect expiration refresh")
		}
	})
	t.Run("atomic rotation and rollback", func(t *testing.T) {
		old := create()
		fresh, err := store.addSession(ctx, identity, time.Now().Add(time.Hour), old)
		if err != nil || fresh == old {
			t.Fatal("rotation failed")
		}
		if _, err := store.identity(ctx, old); !errors.Is(err, ErrUnauthenticated) {
			t.Fatal("old session remains valid")
		}
		_, err = pool.Exec(ctx, `ALTER TABLE framework.sessions ADD CONSTRAINT test_reject_subject CHECK (subject <> 'reject')`)
		if err != nil {
			t.Fatal(err)
		}
		bad := identity
		bad.Subject = "reject"
		if _, err := store.addSession(ctx, bad, time.Now().Add(time.Hour), fresh); !errors.Is(err, ErrStoreUnavailable) {
			t.Fatal("expected insert failure")
		}
		if _, err := store.identity(ctx, fresh); err != nil {
			t.Fatal("failed rotation revoked existing session")
		}
		if _, err := pool.Exec(ctx, `ALTER TABLE framework.sessions DROP CONSTRAINT test_reject_subject`); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("concurrent access and revocation", func(t *testing.T) {
		token := create()
		var group sync.WaitGroup
		for range 16 {
			group.Add(1)
			go func() {
				defer group.Done()
				if _, err := store.identity(ctx, token); err != nil {
					t.Error(err)
				}
			}()
		}
		group.Wait()
		if err := store.deleteSession(ctx, token); err != nil {
			t.Fatal(err)
		}
		if _, err := store.identity(ctx, token); !errors.Is(err, ErrUnauthenticated) {
			t.Fatal("revoked session accepted")
		}
	})
	t.Run("shared one-use login flow", func(t *testing.T) {
		flow := loginFlow{State: oauth2.GenerateVerifier(), Nonce: oauth2.GenerateVerifier(), Verifier: oauth2.GenerateVerifier(), Expires: time.Now().Add(time.Minute)}
		token, err := store.addFlow(ctx, flow)
		if err != nil {
			t.Fatal(err)
		}
		var row string
		if err := pool.QueryRow(ctx, `SELECT row_to_json(f)::text FROM framework.oidc_login_flows f WHERE token_hash=$1`, tokenHash(token)).Scan(&row); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(row, token) || strings.Contains(row, flow.State) {
			t.Fatal("raw flow token/state stored")
		}
		var successes atomic.Int32
		var group sync.WaitGroup
		for range 8 {
			group.Add(1)
			go func() {
				defer group.Done()
				if got, err := store.takeFlow(ctx, token, flow.State); err == nil {
					if got.Nonce != flow.Nonce || got.Verifier != flow.Verifier {
						t.Error("flow data changed")
					}
					successes.Add(1)
				} else if !errors.Is(err, ErrUnauthenticated) {
					t.Error(err)
				}
			}()
		}
		group.Wait()
		if successes.Load() != 1 {
			t.Fatal("login flow consumed more than once")
		}
		for _, expired := range []bool{true, false} {
			token, err := store.addFlow(ctx, flow)
			if err != nil {
				t.Fatal(err)
			}
			state := "wrong"
			if expired {
				state = flow.State
				if _, err := pool.Exec(ctx, `UPDATE framework.oidc_login_flows SET created_at=now()-interval '2 minutes', expires_at=now()-interval '1 minute' WHERE token_hash=$1`, tokenHash(token)); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := store.takeFlow(ctx, token, state); !errors.Is(err, ErrUnauthenticated) {
				t.Fatal("invalid flow accepted")
			}
		}
	})
	t.Run("OIDC callback and logout use PostgreSQL", func(t *testing.T) {
		f := newTestIssuer(t)
		p := f.provider(t)
		p.store = store
		callback, flow := beginLogin(t, f, p)
		// A different provider instance receives the callback after discovery.
		other := f.provider(t)
		other.store = store
		cookie := responseCookie(t, finishLogin(other, callback, flow), sessionCookie)
		if me(p, cookie).Code != http.StatusOK {
			t.Fatal("database-backed login failed")
		}
		request := httptest.NewRequest("POST", testOrigin+"/api/auth/logout", nil)
		request.Header.Set("Origin", testOrigin)
		request.AddCookie(cookie)
		response := httptest.NewRecorder()
		other.Logout(response, request)
		if response.Code != http.StatusNoContent || me(p, cookie).Code != http.StatusUnauthorized {
			t.Fatal("database logout did not revoke session")
		}
	})
	t.Run("migration rollback and reapply", func(t *testing.T) {
		// The historical 1–4 rollback uses its own database; migration 5 is forward-only.
		pool, _ := testdb.New(t)
		testdb.MigrationsThrough(t, pool, "up", 4)
		testdb.MigrationsThrough(t, pool, "down", 4)
		if database.CheckSchema(ctx, pool) == nil {
			t.Fatal("rolled-back schema accepted")
		}
		testdb.MigrationsThrough(t, pool, "up", 4)
		if err := database.CheckSchema(ctx, pool); err != nil {
			t.Fatal(err)
		}
	})
	runtimePool.Close()
	if _, err := store.identity(ctx, oauth2.GenerateVerifier()); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatal("closed database did not fail closed")
	}
}

type brokenDB struct{}
type brokenRow struct{}

func (brokenDB) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errors.New("password=must-not-leak")
}
func (brokenDB) QueryRow(context.Context, string, ...any) pgx.Row { return brokenRow{} }
func (brokenRow) Scan(...any) error                               { return errors.New("password=must-not-leak") }

func TestDatabaseFailuresFailClosed(t *testing.T) {
	store, _ := NewPostgresStore(brokenDB{}, testSessionConfig())
	ctx := context.Background()
	token := oauth2.GenerateVerifier()
	identity := Identity{Issuer: "https://issuer.example.invalid", Subject: "user", Provider: OIDC}
	_, createErr := store.addSession(ctx, identity, time.Now().Add(time.Hour), "")
	_, lookupErr := store.identity(ctx, token)
	deleteErr := store.deleteSession(ctx, token)
	_, flowErr := store.addFlow(ctx, loginFlow{})
	_, takeErr := store.takeFlow(ctx, token, "state")
	for _, err := range []error{createErr, lookupErr, deleteErr, flowErr, takeErr} {
		if err != ErrStoreUnavailable || strings.Contains(err.Error(), "must-not-leak") {
			t.Fatal("database error not sanitized")
		}
	}
	p := &OIDCAuthenticator{store: store, origin: testOrigin, issuer: identity.Issuer, sessionCookie: sessionCookie, flowCookie: flowCookie, secureCookies: true}
	if result := me(p, &http.Cookie{Name: sessionCookie, Value: token}); result.Code != http.StatusServiceUnavailable {
		t.Fatal("database outage did not return 503")
	}
	request := httptest.NewRequest("POST", testOrigin+"/api/auth/logout", nil)
	request.Header.Set("Origin", testOrigin)
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	response := httptest.NewRecorder()
	p.Logout(response, request)
	if response.Code != http.StatusServiceUnavailable || len(response.Result().Cookies()) != 0 {
		t.Fatal("logout pretended revocation succeeded")
	}
	response = httptest.NewRecorder()
	p.Login(response, httptest.NewRequest("GET", testOrigin+"/api/auth/login", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatal("login accepted unavailable storage")
	}
}
