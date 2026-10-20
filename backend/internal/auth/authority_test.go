package auth

import (
	"context"
	"errors"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/testdb"
)

func TestDatabaseAuthorityBoundsMissedNotificationAndClockSkew(t *testing.T) {
	pool, _ := testdb.New(t)
	testdb.Migrations(t, pool, "up")
	f := newTestIssuer(t)
	store, _ := NewPostgresStore(pool, testSessionConfig())
	m := runtimeFor(t, runtimeLocal(t))
	defer m.Close()
	h := runtimeRouter(m)
	var closed atomic.Int32
	runtimeRevision(t, pool, revisionOne, 1, "", f.server.URL)
	p := preparedRuntime(t, f, store, revisionOne, 1, &closed)
	ticket, _ := m.Stage(p, 0)
	if err := ticket.Commit(time.Now()); err != nil {
		t.Fatal(err)
	}
	callback, cookie := runtimeLogin(t, h, f)
	session := responseCookie(t, runtimeCallback(t, h, callback, cookie), sessionCookie)
	pending, flow := runtimeLogin(t, h, f)
	// Other instance commits a cutover; this instance misses every notification.
	runtimeRevisionWithTransition(t, pool, revisionTwo, 2, revisionOne, f.server.URL, 2*time.Second)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, runtimeRequestFor("GET", "/api/auth/me", session))
	if w.Code != 200 {
		t.Fatal("listener failure alone revoked valid draining session", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, runtimeRequestFor("GET", "/api/auth/login"))
	if w.Code == 302 {
		t.Fatal("stale node started old-generation login")
	}
	var deadline time.Time
	if err := pool.QueryRow(context.Background(), `SELECT transition_deadline FROM framework.auth_activation_history WHERE generation=2`).Scan(&deadline); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Until(deadline) + 10*time.Millisecond)
	var before time.Time
	if err := pool.QueryRow(context.Background(), `SELECT last_activity_at FROM framework.sessions WHERE token_hash=$1`, tokenHash(session.Value)).Scan(&before); err != nil {
		t.Fatal(err)
	}
	for _, skew := range []time.Duration{-time.Hour, time.Hour} {
		t.Run(skew.String(), func(t *testing.T) {
			// Simulate a node's wall clock in the lease. A slow clock considers the
			// provider alive; a fast clock may conservatively deny early. Neither may
			// extend database authority, mint a session, or consume a retired flow.
			stale := *(p.provider.store.(*databaseBoundStore))
			stale.lease = &providerLease{retired: true, until: deadline, now: func() time.Time { return time.Now().Add(skew) }}
			if _, err := stale.identity(context.Background(), session.Value); !errors.Is(err, ErrUnauthenticated) {
				t.Fatal("clock skew extended session", err)
			}
			if _, err := stale.takeFlow(context.Background(), flow.Value, "any"); !errors.Is(err, ErrUnauthenticated) {
				t.Fatal("clock skew admitted retired flow", err)
			}
			identity := Identity{Provider: OIDC, Issuer: f.server.URL, Subject: "synthetic"}
			if _, err := stale.addSession(context.Background(), identity, time.Now().Add(time.Hour), ""); !errors.Is(err, ErrUnauthenticated) {
				t.Fatal("clock skew minted retired session", err)
			}
		})
	}
	// A node unaware of retirement has no local deadline at all: SQL still denies.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, runtimeRequestFor("GET", "/api/auth/me", session))
	if w.Code != 401 {
		t.Fatal("stale snapshot survived persisted deadline", w.Code)
	}
	assertFailedCallback(t, runtimeCallback(t, h, pending, flow))
	var after time.Time
	if err := pool.QueryRow(context.Background(), `SELECT last_activity_at FROM framework.sessions WHERE token_hash=$1`, tokenHash(session.Value)).Scan(&after); err != nil || !after.Equal(before) {
		t.Fatal("untrusted session activity updated", err)
	}
}
