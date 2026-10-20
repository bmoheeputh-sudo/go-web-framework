package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/testdb"
)

func TestRehydratedRuntimeRetainsBoundSessionsAndFlows(t *testing.T) {
	pool, _ := testdb.New(t)
	testdb.Migrations(t, pool, "up")
	f := newTestIssuer(t)
	store, _ := NewPostgresStore(pool, testSessionConfig())
	original := runtimeFor(t, runtimeLocal(t))
	defer original.Close()
	var closed atomic.Int32
	runtimeRevision(t, pool, revisionOne, 1, "", f.server.URL)
	p1 := preparedRuntime(t, f, store, revisionOne, 1, &closed)
	first, _ := original.Stage(p1, 0)
	if err := first.Commit(time.Now()); err != nil {
		t.Fatal(err)
	}
	h := runtimeRouter(original)
	location, flow := runtimeLogin(t, h, f)
	session := responseCookie(t, runtimeCallback(t, h, location, flow), sessionCookie)
	callback, pending := runtimeLogin(t, h, f)
	runtimeRevision(t, pool, revisionTwo, 2, revisionOne, f.server.URL)
	p2 := preparedRuntime(t, f, store, revisionTwo, 2, &closed)
	second, err := original.Stage(p2, 1)
	if err != nil {
		t.Fatal(err)
	}
	var activatedAt, deadline time.Time
	if err := pool.QueryRow(context.Background(), `SELECT activated_at,transition_deadline FROM framework.auth_activation_history WHERE generation=2`).Scan(&activatedAt, &deadline); err != nil {
		t.Fatal(err)
	}
	if err = second.Commit(deadline); err != nil {
		t.Fatal(err)
	}
	original.Close()
	active := preparedRuntime(t, f, store, revisionTwo, 2, &closed)
	drain := preparedRuntime(t, f, store, revisionOne, 1, &closed)
	restarted, err := NewDatabaseRuntime(active, drain, activatedAt, deadline)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	h = runtimeRouter(restarted)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, runtimeRequestFor("GET", "/api/auth/me", session))
	if w.Code != 200 {
		t.Fatal("bound old session lost across restart", w.Code)
	}
	if w = runtimeCallback(t, h, callback, pending); w.Header().Get("Location") != testOrigin+"/" {
		t.Fatal("old callback lost across restart", w.Code)
	}
	newSession := responseCookie(t, w, sessionCookie)
	binding, err := store.SessionBinding(context.Background(), newSession.Value)
	if err != nil || binding.RevisionID != revisionOne || binding.ActivationGeneration != 1 {
		t.Fatal("draining callback rebound", err)
	}
	var expiry time.Time
	if err = pool.QueryRow(context.Background(), `SELECT expires_at FROM framework.sessions WHERE token_hash=$1`, tokenHash(newSession.Value)).Scan(&expiry); err != nil || expiry.After(deadline) {
		t.Fatal("restart extended session", err)
	}
	if runtimeCallback(t, h, callback, pending).Code != 401 {
		t.Fatal("restored callback replayed")
	}
}

func TestRuntimeShutdownReleasesReadinessAndCredentialReferences(t *testing.T) {
	pool, _ := testdb.New(t)
	testdb.Migrations(t, pool, "up")
	f := newTestIssuer(t)
	store, _ := NewPostgresStore(pool, testSessionConfig())
	m := runtimeFor(t, runtimeLocal(t))
	runtimeRevision(t, pool, revisionOne, 1, "", f.server.URL)
	var closed atomic.Int32
	candidate := preparedRuntime(t, f, store, revisionOne, 1, &closed)
	w := httptest.NewRecorder()
	if err := m.BeginReadiness(candidate, w, runtimeRequestFor("GET", "/internal"), func(context.Context, Identity) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if len(m.readiness) != 1 {
		t.Fatal("readiness not reserved")
	}
	m.Close()
	if len(m.readiness) != 0 || closed.Load() != 1 {
		t.Fatal("shutdown retained abandoned readiness transport")
	}
	snapshot := m.current.Load()
	if snapshot.auth != nil || snapshot.oidc != nil || snapshot.prepared != nil || snapshot.draining != nil {
		t.Fatal("closed runtime retained credential references")
	}
	w = httptest.NewRecorder()
	runtimeRouter(m).ServeHTTP(w, runtimeRequestFor(http.MethodGet, "/api/auth/me"))
	if w.Code != 503 {
		t.Fatal("closed runtime accepted requests")
	}
}
