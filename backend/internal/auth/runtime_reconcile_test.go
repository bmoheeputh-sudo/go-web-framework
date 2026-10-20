package auth

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/testdb"
)

func TestReconcilePinsRequestsAndCleansRetiredProviders(t *testing.T) {
	pool, _ := testdb.New(t)
	testdb.Migrations(t, pool, "up")
	issuer := newTestIssuer(t)
	store, _ := NewPostgresStore(pool, testSessionConfig())
	m := runtimeFor(t, runtimeLocal(t))
	defer m.Close()
	var oldClosed, newClosed atomic.Int32
	old := preparedRuntime(t, issuer, store, revisionOne, 1, &oldClosed)
	first, _ := m.Stage(old, 0)
	if err := first.Commit(time.Now()); err != nil {
		t.Fatal(err)
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan RuntimeStatus, 1)
	go func() {
		m.Capture(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			close(entered)
			<-release
			status, _ := m.Status(r.Context())
			done <- status
		})).ServeHTTP(httptest.NewRecorder(), runtimeRequestFor("GET", "/held"))
	}()
	<-entered
	next := preparedRuntime(t, issuer, store, revisionTwo, 2, &newClosed)
	now := time.Now()
	candidate, err := NewDatabaseRuntime(next, nil, now, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Reconcile(candidate, 1); err != nil {
		t.Fatal(err)
	}
	candidate.Close()
	if oldClosed.Load() != 0 || newClosed.Load() != 0 {
		t.Fatal("publication closed in-flight or adopted transport")
	}
	close(release)
	if status := <-done; status.AppliedGeneration != 1 {
		t.Fatal("request snapshot changed mid-request")
	}
	// The handler sends status before its Capture defer releases the lease.
	deadline := time.Now().Add(time.Second)
	for oldClosed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if oldClosed.Load() != 1 {
		t.Fatal("old transport not released")
	}
	status, _, _ := m.ControlStatus()
	if status.AppliedGeneration != 2 {
		t.Fatal("new snapshot not published")
	}
	stale := preparedRuntime(t, issuer, store, revisionOne, 1, &oldClosed)
	previous, err := NewDatabaseRuntime(stale, nil, now, now)
	if err != nil {
		t.Fatal(err)
	}
	defer previous.Close()
	if err = m.Reconcile(previous, 2); err == nil {
		t.Fatal("older generation published")
	}
	m.Close()
	if newClosed.Load() != 1 {
		t.Fatal("new transport not cleaned on shutdown")
	}
}
