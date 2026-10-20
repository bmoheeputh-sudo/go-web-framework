package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/testdb"
)

func parallelCallbacks(t *testing.T, h http.Handler, location string, cookie *http.Cookie) int {
	t.Helper()
	u, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	var successes atomic.Int32
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			w := httptest.NewRecorder()
			h.ServeHTTP(w, runtimeRequestFor("GET", u.RequestURI(), cookie))
			if w.Code == 303 && w.Header().Get("Location") == testOrigin+"/" {
				successes.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	return int(successes.Load())
}

func TestPostgresConcurrentCallbackReplay(t *testing.T) {
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
	first, _ := m.Stage(p, 0)
	if err := first.Commit(time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"valid", "invalid state", "expired", "token failure", "binding mismatch"} {
		t.Run(kind, func(t *testing.T) {
			callback, flow := runtimeLogin(t, h, f)
			original := callback
			var before int
			if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM framework.sessions`).Scan(&before); err != nil {
				t.Fatal(err)
			}
			if kind == "invalid state" {
				u, _ := url.Parse(callback)
				q := u.Query()
				q.Set("state", "wrong")
				u.RawQuery = q.Encode()
				callback = u.String()
			}
			if kind == "expired" {
				if _, err := pool.Exec(context.Background(), `UPDATE framework.oidc_login_flows SET created_at=clock_timestamp()-interval '1 hour',expires_at=clock_timestamp()-interval '1 second' WHERE token_hash=$1`, tokenHash(flow.Value)); err != nil {
					t.Fatal(err)
				}
			}
			f.mu.Lock()
			f.tokenError = kind == "token failure"
			exchanges := f.exchanges
			f.mu.Unlock()
			if kind == "binding mismatch" {
				u, _ := url.Parse(callback)
				// Exact SQL predicates reject both wrong revision and wrong generation
				// without consuming a credential belonging to the genuine verifier.
				for _, change := range []func(*Binding){func(b *Binding) { b.ActivationGeneration++ }, func(b *Binding) { b.RevisionID = revisionTwo }} {
					bad := *(p.provider.store.(*databaseBoundStore))
					change(&bad.binding)
					var wg sync.WaitGroup
					errs := make(chan error, 12)
					for range 12 {
						wg.Add(1)
						go func() {
							defer wg.Done()
							_, err := bad.takeFlow(context.Background(), flow.Value, u.Query().Get("state"))
							errs <- err
						}()
					}
					wg.Wait()
					close(errs)
					for err := range errs {
						if !errors.Is(err, ErrUnauthenticated) {
							t.Fatal("foreign verifier consumed flow", err)
						}
					}
				}
			}
			want := 0
			if kind == "valid" || kind == "binding mismatch" {
				want = 1
			}
			if got := parallelCallbacks(t, h, callback, flow); got != want {
				t.Fatal("concurrent success count", got, want)
			}
			var after int
			if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM framework.sessions`).Scan(&after); err != nil || after-before != want {
				t.Fatal("unexpected session creation", after-before, err)
			}
			if _, err := store.FlowBinding(context.Background(), flow.Value); !errors.Is(err, ErrUnauthenticated) {
				t.Fatal("consumed flow retained", err)
			}
			if got := parallelCallbacks(t, h, original, flow); got != 0 {
				t.Fatal("flow replay succeeded")
			}
			f.mu.Lock()
			delta := f.exchanges - exchanges
			f.tokenError = false
			f.mu.Unlock()
			expectedExchanges := 1
			if kind == "invalid state" || kind == "expired" {
				expectedExchanges = 0
			}
			if delta != expectedExchanges {
				t.Fatal("multiple consumers reached token endpoint", delta)
			}
		})
	}
	// Two valid flows of the old provider straddle a recorded transition deadline.
	during, flow := runtimeLogin(t, h, f)
	late, lateFlow := runtimeLogin(t, h, f)
	runtimeRevision(t, pool, revisionTwo, 2, revisionOne, f.server.URL)
	next := preparedRuntime(t, f, store, revisionTwo, 2, &closed)
	publication, err := m.Stage(next, 1)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	if err = publication.Commit(deadline); err != nil {
		t.Fatal(err)
	}
	if got := parallelCallbacks(t, h, during, flow); got != 1 {
		t.Fatal("draining callbacks did not consume once", got)
	}
	time.Sleep(time.Until(deadline) + 10*time.Millisecond)
	if got := parallelCallbacks(t, h, late, lateFlow); got != 0 {
		t.Fatal("retired callback survived deadline")
	}
	if got := parallelCallbacks(t, h, during, flow); got != 0 {
		t.Fatal("draining replay succeeded")
	}
}
