package authconfig

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/jackc/pgx/v5"
)

func waitSynchronization(t *testing.T, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("synchronization condition timed out")
}
func subscriberFixture(t *testing.T, f *fixture, service *ActivationService, provider *mockConnectionIssuer) (*Synchronizer, *auth.Runtime) {
	t.Helper()
	local, err := auth.NewLocalDev("development", auth.LocalDevConfig{Subject: "subscriber", Email: "subscriber@example.test", DisplayName: "Subscriber"})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := auth.NewEnvironmentRuntime(local, f.repo.scope.DeploymentID, f.repo.scope.Environment)
	if err != nil {
		t.Fatal(err)
	}
	reader, _ := NewActivationReader(f.pool, f.repo.scope)
	loader, err := NewStartupLoader(reader, f.repo.cipher, service.sessions, service.callback, false)
	if err != nil {
		t.Fatal(err)
	}
	loader.client = func(context.Context, string) (*http.Client, error) { return provider.client(), nil }
	syncer, err := NewSynchronizer(reader, runtime, loader.Load)
	if err != nil {
		t.Fatal(err)
	}
	syncer.backoff = func(int) time.Duration { return 20 * time.Millisecond }
	t.Cleanup(func() { syncer.Close(); runtime.Close() })
	return syncer, runtime
}
func testNotify(t *testing.T, f *fixture, generation int64) {
	t.Helper()
	tx, err := f.owner.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if err = notifyActivation(context.Background(), tx, f.repo.scope, generation); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func requestStatus(runtime *auth.Runtime) int {
	mux := http.NewServeMux()
	runtime.RegisterRoutes(mux)
	r := httptest.NewRequest("GET", apiOrigin+"/api/auth/me", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	w := httptest.NewRecorder()
	runtime.Capture(mux).ServeHTTP(w, r)
	return w.Code
}

func TestNotificationPayloadIsOnlyAScopedHint(t *testing.T) {
	f, service, provider, _ := activationServiceFixture(t)
	syncer, _ := subscriberFixture(t, f, service, provider)
	_ = service

	valid, err := json.Marshal(activationNotice{
		Deployment:  f.repo.scope.DeploymentID,
		Environment: f.repo.scope.Environment,
		Generation:  9999,
	})
	if err != nil || !syncer.relevant(string(valid)) {
		t.Fatal("valid scoped notification was ignored", err)
	}
	for _, payload := range []string{
		``,
		`not-json`,
		`{"deployment":"other","environment":"development","generation":1}`,
		`{"deployment":"` + f.repo.scope.DeploymentID + `","environment":"production","generation":1}`,
		strings.Repeat("x", 513),
	} {
		if syncer.relevant(payload) {
			t.Fatal("malformed or foreign notification accepted")
		}
	}
}

func TestListenerRejectsObviousLossOfSessionAffinity(t *testing.T) {
	for _, candidate := range []struct {
		before, after int32
		listening     bool
	}{
		{0, 0, true}, {41, 42, true}, {41, 41, false},
	} {
		if listenerSessionValid(candidate.before, candidate.after, candidate.listening) {
			t.Fatal("non-session-affine listener accepted", candidate)
		}
	}
	if !listenerSessionValid(41, 41, true) {
		t.Fatal("session-affine listener rejected")
	}
}

func TestTwoInstancesObserveCommittedActivation(t *testing.T) {
	f, service, provider, m := activationServiceFixture(t)
	a, ar := subscriberFixture(t, f, service, provider)
	b, _ := subscriberFixture(t, f, service, provider)
	// Each initial read happens only after LISTEN, on a dedicated connection.
	connect := a.connect
	a.connect = func(ctx context.Context) (*pgx.Conn, error) {
		conn, err := connect(ctx)
		if err != nil {
			return nil, err
		}
		return conn, nil
	}
	if err := a.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := b.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	var listeners int
	if err := f.owner.QueryRow(context.Background(), `SELECT count(*) FROM pg_stat_activity WHERE application_name='go-web-framework-auth-listener'`).Scan(&listeners); err != nil || listeners != 2 {
		t.Fatal("listeners are not dedicated", listeners, err)
	}
	if requestStatus(ar) != 200 {
		t.Fatal("environment changed before activation")
	}
	request, _ := activationReadiness(t, f, m, "")
	p := prepareActivation(t, f, service, m, 0)
	f.run(t, func(ctx context.Context) {
		if _, err := service.Activate(ctx, p, request); err != nil {
			t.Fatal(err)
		}
	})
	waitSynchronization(t, func() bool { return a.Status().AppliedGeneration == 1 && b.Status().AppliedGeneration == 1 })
	if requestStatus(ar) != 401 {
		t.Fatal("Local DEV survived cutover")
	}
	before := a.Status().LastReconciled
	for _, hint := range []int64{1, 1, 0, 9999, 1} {
		testNotify(t, f, hint)
	}
	waitSynchronization(t, func() bool { return a.Status().LastReconciled.After(before) })
	if a.Status().AppliedGeneration != 1 || a.Status().DesiredGeneration != 1 || a.Status().Degraded {
		t.Fatal("notification payload became authority")
	}
	// Independent concurrent callers serialize and cannot move backward.
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- a.Reconcile(context.Background()) }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	a.Close()
	b.Close()
	if a.Status().Connected || b.Status().Connected {
		t.Fatal("listener not closed")
	}
}

func TestActivationNotificationsAreTransactional(t *testing.T) {
	f, service, _, m := activationServiceFixture(t)
	conn, err := pgx.ConnectConfig(context.Background(), f.pool.Config().ConnConfig.Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer closeListener(conn)
	if _, err = conn.Exec(context.Background(), `LISTEN framework_auth_activation`); err != nil {
		t.Fatal(err)
	}
	noNotice := func() {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 70*time.Millisecond)
		defer cancel()
		if _, err := conn.WaitForNotification(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("unexpected pre-commit notification", err)
		}
	}
	tx, err := f.owner.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err = notifyActivation(context.Background(), tx, f.repo.scope, 77); err != nil {
		t.Fatal(err)
	}
	noNotice()
	if err = tx.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	noNotice()
	request, _ := activationReadiness(t, f, m, "")
	p := prepareActivation(t, f, service, m, 0)
	// Reject at COMMIT, after pg_notify was issued, to exercise atomic rollback.
	if _, err = f.owner.Exec(context.Background(), `CREATE FUNCTION framework.fail_sync_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic'; END $$; CREATE CONSTRAINT TRIGGER fail_sync_commit AFTER INSERT ON framework.auth_activation_history DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION framework.fail_sync_commit()`); err != nil {
		t.Fatal(err)
	}
	f.run(t, func(ctx context.Context) {
		if _, err := service.Activate(ctx, p, request); err == nil {
			t.Fatal("synthetic commit passed")
		}
	})
	noNotice()
	if _, err = f.owner.Exec(context.Background(), `DROP TRIGGER fail_sync_commit ON framework.auth_activation_history; DROP FUNCTION framework.fail_sync_commit()`); err != nil {
		t.Fatal(err)
	}
	status, _, _ := service.runtime.ControlStatus()
	if err = service.runtime.Confirm(status); err != nil {
		t.Fatal(err)
	}
	f.run(t, func(ctx context.Context) {
		if _, err := service.Activate(ctx, p, request); err != nil {
			t.Fatal(err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	notice, err := conn.WaitForNotification(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var payload activationNotice
	if json.Unmarshal([]byte(notice.Payload), &payload) != nil || payload.Deployment != f.repo.scope.DeploymentID || payload.Generation != 1 || notice.Channel != activationChannel {
		t.Fatal("unsafe or incorrect notification")
	}
}

func TestSubscribeBeforeReadAndMissedNotificationRecovery(t *testing.T) {
	f, service, provider, m := activationServiceFixture(t)
	syncer, runtime := subscriberFixture(t, f, service, provider)
	allow := make(chan struct{})
	base := syncer.connect
	var connections atomic.Int32
	syncer.connect = func(ctx context.Context) (*pgx.Conn, error) {
		if connections.Add(1) == 1 {
			return base(ctx)
		}
		select {
		case <-allow:
			return base(ctx)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	load := syncer.load
	syncer.load = func(ctx context.Context) (*auth.Runtime, error) {
		var subscribed bool
		if err := f.owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name='go-web-framework-auth-listener')`).Scan(&subscribed); err != nil || !subscribed {
			return nil, ErrUnavailable
		}
		return load(ctx)
	}
	request, _ := activationReadiness(t, f, m, "")
	p := prepareActivation(t, f, service, m, 0)
	// Commit before the initial subscription: no notification is available, so
	// subscribe-then-read must independently discover the authoritative head.
	f.run(t, func(ctx context.Context) {
		if _, err := service.Activate(ctx, p, request); err != nil {
			t.Fatal(err)
		}
	})
	if err := syncer.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if syncer.Status().AppliedGeneration != 1 {
		t.Fatal("missed initial notification")
	}
	next := nextStartupRevision(t, f, m)
	if _, err := f.owner.Exec(context.Background(), `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='go-web-framework-auth-listener'`); err != nil {
		t.Fatal(err)
	}
	waitSynchronization(t, func() bool { return !syncer.Status().Connected && connections.Load() > 1 })
	status, _, _ := runtime.ControlStatus()
	if status.AppliedGeneration != 1 {
		t.Fatal("disconnect discarded verified snapshot")
	}
	// Deliberately omit NOTIFY using the isolated fixture to represent a missed
	// event; reconnection must still read generation two.
	if err := activationFixture(t, f, next, 2, m.ID, false); err != nil {
		t.Fatal(err)
	}
	close(allow)
	waitSynchronization(t, func() bool { return syncer.Status().Connected && syncer.Status().AppliedGeneration == 2 })
	if syncer.Status().Degraded {
		t.Fatal("reconnect did not recover")
	}
}

func TestSlowPreparationCannotPublishStaleGeneration(t *testing.T) {
	f, service, provider, m := activationServiceFixture(t)
	syncer, _ := subscriberFixture(t, f, service, provider)
	req, user := activationReadiness(t, f, m, "")
	p := prepareActivation(t, f, service, m, 0)
	f.run(t, func(ctx context.Context) {
		if _, err := service.Activate(ctx, p, req); err != nil {
			t.Fatal(err)
		}
	})
	next := nextStartupRevision(t, f, m)
	r2, _ := activationReadiness(t, f, next, user)
	p2 := prepareActivation(t, f, service, next, 1)
	base := syncer.load
	entered, release := make(chan struct{}), make(chan struct{})
	syncer.load = func(ctx context.Context) (*auth.Runtime, error) {
		candidate, err := base(ctx)
		close(entered)
		<-release
		return candidate, err
	}
	result := make(chan error, 1)
	go func() { result <- syncer.Reconcile(context.Background()) }()
	<-entered
	f.run(t, func(ctx context.Context) {
		if _, err := service.Activate(ctx, p2, r2); err != nil {
			t.Fatal(err)
		}
	})
	close(release)
	if err := <-result; !errors.Is(err, ErrConflict) {
		t.Fatal("slow preparation overwrote newer head", err)
	}
	if syncer.Status().AppliedGeneration != 0 || syncer.Status().DesiredGeneration != 2 {
		t.Fatal("stale candidate published")
	}
	syncer.load = base
	if err := syncer.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if syncer.Status().AppliedGeneration != 2 {
		t.Fatal("skipped generation not recovered")
	}
}

func TestSynchronizationFailureDoesNotFallback(t *testing.T) {
	f, service, provider, m := activationServiceFixture(t)
	syncer, runtime := subscriberFixture(t, f, service, provider)
	if err := syncer.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Make provider preparation unavailable while PostgreSQL remains authoritative.
	// The callback never needs a fake administrator principal.
	provider.mu.Lock()
	provider.badKeys = true
	provider.mu.Unlock()
	if err := activationFixture(t, f, m, 1, "", false); err != nil {
		t.Fatal(err)
	}
	testNotify(t, f, 1)
	waitSynchronization(t, func() bool { return syncer.Status().DesiredGeneration == 1 && syncer.Status().Degraded })
	if requestStatus(runtime) != 503 {
		t.Fatal("failed preparation fell back to Local DEV")
	}
	provider.mu.Lock()
	provider.badKeys = false
	provider.mu.Unlock()
	waitSynchronization(t, func() bool { return syncer.Status().AppliedGeneration == 1 && !syncer.Status().Degraded })
	f.pool.Close()
	if err := syncer.Reconcile(context.Background()); err == nil {
		t.Fatal("unavailable DB assumed trusted")
	}
	if syncer.Status().AppliedGeneration != 1 {
		t.Fatal("DB outage discarded verified snapshot")
	}
}

func TestSynchronizerIAPBoundary(t *testing.T) {
	f, service, _, m := activationServiceFixture(t)
	if err := activationFixture(t, f, m, 1, "", false); err != nil {
		t.Fatal(err)
	}
	iap, err := auth.NewGoogleIAP("/projects/123/apps/test-app")
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := auth.NewEnvironmentRuntime(iap, f.repo.scope.DeploymentID, f.repo.scope.Environment)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	reader, _ := NewActivationReader(f.pool, f.repo.scope)
	syncer, err := NewSynchronizer(reader, runtime, func(context.Context) (*auth.Runtime, error) {
		t.Error("IAP attempted OIDC preparation")
		return nil, ErrDenied
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = service
	if err = syncer.Reconcile(context.Background()); !errors.Is(err, ErrDenied) {
		t.Fatal("IAP boundary bypass", err)
	}
	status, _, _ := runtime.ControlStatus()
	if status.Provider != auth.GoogleIAP {
		t.Fatal("IAP provider replaced")
	}
}

func TestReconnectBackoffAndTemporaryConnectionFailure(t *testing.T) {
	f, service, provider, _ := activationServiceFixture(t)
	syncer, _ := subscriberFixture(t, f, service, provider)
	base := syncer.connect
	var attempts atomic.Int32
	syncer.connect = func(ctx context.Context) (*pgx.Conn, error) {
		n := attempts.Add(1)
		if n == 2 || n == 3 {
			return nil, ErrUnavailable
		}
		return base(ctx)
	}
	if err := syncer.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.Exec(context.Background(), `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='go-web-framework-auth-listener'`); err != nil {
		t.Fatal(err)
	}
	waitSynchronization(t, func() bool { return attempts.Load() >= 4 && syncer.Status().Connected && !syncer.Status().Degraded })
	for _, attempt := range []int{0, 1, 5, 6, 1000} {
		for range 20 {
			delay := reconnectDelay(attempt)
			if delay < 250*time.Millisecond || delay > 30*time.Second {
				t.Fatal("unbounded reconnect delay", delay)
			}
		}
	}
	// There is no healthy periodic read/reconnect loop.
	before := syncer.Status().LastReconciled
	connections := attempts.Load()
	time.Sleep(100 * time.Millisecond)
	if attempts.Load() != connections || !syncer.Status().LastReconciled.Equal(before) {
		t.Fatal("healthy synchronization polled")
	}
}
