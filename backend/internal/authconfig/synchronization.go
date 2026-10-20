package authconfig

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/jackc/pgx/v5"
)

const activationChannel = "framework_auth_activation"

// Notification contains only scope and a non-authoritative generation hint.
type activationNotice struct {
	Deployment  string `json:"deployment"`
	Environment string `json:"environment"`
	Generation  int64  `json:"generation"`
}

func notifyActivation(ctx context.Context, tx pgx.Tx, scope Scope, generation int64) error {
	payload, _ := json.Marshal(activationNotice{scope.DeploymentID, scope.Environment, generation})
	_, err := tx.Exec(ctx, `SELECT pg_notify('framework_auth_activation',$1)`, string(payload))
	if err != nil {
		return ErrUnavailable
	}
	return nil
}

type SynchronizationStatus struct {
	DesiredGeneration  int64
	AppliedGeneration  int64
	Provider           auth.Provider
	Connected          bool
	LastReconciled     time.Time
	Degraded           bool
	Mismatched         bool
	TransitionDeadline time.Time
}

// Synchronizer owns one dedicated, non-pooled LISTEN connection and a serialized
// reconciliation path. Healthy waiting never queries configuration periodically.
type Synchronizer struct {
	reader      *ActivationReader
	runtime     *auth.Runtime
	load        func(context.Context) (*auth.Runtime, error)
	connect     func(context.Context) (*pgx.Conn, error)
	reconcileMu sync.Mutex
	mu          sync.Mutex
	status      SynchronizationStatus
	cancel      context.CancelFunc
	done        chan struct{}
	backoff     func(int) time.Duration
}

func NewSynchronizer(reader *ActivationReader, runtime *auth.Runtime, load func(context.Context) (*auth.Runtime, error)) (*Synchronizer, error) {
	if reader == nil || runtime == nil || load == nil {
		return nil, ErrInvalid
	}
	status, _, _ := runtime.ControlStatus()
	if status.DeploymentID != reader.scope.DeploymentID || status.Environment != reader.scope.Environment {
		return nil, ErrInvalid
	}
	// Copy validated TLS/connection settings, never retain a pool checkout.
	cfg := reader.pool.Config().ConnConfig.Copy()
	cfg.RuntimeParams["application_name"] = "go-web-framework-auth-listener"
	s := &Synchronizer{reader: reader, runtime: runtime, load: load, done: make(chan struct{}), backoff: reconnectDelay}
	s.connect = func(ctx context.Context) (*pgx.Conn, error) {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return pgx.ConnectConfig(ctx, cfg.Copy())
	}
	return s, nil
}
func reconnectDelay(attempt int) time.Duration {
	if attempt > 6 {
		attempt = 6
	}
	if attempt < 0 {
		attempt = 0
	}
	cap := time.Duration(1<<attempt) * 500 * time.Millisecond
	if cap > 30*time.Second {
		cap = 30 * time.Second
	}
	return cap/2 + time.Duration(rand.Int64N(int64(cap/2)+1))
}

func (s *Synchronizer) Status() SynchronizationStatus {
	s.mu.Lock()
	v := s.status
	s.mu.Unlock()
	applied, _, mismatch := s.runtime.ControlStatus()
	v.AppliedGeneration = applied.AppliedGeneration
	v.Provider = applied.Provider
	v.TransitionDeadline = applied.TransitionDeadline
	v.Mismatched = mismatch || v.DesiredGeneration != v.AppliedGeneration
	return v
}
func (s *Synchronizer) mark(connected, degraded bool) {
	s.mu.Lock()
	s.status.Connected = connected
	s.status.Degraded = degraded
	s.mu.Unlock()
}

// Environment credentials need an authoritative decision on every use; Local
// DEV cannot continue authenticating new requests after a missed cutover hint.
// Bound OIDC credentials perform their own policy checks in the SQL mutation.
func (s *Synchronizer) admission(ctx context.Context, status auth.RuntimeStatus) error {
	if status.Source == "database" {
		return nil
	}
	if err := s.reader.RequireEnvironmentStartup(ctx); err != nil {
		return auth.ErrStoreUnavailable
	}
	return nil
}

func (s *Synchronizer) Reconcile(ctx context.Context) (err error) {
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()
	defer func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.status.Degraded = err != nil
		if err == nil {
			s.status.LastReconciled = time.Now()
		}
	}()
	applied, _, _ := s.runtime.ControlStatus()
	policyErr := s.reader.RequireEnvironmentStartup(ctx)
	if policyErr == nil {
		if applied.Source != "environment" || applied.AppliedGeneration != 0 {
			return ErrConflict
		}
		s.mu.Lock()
		s.status.DesiredGeneration = 0
		s.mu.Unlock()
		return s.runtime.Confirm(applied)
	}
	if !errors.Is(policyErr, ErrDatabaseRuntimeRequired) {
		return policyErr
	}
	head, err := s.reader.DatabaseHead(ctx)
	if err != nil {
		return err
	}
	if head.RuntimeSource != "database" || head.Generation < 1 {
		return ErrConflict
	}
	s.mu.Lock()
	s.status.DesiredGeneration = head.Generation
	s.mu.Unlock()
	if (applied.Provider != auth.OIDC && applied.Provider != auth.LocalDev) || head.Generation < applied.AppliedGeneration {
		return ErrDenied
	}
	if head.Generation == applied.AppliedGeneration {
		if applied.Source != "database" || head.ActiveRevisionID != applied.ActiveRevisionID {
			return ErrConflict
		}
		return s.runtime.Confirm(applied)
	}
	candidate, err := s.load(ctx)
	if err != nil {
		return err
	}
	defer candidate.Close()
	prepared, _, _ := candidate.ControlStatus()
	// Load may observe a newer head than our first read. Accept only a freshly
	// rechecked exact match, never any generation claimed by a notification.
	head, err = s.reader.DatabaseHead(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.status.DesiredGeneration = head.Generation
	s.mu.Unlock()
	if head.RuntimeSource != "database" || prepared.Source != "database" || head.Generation != prepared.AppliedGeneration || head.ActiveRevisionID != prepared.ActiveRevisionID {
		return ErrConflict
	}
	return s.runtime.Reconcile(candidate, applied.AppliedGeneration)
}

func closeListener(conn *pgx.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = conn.Close(ctx)
}
func listenerSessionValid(before, after int32, listening bool) bool {
	return before > 0 && before == after && listening
}
func (s *Synchronizer) subscribe(ctx context.Context) (*pgx.Conn, error) {
	conn, err := s.connect(ctx)
	if err != nil {
		return nil, ErrUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	var before int32
	err = conn.QueryRow(bounded, `SELECT pg_backend_pid()`).Scan(&before)
	if err == nil {
		_, err = conn.Exec(bounded, `LISTEN framework_auth_activation`)
	}
	var after int32
	var listening bool
	if err == nil {
		err = conn.QueryRow(bounded, `SELECT pg_backend_pid(),EXISTS(SELECT 1 FROM pg_listening_channels() AS channels(channel) WHERE channel='framework_auth_activation')`).Scan(&after, &listening)
	}
	cancel()
	if err != nil || !listenerSessionValid(before, after, listening) {
		closeListener(conn)
		return nil, ErrUnavailable
	}
	s.mark(true, true)
	// Subscribe first, then read. Notifications racing the read remain queued.
	if err = s.Reconcile(ctx); err != nil {
		closeListener(conn)
		s.mark(false, true)
		return nil, err
	}
	return conn, nil
}

// Start subscribes and reconciles before the application accepts requests.
// Subsequent failures retain the snapshot and reconnect; no polling on success.
func (s *Synchronizer) Start(parent context.Context) error {
	s.mu.Lock()
	if s.cancel != nil {
		s.mu.Unlock()
		return ErrConflict
	}
	ctx, cancel := context.WithCancel(parent)
	s.cancel = cancel
	s.mu.Unlock()
	conn, err := s.subscribe(ctx)
	if err != nil {
		cancel()
		s.mark(false, true)
		close(s.done)
		return err
	}
	if err = s.runtime.SetAdmissionGuard(s.admission); err != nil {
		cancel()
		closeListener(conn)
		s.mark(false, true)
		close(s.done)
		return err
	}
	go s.run(ctx, conn)
	return nil
}
func (s *Synchronizer) Close() {
	s.mu.Lock()
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
		<-s.done
	}
}
func (s *Synchronizer) relevant(payload string) bool {
	if len(payload) > 512 {
		return false
	}
	var n activationNotice
	if json.Unmarshal([]byte(payload), &n) != nil {
		return false
	}
	return n.Deployment == s.reader.scope.DeploymentID && n.Environment == s.reader.scope.Environment
}
func (s *Synchronizer) run(ctx context.Context, conn *pgx.Conn) {
	defer close(s.done)
	defer func() {
		if conn != nil {
			closeListener(conn)
		}
		s.mark(false, true)
	}()
	attempt := 0
	for ctx.Err() == nil {
		if conn == nil {
			timer := time.NewTimer(s.backoff(attempt))
			if attempt < 6 {
				attempt++
			}
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			var err error
			conn, err = s.subscribe(ctx)
			if err != nil {
				continue
			}
			attempt = 0
		}
		notice, err := conn.WaitForNotification(ctx)
		if err == nil && s.relevant(notice.Payload) {
			err = s.Reconcile(ctx)
		}
		if err != nil {
			closeListener(conn)
			conn = nil
			s.mark(false, true)
		}
	}
}

// NewSynchronizerFromEnv captures trusted configuration once; notifications can
// never supply keys, callback URLs or provider settings. An environment-only
// deployment can run without management keys, but cannot later load DB OIDC
// until those keys are provisioned and the process restarted.
func NewSynchronizerFromEnv(reader *ActivationReader, runtime *auth.Runtime, getenv func(string) string) (*Synchronizer, error) {
	cipher, keyErr := CipherFromEnv(getenv)
	sessions, sessionErr := auth.SessionConfigFromEnv(getenv)
	callback := getenv("APP_ORIGIN") + "/api/auth/callback"
	address := getenv("HTTP_ADDR")
	if address == "" {
		address = "127.0.0.1:8080"
	}
	host, _, addressErr := net.SplitHostPort(address)
	unsafeHTTP := strings.HasPrefix(callback, "http://") && (addressErr != nil || !net.ParseIP(host).IsLoopback())
	if getenv("AUTH_PROVIDER") == "google_iap" {
		return nil, ErrDenied
	}
	load := func(ctx context.Context) (*auth.Runtime, error) {
		if unsafeHTTP {
			return nil, ErrInvalid
		}
		if keyErr != nil {
			return nil, ErrSecret
		}
		if sessionErr != nil {
			return nil, ErrInvalid
		}
		loader, err := NewStartupLoader(reader, cipher, sessions, callback)
		if err != nil {
			return nil, err
		}
		return loader.Load(ctx)
	}
	return NewSynchronizer(reader, runtime, load)
}
