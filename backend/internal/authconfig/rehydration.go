package authconfig

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/jackc/pgx/v5"
)

// StartupLoader has read-only database authority and no administrator principal.
// It never calls AdminTransaction or changes lifecycle/history/audit records.
type StartupLoader struct {
	reader   *ActivationReader
	cipher   *Cipher
	sessions auth.SessionConfig
	callback string
	client   func(context.Context, string) (*http.Client, error)
}

func NewStartupLoader(reader *ActivationReader, cipher *Cipher, sessions auth.SessionConfig, callback string, iapPinned bool) (*StartupLoader, error) {
	if reader == nil || cipher == nil || cipher.aead == nil || callback == "" {
		return nil, ErrInvalid
	}
	if iapPinned {
		return nil, ErrDenied
	}
	return &StartupLoader{reader, cipher, sessions, callback, newTestClient}, nil
}

type startupRevision struct {
	metadata  Metadata
	encrypted encryptedSecret
}
type startupState struct {
	head             ActivationHead
	event            ActivationEvent
	active, previous startupRevision
	databaseTime     time.Time
}

func (l *StartupLoader) read(ctx context.Context) (startupState, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := l.reader.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return startupState{}, ErrUnavailable
	}
	defer tx.Rollback(ctx)
	scope := l.reader.scope
	s := startupState{head: ActivationHead{Scope: scope}, event: ActivationEvent{Scope: scope}}
	h, e := &s.head, &s.event
	err = tx.QueryRow(ctx, `SELECT h.generation,h.runtime_source,h.active_revision_id::text,h.activated_at,
 a.generation,COALESCE(a.previous_revision_id::text,''),a.target_revision_id::text,a.activated_at,a.transition_deadline,clock_timestamp()
 FROM framework.auth_activation_heads h JOIN framework.auth_activation_history a
 ON a.deployment_id=h.deployment_id AND a.environment=h.environment AND a.generation=h.generation
 WHERE h.deployment_id=$1 AND h.environment=$2`, scope.DeploymentID, scope.Environment).Scan(&h.Generation, &h.RuntimeSource, &h.ActiveRevisionID, &h.ActivatedAt, &e.Generation, &e.PreviousRevisionID, &e.TargetRevisionID, &e.ActivatedAt, &e.TransitionDeadline, &s.databaseTime)
	if err != nil {
		return startupState{}, ErrUnavailable
	}
	if h.RuntimeSource != "database" || h.Generation < 1 || h.ActivatedAt == nil || !h.ActivatedAt.Equal(e.ActivatedAt) || h.ActiveRevisionID != e.TargetRevisionID || e.ActivatedAt.After(s.databaseTime) || e.TransitionDeadline.Before(e.ActivatedAt) || e.TransitionDeadline.After(e.ActivatedAt.Add(30*time.Minute)) || ((h.Generation == 1) != (e.PreviousRevisionID == "")) {
		return startupState{}, ErrInvalid
	}
	var consistent bool
	err = tx.QueryRow(ctx, `SELECT
 (SELECT max(generation) FROM framework.auth_activation_history WHERE deployment_id=$1 AND environment=$2)=$3
 AND (SELECT count(*) FROM framework.auth_config_lifecycle WHERE deployment_id=$1 AND environment=$2 AND status='active')=1`, scope.DeploymentID, scope.Environment, h.Generation).Scan(&consistent)
	if err != nil || !consistent {
		return startupState{}, ErrUnavailable
	}
	load := func(id string, status Status) (startupRevision, error) {
		m, err := scanMetadata(tx.QueryRow(ctx, metadataSelect+`AND r.id=$3`, scope.DeploymentID, scope.Environment, id))
		if err != nil {
			return startupRevision{}, ErrUnavailable
		}
		if m.Scope != scope || m.Provider != auth.OIDC || m.Status != status || m.Generation != map[Status]int64{Active: 4, Superseded: 5}[status] || m.ApprovedAt == nil || m.ActivatedAt == nil || m.RedirectURI != l.callback || !m.HasSecret || (status == Superseded && (m.Generation < 5 || m.SupersededAt == nil)) {
			return startupRevision{}, ErrInvalid
		}
		var encrypted encryptedSecret
		err = tx.QueryRow(ctx, `SELECT encryption_format,encryption_key_id,secret_nonce,secret_ciphertext FROM framework.auth_config_revisions WHERE id=$1 AND deployment_id=$2 AND environment=$3`, id, scope.DeploymentID, scope.Environment).Scan(&encrypted.format, &encrypted.keyID, &encrypted.nonce, &encrypted.ciphertext)
		if err != nil {
			return startupRevision{}, ErrUnavailable
		}
		return startupRevision{m, encrypted}, nil
	}
	s.active, err = load(h.ActiveRevisionID, Active)
	if err != nil {
		return startupState{}, err
	}
	if e.PreviousRevisionID != "" {
		var previous string
		var previousTime time.Time
		err = tx.QueryRow(ctx, `SELECT target_revision_id::text,activated_at FROM framework.auth_activation_history WHERE deployment_id=$1 AND environment=$2 AND generation=$3`, scope.DeploymentID, scope.Environment, h.Generation-1).Scan(&previous, &previousTime)
		if err != nil || previous != e.PreviousRevisionID || previousTime.After(e.ActivatedAt) {
			return startupState{}, ErrInvalid
		}
		// Expired revisions need no old keys or reachable old issuer. They can
		// never be restored just because this process restarted.
		if s.databaseTime.Before(e.TransitionDeadline) {
			s.previous, err = load(previous, Superseded)
			if err != nil {
				return startupState{}, err
			}
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return startupState{}, ErrUnavailable
	}
	return s, nil
}

func (l *StartupLoader) Load(ctx context.Context) (*auth.Runtime, error) {
	ctx, cancel := context.WithTimeout(ctx, 50*time.Second)
	defer cancel()
	s, err := l.read(ctx)
	if err != nil {
		return nil, err
	}
	store, err := auth.NewPostgresStore(l.reader.pool, l.sessions)
	if err != nil {
		return nil, ErrInvalid
	}
	prepare := func(r startupRevision, generation int64) (*auth.PreparedOIDC, error) {
		secret, err := l.cipher.open(r.metadata, r.encrypted)
		if err != nil {
			return nil, ErrSecret
		}
		defer clear(secret.value)
		if validate(l.reader.scope, r.metadata.Settings, secret) != nil {
			return nil, ErrInvalid
		}
		return prepareRuntimeOIDC(ctx, r.metadata, secret, generation, l.sessions, store, l.client)
	}
	active, err := prepare(s.active, s.head.Generation)
	if err != nil {
		return nil, err
	}
	defer active.Close()
	var previous *auth.PreparedOIDC
	if s.previous.metadata.ID != "" && time.Now().Before(s.event.TransitionDeadline) {
		previous, err = prepare(s.previous, s.head.Generation-1)
		if err != nil {
			return nil, err
		}
		defer previous.Close()
	}
	// Discovery is outside the read transaction. Refuse a changed head rather
	// than serving a stale provider or retrying indefinitely.
	latest, err := l.read(ctx)
	if err != nil {
		return nil, err
	}
	if latest.head.Generation != s.head.Generation || latest.head.ActiveRevisionID != s.head.ActiveRevisionID || latest.active.metadata.Generation != s.active.metadata.Generation {
		return nil, ErrConflict
	}
	runtime, err := auth.NewDatabaseRuntime(active, previous, s.event.ActivatedAt, s.event.TransitionDeadline)
	if err != nil {
		return nil, ErrUnavailable
	}
	return runtime, nil
}

// StartupRuntimeFromEnv returns nil only for an explicitly permitted environment
// policy. Missing keys or failed database preparation must never mean fallback.
func StartupRuntimeFromEnv(ctx context.Context, reader *ActivationReader, getenv func(string) string) (*auth.Runtime, error) {
	err := reader.RequireEnvironmentStartup(ctx)
	if err == nil {
		return nil, nil
	}
	if !errors.Is(err, ErrDatabaseRuntimeRequired) {
		return nil, err
	}
	if auth.Provider(getenv("AUTH_PROVIDER")) == auth.GoogleIAP {
		return nil, ErrDenied
	}
	cipher, err := CipherFromEnv(getenv)
	if err != nil {
		return nil, err
	}
	sessions, err := auth.SessionConfigFromEnv(getenv)
	if err != nil {
		return nil, ErrInvalid
	}
	loader, err := NewStartupLoader(reader, cipher, sessions, getenv("APP_ORIGIN")+"/api/auth/callback", false)
	if err != nil {
		return nil, err
	}
	return loader.Load(ctx)
}
