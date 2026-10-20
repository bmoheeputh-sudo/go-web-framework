package authconfig

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/jackc/pgx/v5"
)

var ErrCommitUncertain = errors.New("auth_config_commit_outcome_uncertain")

type RecoveryPreview struct {
	Scope
	OperatorID, AuthorizationKeyID                        string
	CurrentRevisionID, TargetRevisionID, SourceRevisionID string
	ExpectedGeneration, TargetGeneration                  int64
	IssuerURL, ClientID, Reason                           string
	RequiresReauthentication                              bool
}

type PreparedRecovery struct {
	mu          sync.Mutex
	service     *RecoveryService
	metadata    Metadata
	source      Metadata
	previous    string
	expected    int64
	reason      string
	operatorID  string
	operatorKey string
	fingerprint [32]byte
	expires     time.Time
	provider    *auth.PreparedOIDC
	closed      bool
	used        bool
}

func (p *PreparedRecovery) Preview() RecoveryPreview {
	return RecoveryPreview{Scope: p.metadata.Scope, OperatorID: p.operatorID, AuthorizationKeyID: p.operatorKey,
		CurrentRevisionID: p.previous, TargetRevisionID: p.metadata.ID, SourceRevisionID: p.source.ID,
		ExpectedGeneration: p.expected, TargetGeneration: p.expected + 1, IssuerURL: p.metadata.IssuerURL,
		ClientID: p.metadata.ClientID, Reason: p.reason, RequiresReauthentication: true}
}
func (p *PreparedRecovery) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		p.provider.Close()
	}
	p.mu.Unlock()
}
func (p *PreparedRecovery) claim() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.used || !time.Now().Before(p.expires) {
		return false
	}
	p.used = true
	return true
}

type RecoveryResult struct {
	Generation                 int64
	RevisionID                 string
	Committed, CommitUncertain bool
}

// RecoveryService is constructed only by the offline CLI. It prepares the same
// hardened OIDC implementation used by activation but never publishes locally.
type RecoveryService struct {
	repo     *Repository
	store    *auth.PostgresStore
	sessions auth.SessionConfig
	callback string
	client   func(context.Context, string) (*http.Client, error)
}

func NewRecoveryService(repo *Repository, store *auth.PostgresStore, sessions auth.SessionConfig, callback string) (*RecoveryService, error) {
	if repo == nil || store == nil || callback == "" {
		return nil, ErrDenied
	}
	return &RecoveryService{repo: repo, store: store, sessions: sessions, callback: callback, client: newTestClient}, nil
}

type recoveryCandidate struct {
	target, source Metadata
	encrypted      encryptedSecret
	head           ActivationHead
}

func (s *RecoveryService) candidate(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, id string, expected int64, encrypted bool) (recoveryCandidate, error) {
	if !validID(id) || expected < 1 {
		return recoveryCandidate{}, ErrInvalid
	}
	var c recoveryCandidate
	c.head.Scope = s.repo.scope
	if err := q.QueryRow(ctx, `SELECT generation,runtime_source,active_revision_id::text,activated_at FROM framework.auth_activation_heads WHERE deployment_id=$1 AND environment=$2`, s.repo.scope.DeploymentID, s.repo.scope.Environment).Scan(&c.head.Generation, &c.head.RuntimeSource, &c.head.ActiveRevisionID, &c.head.ActivatedAt); err != nil {
		return recoveryCandidate{}, recoveryReadError(err)
	}
	if c.head.Generation != expected || c.head.RuntimeSource != "database" || c.head.ActiveRevisionID == id {
		return recoveryCandidate{}, ErrConflict
	}
	var err error
	c.target, err = scanMetadata(q.QueryRow(ctx, metadataSelect+`AND r.id=$3`, s.repo.scope.DeploymentID, s.repo.scope.Environment, id))
	if err != nil {
		return recoveryCandidate{}, recoveryReadError(err)
	}
	if c.target.Provider != auth.OIDC || c.target.Status != Approved || c.target.Generation != 3 || c.target.RedirectURI != s.callback || !c.target.HasSecret {
		return recoveryCandidate{}, ErrConflict
	}
	var sourceID string
	var provenance int
	err = q.QueryRow(ctx, `SELECT max(a.details->>'recovery_revision_id'),count(*) FROM framework.audit_log a
	 JOIN framework.auth_config_revisions r ON r.id::text=a.target_id AND r.created_by=a.actor_user_id
	 WHERE a.action='auth_config.recovery_draft' AND a.target_id=$1 AND r.deployment_id=$2 AND r.environment=$3
	 HAVING count(*)=1`, id, s.repo.scope.DeploymentID, s.repo.scope.Environment).Scan(&sourceID, &provenance)
	if err != nil || provenance != 1 || !validID(sourceID) || sourceID == id {
		return recoveryCandidate{}, ErrConflict
	}
	c.source, err = scanMetadata(q.QueryRow(ctx, metadataSelect+`AND r.id=$3`, s.repo.scope.DeploymentID, s.repo.scope.Environment, sourceID))
	if err != nil || c.source.Provider != auth.OIDC || c.source.Status != Superseded || c.source.Settings != c.target.Settings {
		return recoveryCandidate{}, ErrConflict
	}
	if encrypted {
		err = q.QueryRow(ctx, `SELECT encryption_format,encryption_key_id,secret_nonce,secret_ciphertext FROM framework.auth_config_revisions WHERE id=$1 AND deployment_id=$2 AND environment=$3`, id, s.repo.scope.DeploymentID, s.repo.scope.Environment).Scan(&c.encrypted.format, &c.encrypted.keyID, &c.encrypted.nonce, &c.encrypted.ciphertext)
		if err != nil {
			return recoveryCandidate{}, recoveryReadError(err)
		}
	}
	return c, nil
}

func recoveryReadError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return ErrUnavailable
}

func (s *RecoveryService) Prepare(ctx context.Context, operator *OfflineOperator, revision string, expected int64, reason string) (*PreparedRecovery, error) {
	reason = strings.TrimSpace(reason)
	if !operator.available() || len(reason) < 8 || len(reason) > 512 || strings.ContainsAny(reason, "\x00\r\n") {
		return nil, ErrInvalid
	}
	var c recoveryCandidate
	err := s.repo.access.AuthRecoveryRead(ctx, func(tx pgx.Tx) error {
		var err error
		c, err = s.candidate(ctx, tx, revision, expected, true)
		return err
	})
	if err != nil {
		return nil, mapRecoveryError(err)
	}
	secret, err := s.repo.cipher.open(c.target, c.encrypted)
	if err != nil {
		return nil, ErrSecret
	}
	defer clear(secret.value)
	if validate(s.repo.scope, c.target.Settings, secret) != nil {
		return nil, ErrInvalid
	}
	provider, err := prepareRuntimeOIDC(ctx, c.target, secret, expected+1, s.sessions, s.store, s.client)
	if err != nil {
		return nil, err
	}
	return &PreparedRecovery{service: s, metadata: c.target, source: c.source, previous: c.head.ActiveRevisionID,
		expected: expected, reason: reason, operatorID: operator.id, operatorKey: operator.keyID,
		fingerprint: operator.fingerprint, expires: time.Now().Add(5 * time.Minute), provider: provider}, nil
}

func recoveryUUID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", ErrUnavailable
	}
	id[6] = (id[6] & 15) | 64
	id[8] = (id[8] & 63) | 128
	raw := hex.EncodeToString(id[:])
	return raw[:8] + "-" + raw[8:12] + "-" + raw[12:16] + "-" + raw[16:20] + "-" + raw[20:], nil
}

func (s *RecoveryService) Recover(ctx context.Context, operator *OfflineOperator, p *PreparedRecovery) (RecoveryResult, error) {
	if p == nil || p.service != s || operator == nil || operator.id != p.operatorID || operator.keyID != p.operatorKey || operator.fingerprint != p.fingerprint || !p.claim() {
		return RecoveryResult{}, ErrDenied
	}
	eventID, err := recoveryUUID()
	if err != nil {
		return RecoveryResult{}, err
	}
	authorization, err := operator.authorize(eventID, p.metadata.Scope, p.expected, p.metadata.ID, p.source.ID, p.reason)
	if err != nil {
		return RecoveryResult{}, err
	}
	defer clear(authorization.nonce)
	defer clear(authorization.tag)
	result := RecoveryResult{Generation: p.expected + 1, RevisionID: p.metadata.ID}
	err = s.repo.access.AuthRecoveryTransaction(ctx, func(tx pgx.Tx) error {
		c, err := s.candidate(ctx, tx, p.metadata.ID, p.expected, false)
		if err != nil {
			return err
		}
		if c.target.Generation != p.metadata.Generation || c.target.Settings != p.metadata.Settings || c.source.ID != p.source.ID || c.head.ActiveRevisionID != p.previous {
			return ErrConflict
		}
		_, err = tx.Exec(ctx, `INSERT INTO framework.auth_recovery_audit(id,deployment_id,environment,generation,target_revision_id,recovery_revision_id,operator_id,authorization_key_id,authorization_format,authorization_key_fingerprint,authorization_nonce,authorization_tag,reason)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,1,$9,$10,$11,$12)`, eventID, c.target.DeploymentID, c.target.Environment, p.expected+1, c.target.ID, c.source.ID, operator.id, operator.keyID, operator.fingerprint[:], authorization.nonce, authorization.tag, p.reason)
		if err != nil {
			return ErrAudit
		}
		previous, err := tx.Exec(ctx, `UPDATE framework.auth_config_lifecycle SET status='superseded',generation=generation+1,updated_by=NULL,updated_by_recovery_audit=$2 WHERE revision_id=$1 AND deployment_id=$3 AND environment=$4 AND status='active'`, p.previous, eventID, c.target.DeploymentID, c.target.Environment)
		if err != nil || previous.RowsAffected() != 1 {
			return ErrConflict
		}
		target, err := tx.Exec(ctx, `UPDATE framework.auth_config_lifecycle SET status='active',generation=generation+1,updated_by=NULL,updated_by_recovery_audit=$2 WHERE revision_id=$1 AND deployment_id=$3 AND environment=$4 AND status='approved' AND generation=3`, c.target.ID, eventID, c.target.DeploymentID, c.target.Environment)
		if err != nil || target.RowsAffected() != 1 {
			return ErrConflict
		}
		var when time.Time
		if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&when); err != nil {
			return ErrUnavailable
		}
		_, err = tx.Exec(ctx, `INSERT INTO framework.auth_activation_history(deployment_id,environment,generation,previous_revision_id,target_revision_id,recovery_revision_id,actor_user_id,recovery_audit_id,activated_at,transition_deadline,reason)
 VALUES($1,$2,$3,$4,$5,$6,NULL,$7,$8,$8,$9)`, c.target.DeploymentID, c.target.Environment, p.expected+1, p.previous, c.target.ID, c.source.ID, eventID, when, p.reason)
		if err != nil {
			return ErrAudit
		}
		head, err := tx.Exec(ctx, `UPDATE framework.auth_activation_heads SET generation=$3,active_revision_id=$4,activated_at=$5 WHERE deployment_id=$1 AND environment=$2 AND generation=$6 AND runtime_source='database' AND active_revision_id=$7`, c.target.DeploymentID, c.target.Environment, p.expected+1, c.target.ID, when, p.expected, p.previous)
		if err != nil || head.RowsAffected() != 1 {
			return ErrConflict
		}
		return notifyActivation(ctx, tx, c.target.Scope, p.expected+1)
	})
	if err == nil {
		result.Committed = true
		return result, nil
	}
	if errors.Is(err, access.ErrCommitUncertain) {
		result.CommitUncertain = true
		return result, ErrCommitUncertain
	}
	return RecoveryResult{}, mapRecoveryError(err)
}

func mapRecoveryError(err error) error {
	for _, known := range []error{ErrInvalid, ErrDenied, ErrConflict, ErrNotFound, ErrSecret, ErrCrypto, ErrAudit, ErrTimeout, ErrCanceled} {
		if errors.Is(err, known) {
			return known
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrTimeout
	}
	if errors.Is(err, context.Canceled) {
		return ErrCanceled
	}
	return ErrUnavailable
}
