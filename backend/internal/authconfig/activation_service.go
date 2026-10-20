package authconfig

import (
	"context"
	"errors"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/jackc/pgx/v5"
)

// ActivationService is a trusted control-plane capability. The HTTP composition
// root does not construct/expose it. No migration, polling or fallback occurs.
type ActivationService struct {
	repo     *Repository
	runtime  *auth.Runtime
	store    *auth.PostgresStore
	sessions auth.SessionConfig
	callback string
	client   func(context.Context, string) (*http.Client, error)
}
type PreparedActivation struct {
	service     *ActivationService
	metadata    Metadata
	actor       string
	expected    int64
	previous    string
	expires     time.Time
	provider    *auth.PreparedOIDC
	publication *auth.Publication
	readiness   ActivationReadiness
}

// ActivationReadiness describes session impact before explicit confirmation.
// It is not proof of activation eligibility: evidence and authorization are
// rechecked by Activate. This value never contains credentials.
type ActivationReadiness struct {
	CurrentProvider          auth.Provider
	CurrentSource            string
	TargetRevisionID         string
	ExpectedGeneration       int64
	RequiresReauthentication bool
	MaximumSessionGrace      time.Duration
}

func (p *PreparedActivation) Readiness() ActivationReadiness { return p.readiness }

func (p *PreparedActivation) Close() {
	if p != nil {
		p.provider.Close()
	}
}
func NewActivationService(repo *Repository, runtime *auth.Runtime, store *auth.PostgresStore, sessions auth.SessionConfig, callback string) (*ActivationService, error) {
	if repo == nil || runtime == nil || store == nil {
		return nil, ErrInvalid
	}
	status, _, mismatch := runtime.ControlStatus()
	if mismatch || status.Provider == auth.GoogleIAP || status.DeploymentID != repo.scope.DeploymentID || status.Environment != repo.scope.Environment {
		return nil, ErrDenied
	}
	return &ActivationService{repo, runtime, store, sessions, callback, newTestClient}, nil
}

// synchronousProbeKeys avoids go-oidc RemoteKeySet's detached background fetches.
// Each callback refreshes validated keys through the same DNS-pinned transport.
type synchronousProbeKeys struct{ probe *connectionProbe }

func (k synchronousProbeKeys) VerifySignature(ctx context.Context, token string) ([]byte, error) {
	keys, err := k.probe.keys(ctx)
	if err != nil {
		return nil, ErrUnavailable
	}
	return keys.VerifySignature(ctx, token)
}

func (s *ActivationService) Prepare(ctx context.Context, id string, generation, expectedActivation int64) (*PreparedActivation, error) {
	if expectedActivation < 0 || expectedActivation == math.MaxInt64 {
		return nil, ErrInvalid
	}
	actor, ok := access.Principal(ctx)
	if !ok {
		return nil, ErrDenied
	}
	var secret Secret
	defer func() { clear(secret.value) }()
	m, err := s.repo.testTransaction(ctx, id, generation, "", "auth_config.activation_prepared", "prepared", nil, &secret)
	if err != nil {
		return nil, err
	}
	if m.RedirectURI != s.callback {
		return nil, ErrInvalid
	}
	provider, err := prepareRuntimeOIDC(ctx, m, secret, expectedActivation+1, s.sessions, s.store, s.client)
	if err != nil {
		return nil, err
	}
	publication, err := s.runtime.Stage(provider, expectedActivation)
	if err != nil {
		provider.Close()
		return nil, ErrConflict
	}
	status, _, mismatch := s.runtime.ControlStatus()
	if mismatch || status.AppliedGeneration != expectedActivation {
		provider.Close()
		return nil, ErrConflict
	}
	readiness := ActivationReadiness{CurrentProvider: status.Provider, CurrentSource: status.Source,
		TargetRevisionID: m.ID, ExpectedGeneration: expectedActivation,
		RequiresReauthentication: status.Source == "environment", MaximumSessionGrace: 30 * time.Minute}
	if readiness.RequiresReauthentication {
		readiness.MaximumSessionGrace = 0
	}
	return &PreparedActivation{service: s, metadata: m, actor: actor.ID, expected: expectedActivation, previous: status.ActiveRevisionID, expires: time.Now().Add(5 * time.Minute), provider: provider, publication: publication, readiness: readiness}, nil
}

// Shared by administrator preparation and read-only startup. The caller owns
// the secret; returned providers own their transport, never the shared DB pool.
func prepareRuntimeOIDC(ctx context.Context, m Metadata, secret Secret, generation int64, sessions auth.SessionConfig, store *auth.PostgresStore, clientFactory func(context.Context, string) (*http.Client, error)) (*auth.PreparedOIDC, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	client, err := clientFactory(ctx, m.IssuerURL)
	if err != nil {
		return nil, ErrUnavailable
	}
	cleanup := func() { client.CloseIdleConnections() }
	probe, err := newConnectionProbe(ctx, m, secret, m.RedirectURI, client)
	if err != nil {
		cleanup()
		return nil, err
	}
	binding := auth.Binding{Source: "database", DeploymentID: m.DeploymentID, Environment: m.Environment, RevisionID: m.ID, ActivationGeneration: generation, Issuer: m.IssuerURL, ClientID: m.ClientID, Purpose: "login"}
	config := auth.OIDCConfig{AppEnv: m.Environment, Issuer: m.IssuerURL, ClientID: m.ClientID, ClientSecret: string(secret.value), RedirectURI: m.RedirectURI, AllowHTTPDevelopment: m.AllowHTTPDevelopment, Sessions: sessions}
	provider, err := auth.NewPreparedDatabaseOIDC(config, probe.config.Endpoint, synchronousProbeKeys{probe}, probe.algorithms, client, store, binding, cleanup)
	probe.config.ClientSecret = ""
	if err != nil {
		cleanup()
		return nil, ErrInvalid
	}
	return provider, nil
}

type ActivationRequest struct {
	AcknowledgeReauthentication                          bool
	IsolatedEvidenceID, NormalEvidenceID, EnrolledUserID string
	Transition                                           time.Duration
	Reason                                               string
}
type ActivationResult struct {
	DesiredGeneration, AppliedGeneration int64
	RevisionID                           string
	Applied                              bool
	Committed, CommitUncertain           bool
}

// Activate is not registered as an HTTP endpoint. External work has already
// finished. All administrator/evidence/head checks and writes share one lock/tx.
func (s *ActivationService) Activate(ctx context.Context, p *PreparedActivation, request ActivationRequest) (ActivationResult, error) {
	if p == nil || p.service != s || request.Transition < 0 || request.Transition > 30*time.Minute || !validID(request.IsolatedEvidenceID) || !validID(request.NormalEvidenceID) || !validID(request.EnrolledUserID) || strings.TrimSpace(request.Reason) == "" || len(request.Reason) > 512 {
		return ActivationResult{}, ErrInvalid
	}
	// First cutover has no safely revision-bound credentials to drain. Do not
	// silently accept a grace request or record a misleading history deadline.
	if p.readiness.RequiresReauthentication && (!request.AcknowledgeReauthentication || request.Transition != 0) {
		return ActivationResult{}, ErrInvalid
	}
	// Preflight refuses a second transition while one drains, and detects stale
	// runtime state without any database changes. Commit still performs its CAS.
	if err := p.publication.Reserve(); err != nil {
		return ActivationResult{}, ErrConflict
	}
	defer p.publication.Abort() // Mismatch/uncertain outcomes remain fenced separately.
	var deadline time.Time
	readyToCommit := false
	err := s.repo.transaction(ctx, func(ctx context.Context, tx pgx.Tx, actor access.User) error {
		if !time.Now().Before(p.expires) {
			return ErrConflict
		}
		if actor.ID != p.actor {
			return ErrDenied
		}
		m, err := s.repo.get(ctx, tx, p.metadata.ID)
		if err != nil {
			return err
		}
		if m.Status != Approved || m.Generation != p.metadata.Generation || m.Provider != auth.OIDC {
			return ErrConflict
		}
		var generation int64
		var previous, source string
		headExists := true
		err = tx.QueryRow(ctx, `SELECT generation,COALESCE(active_revision_id::text,''),runtime_source FROM framework.auth_activation_heads WHERE deployment_id=$1 AND environment=$2 FOR UPDATE`, m.DeploymentID, m.Environment).Scan(&generation, &previous, &source)
		if errors.Is(err, pgx.ErrNoRows) {
			generation = 0
			headExists = false
			source = "environment"
		} else if err != nil {
			return err
		}
		if generation != p.expected || previous != p.previous || (generation == 0 && source != "environment") || (generation > 0 && source != "database") {
			return ErrConflict
		}
		var evidenceOK bool
		// Both purposes must attest to the same explicitly enrolled user. Neither an
		// email match nor a role label substitutes for effective admin.manage.
		err = tx.QueryRow(ctx, `SELECT EXISTS(
   SELECT 1 FROM framework.auth_test_evidence i JOIN framework.auth_test_evidence n
     ON n.revision_id=i.revision_id AND n.issuer=i.issuer AND n.subject=i.subject
   JOIN framework.users u ON u.issuer=i.issuer AND u.subject=i.subject
   WHERE i.id=$1 AND n.id=$2 AND u.id=$3 AND u.active AND u.provider='oidc'
   AND i.deployment_id=$4 AND n.deployment_id=$4 AND i.environment=$5 AND n.environment=$5
   AND i.revision_id=$6 AND i.revision_generation=$7 AND n.revision_generation=$7
   AND i.actor_user_id=$8 AND n.actor_user_id=$8 AND i.issuer=$9
   AND i.purpose='isolated_connection' AND n.purpose='normal_callback'
   AND i.verification_version=1 AND n.verification_version=1
   AND i.completed_at<=clock_timestamp() AND n.completed_at<=clock_timestamp()
   AND i.expires_at>clock_timestamp() AND n.expires_at>clock_timestamp()
   AND EXISTS(SELECT 1 FROM framework.user_roles ur JOIN framework.role_permissions rp ON rp.role=ur.role WHERE ur.user_id=u.id AND rp.permission='admin.manage')
   AND EXISTS(SELECT 1 FROM framework.audit_log a WHERE a.action='auth_config.identity_enrolled' AND a.target_id=u.id::text)
  )`, request.IsolatedEvidenceID, request.NormalEvidenceID, request.EnrolledUserID, m.DeploymentID, m.Environment, m.ID, m.Generation, actor.ID, m.IssuerURL).Scan(&evidenceOK)
		if err != nil {
			return err
		}
		if !evidenceOK {
			return ErrDenied
		}
		var recovery string
		// Recovery provenance is created atomically with the immutable recovery draft.
		err = tx.QueryRow(ctx, `SELECT COALESCE((SELECT details->>'recovery_revision_id' FROM framework.audit_log WHERE action='auth_config.recovery_draft' AND target_id=$1 ORDER BY id DESC LIMIT 1),'')`, m.ID).Scan(&recovery)
		if err != nil {
			return err
		}
		if recovery != "" {
			var ready bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM framework.auth_config_revisions r JOIN framework.auth_config_lifecycle l ON l.revision_id=r.id WHERE r.id=$1 AND r.deployment_id=$2 AND r.environment=$3 AND r.provider='oidc' AND l.status='superseded')`, recovery, m.DeploymentID, m.Environment).Scan(&ready); err != nil {
				return err
			}
			if !ready {
				return ErrConflict
			}
		}
		if previous != "" {
			tag, err := tx.Exec(ctx, `UPDATE framework.auth_config_lifecycle SET status='superseded',generation=generation+1,updated_by=$2,updated_by_recovery_audit=NULL WHERE revision_id=$1 AND deployment_id=$3 AND environment=$4 AND status='active'`, previous, actor.ID, m.DeploymentID, m.Environment)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return ErrConflict
			}
		}
		if _, err = tx.Exec(ctx, `UPDATE framework.auth_config_lifecycle SET status='active',generation=generation+1,updated_by=$2 WHERE revision_id=$1`, m.ID, actor.ID); err != nil {
			return err
		}
		var when time.Time
		if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&when); err != nil {
			return err
		}
		deadline = when.Add(request.Transition)
		_, err = tx.Exec(ctx, `INSERT INTO framework.auth_activation_history(deployment_id,environment,generation,previous_revision_id,target_revision_id,recovery_revision_id,actor_user_id,activated_at,transition_deadline,reason)
   VALUES($1,$2,$3,NULLIF($4,'')::uuid,$5,NULLIF($6,'')::uuid,$7,$8,$9,$10)`, m.DeploymentID, m.Environment, generation+1, previous, m.ID, recovery, actor.ID, when, deadline, request.Reason)
		if err != nil {
			return err
		}
		if headExists {
			_, err = tx.Exec(ctx, `UPDATE framework.auth_activation_heads SET generation=$3,runtime_source='database',active_revision_id=$4,activated_at=$5 WHERE deployment_id=$1 AND environment=$2`, m.DeploymentID, m.Environment, generation+1, m.ID, when)
		} else {
			_, err = tx.Exec(ctx, `INSERT INTO framework.auth_activation_heads(deployment_id,environment,generation,runtime_source,active_revision_id,activated_at) VALUES($1,$2,$3,'database',$4,$5)`, m.DeploymentID, m.Environment, generation+1, m.ID, when)
		}
		if err != nil {
			return err
		}
		details := struct {
			Generation int64  `json:"generation"`
			Previous   string `json:"previous_revision_id"`
			Isolated   string `json:"isolated_evidence_id"`
			Normal     string `json:"normal_evidence_id"`
			User       string `json:"enrolled_user_id"`
		}{generation + 1, previous, request.IsolatedEvidenceID, request.NormalEvidenceID, request.EnrolledUserID}
		if access.RecordAudit(ctx, tx, actor.ID, "auth_config.activated", m.ID, details) != nil {
			return ErrAudit
		}
		// A slow audit/lock must not turn expired evidence into authorization.
		var fresh bool
		if err = tx.QueryRow(ctx, `SELECT count(*)=2 FROM framework.auth_test_evidence WHERE id IN ($1,$2) AND expires_at>clock_timestamp()`, request.IsolatedEvidenceID, request.NormalEvidenceID).Scan(&fresh); err != nil {
			return err
		}
		if !fresh {
			return ErrDenied
		}
		if err := notifyActivation(ctx, tx, m.Scope, generation+1); err != nil {
			return err
		}
		readyToCommit = true
		return nil
	})
	if err != nil {
		if readyToCommit {
			s.runtime.Fence(p.expected + 1)
			status, _, _ := s.runtime.ControlStatus()
			return ActivationResult{DesiredGeneration: p.expected + 1, AppliedGeneration: status.AppliedGeneration, RevisionID: p.metadata.ID, CommitUncertain: true}, auth.ErrRuntimeMismatch
		}
		return ActivationResult{}, err
	}
	result := ActivationResult{DesiredGeneration: p.expected + 1, RevisionID: p.metadata.ID, Committed: true}
	err = p.publication.Commit(deadline)
	status, _, _ := s.runtime.ControlStatus()
	result.AppliedGeneration = status.AppliedGeneration
	result.Applied = err == nil
	if err != nil {
		p.Close()
		return result, auth.ErrRuntimeMismatch
	}
	return result, nil
}
