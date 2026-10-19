package authconfig

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/jackc/pgx/v5"
)

type EvidencePurpose string

const (
	IsolatedConnection EvidencePurpose = "isolated_connection"
	NormalCallback     EvidencePurpose = "normal_callback"
)

func (p EvidencePurpose) valid() bool { return p == IsolatedConnection || p == NormalCallback }

type TestEvidence struct {
	ID string
	Scope
	RevisionID          string
	RevisionGeneration  int64
	ActorUserID         string
	Issuer              string
	Subject             string
	Purpose             EvidencePurpose
	CompletedAt         time.Time
	ExpiresAt           time.Time
	VerificationVersion int
}

// verifiedTestEvidence is deliberately package-private with private fields: it
// cannot be decoded from request JSON or constructed by another package. Only a
// trusted verifier in authconfig may construct it AFTER completing signature,
// issuer, audience, expiration, state, nonce, PKCE and browser-correlation checks.
// This phase does not wire it to any live endpoint. The database cannot attest
// to an OIDC handshake; the verifier and database owner remain trusted code.
type verifiedTestEvidence struct {
	revisionID         string
	revisionGeneration int64
	identity           auth.Identity
	purpose            EvidencePurpose
	completedAt        time.Time
	expiresAt          time.Time
}

// recordTestEvidence does not accept an actor, deployment, environment, arbitrary
// verification metadata, or success flag. Authorization, revision and issuer are
// checked again under AdminTransaction, and evidence/audit share one commit.
func (r *Repository) recordTestEvidence(ctx context.Context, proof verifiedTestEvidence) (TestEvidence, error) {
	now := time.Now()
	if !validID(proof.revisionID) || proof.revisionGeneration < 1 || !proof.purpose.valid() ||
		proof.identity.Validate() != nil || proof.identity.Provider != auth.OIDC || len(proof.identity.Subject) > 1024 ||
		proof.completedAt.IsZero() || proof.completedAt.After(now) || !proof.expiresAt.After(now) ||
		!proof.expiresAt.After(proof.completedAt) || proof.expiresAt.Sub(proof.completedAt) > 5*time.Minute {
		return TestEvidence{}, ErrInvalid
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return TestEvidence{}, ErrUnavailable
	}
	id[6] = (id[6] & 15) | 64
	id[8] = (id[8] & 63) | 128
	e := TestEvidence{ID: fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:16]), Scope: r.scope,
		RevisionID: proof.revisionID, RevisionGeneration: proof.revisionGeneration, Issuer: proof.identity.Issuer,
		Subject: proof.identity.Subject, Purpose: proof.purpose, CompletedAt: proof.completedAt, ExpiresAt: proof.expiresAt, VerificationVersion: 1}
	err := r.transaction(ctx, func(ctx context.Context, tx pgx.Tx, actor access.User) error {
		m, err := r.get(ctx, tx, e.RevisionID)
		if err != nil {
			return err
		}
		if m.Generation != e.RevisionGeneration {
			return ErrConflict
		}
		if m.Status != Approved || m.Provider != auth.OIDC || m.IssuerURL != e.Issuer {
			return ErrInvalid
		}
		e.ActorUserID = actor.ID
		_, err = tx.Exec(ctx, `INSERT INTO framework.auth_test_evidence(id,deployment_id,environment,revision_id,revision_generation,
          actor_user_id,issuer,subject,purpose,completed_at,expires_at,verification_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,1)`,
			e.ID, e.DeploymentID, e.Environment, e.RevisionID, e.RevisionGeneration, e.ActorUserID, e.Issuer, e.Subject, e.Purpose, e.CompletedAt, e.ExpiresAt)
		if err != nil {
			return err
		}
		details := struct {
			EvidenceID string          `json:"evidence_id"`
			Generation int64           `json:"generation"`
			Purpose    EvidencePurpose `json:"purpose"`
		}{e.ID, e.RevisionGeneration, e.Purpose}
		if access.RecordAudit(ctx, tx, actor.ID, "auth_config.test_evidence_recorded", e.RevisionID, details) != nil {
			return ErrAudit
		}
		return nil
	})
	if err != nil {
		return TestEvidence{}, err
	}
	return e, nil
}

// Evidence returns only fresh, same-revision/generation/purpose proof. An isolated
// test cannot qualify as a normal-callback pre-activation test. This is not an
// activation authorization decision: future callers must recheck the head, actor,
// tested identity's admin access and evidence in their locked mutation transaction.
func (r *ActivationReader) Evidence(ctx context.Context, id, revision string, generation int64, purpose EvidencePurpose) (TestEvidence, error) {
	if !validID(id) || !validID(revision) || generation < 1 || !purpose.valid() {
		return TestEvidence{}, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	e := TestEvidence{Scope: r.scope}
	err := r.pool.QueryRow(ctx, `SELECT e.id::text,e.revision_id::text,e.revision_generation,e.actor_user_id::text,e.issuer,e.subject,
        e.purpose,e.completed_at,e.expires_at,e.verification_version
        FROM framework.auth_test_evidence e JOIN framework.auth_config_revisions r ON r.id=e.revision_id
        JOIN framework.auth_config_lifecycle l ON l.revision_id=e.revision_id
        WHERE e.deployment_id=$1 AND e.environment=$2 AND e.id=$3 AND e.revision_id=$4 AND e.revision_generation=$5
        AND e.purpose=$6 AND e.expires_at>clock_timestamp() AND e.completed_at<=clock_timestamp()
        AND l.generation=e.revision_generation AND l.status='approved' AND r.provider='oidc' AND r.issuer_url=e.issuer`,
		r.scope.DeploymentID, r.scope.Environment, id, revision, generation, purpose).
		Scan(&e.ID, &e.RevisionID, &e.RevisionGeneration, &e.ActorUserID, &e.Issuer, &e.Subject, &e.Purpose, &e.CompletedAt, &e.ExpiresAt, &e.VerificationVersion)
	if err != nil {
		return TestEvidence{}, readError(ctx, err)
	}
	return e, nil
}
