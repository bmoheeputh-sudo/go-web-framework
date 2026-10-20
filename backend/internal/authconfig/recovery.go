package authconfig

import (
	"context"
	"strings"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/jackc/pgx/v5"
)

type RecoveryReadiness struct {
	RevisionID                  string `json:"revision_id"`
	SourceRevisionID            string `json:"source_revision_id"`
	Status                      Status `json:"status"`
	ConfigurationPreStaged      bool   `json:"configuration_pre_staged"`
	EnrolledAdministratorReady  bool   `json:"enrolled_administrator_ready"`
	FreshIsolatedEvidence       bool   `json:"fresh_isolated_evidence"`
	FreshNormalCallbackEvidence bool   `json:"fresh_normal_callback_evidence"`
	ReadyForPortalActivation    bool   `json:"ready_for_portal_activation"`
	LiveProviderRequired        bool   `json:"live_provider_required"`
	OfflineRecoveryProcedure    string `json:"offline_recovery_procedure"`
}

func recoverySourceTx(ctx context.Context, tx pgx.Tx, id string) (string, error) {
	var source string
	err := tx.QueryRow(ctx, `SELECT COALESCE((SELECT details->>'recovery_revision_id' FROM framework.audit_log
 WHERE action='auth_config.recovery_draft' AND target_id=$1 ORDER BY id DESC LIMIT 1),'')`, id).Scan(&source)
	return source, err
}

func (r *Repository) recoverySource(ctx context.Context, id string) (string, error) {
	if !validID(id) {
		return "", ErrInvalid
	}
	var source string
	err := r.transaction(ctx, func(ctx context.Context, tx pgx.Tx, _ access.User) error {
		if _, err := r.get(ctx, tx, id); err != nil {
			return err
		}
		var err error
		source, err = recoverySourceTx(ctx, tx, id)
		return err
	})
	return source, err
}

// RecoveryReadiness reports durable pre-staging and short-lived verification
// separately. Expired evidence is never promoted into recovery authority.
func (r *Repository) RecoveryReadiness(ctx context.Context, id, callback string) (RecoveryReadiness, error) {
	if !validID(id) || callback == "" {
		return RecoveryReadiness{}, ErrInvalid
	}
	result := RecoveryReadiness{RevisionID: id, LiveProviderRequired: true, OfflineRecoveryProcedure: "auth-recovery-cli"}
	err := r.transaction(ctx, func(ctx context.Context, tx pgx.Tx, actor access.User) error {
		m, err := r.get(ctx, tx, id)
		if err != nil {
			return err
		}
		result.Status = m.Status
		result.SourceRevisionID, err = recoverySourceTx(ctx, tx, id)
		if err != nil {
			return err
		}
		if result.SourceRevisionID == "" {
			return ErrNotFound
		}
		result.ConfigurationPreStaged = m.Provider == auth.OIDC && m.Status == Approved && m.HasSecret && m.RedirectURI == callback
		if err = tx.QueryRow(ctx, `SELECT EXISTS(
 SELECT 1 FROM framework.users u
 WHERE u.issuer=$1 AND u.active AND u.provider='oidc'
 AND EXISTS(SELECT 1 FROM framework.user_roles ur JOIN framework.role_permissions rp ON rp.role=ur.role
            WHERE ur.user_id=u.id AND rp.permission='admin.manage')
 AND EXISTS(SELECT 1 FROM framework.audit_log a WHERE a.action='auth_config.identity_enrolled' AND a.target_id=u.id::text)
)`, m.IssuerURL).Scan(&result.EnrolledAdministratorReady); err != nil {
			return err
		}
		if err = tx.QueryRow(ctx, `SELECT
 EXISTS(SELECT 1 FROM framework.auth_test_evidence e WHERE e.revision_id=$1 AND e.revision_generation=$2
   AND e.actor_user_id=$3 AND e.deployment_id=$4 AND e.environment=$5 AND e.issuer=$6
   AND e.purpose='isolated_connection' AND e.verification_version=1
   AND e.completed_at<=clock_timestamp() AND e.expires_at>clock_timestamp()),
 EXISTS(SELECT 1 FROM framework.auth_test_evidence e WHERE e.revision_id=$1 AND e.revision_generation=$2
   AND e.actor_user_id=$3 AND e.deployment_id=$4 AND e.environment=$5 AND e.issuer=$6
   AND e.purpose='normal_callback' AND e.verification_version=1
   AND e.completed_at<=clock_timestamp() AND e.expires_at>clock_timestamp()),
 EXISTS(SELECT 1 FROM framework.auth_test_evidence i JOIN framework.auth_test_evidence n
   ON n.revision_id=i.revision_id AND n.revision_generation=i.revision_generation AND n.issuer=i.issuer AND n.subject=i.subject
   JOIN framework.users u ON u.issuer=i.issuer AND u.subject=i.subject
   WHERE i.revision_id=$1 AND i.revision_generation=$2 AND i.actor_user_id=$3 AND n.actor_user_id=$3
   AND i.deployment_id=$4 AND n.deployment_id=$4 AND i.environment=$5 AND n.environment=$5 AND i.issuer=$6
   AND i.purpose='isolated_connection' AND n.purpose='normal_callback'
   AND i.verification_version=1 AND n.verification_version=1
   AND i.completed_at<=clock_timestamp() AND n.completed_at<=clock_timestamp()
   AND i.expires_at>clock_timestamp() AND n.expires_at>clock_timestamp()
   AND u.active AND u.provider='oidc'
   AND EXISTS(SELECT 1 FROM framework.user_roles ur JOIN framework.role_permissions rp ON rp.role=ur.role
              WHERE ur.user_id=u.id AND rp.permission='admin.manage')
   AND EXISTS(SELECT 1 FROM framework.audit_log a WHERE a.action='auth_config.identity_enrolled' AND a.target_id=u.id::text)
 )`, id, m.Generation, actor.ID, m.DeploymentID, m.Environment, m.IssuerURL).
			Scan(&result.FreshIsolatedEvidence, &result.FreshNormalCallbackEvidence, &result.ReadyForPortalActivation); err != nil {
			return err
		}
		result.ReadyForPortalActivation = result.ConfigurationPreStaged && result.EnrolledAdministratorReady && result.ReadyForPortalActivation
		return nil
	})
	if err != nil {
		return RecoveryReadiness{}, err
	}
	return result, nil
}

// PrepareRecoveryDraft copies historical immutable settings into a new draft.
// The existing cipher seals against a new revision ID/version with a fresh nonce.
// Approval, both readiness tests and explicit activation remain mandatory.
func (r *Repository) PrepareRecoveryDraft(ctx context.Context, historicalID string, expectedLatestVersion int64) (Metadata, error) {
	return r.prepareRecoveryDraft(ctx, historicalID, expectedLatestVersion, "")
}

// PrepareRecoveryDraftWithReason is used by the protected HTTP control plane.
// It records the administrator's confirmed reason in the same transaction as
// the immutable recovery draft. It never changes the active configuration.
func (r *Repository) PrepareRecoveryDraftWithReason(ctx context.Context, historicalID string, expectedLatestVersion int64, reason string) (Metadata, error) {
	reason = strings.TrimSpace(reason)
	if len(reason) < 8 || len(reason) > 512 || strings.ContainsAny(reason, "\r\n\x00") {
		return Metadata{}, ErrInvalid
	}
	return r.prepareRecoveryDraft(ctx, historicalID, expectedLatestVersion, reason)
}

func (r *Repository) prepareRecoveryDraft(ctx context.Context, historicalID string, expectedLatestVersion int64, reason string) (Metadata, error) {
	historical, err := r.Read(ctx, historicalID)
	if err != nil {
		return Metadata{}, err
	}
	if historical.Status != Superseded {
		return Metadata{}, ErrConflict
	}
	secret, err := r.ReadSecretPrivileged(ctx, historicalID)
	if err != nil {
		return Metadata{}, err
	}
	defer clear(secret.value)
	return r.createDraft(ctx, expectedLatestVersion, historical.Settings, secret, historical.ID, reason)
}
