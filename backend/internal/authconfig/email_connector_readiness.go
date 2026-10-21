package authconfig

import (
	"context"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/notifications"
	"github.com/jackc/pgx/v5"
)

func (s *EmailConnectorService) writeObservation(ctx context.Context, tx pgx.Tx, c NotificationConnector, actor, operation string, r notifications.Readiness, credential, mailbox string) error {
	if !r.Valid() {
		return ErrInvalid
	}
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO framework.notification_connector_readiness(connector_id,deployment_id,environment,connector_generation,operation_id,status,code,credential_version,mailbox,quota_known,remaining_24_hours,max_per_second,tested_by,tested_at,expires_at)
 VALUES($1,$2,$3,$4,$5,$6,$7,NULLIF($8,'')::uuid,$9,$10,$11,$12,$13,$14,$15)
 ON CONFLICT(connector_id) DO UPDATE SET connector_generation=EXCLUDED.connector_generation,operation_id=EXCLUDED.operation_id,status=EXCLUDED.status,code=EXCLUDED.code,credential_version=EXCLUDED.credential_version,mailbox=EXCLUDED.mailbox,quota_known=EXCLUDED.quota_known,remaining_24_hours=EXCLUDED.remaining_24_hours,max_per_second=EXCLUDED.max_per_second,tested_by=EXCLUDED.tested_by,tested_at=EXCLUDED.tested_at,expires_at=EXCLUDED.expires_at,generation=framework.notification_connector_readiness.generation+1`, c.ID, s.repository.policy.scope.DeploymentID, s.repository.policy.scope.Environment, c.Generation, operation, string(r.Status), r.Code, credential, mailbox, r.QuotaKnown, r.Remaining24Hours, r.MaxPerSecond, actor, now, now.Add(notifications.ReadinessTTL))
	return err
}
func (s *EmailConnectorService) credentialBinding(c NotificationConnector, version string) notifications.CredentialBinding {
	return notifications.CredentialBinding{Deployment: s.repository.policy.scope.DeploymentID, Environment: s.repository.policy.scope.Environment, ConnectorID: c.ID, Version: version, Sender: c.Sender}
}

func (s *EmailConnectorService) Test(ctx context.Context, id string, generation int64, reason string) (EmailConnector, error) {
	if !validID(id) || generation < 1 || !validPolicyReason(reason) {
		return EmailConnector{}, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var c NotificationConnector
	var prior readinessRecord
	var expected InvitationExpectation
	op := operationID()
	err := s.admin(ctx, func(ctx context.Context, tx pgx.Tx, a access.User, b invitationBinding) error {
		var err error
		c, err = s.repository.connector(ctx, tx, id)
		if err != nil {
			return err
		}
		if c.Generation != generation {
			return ErrConflict
		}
		prior, err = s.observation(ctx, tx, id)
		if err != nil {
			return err
		}
		var now time.Time
		if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return err
		}
		if !prior.TestedAt.IsZero() && prior.TestedAt.After(now.Add(-5*time.Second)) {
			return ErrConflict
		}
		expected = InvitationExpectation{PolicyExpectation{b.policy.Generation, b.activationGeneration}, b.revision, b.revisionGeneration}
		if err = s.writeObservation(ctx, tx, c, a.ID, op, notifications.Readiness{Status: notifications.Configured, Code: "not_tested"}, prior.CredentialVersion, prior.Mailbox); err != nil {
			return err
		}
		return notificationAudit(ctx, tx, a.ID, "notification.connector_test_started", id, s.repository.policy.scope, "configured", reason)
	})
	if err != nil {
		return EmailConnector{}, err
	}
	result := notifications.Readiness{Status: notifications.ProviderUnavailable, Code: "gmail_provider_unavailable"}
	if c.Provider == "ses" {
		result = s.ses.Check(ctx, notifications.Probe{Sender: c.Sender, Region: c.Region, PerMinute: c.PerMinute, PerDay: c.PerDay})
	} else {
		gmail, providerErr := s.gmailProvider()
		if providerErr != nil || s.credentials == nil {
			result = notifications.Readiness{Status: notifications.Configured, Code: "gmail_setup_required"}
		} else if prior.CredentialVersion == "" {
			result = notifications.Readiness{Status: notifications.AuthenticationFailed, Code: "gmail_not_authorized"}
		} else {
			var err error
			result, err = s.credentials.Update(ctx, s.credentialBinding(c, prior.CredentialVersion), func(old notifications.GmailCredential) (notifications.GmailCredential, notifications.Readiness) {
				return gmail.Refresh(ctx, old, c.Sender)
			})
			if err != nil {
				result = notifications.Readiness{Status: notifications.AuthenticationFailed, Code: "gmail_authentication_failed"}
			}
		}
	}
	if !result.Valid() {
		result = notifications.Readiness{Status: notifications.ProviderUnavailable, Code: c.Provider + "_provider_unavailable"}
	}
	var response EmailConnector
	err = s.admin(ctx, func(ctx context.Context, tx pgx.Tx, a access.User, _ invitationBinding) error {
		if _, err := s.repository.policy.invitationContext(ctx, tx, &expected); err != nil {
			return err
		}
		current, err := s.repository.connector(ctx, tx, id)
		if err != nil {
			return err
		}
		slot, err := s.observation(ctx, tx, id)
		if err != nil {
			return err
		}
		if current.Generation != generation || slot.Operation != op || slot.CredentialVersion != prior.CredentialVersion {
			return ErrConflict
		}
		if err = s.writeObservation(ctx, tx, c, a.ID, op, result, prior.CredentialVersion, prior.Mailbox); err != nil {
			return err
		}
		if err = notificationAudit(ctx, tx, a.ID, "notification.connector_test_completed", id, s.repository.policy.scope, result.Code, reason); err != nil {
			return err
		}
		response, err = s.dto(ctx, tx, current)
		return err
	})
	return response, err
}
