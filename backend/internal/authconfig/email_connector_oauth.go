package authconfig

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"strings"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/notifications"
	"github.com/jackc/pgx/v5"
	"golang.org/x/oauth2"
)

type GmailAuthorizationInput struct {
	ExpectedGeneration    int64  `json:"expected_generation"`
	Mailbox               string `json:"mailbox"`
	Reason                string `json:"reason"`
	ConfirmSenderSettings bool   `json:"confirm_sender_settings"`
}
type gmailStart struct {
	URL, FlowID, Browser string
	ExpiresAt            time.Time
}

func (s *EmailConnectorService) BeginGmail(ctx context.Context, id string, input GmailAuthorizationInput) (gmailStart, error) {
	key, err := invitationEmailKey(input.Mailbox)
	if err != nil || key != input.Mailbox || !validID(id) || input.ExpectedGeneration < 1 || !validPolicyReason(input.Reason) || !input.ConfirmSenderSettings {
		return gmailStart{}, ErrInvalid
	}
	// Check current administrator eligibility before resolving notification secrets.
	// The write transaction below rechecks it after external credential access.
	if err = s.admin(ctx, func(ctx context.Context, tx pgx.Tx, _ access.User, _ invitationBinding) error {
		c, err := s.repository.connector(ctx, tx, id)
		if err != nil {
			return err
		}
		if c.Provider != "gmail" || c.Generation != input.ExpectedGeneration {
			return ErrConflict
		}
		return nil
	}); err != nil {
		return gmailStart{}, err
	}
	gmail, err := s.gmailProvider()
	if err != nil || s.credentials == nil {
		return gmailStart{}, ErrUnavailable
	}
	flow := operationID()
	state := flow + "." + oauth2.GenerateVerifier()
	browser := oauth2.GenerateVerifier()
	stateHash, browserHash := sha256.Sum256([]byte(state)), sha256.Sum256([]byte(browser))
	clientHash := sha256.Sum256([]byte(s.options.GmailClientID))
	verifier, err := s.credentials.Proof(ctx, s.repository.policy.scope.DeploymentID+"|"+s.repository.policy.scope.Environment+"|"+id+"|"+state)
	if err != nil {
		return gmailStart{}, ErrUnavailable
	}
	var expires time.Time
	err = s.admin(ctx, func(ctx context.Context, tx pgx.Tx, a access.User, b invitationBinding) error {
		c, err := s.repository.connector(ctx, tx, id)
		if err != nil {
			return err
		}
		if c.Provider != "gmail" || c.Generation != input.ExpectedGeneration {
			return ErrConflict
		}
		var count int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM framework.notification_connector_oauth_flows WHERE deployment_id=$1 AND environment=$2 AND actor_user_id=$3 AND status='pending' AND expires_at>clock_timestamp()`, s.repository.policy.scope.DeploymentID, s.repository.policy.scope.Environment, a.ID).Scan(&count); err != nil {
			return err
		}
		if count >= 5 {
			return ErrConflict
		}
		var now time.Time
		if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return err
		}
		expires = now.Add(5 * time.Minute)
		_, err = tx.Exec(ctx, `INSERT INTO framework.notification_connector_oauth_flows(id,deployment_id,environment,connector_id,actor_user_id,connector_generation,policy_generation,activation_generation,revision_id,revision_generation,client_id_digest,state_hash,browser_hash,mailbox,reason,expires_at)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`, flow, s.repository.policy.scope.DeploymentID, s.repository.policy.scope.Environment, id, a.ID, c.Generation, b.policy.Generation, b.activationGeneration, b.revision, b.revisionGeneration, clientHash[:], stateHash[:], browserHash[:], input.Mailbox, input.Reason, expires)
		if err != nil {
			return err
		}
		return notificationAudit(ctx, tx, a.ID, "notification.gmail_authorization_started", id, s.repository.policy.scope, "configured", input.Reason)
	})
	if err != nil {
		return gmailStart{}, err
	}
	return gmailStart{gmail.AuthorizationURL(state, verifier, input.Mailbox), flow, browser, expires}, nil
}
func (s *EmailConnectorService) CompleteGmail(ctx context.Context, state, browser, code, providerError string) error {
	if len(state) > 128 || len(browser) > 128 || len(code) > 4096 || len(providerError) > 128 {
		return ErrInvalid
	}
	parts := strings.Split(state, ".")
	if len(parts) != 2 || !validID(parts[0]) || len(parts[1]) != 43 || len(browser) != 43 {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	flow := parts[0]
	stateHash, browserHash := sha256.Sum256([]byte(state)), sha256.Sum256([]byte(browser))
	clientHash := sha256.Sum256([]byte(s.options.GmailClientID))
	var c NotificationConnector
	var expected InvitationExpectation
	var mailbox, reason string
	err := s.admin(ctx, func(ctx context.Context, tx pgx.Tx, a access.User, _ invitationBinding) error {
		var actor, id, status string
		var generation int64
		var storedState, storedBrowser, storedClient []byte
		var expires time.Time
		err := tx.QueryRow(ctx, `SELECT connector_id::text,actor_user_id::text,connector_generation,policy_generation,activation_generation,revision_id::text,revision_generation,state_hash,browser_hash,client_id_digest,mailbox,status,expires_at,reason FROM framework.notification_connector_oauth_flows WHERE deployment_id=$1 AND environment=$2 AND id=$3`, s.repository.policy.scope.DeploymentID, s.repository.policy.scope.Environment, flow).Scan(&id, &actor, &generation, &expected.Generation, &expected.ActivationGeneration, &expected.RevisionID, &expected.RevisionGeneration, &storedState, &storedBrowser, &storedClient, &mailbox, &status, &expires, &reason)
		if err != nil {
			return err
		}
		var now time.Time
		if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return err
		}
		if status != "pending" || actor != a.ID || !expires.After(now) || !hmac.Equal(storedState, stateHash[:]) || !hmac.Equal(storedBrowser, browserHash[:]) || !hmac.Equal(storedClient, clientHash[:]) {
			return ErrDenied
		}
		if _, err = s.repository.policy.invitationContext(ctx, tx, &expected); err != nil {
			return err
		}
		c, err = s.repository.connector(ctx, tx, id)
		if err != nil {
			return err
		}
		if c.Provider != "gmail" || c.Generation != generation {
			return ErrConflict
		}
		if _, err = tx.Exec(ctx, `UPDATE framework.notification_connector_oauth_flows SET status='consumed',generation=generation+1 WHERE id=$1`, flow); err != nil {
			return err
		}
		return notificationAudit(ctx, tx, a.ID, "notification.gmail_authorization_consumed", c.ID, s.repository.policy.scope, "configured")
	})
	if err != nil {
		return err
	}
	gmail, err := s.gmailProvider()
	if err != nil || s.credentials == nil {
		return ErrUnavailable
	}
	result := notifications.Readiness{Status: notifications.AuthenticationFailed, Code: "gmail_authentication_failed"}
	var credential notifications.GmailCredential
	if providerError == "" && code != "" {
		verifier, err := s.credentials.Proof(ctx, s.repository.policy.scope.DeploymentID+"|"+s.repository.policy.scope.Environment+"|"+c.ID+"|"+state)
		if err != nil {
			return ErrUnavailable
		}
		credential, result = gmail.Exchange(ctx, code, verifier, mailbox, c.Sender)
	}
	if !result.Valid() {
		result = notifications.Readiness{Status: notifications.ProviderUnavailable, Code: "gmail_provider_unavailable"}
	}
	version := ""
	if result.Status == notifications.Ready {
		if err = s.credentials.Save(ctx, s.credentialBinding(c, flow), credential); err != nil {
			return ErrUnavailable
		}
		version = flow
	}
	return s.admin(ctx, func(ctx context.Context, tx pgx.Tx, a access.User, _ invitationBinding) error {
		if _, err := s.repository.policy.invitationContext(ctx, tx, &expected); err != nil {
			return err
		}
		current, err := s.repository.connector(ctx, tx, c.ID)
		if err != nil {
			return err
		}
		if current.Generation != c.Generation {
			return ErrConflict
		}
		// Authorization versions fence other in-flight authorizations/configuration.
		if _, err = tx.Exec(ctx, `UPDATE framework.notification_connectors SET generation=generation+1,updated_by=$4,reason=$5 WHERE deployment_id=$1 AND environment=$2 AND id=$3`, s.repository.policy.scope.DeploymentID, s.repository.policy.scope.Environment, c.ID, a.ID, reason); err != nil {
			return err
		}
		current.Generation++
		if err = s.writeObservation(ctx, tx, current, a.ID, flow, result, version, mailbox); err != nil {
			return err
		}
		return notificationAudit(ctx, tx, a.ID, "notification.gmail_authorization_completed", c.ID, s.repository.policy.scope, result.Code, reason)
	})
}
