package authconfig

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/notifications"
	"github.com/jackc/pgx/v5"
	"golang.org/x/oauth2"
)

const EmailConnectorsPath = "/api/admin/notifications/email-connectors"
const GmailCallbackPath = EmailConnectorsPath + "/gmail/callback"

type EmailConnectorOptions struct {
	Origin                                                               string
	GmailClientID, GmailClientSecretFile, SecretDirectory, SecretKeyFile string
}
type EmailConnectorService struct {
	repository  *NotificationRepository
	options     EmailConnectorOptions
	ses         notifications.SESChecker
	gmail       notifications.GmailAuthorization
	credentials notifications.CredentialStore
}

func NewEmailConnectorService(policy *AccessPolicyRepository, options EmailConnectorOptions) (*EmailConnectorService, error) {
	if policy == nil || access.ValidateOrigin(options.Origin, policy.scope.Environment) != nil {
		return nil, ErrInvalid
	}
	s := &EmailConnectorService{repository: &NotificationRepository{policy: policy}, options: options, ses: notifications.NewSES()}
	if options.GmailClientID != "" && options.GmailClientSecretFile != "" && options.SecretDirectory != "" && options.SecretKeyFile != "" {
		s.credentials, _ = notifications.NewFileCredentials(options.SecretDirectory, options.SecretKeyFile)
	}
	return s, nil
}
func (s *EmailConnectorService) gmailProvider() (notifications.GmailAuthorization, error) {
	if s.gmail != nil {
		return s.gmail, nil
	}
	if s.credentials == nil || s.options.GmailClientID == "" {
		return nil, ErrUnavailable
	}
	info, err := os.Lstat(s.options.GmailClientSecretFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 4096 {
		return nil, ErrUnavailable
	}
	f, err := os.Open(s.options.GmailClientSecretFile)
	if err != nil {
		return nil, ErrUnavailable
	}
	secret, err := io.ReadAll(io.LimitReader(f, 4097))
	_ = f.Close()
	if err != nil || len(secret) == 0 || len(secret) > 4096 {
		return nil, ErrUnavailable
	}
	return notifications.NewGmail(s.options.GmailClientID, string(secret), s.options.Origin+GmailCallbackPath), nil
}
func (s *EmailConnectorService) admin(ctx context.Context, fn func(context.Context, pgx.Tx, access.User, invitationBinding) error) error {
	return s.repository.admin(ctx, func(ctx context.Context, tx pgx.Tx, a access.User) error {
		b, err := s.repository.policy.invitationContext(ctx, tx, nil)
		if err != nil {
			return err
		}
		eligible, err := s.repository.administratorEligible(ctx, tx, a.ID, b)
		if err != nil {
			return err
		}
		if !eligible {
			return ErrDenied
		}
		return fn(ctx, tx, a, b)
	})
}

type EmailConnector struct {
	ID               string                  `json:"id"`
	Provider         string                  `json:"provider"`
	Sender           string                  `json:"sender"`
	Region           string                  `json:"region"`
	Enabled          bool                    `json:"enabled"`
	Default          bool                    `json:"default"`
	PerMinute        int                     `json:"per_minute"`
	PerDay           int                     `json:"per_day"`
	Generation       int64                   `json:"generation"`
	FailureCount     int64                   `json:"failure_count"`
	LastError        string                  `json:"last_error"`
	Readiness        notifications.Readiness `json:"readiness"`
	TestedAt         *time.Time              `json:"tested_at,omitempty"`
	ExpiresAt        *time.Time              `json:"expires_at,omitempty"`
	HasAuthorization bool                    `json:"has_authorization"`
}
type readinessRecord struct {
	Result                                notifications.Readiness
	CredentialVersion, Mailbox, Operation string
	ConnectorGeneration                   int64
	TestedAt, ExpiresAt                   time.Time
}

func (s *EmailConnectorService) observation(ctx context.Context, tx pgx.Tx, id string) (readinessRecord, error) {
	var r readinessRecord
	err := tx.QueryRow(ctx, `SELECT status,code,quota_known,remaining_24_hours,max_per_second,COALESCE(credential_version::text,''),mailbox,operation_id::text,connector_generation,tested_at,expires_at FROM framework.notification_connector_readiness WHERE deployment_id=$1 AND environment=$2 AND connector_id=$3`, s.repository.policy.scope.DeploymentID, s.repository.policy.scope.Environment, id).Scan(&r.Result.Status, &r.Result.Code, &r.Result.QuotaKnown, &r.Result.Remaining24Hours, &r.Result.MaxPerSecond, &r.CredentialVersion, &r.Mailbox, &r.Operation, &r.ConnectorGeneration, &r.TestedAt, &r.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return readinessRecord{Result: notifications.Readiness{Status: notifications.Configured, Code: "not_tested"}}, nil
	}
	return r, err
}
func (s *EmailConnectorService) dto(ctx context.Context, tx pgx.Tx, c NotificationConnector) (EmailConnector, error) {
	r, err := s.observation(ctx, tx, c.ID)
	if err != nil {
		return EmailConnector{}, err
	}
	result := EmailConnector{ID: c.ID, Provider: c.Provider, Sender: c.Sender, Region: c.Region, Enabled: c.Enabled, Default: c.Default, PerMinute: c.PerMinute, PerDay: c.PerDay, Generation: c.Generation, FailureCount: c.FailureCount, LastError: c.LastErrorCode, Readiness: r.Result, HasAuthorization: r.CredentialVersion != ""}
	if r.Result.Status != notifications.Ready && r.Result.Status != notifications.Configured {
		result.LastError = r.Result.Code
	}
	var now time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return EmailConnector{}, err
	}
	if !r.TestedAt.IsZero() {
		result.TestedAt = &r.TestedAt
		result.ExpiresAt = &r.ExpiresAt
	}
	if r.ConnectorGeneration != c.Generation || !r.ExpiresAt.After(now) {
		result.Readiness = notifications.Readiness{Status: notifications.Configured, Code: "not_tested"}
	}
	return result, nil
}
func (s *EmailConnectorService) List(ctx context.Context, offset, limit int) ([]EmailConnector, int, error) {
	if offset < 0 || offset > 100000 || limit < 1 || limit > 100 {
		return nil, 0, ErrInvalid
	}
	items := []EmailConnector{}
	total := 0
	err := s.admin(ctx, func(ctx context.Context, tx pgx.Tx, _ access.User, _ invitationBinding) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM framework.notification_connectors WHERE deployment_id=$1 AND environment=$2`, s.repository.policy.scope.DeploymentID, s.repository.policy.scope.Environment).Scan(&total); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT id::text FROM framework.notification_connectors WHERE deployment_id=$1 AND environment=$2 ORDER BY created_at,id OFFSET $3 LIMIT $4`, s.repository.policy.scope.DeploymentID, s.repository.policy.scope.Environment, offset, limit)
		if err != nil {
			return err
		}
		ids := []string{}
		for rows.Next() {
			var id string
			if err = rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		rows.Close()
		if rows.Err() != nil {
			return rows.Err()
		}
		for _, id := range ids {
			c, err := s.repository.connector(ctx, tx, id)
			if err != nil {
				return err
			}
			item, err := s.dto(ctx, tx, c)
			if err != nil {
				return err
			}
			items = append(items, item)
		}
		return nil
	})
	return items, total, err
}
func (s *EmailConnectorService) Read(ctx context.Context, id string) (EmailConnector, error) {
	if !validID(id) {
		return EmailConnector{}, ErrInvalid
	}
	var result EmailConnector
	err := s.admin(ctx, func(ctx context.Context, tx pgx.Tx, _ access.User, _ invitationBinding) error {
		c, err := s.repository.connector(ctx, tx, id)
		if err != nil {
			return err
		}
		result, err = s.dto(ctx, tx, c)
		return err
	})
	return result, err
}

type EmailConnectorCreate struct {
	ID        string `json:"id"`
	Provider  string `json:"provider"`
	Sender    string `json:"sender"`
	Region    string `json:"region"`
	PerMinute int    `json:"per_minute"`
	PerDay    int    `json:"per_day"`
	Reason    string `json:"reason"`
}

func (s *EmailConnectorService) Create(ctx context.Context, input EmailConnectorCreate) (EmailConnector, error) {
	// Current-policy eligibility is checked in the same transaction as creation.
	key, err := invitationEmailKey(input.Sender)
	if err != nil || key != input.Sender || !validID(input.ID) || !validPolicyReason(input.Reason) || input.PerMinute < 1 || input.PerMinute > 60 || input.PerDay < 1 || input.PerDay > 100000 || !((input.Provider == "gmail" && input.Region == "") || (input.Provider == "ses" && sesRegion.MatchString(input.Region) && len(input.Region) <= 32)) {
		return EmailConnector{}, ErrInvalid
	}
	var result EmailConnector
	err = s.admin(ctx, func(ctx context.Context, tx pgx.Tx, a access.User, _ invitationBinding) error {
		ref := ""
		if input.Provider == "gmail" {
			ref = "notifications/gmail/" + input.ID
		}
		_, err := tx.Exec(ctx, `INSERT INTO framework.notification_connectors(id,deployment_id,environment,provider,sender_email,sender_approved,credential_reference,region,enabled,is_default,per_minute,per_day,created_by,updated_by,reason) VALUES($1,$2,$3,$4,$5,true,$6,$7,false,false,$8,$9,$10,$10,$11)`, input.ID, s.repository.policy.scope.DeploymentID, s.repository.policy.scope.Environment, input.Provider, input.Sender, ref, input.Region, input.PerMinute, input.PerDay, a.ID, input.Reason)
		if err != nil {
			return err
		}
		if err = notificationAudit(ctx, tx, a.ID, "notification.connector_created", input.ID, s.repository.policy.scope, input.Provider, input.Reason); err != nil {
			return err
		}
		c, err := s.repository.connector(ctx, tx, input.ID)
		if err != nil {
			return err
		}
		result, err = s.dto(ctx, tx, c)
		return err
	})
	return result, err
}

type EmailConnectorUpdate struct {
	ExpectedGeneration int64  `json:"expected_generation"`
	Enabled            bool   `json:"enabled"`
	Default            bool   `json:"default"`
	PerMinute          int    `json:"per_minute"`
	PerDay             int    `json:"per_day"`
	Reason             string `json:"reason"`
}

func (s *EmailConnectorService) Configure(ctx context.Context, id string, input EmailConnectorUpdate) (EmailConnector, error) {
	if !validID(id) || input.ExpectedGeneration < 1 || !validPolicyReason(input.Reason) || input.PerMinute < 1 || input.PerMinute > 60 || input.PerDay < 1 || input.PerDay > 100000 || (input.Default && !input.Enabled) {
		return EmailConnector{}, ErrInvalid
	}
	var result EmailConnector
	err := s.admin(ctx, func(ctx context.Context, tx pgx.Tx, a access.User, _ invitationBinding) error {
		c, err := s.repository.connector(ctx, tx, id)
		if err != nil {
			return err
		}
		if c.Generation != input.ExpectedGeneration {
			return ErrConflict
		}
		observed, err := s.dto(ctx, tx, c)
		if err != nil {
			return err
		}
		withinQuota := !observed.Readiness.QuotaKnown || (float64(input.PerDay) <= observed.Readiness.Remaining24Hours && float64(input.PerMinute)/60 <= observed.Readiness.MaxPerSecond)
		if input.Enabled && (observed.Readiness.Status != notifications.Ready || !withinQuota) {
			return ErrConflict
		}
		if input.Default {
			if _, err = tx.Exec(ctx, `UPDATE framework.notification_connectors SET is_default=false,generation=generation+1,updated_by=$4,reason=$5 WHERE deployment_id=$1 AND environment=$2 AND id<>$3 AND is_default`, s.repository.policy.scope.DeploymentID, s.repository.policy.scope.Environment, id, a.ID, input.Reason); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `UPDATE framework.notification_connectors SET enabled=$4,is_default=$5,per_minute=$6,per_day=$7,generation=generation+1,updated_by=$8,reason=$9 WHERE deployment_id=$1 AND environment=$2 AND id=$3`, s.repository.policy.scope.DeploymentID, s.repository.policy.scope.Environment, id, input.Enabled, input.Default, input.PerMinute, input.PerDay, a.ID, input.Reason)
		if err != nil {
			return err
		}
		// A fresh successful observation remains valid only within its measured quota.
		if observed.Readiness.Status == notifications.Ready && withinQuota {
			if _, err = tx.Exec(ctx, `UPDATE framework.notification_connector_readiness SET connector_generation=connector_generation+1,generation=generation+1 WHERE connector_id=$1 AND connector_generation=$2`, id, c.Generation); err != nil {
				return err
			}
		}
		if err = access.RecordAudit(ctx, tx, a.ID, "notification.connector_configured", id, struct {
			Reason            string
			Enabled, Default  bool
			PerMinute, PerDay int
		}{input.Reason, input.Enabled, input.Default, input.PerMinute, input.PerDay}); err != nil {
			return err
		}
		c, err = s.repository.connector(ctx, tx, id)
		if err != nil {
			return err
		}
		result, err = s.dto(ctx, tx, c)
		return err
	})
	return result, err
}
func operationID() string {
	b := sha256.Sum256([]byte(oauth2.GenerateVerifier()))
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmtUUID(b[:16])
}
func fmtUUID(b []byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}
