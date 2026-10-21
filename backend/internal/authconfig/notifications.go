package authconfig

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/notifications"
	"github.com/jackc/pgx/v5"
)

const NotificationMaxJobs = 100

// CommunicationPolicy is deployment-owned configuration, never request input.
// An explicit domain allowlist is required even when OIDC allows all domains.
type CommunicationPolicy struct {
	Origin         string
	AllowedDomains []string
	Cooldown       time.Duration
}
type NotificationRepository struct {
	policy              *AccessPolicyRepository
	communication       CommunicationPolicy
	template            notifications.Template
	communicationDigest [32]byte
}

func NewNotificationRepository(policy *AccessPolicyRepository, communication CommunicationPolicy) (*NotificationRepository, error) {
	if policy == nil || len(communication.AllowedDomains) == 0 {
		return nil, ErrInvalid
	}
	normal, err := normalizePolicy(AccessPolicySettings{Mode: "allow_all", DefaultRole: "Viewer", AllowedEmailDomains: communication.AllowedDomains})
	if err != nil {
		return nil, err
	}
	if communication.Cooldown == 0 {
		communication.Cooldown = 72 * time.Hour
	}
	if communication.Cooldown < 72*time.Hour || communication.Cooldown > 30*24*time.Hour {
		return nil, ErrInvalid
	}
	t, err := notifications.NewTemplate(communication.Origin)
	if err != nil {
		return nil, ErrInvalid
	}
	communication.AllowedDomains = slices.Clone(normal.AllowedEmailDomains)
	encoded, _ := json.Marshal(communication)
	return &NotificationRepository{policy: policy, communication: communication, template: t, communicationDigest: sha256.Sum256(encoded)}, nil
}

func (r *NotificationRepository) isolated(ctx context.Context, tx pgx.Tx) error {
	var ok bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM framework.oidc_access_policies WHERE deployment_id=$1 AND environment=$2)
 AND NOT EXISTS(SELECT 1 FROM framework.oidc_access_policies WHERE deployment_id<>$1 OR environment<>$2)
 AND NOT EXISTS(SELECT 1 FROM framework.auth_activation_heads WHERE deployment_id<>$1 OR environment<>$2)`, r.policy.scope.DeploymentID, r.policy.scope.Environment).Scan(&ok)
	if err != nil {
		return err
	}
	if !ok {
		return ErrConflict
	}
	return nil
}
func (r *NotificationRepository) admin(ctx context.Context, fn func(context.Context, pgx.Tx, access.User) error) error {
	if err := requireImportOIDC(ctx); err != nil {
		return err
	}
	return adminTransaction(ctx, r.policy.store, func(ctx context.Context, tx pgx.Tx, actor access.User) error {
		if err := r.isolated(ctx, tx); err != nil {
			return err
		}
		b, err := r.policy.invitationContext(ctx, tx, nil)
		if err != nil {
			return err
		}
		allowed, err := r.administratorEligible(ctx, tx, actor.ID, b)
		if err != nil {
			return err
		}
		if !allowed {
			return ErrDenied
		}
		return fn(ctx, tx, actor)
	})
}
func (r *NotificationRepository) worker(ctx context.Context, fn func(context.Context, pgx.Tx) error) error {
	err := r.policy.store.NotificationWorkerTransaction(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := r.isolated(ctx, tx); err != nil {
			return err
		}
		return fn(ctx, tx)
	})
	return repositoryError(ctx, err)
}

type NotificationTarget struct {
	InvitationID string
	UserID       string
}

func (t NotificationTarget) key() string {
	if t.InvitationID != "" {
		return "invitation:" + t.InvitationID
	}
	return "user:" + t.UserID
}
func (t NotificationTarget) valid() bool {
	return (validID(t.InvitationID) && t.UserID == "") || (validID(t.UserID) && t.InvitationID == "")
}

type NotificationInput struct {
	ID, IdempotencyKey, Type, TemplateVersion, Locale, ConnectorID string
	ConnectorGeneration                                            int64
	Expected                                                       InvitationExpectation
	Targets                                                        []NotificationTarget
	DueAt                                                          time.Time
	Reason                                                         string
	Confirm                                                        bool
	// Omitted for legacy internal requests, preserving their persisted digest.
	PreviewBinding string `json:"preview_binding,omitempty"`
}
type NotificationRequest struct {
	ID, ActorID, Type, TemplateVersion, Locale, ConnectorID, Sender, Outcome string
	Scope
	JobCount  int
	CreatedAt time.Time
}
type NotificationJob struct {
	ID, RequestID, ConnectorID, Sender, Type, TemplateVersion string
	Scope
	NotificationTarget
	Recipient, RecipientKey, Provenance, DisplayName, Status, Disposition string
	Generation                                                            int64
	DueAt                                                                 time.Time
	LeaseOwner                                                            string
	LeaseExpiresAt                                                        *time.Time
	AttemptCount                                                          int
}
type NotificationAttempt struct {
	JobID, Adapter, ExecutorID, Outcome, ProviderMessageID, ErrorCode string
	Number                                                            int
	StartedAt                                                         time.Time
	CompletedAt                                                       *time.Time
}

func notificationAudit(ctx context.Context, tx pgx.Tx, actor, action, id string, scope Scope, code string, reason ...string) error {
	// Only fixed identifiers/codes. Never recipient addresses, bodies, secret
	// references, raw provider errors, or plaintext idempotency keys.
	auditReason := ""
	if len(reason) > 0 {
		auditReason = reason[0]
	}
	executor := "administrator_repository"
	if strings.HasPrefix(action, "notification.dispatch_") || action == "notification.delivery_recorded" || action == "notification.lease_resolved" || (action == "notification.cancelled" && code != "administrator_cancelled") {
		executor = "notification_worker"
	}
	if access.RecordAudit(ctx, tx, actor, action, id, struct {
		Scope
		Code     string `json:"code"`
		Executor string `json:"executor"`
		Reason   string `json:"reason,omitempty"`
	}{scope, code, executor, auditReason}) != nil {
		return ErrAudit
	}
	return nil
}

const requestColumns = `id::text,actor_user_id::text,notification_type,template_version,locale,connector_id::text,sender_email,outcome,job_count,created_at`

func (r *NotificationRepository) request(ctx context.Context, tx pgx.Tx, id string) (NotificationRequest, error) {
	n := NotificationRequest{Scope: r.policy.scope}
	err := tx.QueryRow(ctx, `SELECT `+requestColumns+` FROM framework.notification_requests WHERE deployment_id=$1 AND environment=$2 AND id=$3`, n.DeploymentID, n.Environment, id).Scan(&n.ID, &n.ActorID, &n.Type, &n.TemplateVersion, &n.Locale, &n.ConnectorID, &n.Sender, &n.Outcome, &n.JobCount, &n.CreatedAt)
	return n, err
}
func (r *NotificationRepository) ReadRequest(ctx context.Context, id string) (NotificationRequest, error) {
	if !validID(id) {
		return NotificationRequest{}, ErrInvalid
	}
	var n NotificationRequest
	err := r.admin(ctx, func(ctx context.Context, tx pgx.Tx, _ access.User) error {
		var err error
		n, err = r.request(ctx, tx, id)
		return err
	})
	return n, err
}

func (r *NotificationRepository) Enqueue(ctx context.Context, input NotificationInput) (NotificationRequest, error) {
	return r.enqueue(ctx, input, nil)
}

// The management preflight runs after idempotency inspection, inside the same
// security transaction as eligibility, job creation and auditing.
func (r *NotificationRepository) enqueue(ctx context.Context, input NotificationInput, preflight func(context.Context, pgx.Tx, access.User) error) (NotificationRequest, error) {
	if !validID(input.ID) || !validID(input.IdempotencyKey) || !input.Confirm || !validPolicyReason(input.Reason) || !input.Expected.valid() || input.ConnectorGeneration < 1 || (input.ConnectorID != "" && !validID(input.ConnectorID)) || len(input.Targets) < 1 || len(input.Targets) > NotificationMaxJobs || (input.Type != "invitation" && input.Type != "reminder") || input.TemplateVersion != notifications.TemplateVersion || !notifications.Locale(input.Locale) {
		return NotificationRequest{}, ErrInvalid
	}
	input.Targets = slices.Clone(input.Targets)
	slices.SortFunc(input.Targets, func(a, b NotificationTarget) int { return strings.Compare(a.key(), b.key()) })
	for i, t := range input.Targets {
		if !t.valid() || (i > 0 && t == input.Targets[i-1]) {
			return NotificationRequest{}, ErrInvalid
		}
	}
	keyDigest := sha256.Sum256([]byte(input.IdempotencyKey))
	// Canonical ordering; the plaintext key never reaches PostgreSQL or audit.
	input.IdempotencyKey = ""
	encoded, err := json.Marshal(input)
	if err != nil {
		return NotificationRequest{}, ErrInvalid
	}
	payload := sha256.Sum256(encoded)
	var n NotificationRequest
	err = r.admin(ctx, func(ctx context.Context, tx pgx.Tx, actor access.User) error {
		var prior string
		var digest []byte
		err := tx.QueryRow(ctx, `SELECT id::text,payload_digest FROM framework.notification_requests WHERE deployment_id=$1 AND environment=$2 AND actor_user_id=$3 AND idempotency_digest=$4`, r.policy.scope.DeploymentID, r.policy.scope.Environment, actor.ID, keyDigest[:]).Scan(&prior, &digest)
		if err == nil {
			if !slices.Equal(digest, payload[:]) {
				return ErrConflict
			}
			n, err = r.request(ctx, tx, prior)
			return err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if preflight != nil {
			if err = preflight(ctx, tx, actor); err != nil {
				return err
			}
		}
		b, err := r.policy.invitationContext(ctx, tx, &input.Expected)
		if err != nil {
			return err
		}
		c, err := r.connector(ctx, tx, input.ConnectorID)
		if err != nil {
			return err
		}
		if !c.Enabled || c.Generation != input.ConnectorGeneration {
			return ErrConflict
		}
		var now time.Time
		if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return err
		}
		due := input.DueAt
		if due.IsZero() {
			due = now
		}
		if due.Before(now.Add(-time.Minute)) || due.After(now.Add(30*24*time.Hour)) {
			return ErrInvalid
		}
		jobs := make([]NotificationJob, 0, len(input.Targets))
		recipients := map[string]bool{}
		for _, t := range input.Targets {
			j := NotificationJob{Scope: r.policy.scope, NotificationTarget: t, Type: input.Type}
			code, err := r.eligible(ctx, tx, b, &j, false)
			if err != nil {
				return err
			}
			if code != "" {
				return ErrConflict
			}
			if _, err := r.template.Render(input.Type, input.TemplateVersion, input.Locale, c.Sender, j.Recipient, j.DisplayName, "vgca."+input.ID); err != nil {
				return ErrInvalid
			}
			family := strings.ToLower(j.RecipientKey)
			if recipients[family] {
				return ErrConflict
			}
			recipients[family] = true
			jobs = append(jobs, j)
		}
		_, err = tx.Exec(ctx, `INSERT INTO framework.notification_requests(id,deployment_id,environment,actor_user_id,notification_type,template_version,locale,connector_id,sender_email,idempotency_digest,payload_digest,policy_generation,revision_id,revision_generation,activation_generation,confirmed,outcome,job_count,reason,communication_digest)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,true,'enqueued',$16,$17,$18)`, input.ID, r.policy.scope.DeploymentID, r.policy.scope.Environment, actor.ID, input.Type, input.TemplateVersion, input.Locale, c.ID, c.Sender, keyDigest[:], payload[:], b.policy.Generation, b.revision, b.revisionGeneration, b.activationGeneration, len(jobs), input.Reason, r.communicationDigest[:])
		if err != nil {
			return err
		}
		for _, j := range jobs {
			_, err = tx.Exec(ctx, `INSERT INTO framework.notification_jobs(request_id,deployment_id,environment,connector_id,sender_email,notification_type,template_version,invitation_id,user_id,recipient_email,recipient_key,provenance,display_name,due_at,updated_by)
 VALUES($1,$2,$3,$4,$5,$6,$7,NULLIF($8,'')::uuid,NULLIF($9,'')::uuid,$10,$11,$12,$13,$14,$15)`, input.ID, j.DeploymentID, j.Environment, c.ID, c.Sender, input.Type, input.TemplateVersion, j.InvitationID, j.UserID, j.Recipient, j.RecipientKey, j.Provenance, j.DisplayName, due, actor.ID)
			if err != nil {
				return err
			}
		}
		if err = notificationAudit(ctx, tx, actor.ID, "notification.enqueued", input.ID, r.policy.scope, "enqueued", input.Reason); err != nil {
			return err
		}
		n, err = r.request(ctx, tx, input.ID)
		return err
	})
	if err != nil {
		return NotificationRequest{}, err
	}
	return n, nil
}

const jobColumns = `id::text,request_id::text,connector_id::text,sender_email,notification_type,template_version,COALESCE(invitation_id::text,''),COALESCE(user_id::text,''),recipient_email,recipient_key,provenance,display_name,status,disposition_code,generation,due_at,COALESCE(lease_owner::text,''),lease_expires_at,attempt_count`

func scanNotificationJob(row pgx.Row, scope Scope) (NotificationJob, error) {
	j := NotificationJob{Scope: scope}
	err := row.Scan(&j.ID, &j.RequestID, &j.ConnectorID, &j.Sender, &j.Type, &j.TemplateVersion, &j.InvitationID, &j.UserID, &j.Recipient, &j.RecipientKey, &j.Provenance, &j.DisplayName, &j.Status, &j.Disposition, &j.Generation, &j.DueAt, &j.LeaseOwner, &j.LeaseExpiresAt, &j.AttemptCount)
	return j, err
}
func (r *NotificationRepository) job(ctx context.Context, tx pgx.Tx, id string) (NotificationJob, error) {
	return scanNotificationJob(tx.QueryRow(ctx, `SELECT `+jobColumns+` FROM framework.notification_jobs WHERE deployment_id=$1 AND environment=$2 AND id=$3`, r.policy.scope.DeploymentID, r.policy.scope.Environment, id), r.policy.scope)
}
func (r *NotificationRepository) ReadJob(ctx context.Context, id string) (NotificationJob, error) {
	if !validID(id) {
		return NotificationJob{}, ErrInvalid
	}
	var j NotificationJob
	err := r.admin(ctx, func(ctx context.Context, tx pgx.Tx, _ access.User) error {
		var err error
		j, err = r.job(ctx, tx, id)
		return err
	})
	return j, err
}
func (r *NotificationRepository) ListJobs(ctx context.Context, requestID string, offset, limit int) ([]NotificationJob, error) {
	if !validID(requestID) || offset < 0 || offset > 100000 || limit < 1 || limit > 100 {
		return nil, ErrInvalid
	}
	jobs := []NotificationJob{}
	err := r.admin(ctx, func(ctx context.Context, tx pgx.Tx, _ access.User) error {
		rows, err := tx.Query(ctx, `SELECT `+jobColumns+` FROM framework.notification_jobs WHERE deployment_id=$1 AND environment=$2 AND request_id=$3 ORDER BY created_at,id OFFSET $4 LIMIT $5`, r.policy.scope.DeploymentID, r.policy.scope.Environment, requestID, offset, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			j, err := scanNotificationJob(rows, r.policy.scope)
			if err != nil {
				return err
			}
			jobs = append(jobs, j)
		}
		return rows.Err()
	})
	return jobs, err
}

type NotificationConnectorInput struct {
	ID, Provider, Sender, Region, CredentialReference, Reason string
	SenderApproved, Enabled, Default                          bool
	PerMinute, PerDay                                         int
}
type NotificationConnector struct {
	ID, Provider, Sender, Region, CredentialReference, LastErrorCode string
	Status, CredentialMode, OAuthScope                               string
	Enabled, Default                                                 bool
	PerMinute, PerDay                                                int
	Generation, FailureCount                                         int64
	LastAcceptedAt                                                   *time.Time
}

var sesRegion = regexp.MustCompile(`^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$`)
var mailCredentialReference = regexp.MustCompile(`^notifications/[a-zA-Z0-9/_-]{1,100}$`)

func (r *NotificationRepository) CreateConnector(ctx context.Context, input NotificationConnectorInput) (NotificationConnector, error) {
	key, err := invitationEmailKey(input.Sender)
	if err != nil || key != input.Sender || !validID(input.ID) || !input.SenderApproved || !validPolicyReason(input.Reason) || input.PerMinute < 1 || input.PerMinute > 60 || input.PerDay < 1 || input.PerDay > 100000 || (input.Default && !input.Enabled) {
		return NotificationConnector{}, ErrInvalid
	}
	if !((input.Provider == "gmail" && mailCredentialReference.MatchString(input.CredentialReference) && input.Region == "") || (input.Provider == "ses" && input.CredentialReference == "" && len(input.Region) <= 32 && sesRegion.MatchString(input.Region))) {
		return NotificationConnector{}, ErrInvalid
	}
	var c NotificationConnector
	err = r.admin(ctx, func(ctx context.Context, tx pgx.Tx, actor access.User) error {
		_, err := tx.Exec(ctx, `INSERT INTO framework.notification_connectors(id,deployment_id,environment,provider,sender_email,sender_approved,credential_reference,region,enabled,is_default,per_minute,per_day,created_by,updated_by,reason)
 VALUES($1,$2,$3,$4,$5,true,$6,$7,$8,$9,$10,$11,$12,$12,$13)`, input.ID, r.policy.scope.DeploymentID, r.policy.scope.Environment, input.Provider, input.Sender, input.CredentialReference, input.Region, input.Enabled, input.Default, input.PerMinute, input.PerDay, actor.ID, input.Reason)
		if err != nil {
			return err
		}
		if err = notificationAudit(ctx, tx, actor.ID, "notification.connector_created", input.ID, r.policy.scope, input.Provider, input.Reason); err != nil {
			return err
		}
		c, err = r.connector(ctx, tx, input.ID)
		return err
	})
	return c, err
}
func (r *NotificationRepository) connector(ctx context.Context, tx pgx.Tx, id string) (NotificationConnector, error) {
	var c NotificationConnector
	err := tx.QueryRow(ctx, `SELECT id::text,provider,sender_email,region,credential_reference,enabled,is_default,per_minute,per_day,generation,failure_count,last_error_code,last_accepted_at FROM framework.notification_connectors
 WHERE deployment_id=$1 AND environment=$2 AND (($3='' AND is_default) OR id=NULLIF($3,'')::uuid)`, r.policy.scope.DeploymentID, r.policy.scope.Environment, id).Scan(&c.ID, &c.Provider, &c.Sender, &c.Region, &c.CredentialReference, &c.Enabled, &c.Default, &c.PerMinute, &c.PerDay, &c.Generation, &c.FailureCount, &c.LastErrorCode, &c.LastAcceptedAt)
	c.Status = "disabled"
	if c.Enabled {
		c.Status = "configured"
		if c.LastErrorCode != "" {
			c.Status = "degraded"
		}
	}
	c.CredentialMode = "aws_sdk_default_chain"
	if c.Provider == "gmail" {
		c.CredentialMode = "dedicated_mailbox_offline_oauth"
		c.OAuthScope = notifications.GmailScope
	}
	return c, err
}
func (r *NotificationRepository) ReadConnector(ctx context.Context, id string) (NotificationConnector, error) {
	if id != "" && !validID(id) {
		return NotificationConnector{}, ErrInvalid
	}
	var c NotificationConnector
	err := r.admin(ctx, func(ctx context.Context, tx pgx.Tx, _ access.User) error {
		var err error
		c, err = r.connector(ctx, tx, id)
		return err
	})
	return c, err
}
func (r *NotificationRepository) ConfigureConnector(ctx context.Context, id string, generation int64, enabled, defaultConnector bool, perMinute, perDay int, reason string) error {
	if !validID(id) || generation < 1 || !validPolicyReason(reason) || (defaultConnector && !enabled) || perMinute < 1 || perMinute > 60 || perDay < 1 || perDay > 100000 {
		return ErrInvalid
	}
	return r.admin(ctx, func(ctx context.Context, tx pgx.Tx, actor access.User) error {
		// Switching the default is one transaction; queued jobs retain their IDs.
		if defaultConnector {
			if _, err := tx.Exec(ctx, `UPDATE framework.notification_connectors SET is_default=false,generation=generation+1,updated_by=$4,reason=$5 WHERE deployment_id=$1 AND environment=$2 AND id<>$3 AND is_default`, r.policy.scope.DeploymentID, r.policy.scope.Environment, id, actor.ID, reason); err != nil {
				return err
			}
		}
		tag, err := tx.Exec(ctx, `UPDATE framework.notification_connectors SET enabled=$4,is_default=$5,per_minute=$6,per_day=$7,generation=generation+1,updated_by=$8,reason=$9 WHERE deployment_id=$1 AND environment=$2 AND id=$3 AND generation=$10`, r.policy.scope.DeploymentID, r.policy.scope.Environment, id, enabled, defaultConnector, perMinute, perDay, actor.ID, reason, generation)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrConflict
		}
		return access.RecordAudit(ctx, tx, actor.ID, "notification.connector_configured", id, struct {
			Scope
			Enabled, Default  bool
			PerMinute, PerDay int
			Reason            string
		}{r.policy.scope, enabled, defaultConnector, perMinute, perDay, reason})
	})
}
