package authconfig

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/notifications"
	"github.com/jackc/pgx/v5"
)

const NotificationManagementPath = "/api/admin/notifications"
const notificationPreviewTTL = 5 * time.Minute

// This service has no delivery adapter, worker capability or scheduling hook.
type NotificationManagement struct {
	repository *NotificationRepository
	connectors *EmailConnectorService
	configured bool
}

func NewNotificationManagement(policy *AccessPolicyRepository, connectors *EmailConnectorService, communication CommunicationPolicy) *NotificationManagement {
	if policy == nil || connectors == nil || connectors.repository.policy != policy {
		return nil
	}
	r, err := NewNotificationRepository(policy, communication)
	if err != nil {
		// History and onboarding observations remain inspectable without enabling
		// communications. Missing deployment policy must never admit recipients.
		r = &NotificationRepository{policy: policy}
	}
	return &NotificationManagement{r, connectors, err == nil}
}

func NotificationCommunicationFromEnv(origin string, getenv func(string) string) CommunicationPolicy {
	p := CommunicationPolicy{Origin: origin}
	if raw := getenv("NOTIFICATION_ALLOWED_DOMAINS"); raw != "" {
		for _, domain := range strings.Split(raw, ",") {
			p.AllowedDomains = append(p.AllowedDomains, strings.TrimSpace(domain))
		}
	}
	if raw := getenv("NOTIFICATION_COOLDOWN_HOURS"); raw != "" {
		hours, err := strconv.Atoi(raw)
		if err != nil || hours < 72 || hours > 720 {
			p.AllowedDomains = nil
		} else {
			p.Cooldown = time.Duration(hours) * time.Hour
		}
	}
	return p
}

func notificationTarget(ref string) (NotificationTarget, error) {
	parts := strings.Split(ref, ":")
	if len(parts) != 2 || !validID(parts[1]) || ref != strings.ToLower(ref) {
		return NotificationTarget{}, ErrInvalid
	}
	switch parts[0] {
	case "invitation":
		return NotificationTarget{InvitationID: parts[1]}, nil
	case "user":
		return NotificationTarget{UserID: parts[1]}, nil
	}
	return NotificationTarget{}, ErrInvalid
}

type NotificationPreviewInput struct {
	RequestID   string   `json:"request_id"`
	Type        string   `json:"type"`
	Locale      string   `json:"locale"`
	ConnectorID string   `json:"connector_id"`
	Targets     []string `json:"targets"`
}

func (i NotificationPreviewInput) valid() bool {
	if !validID(i.RequestID) || i.RequestID != strings.ToLower(i.RequestID) || !validID(i.ConnectorID) || !notifications.Locale(i.Locale) || (i.Type != "invitation" && i.Type != "reminder") || len(i.Targets) < 1 || len(i.Targets) > NotificationMaxJobs {
		return false
	}
	seen := map[string]bool{}
	for _, ref := range i.Targets {
		t, err := notificationTarget(ref)
		if err != nil || seen[ref] || (i.Type == "invitation" && t.InvitationID == "") {
			return false
		}
		seen[ref] = true
	}
	return true
}

type NotificationPreviewRow struct {
	Target      string `json:"target"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Code        string `json:"code"`
	Subject     string `json:"subject,omitempty"`
	Text        string `json:"text,omitempty"`
}
type NotificationPreview struct {
	Input               NotificationPreviewInput `json:"input"`
	Expected            ImportExpectation        `json:"expected"`
	ConnectorGeneration int64                    `json:"connector_generation"`
	Sender              string                   `json:"sender"`
	TemplateVersion     string                   `json:"template_version"`
	Rows                []NotificationPreviewRow `json:"rows"`
	SelectedTargets     []string                 `json:"selected_targets"`
	Ready               int                      `json:"ready_count"`
	Skipped             int                      `json:"skipped_count"`
	Digest              string                   `json:"preview_digest"`
	ExpiresAt           time.Time                `json:"preview_expires_at"`
	DeliveryEnabled     bool                     `json:"delivery_enabled"`
}

func (s *NotificationManagement) readyConnector(ctx context.Context, tx pgx.Tx, id string) (EmailConnector, readinessRecord, error) {
	c, err := s.repository.connector(ctx, tx, id)
	if err != nil {
		return EmailConnector{}, readinessRecord{}, err
	}
	dto, err := s.connectors.dto(ctx, tx, c)
	if err != nil {
		return dto, readinessRecord{}, err
	}
	if !dto.Enabled || dto.Readiness.Status != notifications.Ready {
		return dto, readinessRecord{}, ErrConflict
	}
	r, err := s.connectors.observation(ctx, tx, id)
	return dto, r, err
}

func (s *NotificationManagement) snapshot(ctx context.Context, tx pgx.Tx, input NotificationPreviewInput) (NotificationPreview, readinessRecord, error) {
	p := NotificationPreview{Input: input, TemplateVersion: notifications.TemplateVersion, Rows: []NotificationPreviewRow{}, SelectedTargets: []string{}}
	b, err := s.repository.policy.invitationContext(ctx, tx, nil)
	if err != nil {
		return p, readinessRecord{}, err
	}
	p.Expected = importExpectation(b)
	c, observation, err := s.readyConnector(ctx, tx, input.ConnectorID)
	if err != nil {
		return p, observation, err
	}
	p.ConnectorGeneration, p.Sender = c.Generation, c.Sender
	seen := map[string]bool{}
	for _, ref := range input.Targets {
		t, _ := notificationTarget(ref)
		j := NotificationJob{NotificationTarget: t, Type: input.Type}
		code, err := s.repository.eligible(ctx, tx, b, &j, false)
		if err != nil {
			return p, observation, err
		}
		// Snapshot names/emails for skipped rows too, without mailbox-based identity
		// selection. Unknown/out-of-scope references fail the entire preview.
		row, err := s.targetContact(ctx, tx, b, ref)
		if err != nil {
			return p, observation, err
		}
		row.Code = code
		if code == "" && seen[strings.ToLower(j.RecipientKey)] {
			row.Code = "review_required"
		}
		if row.Code == "" {
			m, err := s.repository.template.Render(input.Type, notifications.TemplateVersion, input.Locale, c.Sender, j.Recipient, j.DisplayName, "vgca."+input.RequestID)
			if err != nil {
				return p, observation, ErrInvalid
			}
			row.Subject, row.Text = m.Subject(), m.Text()
			seen[strings.ToLower(j.RecipientKey)] = true
			p.SelectedTargets = append(p.SelectedTargets, ref)
		}
		p.Rows = append(p.Rows, row)
	}
	p.Ready = len(p.SelectedTargets)
	p.Skipped = len(p.Rows) - p.Ready
	return p, observation, nil
}

// Reuse the installation-local import signing seed with explicit domain
// separation. No new credential, migration or persistent preview queue is needed.
func (s *NotificationManagement) proof(ctx context.Context, tx pgx.Tx, actor string, p NotificationPreview, observation readinessRecord) (string, error) {
	var key []byte
	if err := tx.QueryRow(ctx, `SELECT signing_key FROM framework.oidc_invitation_import_keys WHERE singleton`).Scan(&key); err != nil {
		return "", err
	}
	if len(key) != 32 {
		return "", ErrUnavailable
	}
	p.Digest = ""
	payload, err := json.Marshal(struct {
		Purpose            string
		Scope              Scope
		Actor              string
		Communication      [32]byte
		Preview            NotificationPreview
		ReadinessOperation string
		ReadinessExpires   time.Time
	}{"vgca.notification.preview.v1", s.repository.policy.scope, actor, s.repository.communicationDigest, p, observation.Operation, observation.ExpiresAt.UTC()})
	if err != nil {
		return "", ErrUnavailable
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func (s *NotificationManagement) Preview(ctx context.Context, input NotificationPreviewInput) (NotificationPreview, error) {
	if !input.valid() {
		return NotificationPreview{}, ErrInvalid
	}
	if !s.configured {
		return NotificationPreview{}, ErrUnavailable
	}
	input.Targets = slices.Clone(input.Targets)
	slices.Sort(input.Targets)
	var result NotificationPreview
	err := s.repository.admin(ctx, func(ctx context.Context, tx pgx.Tx, actor access.User) error {
		p, r, err := s.snapshot(ctx, tx, input)
		if err != nil {
			return err
		}
		var now time.Time
		if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return err
		}
		p.ExpiresAt = now.Add(notificationPreviewTTL).UTC()
		if r.ExpiresAt.Before(p.ExpiresAt) {
			p.ExpiresAt = r.ExpiresAt.UTC()
		}
		p.Digest, err = s.proof(ctx, tx, actor.ID, p, r)
		result = p
		return err
	})
	return result, err
}

type NotificationEnqueueInput struct {
	Input               NotificationPreviewInput `json:"input"`
	Expected            ImportExpectation        `json:"expected"`
	ConnectorGeneration int64                    `json:"connector_generation"`
	SelectedTargets     []string                 `json:"selected_targets"`
	Digest              string                   `json:"preview_digest"`
	ExpiresAt           time.Time                `json:"preview_expires_at"`
	IdempotencyKey      string                   `json:"idempotency_key"`
	Reason              string                   `json:"reason"`
	Confirm             bool                     `json:"confirm"`
}

func (s *NotificationManagement) Enqueue(ctx context.Context, input NotificationEnqueueInput) (NotificationRequest, error) {
	proof, err := hex.DecodeString(input.Digest)
	if err != nil || len(proof) != 32 || !input.Input.valid() || !input.Expected.invitation().valid() || input.ConnectorGeneration < 1 || !input.Confirm || !validPolicyReason(input.Reason) || !validID(input.IdempotencyKey) || len(input.SelectedTargets) < 1 || len(input.SelectedTargets) > NotificationMaxJobs || input.ExpiresAt.IsZero() {
		return NotificationRequest{}, ErrInvalid
	}
	if !s.configured {
		return NotificationRequest{}, ErrUnavailable
	}
	input.Input.Targets = slices.Clone(input.Input.Targets)
	input.SelectedTargets = slices.Clone(input.SelectedTargets)
	slices.Sort(input.Input.Targets)
	slices.Sort(input.SelectedTargets)
	input.ExpiresAt = input.ExpiresAt.UTC()
	canonical, _ := json.Marshal(input)
	i := NotificationInput{ID: input.Input.RequestID, IdempotencyKey: input.IdempotencyKey, Type: input.Input.Type, TemplateVersion: notifications.TemplateVersion, Locale: input.Input.Locale, ConnectorID: input.Input.ConnectorID, ConnectorGeneration: input.ConnectorGeneration, Expected: input.Expected.invitation(), Reason: input.Reason, Confirm: true, PreviewBinding: shaText(string(canonical))}
	for _, ref := range input.SelectedTargets {
		t, err := notificationTarget(ref)
		if err != nil {
			return NotificationRequest{}, err
		}
		i.Targets = append(i.Targets, t)
	}
	return s.repository.enqueue(ctx, i, func(ctx context.Context, tx pgx.Tx, actor access.User) error {
		var now time.Time
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return err
		}
		if !input.ExpiresAt.After(now) || input.ExpiresAt.After(now.Add(notificationPreviewTTL)) {
			return ErrConflict
		}
		p, r, err := s.snapshot(ctx, tx, input.Input)
		if err != nil {
			return err
		}
		if p.Expected != input.Expected || p.ConnectorGeneration != input.ConnectorGeneration || !slices.Equal(p.SelectedTargets, input.SelectedTargets) {
			return ErrConflict
		}
		p.ExpiresAt = input.ExpiresAt
		actual, err := s.proof(ctx, tx, actor.ID, p, r)
		if err != nil {
			return err
		}
		decoded, _ := hex.DecodeString(actual)
		if !hmac.Equal(proof, decoded) {
			return ErrConflict
		}
		return nil
	})
}

func (s *NotificationManagement) targetContact(ctx context.Context, tx pgx.Tx, b invitationBinding, ref string) (NotificationPreviewRow, error) {
	t, err := notificationTarget(ref)
	row := NotificationPreviewRow{Target: ref}
	if err != nil {
		return row, err
	}
	if t.InvitationID != "" {
		err = tx.QueryRow(ctx, `SELECT email,display_name FROM framework.oidc_invitations WHERE deployment_id=$1 AND environment=$2 AND id=$3`, s.repository.policy.scope.DeploymentID, s.repository.policy.scope.Environment, t.InvitationID).Scan(&row.Email, &row.DisplayName)
	} else {
		err = tx.QueryRow(ctx, `SELECT email,display_name FROM framework.users WHERE id=$1 AND issuer=$2 COLLATE "C" AND provider='oidc'`, t.UserID, b.issuer).Scan(&row.Email, &row.DisplayName)
	}
	return row, err
}

type NotificationSuppressionDTO struct {
	Target     string `json:"target"`
	Active     bool   `json:"active"`
	Generation int64  `json:"generation"`
	Reason     string `json:"reason"`
}

func (s *NotificationManagement) Suppression(ctx context.Context, ref string) (NotificationSuppressionDTO, error) {
	t, err := notificationTarget(ref)
	result := NotificationSuppressionDTO{Target: ref}
	if err != nil {
		return result, err
	}
	err = s.repository.admin(ctx, func(ctx context.Context, tx pgx.Tx, _ access.User) error {
		b, err := s.repository.policy.invitationContext(ctx, tx, nil)
		if err != nil {
			return err
		}
		if _, err = s.targetContact(ctx, tx, b, ref); err != nil {
			return err
		}
		err = tx.QueryRow(ctx, `SELECT active,generation,reason FROM framework.notification_suppressions WHERE deployment_id=$1 AND environment=$2 AND target_key=$3`, s.repository.policy.scope.DeploymentID, s.repository.policy.scope.Environment, t.key()).Scan(&result.Active, &result.Generation, &result.Reason)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	return result, err
}
