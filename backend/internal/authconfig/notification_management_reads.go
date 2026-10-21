package authconfig

import (
	"context"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/jackc/pgx/v5"
)

type NotificationPageQuery struct {
	Search, Category, ImportID, Status, RequestID string
	Offset, Limit                                 int
}

func (q NotificationPageQuery) valid() bool {
	return q.Offset >= 0 && q.Offset <= 100000 && q.Limit >= 1 && q.Limit <= 100 && utf8.ValidString(q.Search) && utf8.RuneCountInString(q.Search) <= 100 && !strings.ContainsAny(q.Search, "\x00\r\n") && (q.ImportID == "" || validID(q.ImportID)) && (q.RequestID == "" || validID(q.RequestID))
}

type OnboardingTarget struct {
	Target        string     `json:"target"`
	Email         string     `json:"email"`
	DisplayName   string     `json:"display_name"`
	Category      string     `json:"category"`
	Code          string     `json:"code"`
	FirstLogin    *time.Time `json:"first_successful_oidc_login_at,omitempty"`
	LastLogin     *time.Time `json:"last_successful_oidc_login_at,omitempty"`
	ClaimEvidence bool       `json:"claim_evidence"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	ImportID      string     `json:"import_id,omitempty"`
}
type OnboardingCounts struct {
	Onboarded  int `json:"onboarded"`
	Pending    int `json:"pending"`
	Unobserved int `json:"unobserved"`
	Inactive   int `json:"inactive"`
}
type OnboardingPage struct {
	Items                   []OnboardingTarget `json:"items"`
	Counts                  OnboardingCounts   `json:"counts"`
	Total                   int                `json:"total"`
	Offset                  int                `json:"offset"`
	Limit                   int                `json:"limit"`
	CommunicationConfigured bool               `json:"communication_configured"`
	DeliveryEnabled         bool               `json:"delivery_enabled"`
	MaxBatch                int                `json:"max_batch"`
	AccessMode              string             `json:"access_mode"`
}

// Counts are mutually exclusive for current-issuer OIDC users. Invitations are
// separate known records; they are never used to infer the employee population.
const onboardingCTE = `WITH known_users AS (
 SELECT u.*,EXISTS(SELECT 1 FROM framework.oidc_invitations i WHERE i.deployment_id=$1 AND i.environment=$2 AND i.status='claimed' AND i.claimed_user_id=u.id) AS claim_evidence
 FROM framework.users u WHERE u.provider='oidc' AND u.issuer=$3 COLLATE "C"
), targets AS (
 SELECT 'user:'||u.id::text AS target,u.email,u.display_name,
 CASE WHEN NOT u.active THEN 'inactive' WHEN u.first_successful_oidc_login_at IS NOT NULL OR u.claim_evidence THEN 'onboarded' ELSE 'unobserved' END AS category,
 u.first_successful_oidc_login_at AS first_login,u.last_successful_oidc_login_at AS last_login,u.claim_evidence,NULL::timestamptz AS expires_at,''::text AS import_id,u.created_at
 FROM known_users u
 UNION ALL
 SELECT 'invitation:'||i.id::text,i.email,i.display_name,'pending',NULL::timestamptz,NULL::timestamptz,false,i.expires_at,COALESCE(i.import_id::text,''),i.created_at
 FROM framework.oidc_invitations i WHERE i.deployment_id=$1 AND i.environment=$2 AND i.status='pending' AND i.expires_at>clock_timestamp()
)
`

func (s *NotificationManagement) Onboarding(ctx context.Context, q NotificationPageQuery) (OnboardingPage, error) {
	p := OnboardingPage{Items: []OnboardingTarget{}, Offset: q.Offset, Limit: q.Limit, CommunicationConfigured: s.configured, MaxBatch: NotificationMaxJobs}
	if !q.valid() || (q.Category != "onboarded" && q.Category != "pending" && q.Category != "unobserved" && q.Category != "inactive") || (q.ImportID != "" && q.Category != "pending") {
		return p, ErrInvalid
	}
	err := s.repository.admin(ctx, func(ctx context.Context, tx pgx.Tx, _ access.User) error {
		b, err := s.repository.policy.invitationContext(ctx, tx, nil)
		if err != nil {
			return err
		}
		p.AccessMode = b.policy.Mode
		scope := s.repository.policy.scope
		if q.ImportID != "" {
			var id string
			if err = tx.QueryRow(ctx, `SELECT id::text FROM framework.oidc_invitation_imports WHERE deployment_id=$1 AND environment=$2 AND id=$3`, scope.DeploymentID, scope.Environment, q.ImportID).Scan(&id); err != nil {
				return err
			}
		}
		if err = tx.QueryRow(ctx, onboardingCTE+`SELECT count(*) FILTER(WHERE category='onboarded'),count(*) FILTER(WHERE category='pending'),count(*) FILTER(WHERE category='unobserved'),count(*) FILTER(WHERE category='inactive') FROM targets`, scope.DeploymentID, scope.Environment, b.issuer).Scan(&p.Counts.Onboarded, &p.Counts.Pending, &p.Counts.Unobserved, &p.Counts.Inactive); err != nil {
			return err
		}
		where := ` FROM targets WHERE category=$4 AND ($5='' OR strpos(lower(email||' '||display_name),lower($5))>0) AND ($6='' OR import_id=$6)`
		args := []any{scope.DeploymentID, scope.Environment, b.issuer, q.Category, q.Search, q.ImportID}
		if err = tx.QueryRow(ctx, onboardingCTE+`SELECT count(*)`+where, args...).Scan(&p.Total); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, onboardingCTE+`SELECT target,email,display_name,category,first_login,last_login,claim_evidence,expires_at,import_id`+where+` ORDER BY created_at DESC,target OFFSET $7 LIMIT $8`, append(args, q.Offset, q.Limit)...)
		if err != nil {
			return err
		}
		for rows.Next() {
			var item OnboardingTarget
			if err = rows.Scan(&item.Target, &item.Email, &item.DisplayName, &item.Category, &item.FirstLogin, &item.LastLogin, &item.ClaimEvidence, &item.ExpiresAt, &item.ImportID); err != nil {
				rows.Close()
				return err
			}
			p.Items = append(p.Items, item)
		}
		rows.Close()
		if rows.Err() != nil {
			return rows.Err()
		}
		for n := range p.Items {
			if !s.configured {
				p.Items[n].Code = "communication_unavailable"
				continue
			}
			t, _ := notificationTarget(p.Items[n].Target)
			j := NotificationJob{NotificationTarget: t, Type: "reminder"}
			p.Items[n].Code, err = s.repository.eligible(ctx, tx, b, &j, false)
			if err != nil {
				return err
			}
		}
		return nil
	})
	return p, err
}

type NotificationHistoryItem struct {
	ID             string    `json:"id"`
	RequestID      string    `json:"request_id"`
	Target         string    `json:"target"`
	Recipient      string    `json:"recipient"`
	DisplayName    string    `json:"display_name"`
	Type           string    `json:"type"`
	ConnectorID    string    `json:"connector_id"`
	Provider       string    `json:"provider"`
	Sender         string    `json:"sender"`
	ActorID        string    `json:"actor_id"`
	ActorName      string    `json:"actor_name"`
	Status         string    `json:"status"`
	AttemptOutcome string    `json:"attempt_outcome"`
	Disposition    string    `json:"disposition"`
	CreatedAt      time.Time `json:"created_at"`
	Generation     int64     `json:"generation"`
	AttemptCount   int       `json:"attempt_count"`
}
type NotificationHistoryPage struct {
	Items           []NotificationHistoryItem `json:"items"`
	Total           int                       `json:"total"`
	Offset          int                       `json:"offset"`
	Limit           int                       `json:"limit"`
	DeliveryEnabled bool                      `json:"delivery_enabled"`
}

const historyFrom = ` FROM framework.notification_jobs j
 JOIN framework.notification_requests r ON r.id=j.request_id
 JOIN framework.notification_connectors c ON c.id=j.connector_id
 JOIN framework.users u ON u.id=r.actor_user_id
 LEFT JOIN LATERAL(SELECT COALESCE(a.outcome,'in_progress') AS outcome FROM framework.notification_attempts a WHERE a.job_id=j.id ORDER BY a.attempt_number DESC LIMIT 1) last_attempt ON true
 WHERE j.deployment_id=$1 AND j.environment=$2`
const historyColumns = `j.id::text,j.request_id::text,CASE WHEN j.invitation_id IS NOT NULL THEN 'invitation:'||j.invitation_id::text ELSE 'user:'||j.user_id::text END,
 j.recipient_email,j.display_name,j.notification_type,j.connector_id::text,c.provider,j.sender_email,r.actor_user_id::text,u.display_name,j.status,COALESCE(last_attempt.outcome,''),j.disposition_code,j.created_at,j.generation,j.attempt_count`

func scanNotificationHistory(row pgx.Row) (NotificationHistoryItem, error) {
	var i NotificationHistoryItem
	err := row.Scan(&i.ID, &i.RequestID, &i.Target, &i.Recipient, &i.DisplayName, &i.Type, &i.ConnectorID, &i.Provider, &i.Sender, &i.ActorID, &i.ActorName, &i.Status, &i.AttemptOutcome, &i.Disposition, &i.CreatedAt, &i.Generation, &i.AttemptCount)
	return i, err
}
func historyStatus(value string) bool {
	switch value {
	case "", "queued", "leased", "dispatching", "sent", "failed", "cancelled", "needs_inspection":
		return true
	}
	return false
}
func (s *NotificationManagement) history(ctx context.Context, tx pgx.Tx, q NotificationPageQuery) (NotificationHistoryPage, error) {
	p := NotificationHistoryPage{Items: []NotificationHistoryItem{}, Offset: q.Offset, Limit: q.Limit}
	where := historyFrom + ` AND ($3='' OR j.status=$3) AND ($4='' OR j.request_id=NULLIF($4,'')::uuid) AND ($5='' OR strpos(lower(j.recipient_email||' '||j.display_name),lower($5))>0)`
	scope := s.repository.policy.scope
	args := []any{scope.DeploymentID, scope.Environment, q.Status, q.RequestID, q.Search}
	if err := tx.QueryRow(ctx, `SELECT count(*)`+where, args...).Scan(&p.Total); err != nil {
		return p, err
	}
	rows, err := tx.Query(ctx, `SELECT `+historyColumns+where+` ORDER BY j.created_at DESC,j.id OFFSET $6 LIMIT $7`, append(args, q.Offset, q.Limit)...)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	for rows.Next() {
		i, err := scanNotificationHistory(rows)
		if err != nil {
			return p, err
		}
		p.Items = append(p.Items, i)
	}
	return p, rows.Err()
}
func (s *NotificationManagement) History(ctx context.Context, q NotificationPageQuery) (NotificationHistoryPage, error) {
	var p NotificationHistoryPage
	if !q.valid() || !historyStatus(q.Status) {
		return p, ErrInvalid
	}
	err := s.repository.admin(ctx, func(ctx context.Context, tx pgx.Tx, _ access.User) error {
		var err error
		p, err = s.history(ctx, tx, q)
		return err
	})
	return p, err
}

type NotificationReceipt struct {
	ID              string                  `json:"id"`
	ActorID         string                  `json:"actor_id"`
	Type            string                  `json:"type"`
	ConnectorID     string                  `json:"connector_id"`
	Sender          string                  `json:"sender"`
	TemplateVersion string                  `json:"template_version"`
	Locale          string                  `json:"locale"`
	Reason          string                  `json:"reason"`
	JobCount        int                     `json:"job_count"`
	Outcome         string                  `json:"outcome"`
	CreatedAt       time.Time               `json:"created_at"`
	Jobs            NotificationHistoryPage `json:"jobs"`
	DeliveryEnabled bool                    `json:"delivery_enabled"`
}

func (s *NotificationManagement) Receipt(ctx context.Context, id string, offset, limit int) (NotificationReceipt, error) {
	var p NotificationReceipt
	q := NotificationPageQuery{RequestID: id, Offset: offset, Limit: limit}
	if !validID(id) || !q.valid() {
		return p, ErrInvalid
	}
	err := s.repository.admin(ctx, func(ctx context.Context, tx pgx.Tx, _ access.User) error {
		scope := s.repository.policy.scope
		err := tx.QueryRow(ctx, `SELECT id::text,actor_user_id::text,notification_type,connector_id::text,sender_email,template_version,locale,reason,job_count,outcome,created_at FROM framework.notification_requests WHERE deployment_id=$1 AND environment=$2 AND id=$3`, scope.DeploymentID, scope.Environment, id).Scan(&p.ID, &p.ActorID, &p.Type, &p.ConnectorID, &p.Sender, &p.TemplateVersion, &p.Locale, &p.Reason, &p.JobCount, &p.Outcome, &p.CreatedAt)
		if err != nil {
			return err
		}
		p.Jobs, err = s.history(ctx, tx, q)
		return err
	})
	return p, err
}

type NotificationAttemptDTO struct {
	Number            int        `json:"number"`
	Adapter           string     `json:"adapter"`
	Outcome           string     `json:"outcome"`
	ProviderMessageID string     `json:"provider_message_id"`
	Code              string     `json:"code"`
	StartedAt         time.Time  `json:"started_at"`
	CompletedAt       *time.Time `json:"completed_at,omitempty"`
}
type NotificationJobDetail struct {
	Item            NotificationHistoryItem  `json:"item"`
	Attempts        []NotificationAttemptDTO `json:"attempts"`
	DeliveryEnabled bool                     `json:"delivery_enabled"`
}

func (s *NotificationManagement) Job(ctx context.Context, id string) (NotificationJobDetail, error) {
	p := NotificationJobDetail{Attempts: []NotificationAttemptDTO{}}
	if !validID(id) {
		return p, ErrInvalid
	}
	err := s.repository.admin(ctx, func(ctx context.Context, tx pgx.Tx, _ access.User) error {
		scope := s.repository.policy.scope
		var err error
		p.Item, err = scanNotificationHistory(tx.QueryRow(ctx, `SELECT `+historyColumns+historyFrom+` AND j.id=$3`, scope.DeploymentID, scope.Environment, id))
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT attempt_number,adapter,COALESCE(outcome,'in_progress'),provider_message_id,error_code,started_at,completed_at FROM framework.notification_attempts WHERE job_id=$1 ORDER BY attempt_number LIMIT 10`, id)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a NotificationAttemptDTO
			if err = rows.Scan(&a.Number, &a.Adapter, &a.Outcome, &a.ProviderMessageID, &a.Code, &a.StartedAt, &a.CompletedAt); err != nil {
				return err
			}
			p.Attempts = append(p.Attempts, a)
		}
		return rows.Err()
	})
	return p, err
}
