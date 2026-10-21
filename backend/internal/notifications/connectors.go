package notifications

import (
	"context"
	"math"
	"time"
)

type ReadinessStatus string

const (
	Configured           ReadinessStatus = "configured"
	Ready                ReadinessStatus = "ready"
	AuthenticationFailed ReadinessStatus = "authentication_failed"
	SenderNotVerified    ReadinessStatus = "sender_not_verified"
	PermissionDenied     ReadinessStatus = "permission_denied"
	QuotaUnavailable     ReadinessStatus = "quota_unavailable"
	ProviderUnavailable  ReadinessStatus = "provider_unavailable"
)

type Readiness struct {
	Status           ReadinessStatus `json:"status"`
	Code             string          `json:"code"`
	QuotaKnown       bool            `json:"quota_known"`
	Remaining24Hours float64         `json:"remaining_24_hours"`
	MaxPerSecond     float64         `json:"max_per_second"`
}

func (r Readiness) Valid() bool {
	if math.IsNaN(r.Remaining24Hours) || math.IsNaN(r.MaxPerSecond) || r.Remaining24Hours < 0 || r.Remaining24Hours >= 1e12 || r.MaxPerSecond < 0 || r.MaxPerSecond >= 1e9 {
		return false
	}
	switch r.Status {
	case Configured, Ready, AuthenticationFailed, SenderNotVerified, PermissionDenied, QuotaUnavailable, ProviderUnavailable:
	default:
		return false
	}
	switch r.Code {
	case "", "not_tested", "ready", "gmail_not_authorized", "gmail_setup_required", "gmail_scope_required", "gmail_authentication_failed", "gmail_sender_not_verified", "gmail_permission_denied", "gmail_quota_unavailable", "gmail_provider_unavailable", "ses_authentication_failed", "ses_sender_not_verified", "ses_permission_denied", "ses_sandbox", "ses_sending_disabled", "ses_quota_unavailable", "ses_provider_unavailable":
		return true
	}
	return false
}

type Probe struct {
	Sender, Region    string
	PerMinute, PerDay int
}

// SESChecker is intentionally incapable of sending to arbitrary test recipients.
type SESChecker interface {
	Check(context.Context, Probe) Readiness
}
type GmailAuthorization interface {
	AuthorizationURL(state, verifier, mailbox string) string
	Exchange(context.Context, string, string, string, string) (GmailCredential, Readiness)
	Refresh(context.Context, GmailCredential, string) (GmailCredential, Readiness)
}
type CredentialBinding struct{ Deployment, Environment, ConnectorID, Version, Sender string }
type CredentialStore interface {
	Proof(context.Context, string) (string, error)
	Save(context.Context, CredentialBinding, GmailCredential) error
	Update(context.Context, CredentialBinding, func(GmailCredential) (GmailCredential, Readiness)) (Readiness, error)
}

// Connection tests are short-lived observations, not delivery guarantees.
const ReadinessTTL = 5 * time.Minute
