package notifications

import (
	"context"
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
	"github.com/aws/smithy-go"
)

type SESClient interface {
	GetAccount(context.Context, *sesv2.GetAccountInput, ...func(*sesv2.Options)) (*sesv2.GetAccountOutput, error)
	GetEmailIdentity(context.Context, *sesv2.GetEmailIdentityInput, ...func(*sesv2.Options)) (*sesv2.GetEmailIdentityOutput, error)
	SendEmail(context.Context, *sesv2.SendEmailInput, ...func(*sesv2.Options)) (*sesv2.SendEmailOutput, error)
}
type SES struct {
	load func(context.Context, string) (SESClient, error)
}

var errSESCredentials = errors.New("ses credentials unavailable")

func NewSES() *SES {
	return &SES{load: func(ctx context.Context, region string) (SESClient, error) {
		cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region), config.WithHTTPClient(providerHTTPClient()), config.WithRetryer(func() aws.Retryer { return aws.NopRetryer{} }))
		if err != nil {
			return nil, err
		}
		if cfg.Credentials == nil {
			return nil, errSESCredentials
		}
		if _, err = cfg.Credentials.Retrieve(ctx); err != nil {
			return nil, errSESCredentials
		}
		// Preserve resolved credentials/region, while disallowing service endpoint
		// overrides from shared profiles/environment on the administrator surface.
		cfg.ConfigSources = nil
		cfg.BaseEndpoint = nil
		cfg.EndpointResolver = nil
		cfg.EndpointResolverWithOptions = nil
		return sesv2.NewFromConfig(cfg), nil
	}}
}
func sesFailure(err error) Readiness {
	if errors.Is(err, errSESCredentials) {
		return Readiness{Status: AuthenticationFailed, Code: "ses_authentication_failed"}
	}
	var api smithy.APIError
	if errors.As(err, &api) {
		switch api.ErrorCode() {
		case "AccessDenied", "AccessDeniedException", "UnauthorizedException":
			return Readiness{Status: PermissionDenied, Code: "ses_permission_denied"}
		case "InvalidClientTokenId", "ExpiredToken", "ExpiredTokenException", "UnrecognizedClientException", "SignatureDoesNotMatch":
			return Readiness{Status: AuthenticationFailed, Code: "ses_authentication_failed"}
		case "NotFoundException":
			return Readiness{Status: SenderNotVerified, Code: "ses_sender_not_verified"}
		case "TooManyRequestsException", "LimitExceededException":
			return Readiness{Status: QuotaUnavailable, Code: "ses_quota_unavailable"}
		}
	}
	return Readiness{Status: ProviderUnavailable, Code: "ses_provider_unavailable"}
}
func (s *SES) check(ctx context.Context, client SESClient, p Probe) Readiness {
	account, err := client.GetAccount(ctx, &sesv2.GetAccountInput{})
	if err != nil {
		return sesFailure(err)
	}
	if account == nil || !account.SendingEnabled {
		return Readiness{Status: PermissionDenied, Code: "ses_sending_disabled"}
	}
	if !account.ProductionAccessEnabled {
		return Readiness{Status: PermissionDenied, Code: "ses_sandbox"}
	}
	identity, err := client.GetEmailIdentity(ctx, &sesv2.GetEmailIdentityInput{EmailIdentity: aws.String(p.Sender)})
	if err != nil {
		var e smithy.APIError
		if errors.As(err, &e) && e.ErrorCode() == "NotFoundException" {
			parts := strings.Split(p.Sender, "@")
			if len(parts) != 2 {
				return Readiness{Status: SenderNotVerified, Code: "ses_sender_not_verified"}
			}
			identity, err = client.GetEmailIdentity(ctx, &sesv2.GetEmailIdentityInput{EmailIdentity: aws.String(parts[1])})
		}
	}
	if err != nil {
		return sesFailure(err)
	}
	if identity == nil || !identity.VerifiedForSendingStatus {
		return Readiness{Status: SenderNotVerified, Code: "ses_sender_not_verified"}
	}
	if account.SendQuota == nil {
		return Readiness{Status: QuotaUnavailable, Code: "ses_quota_unavailable"}
	}
	remaining := account.SendQuota.Max24HourSend - account.SendQuota.SentLast24Hours
	if remaining < 0 {
		remaining = 0
	}
	result := Readiness{Status: Ready, Code: "ready", QuotaKnown: true, Remaining24Hours: remaining, MaxPerSecond: account.SendQuota.MaxSendRate}
	if remaining < float64(p.PerDay) || account.SendQuota.MaxSendRate < float64(p.PerMinute)/60 || account.SendQuota.MaxSendRate <= 0 {
		result.Status = QuotaUnavailable
		result.Code = "ses_quota_unavailable"
	}
	return result
}
func (s *SES) Check(ctx context.Context, p Probe) Readiness {
	client, err := s.load(ctx, p.Region)
	if err != nil {
		return sesFailure(err)
	}
	return s.check(ctx, client, p)
}

// SESAdapter is available for future explicit dispatch wiring only. No server
// worker or public sending endpoint is registered. SDK retries are disabled.
type SESAdapter struct {
	SES   *SES
	Probe Probe
}

func (*SESAdapter) Provider() string { return "ses" }
func (s *SESAdapter) Send(ctx context.Context, m Message) Result {
	rejected := Result{Outcome: Rejected, ErrorCode: "provider_rejected"}
	if m.sender != s.Probe.Sender || m.reference == "" {
		return rejected
	}
	client, err := s.SES.load(ctx, s.Probe.Region)
	if err != nil {
		return rejected
	}
	if s.SES.check(ctx, client, s.Probe).Status != Ready {
		return rejected
	}
	body := &types.Body{Text: &types.Content{Charset: aws.String("UTF-8"), Data: aws.String(m.text)}}
	if m.html != "" {
		body.Html = &types.Content{Charset: aws.String("UTF-8"), Data: aws.String(m.html)}
	}
	output, err := client.SendEmail(ctx, &sesv2.SendEmailInput{FromEmailAddress: aws.String(m.sender), Destination: &types.Destination{ToAddresses: []string{m.recipient}}, Content: &types.EmailContent{Simple: &types.Message{Subject: &types.Content{Charset: aws.String("UTF-8"), Data: aws.String(m.subject)}, Body: body}}, EmailTags: []types.MessageTag{{Name: aws.String("vgca_reference"), Value: aws.String(m.reference)}}})
	if err != nil {
		var e smithy.APIError
		if errors.As(err, &e) {
			switch e.ErrorCode() {
			case "MessageRejected", "BadRequestException", "MailFromDomainNotVerifiedException", "SendingPausedException", "AccountSuspendedException", "AccessDeniedException", "TooManyRequestsException", "LimitExceededException":
				return rejected
			}
		}
		return Result{Outcome: Uncertain, ErrorCode: "provider_uncertain"}
	}
	if output == nil || aws.ToString(output.MessageId) == "" {
		return Result{Outcome: Uncertain, ErrorCode: "provider_uncertain"}
	}
	result := Result{Outcome: Accepted, ProviderMessageID: aws.ToString(output.MessageId)}
	if !result.Validate() {
		return Result{Outcome: Uncertain, ErrorCode: "provider_uncertain"}
	}
	return result
}
