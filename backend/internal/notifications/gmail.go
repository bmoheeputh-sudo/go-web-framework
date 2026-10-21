package notifications

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

const GmailSenderScope = "https://www.googleapis.com/auth/gmail.settings.basic"

type GmailCredential struct {
	RefreshToken     string
	Mailbox          string
	Scopes           string
	RefreshExpiresAt time.Time
}

func (GmailCredential) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, "[GMAIL CREDENTIAL]") }
func (GmailCredential) MarshalJSON() ([]byte, error) {
	return nil, errors.New("credential serialization prohibited")
}

// Gmail has fixed production endpoints and no credential logging. Tests replace
// the private transport/endpoint fields, never accept URLs through admin APIs.
type Gmail struct {
	config             oauth2.Config
	client             *http.Client
	sendAsURL, sendURL string
}

func (*Gmail) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, "[GMAIL CONNECTOR]") }
func NewGmail(clientID, clientSecret, callback string) *Gmail {
	return &Gmail{config: oauth2.Config{ClientID: clientID, ClientSecret: clientSecret, RedirectURL: callback, Scopes: []string{GmailScope, GmailSenderScope}, Endpoint: oauth2.Endpoint{AuthURL: "https://accounts.google.com/o/oauth2/v2/auth", TokenURL: "https://oauth2.googleapis.com/token", AuthStyle: oauth2.AuthStyleInParams}}, client: providerHTTPClient(), sendAsURL: "https://gmail.googleapis.com/gmail/v1/users/me/settings/sendAs", sendURL: "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"}
}
func providerHTTPClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func (g *Gmail) AuthorizationURL(state, verifier, mailbox string) string {
	return g.config.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("prompt", "consent"), oauth2.SetAuthURLParam("include_granted_scopes", "false"), oauth2.SetAuthURLParam("login_hint", mailbox), oauth2.S256ChallengeOption(verifier))
}
func gmailFailure(status int) Readiness {
	switch status {
	case 400, 401:
		return Readiness{Status: AuthenticationFailed, Code: "gmail_authentication_failed"}
	case 403:
		return Readiness{Status: PermissionDenied, Code: "gmail_permission_denied"}
	case 429:
		return Readiness{Status: QuotaUnavailable, Code: "gmail_quota_unavailable"}
	default:
		return Readiness{Status: ProviderUnavailable, Code: "gmail_provider_unavailable"}
	}
}
func grantedScopes(scopes string) bool {
	f := strings.Fields(scopes)
	has := func(s string) bool {
		for _, v := range f {
			if v == s {
				return true
			}
		}
		return false
	}
	return has(GmailScope) && has(GmailSenderScope)
}
func (g *Gmail) verify(ctx context.Context, token *oauth2.Token, mailbox, sender string) Readiness {
	req, err := http.NewRequestWithContext(ctx, "GET", g.sendAsURL, nil)
	if err != nil {
		return gmailFailure(503)
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	response, err := g.client.Do(req)
	if err != nil {
		return gmailFailure(503)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return gmailFailure(response.StatusCode)
	}
	var data struct {
		SendAs []struct {
			Email        string `json:"sendAsEmail"`
			Primary      bool   `json:"isPrimary"`
			Verification string `json:"verificationStatus"`
		} `json:"sendAs"`
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(raw) > 65536 || json.Unmarshal(raw, &data) != nil {
		return gmailFailure(503)
	}
	primary, verified := false, false
	for _, a := range data.SendAs {
		if a.Primary && a.Email == mailbox {
			primary = true
		}
		if a.Email == sender && a.Verification == "accepted" {
			verified = true
		}
	}
	if !primary || !verified {
		return Readiness{Status: SenderNotVerified, Code: "gmail_sender_not_verified"}
	}
	// Gmail exposes no mailbox remaining-send-quota endpoint under these scopes.
	return Readiness{Status: Ready, Code: "ready", QuotaKnown: false}
}
func tokenFailure(err error) Readiness {
	var e *oauth2.RetrieveError
	if errors.As(err, &e) {
		if e.Response == nil {
			return gmailFailure(401)
		}
		return gmailFailure(e.Response.StatusCode)
	}
	return gmailFailure(503)
}
func (g *Gmail) Exchange(ctx context.Context, code, verifier, mailbox, sender string) (GmailCredential, Readiness) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, g.client)
	token, err := g.config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return GmailCredential{}, tokenFailure(err)
	}
	scopes, _ := token.Extra("scope").(string)
	if scopes == "" {
		scopes = GmailScope + " " + GmailSenderScope
	}
	if token.RefreshToken == "" || !grantedScopes(scopes) {
		return GmailCredential{}, Readiness{Status: PermissionDenied, Code: "gmail_scope_required"}
	}
	credential := GmailCredential{RefreshToken: token.RefreshToken, Mailbox: mailbox, Scopes: scopes}
	if seconds, ok := token.Extra("refresh_token_expires_in").(float64); ok && seconds > 0 && seconds < 365*24*3600 {
		credential.RefreshExpiresAt = time.Now().Add(time.Duration(seconds) * time.Second)
	}
	result := g.verify(ctx, token, mailbox, sender)
	return credential, result
}
func (g *Gmail) refreshToken(ctx context.Context, c GmailCredential) (*oauth2.Token, GmailCredential, Readiness) {
	if c.RefreshToken == "" || (!c.RefreshExpiresAt.IsZero() && !c.RefreshExpiresAt.After(time.Now())) {
		return nil, c, gmailFailure(401)
	}
	if !grantedScopes(c.Scopes) {
		return nil, c, Readiness{Status: PermissionDenied, Code: "gmail_scope_required"}
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, g.client)
	token, err := g.config.TokenSource(ctx, &oauth2.Token{RefreshToken: c.RefreshToken, Expiry: time.Now().Add(-time.Hour)}).Token()
	if err != nil {
		return nil, c, tokenFailure(err)
	}
	if token.RefreshToken != "" {
		c.RefreshToken = token.RefreshToken
	}
	if scopes, ok := token.Extra("scope").(string); ok && scopes != "" {
		c.Scopes = scopes
	}
	if !grantedScopes(c.Scopes) {
		return nil, c, Readiness{Status: PermissionDenied, Code: "gmail_scope_required"}
	}
	return token, c, Readiness{Status: Ready, Code: "ready"}
}
func (g *Gmail) Refresh(ctx context.Context, c GmailCredential, sender string) (GmailCredential, Readiness) {
	token, next, result := g.refreshToken(ctx, c)
	if token == nil {
		return next, result
	}
	return next, g.verify(ctx, token, next.Mailbox, sender)
}

// GmailAdapter is not registered with any production worker. Send is a single
// provider request; transport/5xx uncertainty never triggers retries or failover.
type GmailAdapter struct {
	Gmail   *Gmail
	Store   CredentialStore
	Binding CredentialBinding
}

func (*GmailAdapter) Provider() string { return "gmail" }
func (a *GmailAdapter) Send(ctx context.Context, m Message) Result {
	if m.sender != a.Binding.Sender || m.reference == "" {
		return Result{Outcome: Rejected, ErrorCode: "provider_rejected"}
	}
	outcome := Result{Outcome: Rejected, ErrorCode: "provider_rejected"}
	_, err := a.Store.Update(ctx, a.Binding, func(c GmailCredential) (GmailCredential, Readiness) {
		token, next, ready := a.Gmail.refreshToken(ctx, c)
		if token == nil {
			return next, ready
		}
		if check := a.Gmail.verify(ctx, token, next.Mailbox, a.Binding.Sender); check.Status != Ready {
			return next, check
		}
		// Private validated fields prevent recipient/header injection. Base64 MIME
		// transfer encoding keeps Unicode display names/body out of header parsing.
		encoded := base64.StdEncoding.EncodeToString([]byte(m.text))
		var bodyLines strings.Builder
		for len(encoded) > 76 {
			bodyLines.WriteString(encoded[:76] + "\r\n")
			encoded = encoded[76:]
		}
		bodyLines.WriteString(encoded + "\r\n")
		raw := "From: " + m.sender + "\r\nTo: " + m.recipient + "\r\nSubject: " + mime.QEncoding.Encode("utf-8", m.subject) + "\r\nMessage-ID: <" + m.reference + "@vgca.invalid>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n" + bodyLines.String()
		body, _ := json.Marshal(struct {
			Raw string `json:"raw"`
		}{base64.RawURLEncoding.EncodeToString([]byte(raw))})
		req, _ := http.NewRequestWithContext(ctx, "POST", a.Gmail.sendURL, strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token.AccessToken)
		response, err := a.Gmail.client.Do(req)
		if err != nil {
			outcome = Result{Outcome: Uncertain, ErrorCode: "provider_uncertain"}
			return next, gmailFailure(503)
		}
		defer response.Body.Close()
		if response.StatusCode >= 500 || response.StatusCode == 408 {
			outcome = Result{Outcome: Uncertain, ErrorCode: "provider_uncertain"}
			return next, gmailFailure(response.StatusCode)
		}
		if response.StatusCode != 200 {
			return next, gmailFailure(response.StatusCode)
		}
		var reply struct {
			ID string `json:"id"`
		}
		data, err := io.ReadAll(io.LimitReader(response.Body, 4097))
		if err != nil || len(data) > 4096 || json.Unmarshal(data, &reply) != nil || reply.ID == "" {
			outcome = Result{Outcome: Uncertain, ErrorCode: "provider_uncertain"}
			return next, gmailFailure(503)
		}
		outcome = Result{Outcome: Accepted, ProviderMessageID: reply.ID}
		return next, Readiness{Status: Ready, Code: "ready"}
	})
	if err != nil || !outcome.Validate() {
		return Result{Outcome: Uncertain, ErrorCode: "provider_uncertain"}
	}
	return outcome
}
