// Package notifications defines delivery contracts, not authentication policy.
// It contains no real provider transport and is not started by the server.
package notifications

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var ErrInvalid = errors.New("notification_invalid")

const TemplateVersion = "onboarding.v1"
const GmailScope = "https://www.googleapis.com/auth/gmail.send"

type Outcome string

const (
	Accepted  Outcome = "accepted" // Provider acceptance only; never inbox delivery.
	Rejected  Outcome = "rejected" // Explicit non-acceptance; no silent retry.
	Uncertain Outcome = "uncertain"
)

type Result struct {
	Outcome           Outcome
	ProviderMessageID string
	ErrorCode         string
}

func (r Result) Validate() bool {
	if r.Outcome != Accepted && r.Outcome != Rejected && r.Outcome != Uncertain {
		return false
	}
	if len(r.ProviderMessageID) > 256 || strings.ContainsFunc(r.ProviderMessageID, unicode.IsControl) {
		return false
	}
	if r.Outcome == Accepted {
		return r.ErrorCode == ""
	}
	return r.ProviderMessageID == "" && ((r.Outcome == Rejected && r.ErrorCode == "provider_rejected") || (r.Outcome == Uncertain && r.ErrorCode == "provider_uncertain"))
}

// Message has private fields and is passed by value. Only the approved template
// renderer can construct one; adapters cannot replace its sender or recipients.
type Message struct{ sender, recipient, subject, text, html, reference string }

func (m Message) Sender() string           { return m.sender }
func (m Message) Recipient() string        { return m.recipient }
func (m Message) Subject() string          { return m.subject }
func (m Message) Text() string             { return m.text }
func (m Message) HTML() string             { return m.html }
func (m Message) Reference() string        { return m.reference }
func (Message) Format(w fmt.State, _ rune) { _, _ = fmt.Fprint(w, "[NOTIFICATION MESSAGE]") }

type Adapter interface {
	Provider() string
	Send(context.Context, Message) Result
}

// Future authenticated SES event handlers normalize evidence here, independently
// of Send's acceptance result. No public event endpoint exists in this phase.
type ProviderEvent struct {
	ConnectorID, EventID, ProviderMessageID string
	Kind                                    string // delivery, bounce or complaint; never proof of onboarding.
}

var referencePattern = regexp.MustCompile(`^vgca\.[0-9a-f-]{36}$`)

func mailbox(value string) bool {
	a, err := mail.ParseAddress(value)
	return err == nil && a.Address == value && a.Name == "" && len(value) <= 254 && !strings.ContainsFunc(value, unicode.IsControl)
}
func Locale(value string) bool {
	switch value {
	case "en", "nl", "fr", "es", "pt-BR", "zh-CN", "id", "ms", "th", "vi", "hi", "ar":
		return true
	}
	return false
}

// Template supplies only approved personalization. Localized editorial content
// is intentionally deferred to 10.4C; locale and version remain pinned now.
type Template struct{ loginURL string }

func NewTemplate(origin string) (Template, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Path != "" || u.Opaque != "" {
		return Template{}, ErrInvalid
	}
	return Template{origin + "/api/auth/login"}, nil
}
func (t Template) Render(kind, version, locale, sender, recipient, name, reference string) (Message, error) {
	if t.loginURL == "" || (kind != "invitation" && kind != "reminder") || version != TemplateVersion || !Locale(locale) || !mailbox(sender) || !mailbox(recipient) || !referencePattern.MatchString(reference) || !utf8.ValidString(name) || utf8.RuneCountInString(name) > 200 || strings.ContainsFunc(name, unicode.IsControl) {
		return Message{}, ErrInvalid
	}
	// Fixed subject and escaped variables: no arbitrary HTML, headers, links,
	// credentials, roles, subjects or OIDC identity assertions are accepted.
	subject := "VGCA invitation"
	if kind == "reminder" {
		subject = "VGCA onboarding reminder"
	}
	text := "Hello " + name + ",\n\nSign in to VGCA: " + t.loginURL + "\nYour organization's authentication and access rules apply."
	html := "<p>Hello " + template.HTMLEscapeString(name) + ",</p><p><a href=\"" + template.HTMLEscapeString(t.loginURL) + "\">Sign in to VGCA</a></p><p>Your organization&#39;s authentication and access rules apply.</p>"
	return Message{sender, recipient, subject, text, html, reference}, nil
}
