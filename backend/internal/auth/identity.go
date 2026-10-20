// Package auth defines the identity shared by authentication providers.
package auth

import (
	"errors"
	"net/mail"
	"strings"
	"unicode"
)

type Provider string

const (
	OIDC     Provider = "oidc"
	LocalDev Provider = "local_dev"
)

// Identity is the result of authentication, never a client-supplied login payload.
// Issuer and Subject together identify a user; email is not a stable identifier.
// Email and DisplayName are optional because upstream providers may omit them.
type Identity struct {
	Issuer        string   `json:"issuer"`
	Subject       string   `json:"subject"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	DisplayName   string   `json:"display_name"`
	Provider      Provider `json:"provider"`
}

// Validate checks the normalized identity's shape, not credential authenticity.
// Each provider must verify its own credentials before returning an Identity.
func (i Identity) Validate() error {
	if i.Issuer == "" || i.Subject == "" {
		return errors.New("identity requires issuer and subject")
	}
	for _, value := range []string{i.Issuer, i.Subject, i.Email, i.DisplayName} {
		if strings.TrimSpace(value) != value || strings.ContainsFunc(value, unicode.IsControl) {
			return errors.New("identity fields cannot contain surrounding whitespace or control characters")
		}
	}
	switch i.Provider {
	case OIDC, LocalDev:
	default:
		return errors.New("identity has an unsupported authentication provider")
	}
	if i.Email != "" {
		address, err := mail.ParseAddress(i.Email)
		if err != nil || address.Address != i.Email {
			return errors.New("identity email must be a plain email address")
		}
	} else if i.EmailVerified {
		return errors.New("identity cannot verify an absent email")
	}
	return nil
}
