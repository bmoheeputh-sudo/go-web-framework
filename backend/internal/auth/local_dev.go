package auth

import (
	"errors"
	"fmt"
	"net"
	"net/http"
)

const LocalDevIssuer = "urn:go-web-framework:local-dev"

type LocalDevConfig struct {
	Subject     string
	Email       string
	DisplayName string
}

// LocalDevAuthenticator holds one immutable, server-configured development identity. It does
// not accept credentials or identity claims from headers, cookies or query data,
// and it never creates a session or asserts that an email was verified.
type LocalDevAuthenticator struct {
	identity Identity
}

func NewLocalDev(appEnv string, config LocalDevConfig) (*LocalDevAuthenticator, error) {
	if appEnv != "development" {
		return nil, errors.New("local_dev authentication requires APP_ENV=development")
	}
	if config.Subject == "" || config.Email == "" || config.DisplayName == "" {
		return nil, errors.New("local_dev requires LOCAL_DEV_SUBJECT, LOCAL_DEV_EMAIL and LOCAL_DEV_DISPLAY_NAME")
	}
	identity := Identity{
		Issuer: LocalDevIssuer, Subject: config.Subject, Email: config.Email,
		DisplayName: config.DisplayName, Provider: LocalDev, EmailVerified: false,
	}
	if err := identity.Validate(); err != nil {
		return nil, fmt.Errorf("invalid local_dev identity: %w", err)
	}
	return &LocalDevAuthenticator{identity: identity}, nil
}

func (p *LocalDevAuthenticator) Authenticate(r *http.Request) (Identity, error) {
	// Defense in depth in addition to the server's loopback-only listener. Proxy
	// forwarding headers are deliberately ignored; RemoteAddr is the TCP peer.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || !net.ParseIP(host).IsLoopback() || p.identity.Provider != LocalDev {
		return Identity{}, ErrUnauthenticated
	}
	return p.identity, nil
}
