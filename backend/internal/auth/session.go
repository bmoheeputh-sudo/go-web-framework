package auth

import (
	"context"
	"errors"
	"time"
)

const loginLifetime = 10 * time.Minute

var ErrStoreUnavailable = errors.New("session store unavailable")

type loginFlow struct {
	State, Nonce, Verifier string
	Expires                time.Time
}

// Sessions and one-use browser-bound login transactions are shared between
// backend instances. No OAuth tokens are persisted by this interface.
type sessionStore interface {
	addSession(context.Context, Identity, time.Time, string) (string, error)
	identity(context.Context, string) (Identity, error)
	deleteSession(context.Context, string) error
	addFlow(context.Context, loginFlow) (string, error)
	takeFlow(context.Context, string, string) (loginFlow, error)
}

type SessionConfig struct {
	IdleTimeout     time.Duration
	AbsoluteTimeout time.Duration
}

func SessionConfigFromEnv(getenv func(string) string) (SessionConfig, error) {
	config := SessionConfig{IdleTimeout: 30 * time.Minute, AbsoluteTimeout: 8 * time.Hour}
	for key, target := range map[string]*time.Duration{
		"SESSION_IDLE_TIMEOUT":     &config.IdleTimeout,
		"SESSION_ABSOLUTE_TIMEOUT": &config.AbsoluteTimeout,
	} {
		if value := getenv(key); value != "" {
			duration, err := time.ParseDuration(value)
			if err != nil {
				return SessionConfig{}, errors.New("session timeouts must be valid Go durations, such as 30m or 8h")
			}
			*target = duration
		}
	}
	if err := config.validate(); err != nil {
		return SessionConfig{}, err
	}
	return config, nil
}

func (c SessionConfig) validate() error {
	if c.IdleTimeout < time.Second || c.AbsoluteTimeout < time.Second ||
		c.IdleTimeout > c.AbsoluteTimeout || c.AbsoluteTimeout > 30*24*time.Hour {
		return errors.New("session timeouts must be at least 1s, idle <= absolute, and absolute <= 720h")
	}
	return nil
}
