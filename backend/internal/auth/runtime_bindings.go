package auth

import "context"

// The binding reader is separate from session mutation/expiration. Production
// PostgreSQL implements it; the existing test-only memory store is legacy-only.
type bindingReader interface {
	SessionBinding(context.Context, string) (Binding, error)
	FlowBinding(context.Context, string) (Binding, error)
}

type environmentBoundStore struct {
	sessionStore
	reader   bindingReader
	expected Binding
}

func (s environmentBoundStore) accepts(b Binding) bool {
	if b.Source == "legacy" {
		// Legacy sessions have an issuer; legacy flows do not. The original
		// OIDC authenticator still checks the session issuer and token claims.
		return b.DeploymentID == "" && b.Environment == "" && b.RevisionID == "" &&
			b.ActivationGeneration == 0 && b.ClientID == "" && b.Purpose == "login" &&
			(b.Issuer == "" || b.Issuer == s.expected.Issuer)
	}
	return b.Source == "environment" && s.expected.DeploymentID != "" &&
		s.expected.Environment != "" && b == s.expected
}

func (s environmentBoundStore) identity(ctx context.Context, token string) (Identity, error) {
	b, err := s.reader.SessionBinding(ctx, token)
	if err != nil {
		return Identity{}, err
	}
	if !s.accepts(b) {
		return Identity{}, ErrUnauthenticated
	}
	return s.sessionStore.identity(ctx, token)
}

func (s environmentBoundStore) takeFlow(ctx context.Context, token, state string) (loginFlow, error) {
	b, err := s.reader.FlowBinding(ctx, token)
	if err != nil {
		return loginFlow{}, err
	}
	if !s.accepts(b) {
		return loginFlow{}, ErrUnauthenticated
	}
	return s.sessionStore.takeFlow(ctx, token, state)
}
