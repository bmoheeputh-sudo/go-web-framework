package auth

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Binding is persistence metadata, not an authentication decision. Legacy rows
// remain environment-only and must never be inferred to belong to a DB revision.
// Read methods do not touch activity, consume flows, or return credentials.
type Binding struct {
	Source               string
	DeploymentID         string
	Environment          string
	RevisionID           string
	ActivationGeneration int64
	Issuer               string
	ClientID             string
	Purpose              string
}

// MatchesDatabase is deliberately exact; absence of a binding is never a match.
// Future authentication must additionally enforce expiration, revocation and the
// authoritative activation policy. This method alone grants no access.
func (b Binding) MatchesDatabase(expected Binding) bool {
	return b.Source == "database" && expected.Source == "database" && b.RevisionID != "" &&
		b.DeploymentID != "" && b.Environment != "" && b.Issuer != "" && b.ClientID != "" &&
		b.ActivationGeneration > 0 && b.Purpose == "login" && b == expected
}

func (s *PostgresStore) SessionBinding(ctx context.Context, token string) (Binding, error) {
	return s.readBinding(ctx, token, false)
}
func (s *PostgresStore) FlowBinding(ctx context.Context, token string) (Binding, error) {
	return s.readBinding(ctx, token, true)
}
func (s *PostgresStore) readBinding(ctx context.Context, token string, flow bool) (Binding, error) {
	if !validToken(token) {
		return Binding{}, ErrUnauthenticated
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	// Table selection is code-owned, never request-controlled.
	table := "framework.sessions"
	if flow {
		table = "framework.oidc_login_flows"
	}
	var b Binding
	err := s.db.QueryRow(ctx, `SELECT binding_source,COALESCE(deployment_id,''),COALESCE(environment,''),
      COALESCE(revision_id::text,''),COALESCE(activation_generation,0),COALESCE(issuer,''),COALESCE(client_id,''),flow_purpose
      FROM `+table+` WHERE token_hash=$1`, tokenHash(token)).Scan(&b.Source, &b.DeploymentID, &b.Environment, &b.RevisionID, &b.ActivationGeneration, &b.Issuer, &b.ClientID, &b.Purpose)
	if errors.Is(err, pgx.ErrNoRows) {
		return Binding{}, ErrUnauthenticated
	}
	if err != nil {
		return Binding{}, ErrStoreUnavailable
	}
	return b, nil
}
