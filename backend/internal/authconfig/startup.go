package authconfig

import (
	"context"
	"errors"
	"time"
)

var ErrDatabaseRuntimeRequired = errors.New("database authentication is required; runtime activation loading is not implemented")

// RequireEnvironmentStartup is read-only and independent of HTTP authorization.
// One SQL statement observes a consistent policy snapshot. Unknown/missing schema
// or a database error never means permission to run an environment provider.
func (r *ActivationReader) RequireEnvironmentStartup(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var exists, databaseRequired, cleanEnvironment, history, active, otherDatabase bool
	err := r.pool.QueryRow(ctx, `SELECT
 EXISTS(SELECT 1 FROM framework.auth_activation_heads WHERE deployment_id=$1 AND environment=$2),
 EXISTS(SELECT 1 FROM framework.auth_activation_heads WHERE deployment_id=$1 AND environment=$2 AND runtime_source='database'),
 EXISTS(SELECT 1 FROM framework.auth_activation_heads WHERE deployment_id=$1 AND environment=$2 AND runtime_source='environment' AND generation=0 AND active_revision_id IS NULL AND activated_at IS NULL),
 EXISTS(SELECT 1 FROM framework.auth_activation_history WHERE deployment_id=$1 AND environment=$2),
 EXISTS(SELECT 1 FROM framework.auth_config_lifecycle WHERE deployment_id=$1 AND environment=$2 AND status='active'),
 EXISTS(SELECT 1 FROM framework.auth_activation_heads WHERE runtime_source='database')`, r.scope.DeploymentID, r.scope.Environment).
		Scan(&exists, &databaseRequired, &cleanEnvironment, &history, &active, &otherDatabase)
	if err != nil {
		return ErrUnavailable
	}
	if databaseRequired {
		return ErrDatabaseRuntimeRequired
	}
	// A missing head in a DB with an enrolled deployment could be a mistyped
	// scope. Require an explicit environment head there; never guess a fallback.
	if history || active || (exists && !cleanEnvironment) || (!exists && otherDatabase) {
		return ErrUnavailable
	}
	return nil
}
