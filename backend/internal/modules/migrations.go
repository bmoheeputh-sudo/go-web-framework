package modules

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/module"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MigrationPlan is derived exclusively from validated compile-time metadata.
// Journal is a table name in public, distinct from the core schema_migrations.
type MigrationPlan struct {
	ID, Schema, Directory, Journal string
	RequiredVersion                int64
}

func migrationPlan(id string, spec module.MigrationSpec) (MigrationPlan, error) {
	if !validID(id) || strings.HasPrefix(id, "pg_") || id == "information_schema" ||
		spec.Schema != id || spec.Directory != "database/modules/"+id+"/migrations" || spec.RequiredVersion < 1 {
		return MigrationPlan{}, fmt.Errorf("invalid migration metadata for module %q", id)
	}
	return MigrationPlan{ID: id, Schema: spec.Schema, Directory: spec.Directory, Journal: "schema_migrations_" + id, RequiredVersion: spec.RequiredVersion}, nil
}

// MigrationPlans returns copies for enabled modules only. No filesystem scans,
// SQL sources, credentials, or migration execution hooks are exposed.
func (r *Registry) MigrationPlans() []MigrationPlan {
	return append([]MigrationPlan{}, r.migrations...)
}

// CheckMigrations is read-only, including when a schema/journal is missing. Do not
// replace it with migrate.Version: initializing that driver can create a journal.
// A repeatable-read snapshot prevents mixing schema and version observations.
func (r *Registry) CheckMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	if len(r.migrations) == 0 {
		return nil
	}
	if pool == nil {
		return fmt.Errorf("enabled module migrations require PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return fmt.Errorf("module migration status unavailable")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	for _, plan := range r.migrations {
		var exists, usable bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname=$1),
   COALESCE((SELECT pg_catalog.has_schema_privilege(current_user,oid,'USAGE') FROM pg_catalog.pg_namespace WHERE nspname=$1),false)`, plan.Schema).Scan(&exists, &usable); err != nil {
			return migrationError(plan, "status unavailable")
		}
		if !exists {
			return migrationError(plan, "schema missing")
		}
		if !usable {
			return migrationError(plan, "schema inaccessible")
		}
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=$1 AND c.relkind='r')`, plan.Journal).Scan(&exists); err != nil {
			return migrationError(plan, "status unavailable")
		}
		if !exists {
			return migrationError(plan, "journal missing")
		}
		// Identifiers are validated/derived before SQL construction and additionally
		// quoted with pgx. No arbitrary table names or search_path changes are allowed.
		rows, err := tx.Query(ctx, `SELECT version,dirty FROM `+pgx.Identifier{"public", plan.Journal}.Sanitize()+` LIMIT 2`)
		if err != nil {
			return migrationError(plan, "journal unreadable")
		}
		count := 0
		var version int64
		var dirty bool
		for rows.Next() {
			count++
			if err := rows.Scan(&version, &dirty); err != nil {
				rows.Close()
				return migrationError(plan, "invalid journal")
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return migrationError(plan, "journal unreadable")
		}
		if count != 1 {
			return migrationError(plan, "journal must contain exactly one installed version")
		}
		if dirty {
			return migrationError(plan, "dirty migration state; inspect and repair manually")
		}
		if version != plan.RequiredVersion {
			return migrationError(plan, fmt.Sprintf("version %d installed; exactly %d required", version, plan.RequiredVersion))
		}
	}
	return nil
}
func migrationError(plan MigrationPlan, reason string) error {
	return fmt.Errorf("module %q: %s; review its independent migrations before startup", plan.ID, reason)
}
