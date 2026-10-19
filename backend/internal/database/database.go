// Package database owns validated connection settings and pool lifecycle.
package database

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func Config(getenv func(string) string) (*pgxpool.Config, error) {
	host, name, user, password := getenv("DB_HOST"), getenv("DB_NAME"), getenv("DB_USER"), getenv("DB_PASSWORD")
	if host == "" || name == "" || user == "" || password == "" {
		return nil, errors.New("DB_HOST, DB_NAME, DB_USER and DB_PASSWORD are required for PostgreSQL")
	}
	port := getenv("DB_PORT")
	if port == "" {
		port = "5432"
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return nil, errors.New("DB_PORT must be between 1 and 65535")
	}
	mode := getenv("DB_SSLMODE")
	if mode == "" {
		mode = "verify-full"
	}
	if mode != "verify-full" && mode != "disable" {
		return nil, errors.New("DB_SSLMODE must be verify-full, or disable for local development only")
	}
	local := host == "localhost" || net.ParseIP(host).IsLoopback()
	if mode == "disable" && (getenv("APP_ENV") != "development" || !local) {
		return nil, errors.New("unencrypted PostgreSQL is allowed only on loopback in APP_ENV=development")
	}
	if getenv("APP_ENV") != "development" && getenv("DB_SSLROOTCERT") == "" {
		return nil, errors.New("DB_SSLROOTCERT is required outside development")
	}
	// Encode credential characters safely. ParseConfig errors can contain DSNs.
	u := &url.URL{Scheme: "postgres", Host: net.JoinHostPort(host, port), Path: "/" + name, User: url.UserPassword(user, password)}
	query := url.Values{"sslmode": {mode}, "connect_timeout": {"5"}}
	if ca := getenv("DB_SSLROOTCERT"); ca != "" {
		query.Set("sslrootcert", ca)
	}
	u.RawQuery = query.Encode()
	config, err := pgxpool.ParseConfig(u.String())
	if err != nil {
		return nil, errors.New("invalid PostgreSQL settings or TLS CA file")
	}
	config.MaxConns = 10
	if value := getenv("DB_MAX_CONNS"); value != "" {
		limit, err := strconv.Atoi(value)
		if err != nil || limit < 1 || limit > 100 {
			return nil, errors.New("DB_MAX_CONNS must be between 1 and 100")
		}
		config.MaxConns = int32(limit)
	}
	config.MinConns = 0
	config.MaxConnLifetime = 30 * time.Minute
	config.MaxConnIdleTime = 5 * time.Minute
	config.HealthCheckPeriod = time.Minute
	config.ConnConfig.ConnectTimeout = 5 * time.Second
	config.ConnConfig.RuntimeParams["statement_timeout"] = "5000"
	config.ConnConfig.RuntimeParams["lock_timeout"] = "2000"
	config.ConnConfig.RuntimeParams["idle_in_transaction_session_timeout"] = "5000"
	config.ConnConfig.RuntimeParams["application_name"] = "go-web-framework"
	if strings.Contains(host, ",") {
		return nil, errors.New("DB_HOST must specify one PostgreSQL host")
	}
	return config, nil
}

func Open(ctx context.Context, getenv func(string) string) (*pgxpool.Pool, error) {
	config, err := Config(getenv)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, errors.New("PostgreSQL pool initialization failed")
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, errors.New("PostgreSQL unavailable; check DB settings, service and TLS trust")
	}
	if err := CheckSchema(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	return pool, nil
}

// Read-only readiness checks. Migrations are always a separate manual action.
func CheckSchema(ctx context.Context, pool *pgxpool.Pool) error {
	for _, query := range []string{
		`SELECT token_hash, issuer, subject, email, email_verified, display_name, provider,
		 created_at, expires_at, last_activity_at FROM framework.sessions LIMIT 0`,
		`SELECT token_hash, state_hash, nonce, pkce_verifier, expires_at FROM framework.oidc_login_flows LIMIT 0`,
	} {
		if _, err := pool.Exec(ctx, query); err != nil {
			return errors.New("PostgreSQL session schema unavailable; review and apply the versioned migrations manually")
		}
	}
	return nil
}
