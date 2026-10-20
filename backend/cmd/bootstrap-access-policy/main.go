// bootstrap-access-policy initializes policy for an already active database
// OIDC deployment. It is an offline rollout command, never a login endpoint.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/authconfig"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/database"
)

func run(args []string, getenv func(string) string, input io.Reader) error {
	flags := flag.NewFlagSet("bootstrap-access-policy", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	generation := flags.Int64("expected-activation-generation", -1, "Current database activation generation")
	mode := flags.String("mode", "", "allow_all or approved_users_only")
	role := flags.String("default-role", "", "Viewer or User")
	domains := flags.String("allowed-domains", "", "Optional comma-separated exact email domains")
	reason := flags.String("reason", "", "Audited reason (8–512 characters)")
	confirm := flags.Bool("confirm", false, "Explicitly initialize policy and approve the verified existing administrator")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !*confirm || *generation < 1 || (*mode != "allow_all" && *mode != "approved_users_only") || (*role != "Viewer" && *role != "User") {
		return errors.New("required: --expected-activation-generation N --mode allow_all|approved_users_only --default-role Viewer|User --reason 'rollout reason' --confirm; supply existing OIDC session cookie on stdin, never in arguments")
	}
	scope, err := authconfig.ScopeFromEnv(getenv)
	if err != nil {
		return errors.New("trusted deployment/environment scope is required")
	}
	sessions, err := auth.SessionConfigFromEnv(getenv)
	if err != nil {
		return errors.New("invalid trusted session configuration")
	}
	raw, err := io.ReadAll(io.LimitReader(input, 46))
	if err != nil {
		return errors.New("session input unavailable")
	}
	defer clear(raw)
	token := strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
	if len(token) != 43 {
		return errors.New("a current database-bound OIDC administrator session is required on stdin")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, getenv)
	if err != nil {
		return errors.New("database unavailable; bootstrap made no confirmed changes")
	}
	defer pool.Close()
	repo, err := authconfig.NewAccessPolicyRepository(access.New(pool), scope)
	if err != nil {
		return errors.New("access policy repository unavailable")
	}
	settings := authconfig.AccessPolicySettings{Mode: *mode, DefaultRole: *role, AllowedEmailDomains: []string{}}
	if *domains != "" {
		settings.AllowedEmailDomains = strings.Split(*domains, ",")
	}
	_, err = repo.BootstrapSession(ctx, token, *generation, sessions.IdleTimeout, settings, *reason)
	if errors.Is(err, authconfig.ErrCommitUncertain) {
		return errors.New("bootstrap commit outcome uncertain; inspect authoritative policy and audit state before retrying")
	}
	if err != nil {
		return errors.New("bootstrap refused; verify migration 000008, current bound administrator session, generation, eligible domains and absence of an existing policy")
	}
	return nil
}
func main() {
	if err := run(os.Args[1:], os.Getenv, os.Stdin); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("Access policy and exact administrator approval initialized and audited. No roles or authentication providers changed.")
}
