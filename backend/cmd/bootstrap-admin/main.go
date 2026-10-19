// bootstrap-admin is a one-time operator tool, never an HTTP endpoint.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/database"
)

func run(args []string, getenv func(string) string) error {
	flags := flag.NewFlagSet("bootstrap-admin", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	issuer := flags.String("issuer", "", "Exact issuer from a verified /api/auth/me response")
	subject := flags.String("subject", "", "Exact subject from that verified response")
	confirmed := flags.Bool("confirm-verified-identity", false, "Confirm the operator verified the issuer and subject")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !*confirmed || *issuer == "" || *subject == "" {
		return errors.New("required: --issuer <verified issuer> --subject <verified subject> --confirm-verified-identity; target must first call /api/access/me after authentication")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, getenv)
	if err != nil {
		return err
	}
	defer pool.Close()
	store := access.New(pool)
	if err = store.Check(ctx); err != nil {
		return errors.New("RBAC schema unavailable; apply migration 000004 with approval first")
	}
	err = store.Bootstrap(ctx, *issuer, *subject, getenv("APP_ENV"))
	if errors.Is(err, access.ErrConflict) {
		return errors.New("bootstrap already used or an administrator already exists")
	}
	if errors.Is(err, access.ErrDenied) {
		return errors.New("target is not an active previously verified identity, or Local DEV is not allowed in this environment")
	}
	if err != nil {
		return errors.New("bootstrap failed; check schema and operator database privileges")
	}
	return nil
}
func main() {
	if err := run(os.Args[1:], os.Getenv); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("Administrator bootstrap completed and audited. Restore runtime database credentials before starting the application.")
}
