// auth-recovery is an offline break-glass operator tool, never an HTTP endpoint.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/authconfig"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/database"
	"github.com/jackc/pgx/v5/pgxpool"
)

type workflow interface {
	Prepare(context.Context, string, int64, string) (authconfig.RecoveryPreview, error)
	Recover(context.Context) (authconfig.RecoveryResult, error)
	Close()
}

type liveWorkflow struct {
	pool     *pgxpool.Pool
	operator *authconfig.OfflineOperator
	service  *authconfig.RecoveryService
	prepared *authconfig.PreparedRecovery
}

func (w *liveWorkflow) Prepare(ctx context.Context, revision string, generation int64, reason string) (authconfig.RecoveryPreview, error) {
	prepared, err := w.service.Prepare(ctx, w.operator, revision, generation, reason)
	if err != nil {
		return authconfig.RecoveryPreview{}, err
	}
	w.prepared = prepared
	return prepared.Preview(), nil
}
func (w *liveWorkflow) Recover(ctx context.Context) (authconfig.RecoveryResult, error) {
	return w.service.Recover(ctx, w.operator, w.prepared)
}
func (w *liveWorkflow) Close() {
	if w.prepared != nil {
		w.prepared.Close()
	}
	if w.pool != nil {
		w.pool.Close()
	}
}

type opener func(context.Context, func(string) string, *authconfig.OfflineOperator) (workflow, error)

func openLive(ctx context.Context, getenv func(string) string, operator *authconfig.OfflineOperator) (workflow, error) {
	pool, err := database.Open(ctx, getenv)
	if err != nil {
		return nil, errors.New("recovery database unavailable or schema is not current")
	}
	store := access.New(pool)
	scope, err := authconfig.ScopeFromEnv(getenv)
	if err != nil {
		pool.Close()
		return nil, errors.New("invalid trusted deployment scope")
	}
	cipher, err := authconfig.CipherFromEnv(getenv)
	if err != nil {
		pool.Close()
		return nil, errors.New("required authentication encryption key is unavailable")
	}
	repo, err := authconfig.NewRepository(store, scope, cipher)
	if err != nil {
		pool.Close()
		return nil, errors.New("authentication configuration repository unavailable")
	}
	sessions, err := auth.SessionConfigFromEnv(getenv)
	if err != nil {
		pool.Close()
		return nil, errors.New("invalid session configuration")
	}
	postgres, err := auth.NewPostgresStore(pool, sessions)
	if err != nil {
		pool.Close()
		return nil, errors.New("session store unavailable")
	}
	if getenv("AUTH_PROVIDER") == "google_iap" {
		return nil, errors.New("AUTH_PROVIDER=google_iap is no longer supported")
	}
	service, err := authconfig.NewRecoveryService(repo, postgres, sessions, getenv("APP_ORIGIN")+"/api/auth/callback")
	if err != nil {
		pool.Close()
		return nil, errors.New("offline OIDC recovery is not permitted for this deployment")
	}
	return &liveWorkflow{pool: pool, operator: operator, service: service}, nil
}

func safeRecoveryError(err error) error {
	switch {
	case errors.Is(err, authconfig.ErrCommitUncertain):
		return errors.New("recovery commit outcome is uncertain; do not retry—inspect the scoped activation head and recovery audit first")
	case errors.Is(err, authconfig.ErrDenied):
		return errors.New("offline recovery authorization was denied")
	case errors.Is(err, authconfig.ErrConflict):
		return errors.New("recovery conflicts with the current activation generation or revision state")
	case errors.Is(err, authconfig.ErrNotFound):
		return errors.New("eligible recovery revision was not found in the trusted deployment scope")
	case errors.Is(err, authconfig.ErrSecret):
		return errors.New("required authentication encryption key is unavailable")
	case errors.Is(err, authconfig.ErrInvalid):
		return errors.New("recovery input or revision configuration is invalid")
	default:
		return errors.New("offline recovery failed; no fallback was enabled")
	}
}

func run(args []string, getenv func(string) string, input io.Reader, output io.Writer, open opener) error {
	flags := flag.NewFlagSet("auth-recovery", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	deployment := flags.String("deployment", "", "Exact deployment scope")
	environment := flags.String("environment", "", "Exact environment scope")
	generation := flags.String("expected-generation", "", "Current activation generation")
	revision := flags.String("revision", "", "Approved immutable recovery revision UUID")
	reason := flags.String("reason", "", "Investigation/change reference")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *deployment == "" || *environment == "" || *generation == "" || *revision == "" || strings.TrimSpace(*reason) == "" {
		return errors.New("required: --deployment --environment --expected-generation --revision --reason")
	}
	expected, err := strconv.ParseInt(*generation, 10, 64)
	if err != nil || expected < 1 {
		return errors.New("expected activation generation must be a positive integer")
	}
	trusted, err := authconfig.ScopeFromEnv(getenv)
	if err != nil || *deployment != trusted.DeploymentID || *environment != trusted.Environment {
		return errors.New("requested scope does not match trusted deployment configuration")
	}
	operator, err := authconfig.OfflineOperatorFromEnv(getenv)
	if err != nil {
		return errors.New("offline recovery capability is not enabled or authorized")
	}
	defer operator.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	w, err := open(ctx, getenv, operator)
	if err != nil {
		return err
	}
	defer w.Close()
	preview, err := w.Prepare(ctx, *revision, expected, *reason)
	if err != nil {
		return safeRecoveryError(err)
	}
	fmt.Fprintf(output, "Offline OIDC recovery preview\nDeployment: %s\nEnvironment: %s\nOperator: %s\nAuthorization key: %s\nCurrent generation: %d\nTarget generation: %d\nCurrent revision: %s\nRecovery revision: %s\nHistorical source revision: %s\nIssuer: %s\nClient ID: %s\nReason: %s\nSession impact: immediate reauthentication; no previous-provider grace\n",
		preview.DeploymentID, preview.Environment, preview.OperatorID, preview.AuthorizationKeyID, preview.ExpectedGeneration, preview.TargetGeneration,
		preview.CurrentRevisionID, preview.TargetRevisionID, preview.SourceRevisionID, preview.IssuerURL, preview.ClientID, preview.Reason)
	confirmation := fmt.Sprintf("RECOVER %s/%s GENERATION %d REVISION %s", preview.DeploymentID, preview.Environment, preview.TargetGeneration, preview.TargetRevisionID)
	fmt.Fprintf(output, "Type exactly: %s\n> ", confirmation)
	reader := bufio.NewReader(io.LimitReader(input, 2048))
	line, readErr := reader.ReadString('\n')
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return errors.New("confirmation could not be read")
	}
	if strings.TrimSpace(line) != confirmation {
		return errors.New("recovery cancelled: confirmation did not match")
	}
	commitCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	result, err := w.Recover(commitCtx)
	if err != nil {
		return safeRecoveryError(err)
	}
	fmt.Fprintf(output, "Recovery committed for generation %d and revision %s. Instances will reconcile through PostgreSQL notification.\n", result.Generation, result.RevisionID)
	return nil
}

func main() {
	if err := run(os.Args[1:], os.Getenv, os.Stdin, os.Stdout, openLive); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
