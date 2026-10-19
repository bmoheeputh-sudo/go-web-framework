package auth

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/testdb"
	"golang.org/x/oauth2"
)

func TestLegacyBindingsMigration(t *testing.T) {
	pool, _ := testdb.New(t)
	ctx := context.Background()
	testdb.MigrationsThrough(t, pool, "up", 5)
	store, err := NewPostgresStore(pool, testSessionConfig())
	if err != nil {
		t.Fatal(err)
	}
	identity := Identity{Provider: OIDC, Issuer: "https://issuer.example.test", Subject: "legacy-user"}
	expires := time.Now().Add(time.Hour)
	session, err := store.addSession(ctx, identity, expires, "")
	if err != nil {
		t.Fatal(err)
	}
	state := oauth2.GenerateVerifier()
	flow, err := store.addFlow(ctx, loginFlow{State: state, Nonce: "synthetic", Verifier: oauth2.GenerateVerifier(), Expires: time.Now().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	migration, err := os.ReadFile("../../../database/migrations/000006_auth_activation.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, string(migration)); err != nil {
		t.Fatal(err)
	}
	for name, read := range map[string]func() (Binding, error){"session": func() (Binding, error) { return store.SessionBinding(ctx, session) }, "flow": func() (Binding, error) { return store.FlowBinding(ctx, flow) }} {
		t.Run(name, func(t *testing.T) {
			b, err := read()
			if err != nil || b.Source != "legacy" || b.RevisionID != "" || b.ActivationGeneration != 0 || b.DeploymentID != "" || b.Purpose != "login" {
				t.Fatal("legacy row rebound")
			}
			expected := b
			expected.Source = "database"
			expected.RevisionID = "11111111-1111-4111-8111-111111111111"
			expected.ActivationGeneration = 1
			if b.MatchesDatabase(expected) {
				t.Fatal("legacy session qualified for database authentication")
			}
		})
	}
	var actual time.Time
	if err := pool.QueryRow(ctx, `SELECT expires_at FROM framework.sessions WHERE token_hash=$1`, tokenHash(session)).Scan(&actual); err != nil || actual.Sub(expires).Abs() > time.Microsecond {
		t.Fatal("session expiry changed")
	}
	if got, err := store.identity(ctx, session); err != nil || got != identity {
		t.Fatal("existing environment session broken")
	}
	if _, err := store.takeFlow(ctx, flow, state); err != nil {
		t.Fatal("existing environment login flow broken")
	}
	if _, err := store.takeFlow(ctx, flow, state); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("flow replay accepted")
	}
	fresh, err := store.addSession(ctx, identity, expires, "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := store.SessionBinding(ctx, fresh)
	if err != nil || b.Source != "legacy" {
		t.Fatal("unchanged environment writer enrolled session")
	}
	_, err = pool.Exec(ctx, `UPDATE framework.sessions SET binding_source='environment',deployment_id='installation-a',environment='development',client_id='test-client' WHERE token_hash=$1`, tokenHash(session))
	if err == nil {
		t.Fatal("legacy binding could be reclassified")
	}
	for _, token := range []string{"malformed", oauth2.GenerateVerifier()} {
		if _, err := store.SessionBinding(ctx, token); !errors.Is(err, ErrUnauthenticated) {
			t.Fatal("invalid or absent token accepted")
		}
	}
}

func TestEnvironmentBindingPersistence(t *testing.T) {
	pool, _ := testdb.New(t)
	ctx := context.Background()
	testdb.Migrations(t, pool, "up")
	store, _ := NewPostgresStore(pool, testSessionConfig())
	session, flow := oauth2.GenerateVerifier(), oauth2.GenerateVerifier()
	_, err := pool.Exec(ctx, `INSERT INTO framework.sessions(token_hash,issuer,subject,provider,expires_at,binding_source,deployment_id,environment,client_id)
        VALUES($1,'https://issuer.example.test','user','oidc',clock_timestamp()+interval '1 hour','environment','installation-a','development','client')`, tokenHash(session))
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(ctx, `INSERT INTO framework.oidc_login_flows(token_hash,state_hash,nonce,pkce_verifier,expires_at,binding_source,deployment_id,environment,issuer,client_id)
        VALUES($1,$2,'nonce','verifier',clock_timestamp()+interval '5 minutes','environment','installation-a','development','https://issuer.example.test','client')`, tokenHash(flow), tokenHash("state"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := store.SessionBinding(ctx, session)
	if err != nil || b.Source != "environment" || b.RevisionID != "" || b.ClientID != "client" || b.DeploymentID != "installation-a" {
		t.Fatal("environment session binding not preserved")
	}
	fb, err := store.FlowBinding(ctx, flow)
	if err != nil || fb != b {
		t.Fatal("environment flow binding not preserved")
	}
	if b.MatchesDatabase(b) {
		t.Fatal("environment binding qualifies as database")
	}
	pool.Close()
	if _, err := store.SessionBinding(ctx, session); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatal("database error leaked")
	}
}
