package authconfig

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"golang.org/x/oauth2"
)

func TestDatabaseBindingIntegrity(t *testing.T) {
	f := newFixture(t)
	m := approvedRevision(t, f, 0)
	if err := activationFixture(t, f, m, 1, "", false); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	store, err := auth.NewPostgresStore(f.pool, auth.SessionConfig{IdleTimeout: 30 * time.Minute, AbsoluteTimeout: 8 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	token, flow := oauth2.GenerateVerifier(), oauth2.GenerateVerifier()
	hash, flowHash := sha256.Sum256([]byte(token)), sha256.Sum256([]byte(flow))
	_, err = f.owner.Exec(ctx, `INSERT INTO framework.sessions(token_hash,issuer,subject,provider,expires_at,binding_source,deployment_id,environment,revision_id,activation_generation,client_id)
        VALUES($1,$2,'synthetic-user','oidc',clock_timestamp()+interval '1 hour','database',$3,$4,$5,1,$6)`, hash[:], m.IssuerURL, m.DeploymentID, m.Environment, m.ID, m.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.owner.Exec(ctx, `INSERT INTO framework.oidc_login_flows(token_hash,state_hash,nonce,pkce_verifier,expires_at,binding_source,deployment_id,environment,revision_id,activation_generation,issuer,client_id)
        VALUES($1,$2,'nonce','verifier',clock_timestamp()+interval '5 minutes','database',$3,$4,$5,1,$6,$7)`, flowHash[:], hash[:], m.DeploymentID, m.Environment, m.ID, m.IssuerURL, m.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	expected := auth.Binding{Source: "database", DeploymentID: m.DeploymentID, Environment: m.Environment, RevisionID: m.ID, ActivationGeneration: 1, Issuer: m.IssuerURL, ClientID: m.ClientID, Purpose: "login"}
	b, err := store.SessionBinding(ctx, token)
	if err != nil || !b.MatchesDatabase(expected) {
		t.Fatal("bound session metadata incorrect")
	}
	fb, err := store.FlowBinding(ctx, flow)
	if err != nil || !fb.MatchesDatabase(expected) {
		t.Fatal("bound flow metadata incorrect")
	}
	for name, edit := range map[string]func(*auth.Binding){
		"deployment": func(b *auth.Binding) { b.DeploymentID = "other" }, "environment": func(b *auth.Binding) { b.Environment = "production" },
		"revision": func(b *auth.Binding) { b.RevisionID = "other" }, "generation": func(b *auth.Binding) { b.ActivationGeneration++ },
		"issuer": func(b *auth.Binding) { b.Issuer = "https://other.example.test" }, "client": func(b *auth.Binding) { b.ClientID = "other" },
		"purpose": func(b *auth.Binding) { b.Purpose = "normal_callback" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := expected
			edit(&bad)
			if b.MatchesDatabase(bad) {
				t.Fatal("incorrect binding accepted")
			}
		})
	}
	for _, table := range []string{"framework.sessions", "framework.oidc_login_flows"} {
		for _, change := range []string{"deployment_id='other'", "environment='production'", "activation_generation=2", "issuer='https://other.example.test'", "client_id='other'", "flow_purpose='normal_callback'"} {
			if _, err := f.owner.Exec(ctx, `UPDATE `+table+` SET `+change); err == nil {
				t.Fatal("binding mutation accepted")
			}
		}
	}
	// Test insertion constraints independently of the immutability trigger.
	for _, change := range []string{"deployment_id='other'", "environment='production'", "activation_generation=2", "activation_generation=NULL", "issuer='https://other.example.test'", "client_id='other'", "client_id=NULL", "flow_purpose='normal_callback'", "revision_id=NULL"} {
		tx, err := f.owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, `CREATE TEMP TABLE binding_candidate ON COMMIT DROP AS SELECT * FROM framework.sessions`)
		if err == nil {
			_, err = tx.Exec(ctx, `UPDATE binding_candidate SET token_hash=decode(repeat('ab',32),'hex')`)
		}
		if err == nil {
			_, err = tx.Exec(ctx, `UPDATE binding_candidate SET `+change)
		}
		if err == nil {
			_, err = tx.Exec(ctx, `INSERT INTO framework.sessions SELECT * FROM binding_candidate`)
		}
		_ = tx.Rollback(ctx)
		if err == nil {
			t.Fatal("invalid inserted binding accepted", change)
		}
	}
}
