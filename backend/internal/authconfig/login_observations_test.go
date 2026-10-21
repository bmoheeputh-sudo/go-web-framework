package authconfig

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/jackc/pgx/v5"
	"golang.org/x/oauth2"
)

func normalSessionWrite(identity auth.Identity) func(context.Context, pgx.Tx) error {
	return func(ctx context.Context, tx pgx.Tx) error {
		hash := sha256.Sum256([]byte(oauth2.GenerateVerifier()))
		_, err := tx.Exec(ctx, `INSERT INTO framework.sessions(token_hash,issuer,subject,provider,expires_at) VALUES($1,$2,$3,'oidc',clock_timestamp()+interval '1 hour')`, hash[:], identity.Issuer, identity.Subject)
		return err
	}
}
func observations(t *testing.T, f *fixture, subject string) (*time.Time, *time.Time) {
	t.Helper()
	var first, last *time.Time
	if err := f.owner.QueryRow(context.Background(), `SELECT first_successful_oidc_login_at,last_successful_oidc_login_at FROM framework.users WHERE subject=$1`, subject).Scan(&first, &last); err != nil {
		t.Fatal(err)
	}
	return first, last
}
func TestSuccessfulOIDCLoginObservations(t *testing.T) {
	a := newAdmissionFixture(t)
	if first, last := observations(t, a.f, "enrolled-admin"); first != nil || last != nil {
		t.Fatal("readiness/enrollment fabricated history")
	}
	a.changePolicy(t, "allow_all", "Viewer", []string{"example.test"})
	policyUser(t, a.f, "existing-unobserved", "unobserved@example.test", "User", true)
	if first, last := observations(t, a.f, "existing-unobserved"); first != nil || last != nil {
		t.Fatal("user creation inferred history")
	}
	for _, subject := range []string{"new-observation", "existing-unobserved"} {
		sessionCookieFor(t, a.login(t, subject, subject+"@example.test", true))
		first, last := observations(t, a.f, subject)
		if first == nil || last == nil || !first.Equal(*last) {
			t.Fatal("first login not observed atomically")
		}
		sessionCookieFor(t, a.login(t, subject, subject+"@example.test", true))
		first2, last2 := observations(t, a.f, subject)
		if !first2.Equal(*first) || !last2.After(*last) {
			t.Fatal("first changed or last did not advance")
		}
		if _, err := a.f.owner.Exec(context.Background(), `UPDATE framework.users SET first_successful_oidc_login_at=clock_timestamp() WHERE subject=$1`, subject); err == nil {
			t.Fatal("first observation mutable")
		}
	}
	if _, err := a.f.owner.Exec(context.Background(), `CREATE FUNCTION framework.reject_observed_session() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic session failure'; END $$; CREATE TRIGGER reject_observed_session BEFORE INSERT ON framework.sessions FOR EACH ROW EXECUTE FUNCTION framework.reject_observed_session()`); err != nil {
		t.Fatal(err)
	}
	first, last := observations(t, a.f, "existing-unobserved")
	if !loginDenied(a.login(t, "existing-unobserved", "changed@example.test", true)) {
		t.Fatal("failed session succeeded")
	}
	first2, last2 := observations(t, a.f, "existing-unobserved")
	if !first2.Equal(*first) || !last2.Equal(*last) {
		t.Fatal("failed session updated observations")
	}
}

func TestLoginObservationRequiresSuccessfulExactSession(t *testing.T) {
	f, p := policyFixture(t)
	bootstrapPolicy(t, f, p)
	f.run(t, func(ctx context.Context) {
		if _, err := p.Update(ctx, PolicyExpectation{1, 1}, AccessPolicySettings{"allow_all", nil, "Viewer"}, "allow normal observation checks"); err != nil {
			t.Fatal(err)
		}
	})
	identity := auth.Identity{Issuer: f.identity.Issuer, Subject: "no-session", Provider: auth.OIDC}
	admission := f.store.OIDCAdmission(f.repo.scope.DeploymentID, f.repo.scope.Environment)
	if err := admission.Login(context.Background(), identity, auth.Binding{}, func(context.Context, pgx.Tx) error { return nil }); err == nil {
		t.Fatal("observation without session")
	}
	var count int
	if err := f.owner.QueryRow(context.Background(), `SELECT count(*) FROM framework.users WHERE subject='no-session'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("incomplete transaction provisioned user", err)
	}
	identity.Subject = "wrong-session"
	wrong := identity
	wrong.Subject = "another-identity"
	if err := admission.Login(context.Background(), identity, auth.Binding{}, normalSessionWrite(wrong)); err == nil {
		t.Fatal("wrong exact identity observed")
	}
	policyUser(t, f, "existing-history-unknown", "unknown@vopak.com", "Viewer", true)
	if _, err := f.owner.Exec(context.Background(), `UPDATE framework.users SET first_successful_oidc_login_at=clock_timestamp(),last_successful_oidc_login_at=clock_timestamp() WHERE subject='existing-history-unknown'`); err == nil {
		t.Fatal("administrator fabricated observation")
	}
}
