package authconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/testdb"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type fixture struct {
	owner, pool *pgxpool.Pool
	store       *access.Store
	repo        *Repository
	identity    auth.Identity
}
type fixedAuth struct{ identity auth.Identity }

func (f fixedAuth) Authenticate(*http.Request) (auth.Identity, error) { return f.identity, nil }
func newFixture(t *testing.T) *fixture {
	t.Helper()
	owner, connection := testdb.New(t)
	testdb.Migrations(t, owner, "up")
	config, err := pgxpool.ParseConfig(connection)
	if err != nil {
		t.Fatal("test config invalid")
	}
	config.ConnConfig.User = "go_web_app"
	config.ConnConfig.RuntimeParams["search_path"] = "pg_catalog"
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal("test pool unavailable")
	}
	t.Cleanup(pool.Close)
	store := access.New(pool)
	identity := auth.Identity{Issuer: "https://issuer.example.test", Subject: "config-admin", Provider: auth.OIDC}
	if _, err = store.Resolve(context.Background(), identity); err != nil {
		t.Fatal(err)
	}
	if err = access.New(owner).Bootstrap(context.Background(), identity.Issuer, identity.Subject, "development"); err != nil {
		t.Fatal(err)
	}
	repo, err := NewRepository(store, Scope{"installation-a", "development"}, testCipher(t, "key-v1"))
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{owner, pool, store, repo, identity}
}
func (f *fixture) run(t *testing.T, fn func(context.Context)) {
	t.Helper()
	called := false
	handler := auth.Require(fixedAuth{f.identity}, f.store.Require(access.AdminManage, "", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; fn(r.Context()); w.WriteHeader(204) })))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", "/test-only", nil))
	if !called || response.Code != 204 {
		t.Fatal("test administrator context unavailable")
	}
}
func (f *fixture) draft(t *testing.T, version int64) Metadata {
	t.Helper()
	var m Metadata
	f.run(t, func(ctx context.Context) {
		var err error
		m, err = f.repo.CreateDraft(ctx, version, testMetadata().Settings, NewSecret([]byte("fake-secret-for-tests")))
		if err != nil {
			t.Fatal(err)
		}
	})
	return m
}
func (f *fixture) counts(t *testing.T) string {
	t.Helper()
	var data string
	err := f.owner.QueryRow(context.Background(), `SELECT jsonb_build_array((SELECT count(*) FROM framework.auth_config_revisions),(SELECT COALESCE(jsonb_agg(to_jsonb(l) ORDER BY revision_id),'[]'::jsonb) FROM framework.auth_config_lifecycle l),(SELECT count(*) FROM framework.audit_log))::text`).Scan(&data)
	if err != nil {
		t.Fatal("test snapshot failed")
	}
	return data
}
func TestRepository(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.run(t, func(ctx context.Context) {
		if _, err := f.repo.CurrentActive(ctx); !errors.Is(err, ErrNotFound) {
			t.Fatal("migration activated configuration")
		}
	})
	first := f.draft(t, 0)
	t.Run("metadata secret access and no plaintext storage", func(t *testing.T) {
		f.run(t, func(ctx context.Context) {
			got, err := f.repo.Read(ctx, first.ID)
			if err != nil || got.Status != Draft || got.Generation != 1 || got.Version != 1 || !got.HasSecret || got.EncryptionKeyID != "key-v1" {
				t.Fatal("invalid draft metadata")
			}
			secret, err := f.repo.ReadSecretPrivileged(ctx, first.ID)
			if err != nil || !bytes.Equal(secret.Bytes(), []byte("fake-secret-for-tests")) {
				t.Fatal("secret retrieval failed")
			}
			list, err := f.repo.List(ctx, 0, 100)
			if err != nil || len(list) != 1 {
				t.Fatal("list failed")
			}
			version, err := f.repo.LatestVersion(ctx)
			if err != nil || version != 1 {
				t.Fatal("latest version failed")
			}
			data, err := json.Marshal(list)
			if err != nil || bytes.Contains(data, []byte("fake-secret-for-tests")) {
				t.Fatal("plaintext in metadata")
			}
		})
		var plaintext, nonces, ciphertext int
		err := f.owner.QueryRow(ctx, `SELECT count(*) FILTER (WHERE position(convert_to('fake-secret-for-tests','UTF8') IN secret_ciphertext)>0),min(octet_length(secret_nonce)),min(octet_length(secret_ciphertext)) FROM framework.auth_config_revisions`).Scan(&plaintext, &nonces, &ciphertext)
		if err != nil || plaintext != 0 || nonces != 12 || ciphertext <= 16 {
			t.Fatal("invalid encrypted storage")
		}
		var audits string
		if err = f.owner.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(a))::text FROM framework.audit_log a`).Scan(&audits); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(audits, "fake-secret-for-tests") || !strings.Contains(audits, "auth_config.secret_access") {
			t.Fatal("unsafe or missing audit")
		}
	})
	t.Run("immutable fields history and provider integrity", func(t *testing.T) {
		_, err := f.owner.Exec(ctx, `TRUNCATE framework.auth_config_revisions,framework.auth_config_lifecycle`)
		assertConstraint(t, err)
		for _, sql := range []string{`UPDATE framework.auth_config_revisions SET client_id='changed' WHERE id=$1`, `UPDATE framework.auth_config_revisions SET secret_ciphertext=decode('00','hex') WHERE id=$1`, `UPDATE framework.auth_config_revisions SET configuration_version=9 WHERE id=$1`, `DELETE FROM framework.auth_config_revisions WHERE id=$1`, `DELETE FROM framework.auth_config_lifecycle WHERE revision_id=$1`, `UPDATE framework.auth_config_lifecycle SET deployment_id='other',generation=generation+1,status='validated',validation='{"check":"static","version":1}' WHERE revision_id=$1`} {
			_, err := f.owner.Exec(ctx, sql, first.ID)
			assertConstraint(t, err)
		}
		for _, sql := range []string{
			// Otherwise-valid insertion without its lifecycle row must fail at commit.
			`INSERT INTO framework.auth_config_revisions SELECT gen_random_uuid(),deployment_id,environment,99,provider,issuer_url,client_id,redirect_uri,iap_audience,allow_http_development,secret_ciphertext,secret_nonce,encryption_format,encryption_key_id,created_by,created_at FROM framework.auth_config_revisions WHERE id=$1`,
			`INSERT INTO framework.auth_config_revisions SELECT gen_random_uuid(),deployment_id,environment,99,provider,issuer_url,client_id,'http://remote.example.test/api/auth/callback',iap_audience,true,secret_ciphertext,secret_nonce,encryption_format,encryption_key_id,created_by,created_at FROM framework.auth_config_revisions WHERE id=$1`,
			`INSERT INTO framework.auth_config_revisions SELECT gen_random_uuid(),deployment_id,environment,99,'forged',issuer_url,client_id,redirect_uri,iap_audience,allow_http_development,secret_ciphertext,secret_nonce,encryption_format,encryption_key_id,created_by,created_at FROM framework.auth_config_revisions WHERE id=$1`,
			`INSERT INTO framework.auth_config_revisions SELECT gen_random_uuid(),deployment_id,'production',99,'local_dev','','','','',false,NULL,NULL,NULL,NULL,created_by,created_at FROM framework.auth_config_revisions WHERE id=$1`,
			`INSERT INTO framework.auth_config_revisions SELECT gen_random_uuid(),deployment_id,environment,configuration_version,provider,issuer_url,client_id,redirect_uri,iap_audience,allow_http_development,secret_ciphertext,secret_nonce,encryption_format,encryption_key_id,created_by,created_at FROM framework.auth_config_revisions WHERE id=$1`,
			`INSERT INTO framework.auth_config_revisions SELECT gen_random_uuid(),deployment_id,environment,99,provider,issuer_url,client_id,redirect_uri,iap_audience,allow_http_development,NULL,secret_nonce,NULL,encryption_key_id,created_by,created_at FROM framework.auth_config_revisions WHERE id=$1`,
		} {
			_, err := f.owner.Exec(ctx, sql, first.ID)
			assertConstraint(t, err)
		}
	})
	t.Run("offline lifecycle CAS and reserved active states", func(t *testing.T) {
		f.run(t, func(ctx context.Context) {
			if _, err := f.repo.Transition(ctx, first.ID, 1, Approved); !errors.Is(err, ErrInvalid) {
				t.Fatal("validation skipped")
			}
			validated, err := f.repo.Transition(ctx, first.ID, 1, Validated)
			if err != nil || validated.Generation != 2 || validated.ValidatedAt == nil || validated.Validation.Check != "static" {
				t.Fatal("validation failed", err)
			}
			if _, err = f.repo.Transition(ctx, first.ID, 1, Approved); !errors.Is(err, ErrConflict) {
				t.Fatal("stale generation accepted")
			}
			approved, err := f.repo.Transition(ctx, first.ID, 2, Approved)
			if err != nil || approved.Generation != 3 || approved.ApprovedAt == nil {
				t.Fatal("approval failed", err)
			}
			for _, status := range []Status{Draft, Active, Superseded, "bogus"} {
				if _, err = f.repo.Transition(ctx, first.ID, 3, status); !errors.Is(err, ErrInvalid) {
					t.Fatal("reserved transition accepted")
				}
			}
			if _, err = f.repo.CurrentActive(ctx); !errors.Is(err, ErrNotFound) {
				t.Fatal("approval activated provider")
			}
		})
		if _, err := f.owner.Exec(ctx, `UPDATE framework.auth_config_lifecycle SET status='active',generation=generation+1,validation='{"token":"must-not-store"}' WHERE revision_id=$1`, first.ID); err == nil {
			t.Fatal("credential validation metadata accepted")
		}
	})
	t.Run("concurrent draft creation and historical version retention", func(t *testing.T) {
		var wg sync.WaitGroup
		results := make(chan error, 2)
		for range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				f.run(t, func(ctx context.Context) {
					_, err := f.repo.CreateDraft(ctx, 1, testMetadata().Settings, NewSecret([]byte("fake-secret-two")))
					results <- err
				})
			}()
		}
		wg.Wait()
		close(results)
		successes, conflicts := 0, 0
		for err := range results {
			if err == nil {
				successes++
			} else if errors.Is(err, ErrConflict) {
				conflicts++
			} else {
				t.Fatal(err)
			}
		}
		if successes != 1 || conflicts != 1 {
			t.Fatal("concurrent creation overwrote a version")
		}
		f.run(t, func(ctx context.Context) {
			list, err := f.repo.List(ctx, 2, 10)
			if err != nil || len(list) != 1 || list[0].ID != first.ID || list[0].ClientID != "test-client" {
				t.Fatal("history was erased")
			}
		})
	})
	t.Run("deployment and environment isolation", func(t *testing.T) {
		for _, scope := range []Scope{{"other", "development"}, {"installation-a", "test"}, {"installation-a", "production"}} {
			other, err := NewRepository(f.store, scope, f.repo.cipher)
			if err != nil {
				t.Fatal(err)
			}
			f.run(t, func(ctx context.Context) {
				if _, err := other.Read(ctx, first.ID); !errors.Is(err, ErrNotFound) {
					t.Fatal("cross-deployment metadata")
				}
				if _, err := other.ReadSecretPrivileged(ctx, first.ID); !errors.Is(err, ErrNotFound) {
					t.Fatal("cross-deployment secret")
				}
				m, err := other.CreateDraft(ctx, 0, Settings{Provider: auth.GoogleIAP, IAPAudience: "/projects/123/apps/app-test"}, Secret{})
				if err != nil || m.Version != 1 {
					t.Fatal("independent versions failed", err)
				}
			})
		}
	})
	t.Run("rollback on audit failure including secret access", func(t *testing.T) {
		pending := f.draft(t, 2)
		if _, err := f.owner.Exec(ctx, `REVOKE INSERT ON framework.audit_log FROM go_web_app`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			_, err := f.owner.Exec(ctx, `GRANT INSERT ON framework.audit_log TO go_web_app`)
			if err != nil {
				t.Error(err)
			}
		}()
		before := f.counts(t)
		f.run(t, func(ctx context.Context) {
			if _, err := f.repo.CreateDraft(ctx, 3, testMetadata().Settings, NewSecret([]byte("fake-secret-new"))); !errors.Is(err, ErrAudit) {
				t.Fatal("audit failure not propagated")
			}
			if _, err := f.repo.Transition(ctx, pending.ID, 1, Validated); !errors.Is(err, ErrAudit) {
				t.Fatal("lifecycle changed without audit")
			}
			secret, err := f.repo.ReadSecretPrivileged(ctx, first.ID)
			if !errors.Is(err, ErrAudit) || len(secret.Bytes()) != 0 {
				t.Fatal("secret released before audit commit")
			}
		})
		if f.counts(t) != before {
			t.Fatal("partial draft or audit committed")
		}
	})
	t.Run("missing principal cancellation and invalid IDs", func(t *testing.T) {
		if _, err := f.repo.Read(ctx, first.ID); !errors.Is(err, ErrDenied) {
			t.Fatal("missing principal accepted")
		}
		f.run(t, func(ctx context.Context) {
			canceled, cancel := context.WithCancel(ctx)
			cancel()
			if _, err := f.repo.Read(canceled, first.ID); !errors.Is(err, ErrCanceled) {
				t.Fatal("cancellation ignored")
			}
			expired, cancel := context.WithDeadline(ctx, time.Now().Add(-time.Second))
			defer cancel()
			if _, err := f.repo.Read(expired, first.ID); !errors.Is(err, ErrTimeout) {
				t.Fatal("timeout ignored")
			}
			if _, err := f.repo.Read(ctx, "malformed"); !errors.Is(err, ErrInvalid) {
				t.Fatal("invalid id accepted")
			}
		})
	})
	t.Run("wrong key no secret returned", func(t *testing.T) {
		wrong, _ := NewRepository(f.store, f.repo.scope, testCipher(t, "key-v1"))
		f.run(t, func(ctx context.Context) {
			secret, err := wrong.ReadSecretPrivileged(ctx, first.ID)
			if !errors.Is(err, ErrSecret) || len(secret.Bytes()) != 0 {
				t.Fatal("wrong key accepted")
			}
		})
	})
	t.Run("database failure sanitized", func(t *testing.T) {
		// Close only after middleware established the verified context.
		f.run(t, func(ctx context.Context) {
			f.pool.Close()
			_, err := f.repo.Read(ctx, first.ID)
			if !errors.Is(err, ErrUnavailable) {
				t.Fatal("database error not sanitized")
			}
			if strings.Contains(fmt.Sprint(err), "postgres") {
				t.Fatal("database details leaked")
			}
		})
	})
}

func TestActiveUniqueness(t *testing.T) {
	f := newFixture(t)
	a, b := f.draft(t, 0), f.draft(t, 1)
	for _, m := range []Metadata{a, b} {
		f.run(t, func(ctx context.Context) {
			if _, err := f.repo.Transition(ctx, m.ID, 1, Validated); err != nil {
				t.Fatal(err)
			}
			if _, err := f.repo.Transition(ctx, m.ID, 2, Approved); err != nil {
				t.Fatal(err)
			}
		})
	}
	ctx := context.Background()
	// SQL fixture only: no repository activation operation exists in this phase.
	if _, err := f.owner.Exec(ctx, `UPDATE framework.auth_config_lifecycle SET status='active',generation=generation+1 WHERE revision_id=$1`, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.Exec(ctx, `UPDATE framework.auth_config_lifecycle SET status='active',generation=generation+1 WHERE revision_id=$1`, b.ID); err == nil {
		t.Fatal("two active revisions accepted")
	}
	f.run(t, func(ctx context.Context) {
		active, err := f.repo.CurrentActive(ctx)
		if err != nil || active.ID != a.ID {
			t.Fatal("active tracking failed")
		}
	})
	// A later draft must never replace the active revision.
	f.draft(t, 2)
	tx, err := f.owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `UPDATE framework.auth_config_lifecycle SET status='superseded',generation=generation+1 WHERE revision_id=$1`, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE framework.auth_config_lifecycle SET status='active',generation=generation+1 WHERE revision_id=$1`, b.ID); err != nil {
		t.Fatal(err)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	f.run(t, func(ctx context.Context) {
		active, err := f.repo.CurrentActive(ctx)
		if err != nil || active.ID != a.ID {
			t.Fatal("rolled-back replacement changed active revision")
		}
	})
}

func TestInvalidSettings(t *testing.T) {
	scope := testMetadata().Scope
	settings := testMetadata().Settings
	secret := NewSecret([]byte("fake-secret"))
	for name, change := range map[string]func(*Settings){"provider": func(s *Settings) { s.Provider = "unknown" }, "issuer": func(s *Settings) { s.IssuerURL = "http://issuer.test" }, "userinfo": func(s *Settings) { s.IssuerURL = "https://user:pass@issuer.test" }, "client": func(s *Settings) { s.ClientID = "" }, "callback": func(s *Settings) { s.RedirectURI = "https://app.test/other" }, "query": func(s *Settings) { s.RedirectURI += "?token=bad" }, "mixed": func(s *Settings) { s.IAPAudience = "/projects/1/apps/test" }} {
		t.Run(name, func(t *testing.T) {
			copy := settings
			change(&copy)
			if validate(scope, copy, secret) == nil {
				t.Fatal("invalid settings accepted")
			}
		})
	}
	for _, environment := range []string{"test", "production"} {
		if validate(Scope{"deployment", environment}, Settings{Provider: auth.LocalDev}, Secret{}) == nil {
			t.Fatal("Local DEV outside development accepted")
		}
	}
	if validate(scope, Settings{Provider: auth.GoogleIAP, IAPAudience: "bad"}, Secret{}) == nil || validate(scope, settings, Secret{}) == nil {
		t.Fatal("missing credential or invalid audience accepted")
	}
	for _, scope := range []Scope{{"", "development"}, {"../bad", "development"}, {"deployment", "unknown"}} {
		if scope.valid() {
			t.Fatal("invalid scope accepted")
		}
	}
	if _, err := NewRepository(nil, testMetadata().Scope, nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("nil store accepted")
	}
}

func TestRepositoryAuthorizationRecheck(t *testing.T) {
	f := newFixture(t)
	m := f.draft(t, 0)
	for _, mutation := range []string{`UPDATE framework.users SET active=false WHERE subject='config-admin'`, `DELETE FROM framework.user_roles WHERE role='Admin'`} {
		f.run(t, func(ctx context.Context) {
			if _, err := f.owner.Exec(ctx, mutation); err != nil {
				t.Fatal(err)
			}
			before := f.counts(t)
			if _, err := f.repo.ReadSecretPrivileged(ctx, m.ID); !errors.Is(err, ErrDenied) {
				t.Fatal("revoked principal read secret")
			}
			if _, err := f.repo.Transition(ctx, m.ID, 1, Validated); !errors.Is(err, ErrDenied) {
				t.Fatal("revoked principal changed lifecycle")
			}
			if f.counts(t) != before {
				t.Fatal("revoked operation changed records")
			}
			if _, err := f.owner.Exec(ctx, `UPDATE framework.users SET active=true WHERE subject='config-admin'; INSERT INTO framework.user_roles(user_id,role) SELECT id,'Admin' FROM framework.users WHERE subject='config-admin' ON CONFLICT DO NOTHING`); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, role := range []string{"User", "Viewer"} {
		i := auth.Identity{Issuer: f.identity.Issuer, Subject: "config-" + role, Provider: auth.OIDC}
		u, err := f.store.Resolve(context.Background(), i)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.owner.Exec(context.Background(), `INSERT INTO framework.user_roles(user_id,role) VALUES($1,$2)`, u.ID, role); err != nil {
			t.Fatal(err)
		}
		// A verified identity without framework authorization context is insufficient.
		handler := auth.Require(fixedAuth{i}, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			if _, err := f.repo.ReadSecretPrivileged(r.Context(), m.ID); !errors.Is(err, ErrDenied) {
				t.Fatal("identity alone read secret")
			}
		}))
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/test-only", nil))
	}
}
func TestConcurrentLifecycleAndRotationDraft(t *testing.T) {
	f := newFixture(t)
	m := f.draft(t, 0)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f.run(t, func(ctx context.Context) { _, err := f.repo.Transition(ctx, m.ID, 1, Validated); results <- err })
		}()
	}
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrConflict) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatal("lifecycle update lost concurrency control")
	}
	rotated, err := NewRepository(f.store, f.repo.scope, testCipher(t, "key-v2"))
	if err != nil {
		t.Fatal(err)
	}
	f.run(t, func(ctx context.Context) {
		oldSecret, err := f.repo.ReadSecretPrivileged(ctx, m.ID)
		if err != nil {
			t.Fatal(err)
		}
		newDraft, err := rotated.CreateDraft(ctx, 1, m.Settings, oldSecret)
		if err != nil || newDraft.Status != Draft || newDraft.EncryptionKeyID != "key-v2" {
			t.Fatal("rotation draft failed", err)
		}
		newSecret, err := rotated.ReadSecretPrivileged(ctx, newDraft.ID)
		if err != nil || !bytes.Equal(newSecret.Bytes(), oldSecret.Bytes()) {
			t.Fatal("rotation changed secret")
		}
		if _, err = rotated.ReadSecretPrivileged(ctx, m.ID); !errors.Is(err, ErrSecret) {
			t.Fatal("new key read historical ciphertext")
		}
		if _, err = f.repo.ReadSecretPrivileged(ctx, m.ID); err != nil {
			t.Fatal("historical key cannot recover history")
		}
		original, err := f.repo.Read(ctx, m.ID)
		if err != nil || original.EncryptionKeyID != "key-v1" {
			t.Fatal("rotation rewrote history")
		}
		if _, err = rotated.CurrentActive(ctx); !errors.Is(err, ErrNotFound) {
			t.Fatal("rotation activated settings")
		}
	})
}

func assertConstraint(t *testing.T, err error) {
	t.Helper()
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || (pg.Code != "23514" && pg.Code != "23503" && pg.Code != "23505") {
		t.Fatal("expected database integrity violation")
	}
}
func TestScopeAndMissingKey(t *testing.T) {
	for input, want := range map[string]string{"development": "development", "test": "test", "TEST": "test", "production": "production", "PRD": "production", "prd": "production"} {
		scope, err := ScopeFromEnv(func(key string) string {
			if key == "APP_ENV" {
				return input
			}
			return "isolated-deployment"
		})
		if err != nil || scope.Environment != want {
			t.Fatal("incorrect scope normalization")
		}
	}
	if _, err := ScopeFromEnv(func(string) string { return "" }); !errors.Is(err, ErrInvalid) {
		t.Fatal("missing deployment scope accepted")
	}
	if _, err := NewRepository(access.New(nil), Scope{"deployment", "development"}, nil); !errors.Is(err, ErrKey) {
		t.Fatal("missing cipher accepted")
	}
}
