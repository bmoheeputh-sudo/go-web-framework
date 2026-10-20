package authconfig

import (
	"context"
	"crypto/cipher"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
)

func startupFixture(t *testing.T) (*fixture, *ActivationService, *StartupLoader, Metadata) {
	t.Helper()
	f, s, provider, m := activationServiceFixture(t)
	req, _ := activationReadiness(t, f, m, "")
	p := prepareActivation(t, f, s, m, 0)
	f.run(t, func(ctx context.Context) {
		if _, err := s.Activate(ctx, p, req); err != nil {
			t.Fatal(err)
		}
	})
	reader, _ := NewActivationReader(f.pool, f.repo.scope)
	l, err := NewStartupLoader(reader, f.repo.cipher, s.sessions, s.callback)
	if err != nil {
		t.Fatal(err)
	}
	l.client = func(context.Context, string) (*http.Client, error) { return provider.client(), nil }
	return f, s, l, m
}

func TestStartupRehydratesCommittedRuntimeReadOnly(t *testing.T) {
	f, _, l, m := startupFixture(t)
	before := activationState(t, f)
	runtime, err := l.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	status, desired, mismatch := runtime.ControlStatus()
	if mismatch || desired != 1 || status.AppliedGeneration != 1 || status.ActiveRevisionID != m.ID || status.Source != "database" || status.Provider != auth.OIDC || status.TransitionState != "none" {
		t.Fatal("incorrect rehydration", status)
	}
	if before != activationState(t, f) {
		t.Fatal("startup wrote lifecycle/history/audit")
	}
	mux := http.NewServeMux()
	runtime.RegisterRoutes(mux)
	w := httptest.NewRecorder()
	runtime.Capture(mux).ServeHTTP(w, httptest.NewRequest("GET", apiOrigin+"/api/auth/login", nil))
	if w.Code != 302 {
		t.Fatal("rehydrated login unavailable", w.Code)
	}
	w = httptest.NewRecorder()
	runtime.Capture(mux).ServeHTTP(w, httptest.NewRequest("GET", apiOrigin+"/api/auth/me", nil))
	if w.Code != 401 {
		t.Fatal("rehydration admitted Local DEV", w.Code)
	}
}

func nextStartupRevision(t *testing.T, f *fixture, m Metadata) Metadata {
	t.Helper()
	var next Metadata
	f.run(t, func(ctx context.Context) {
		var err error
		next, err = f.repo.CreateDraft(ctx, m.Version, m.Settings, NewSecret([]byte(apiSecret)))
		if err != nil {
			t.Fatal(err)
		}
		for _, to := range []Status{Validated, Approved} {
			next, err = f.repo.Transition(ctx, next.ID, next.Generation, to)
			if err != nil {
				t.Fatal(err)
			}
		}
	})
	return next
}

func TestStartupRestoresOnlyRecordedDrainingGeneration(t *testing.T) {
	for _, grace := range []time.Duration{0, time.Minute} {
		t.Run(grace.String(), func(t *testing.T) {
			f, s, l, first := startupFixture(t)
			oldCipher := f.repo.cipher
			current := testCipher(t, "key-v2")
			f.repo.cipher = current
			second := nextStartupRevision(t, f, first)
			ring := *current
			ring.keys = map[string]cipher.AEAD{current.keyID: current.aead, oldCipher.keyID: oldCipher.aead}
			l.cipher = &ring
			var enrolled string
			if err := f.owner.QueryRow(context.Background(), `SELECT id::text FROM framework.users WHERE issuer=$1 AND subject='enrolled-admin'`, first.IssuerURL).Scan(&enrolled); err != nil {
				t.Fatal(err)
			}
			request, _ := activationReadiness(t, f, second, enrolled)
			request.Transition = grace
			p := prepareActivation(t, f, s, second, 1)
			f.run(t, func(ctx context.Context) {
				if _, err := s.Activate(ctx, p, request); err != nil {
					t.Fatal(err)
				}
			})
			missing := *l
			missing.cipher = current
			missingRuntime, missingErr := missing.Load(context.Background())
			if grace > 0 {
				if missingErr == nil || missingRuntime != nil {
					t.Fatal("missing draining key admitted")
				}
			} else {
				if missingErr != nil {
					t.Fatal("expired provider still requires historical key", missingErr)
				}
				missingRuntime.Close()
			}
			before := activationState(t, f)
			var calls atomic.Int32
			base := l.client
			l.client = func(ctx context.Context, issuer string) (*http.Client, error) { calls.Add(1); return base(ctx, issuer) }
			runtime, err := l.Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer runtime.Close()
			status, _, _ := runtime.ControlStatus()
			if status.AppliedGeneration != 2 || status.ActiveRevisionID != second.ID {
				t.Fatal("wrong generation")
			}
			if grace == 0 {
				if calls.Load() != 1 || status.PreviousRevisionID != "" {
					t.Fatal("expired provider restored")
				}
			} else {
				if calls.Load() != 2 || status.PreviousRevisionID != first.ID || status.TransitionState != "draining" {
					t.Fatal("permitted drain lost")
				}
				var deadline time.Time
				if err := f.pool.QueryRow(context.Background(), `SELECT transition_deadline FROM framework.auth_activation_history WHERE generation=2`).Scan(&deadline); err != nil || !deadline.Equal(status.TransitionDeadline) {
					t.Fatal("restart extended deadline", err)
				}
			}
			if before != activationState(t, f) {
				t.Fatal("restart changed activation state")
			}
		})
	}
}

func TestStartupRehydrationFailsClosed(t *testing.T) {
	f, _, l, _ := startupFixture(t)
	before := activationState(t, f)
	for name, change := range map[string]func(*StartupLoader){
		"missing historical key": func(v *StartupLoader) { v.cipher = testCipher(t, "another-key") },
		"wrong deployment":       func(v *StartupLoader) { v.reader, _ = NewActivationReader(f.pool, Scope{"wrong", "development"}) },
		"wrong environment": func(v *StartupLoader) {
			v.reader, _ = NewActivationReader(f.pool, Scope{f.repo.scope.DeploymentID, "production"})
		},
		"wrong callback": func(v *StartupLoader) { v.callback = apiOrigin + "/wrong" },
		"network unavailable": func(v *StartupLoader) {
			v.client = func(context.Context, string) (*http.Client, error) { return nil, ErrUnavailable }
		},
		"invalid issuer": func(v *StartupLoader) {
			p := newMockConnectionIssuer(t)
			p.metadata = func(m map[string]any) { m["issuer"] = "https://wrong.example.test/" }
			v.client = func(context.Context, string) (*http.Client, error) { return p.client(), nil }
		},
		"invalid JWKS": func(v *StartupLoader) {
			p := newMockConnectionIssuer(t)
			p.badKeys = true
			v.client = func(context.Context, string) (*http.Client, error) { return p.client(), nil }
		},
		"unsafe endpoint": func(v *StartupLoader) {
			p := newMockConnectionIssuer(t)
			p.metadata = func(m map[string]any) { m["token_endpoint"] = "http://169.254.169.254/token" }
			v.client = func(context.Context, string) (*http.Client, error) { return p.client(), nil }
		},
	} {
		t.Run(name, func(t *testing.T) {
			copy := *l
			change(&copy)
			runtime, err := copy.Load(context.Background())
			if err == nil || runtime != nil {
				t.Fatal("unsafe startup succeeded")
			}
		})
	}
	if before != activationState(t, f) {
		t.Fatal("failed startup changed database")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if runtime, err := l.Load(ctx); err == nil || runtime != nil {
		t.Fatal("canceled load succeeded")
	}
	f.pool.Close()
	if runtime, err := l.Load(context.Background()); err == nil || runtime != nil {
		t.Fatal("DB outage fell back")
	}
}

func TestStartupRejectsHeadChangedDuringDiscovery(t *testing.T) {
	f, _, l, m := startupFixture(t)
	next := nextStartupRevision(t, f, m)
	base := l.client
	l.client = func(ctx context.Context, issuer string) (*http.Client, error) {
		if err := activationFixture(t, f, next, 2, m.ID, false); err != nil {
			t.Fatal(err)
		}
		return base(ctx, issuer)
	}
	if runtime, err := l.Load(context.Background()); runtime != nil || !errors.Is(err, ErrConflict) {
		t.Fatal("stale startup published", err)
	}
}

func TestStartupRejectsInconsistentLifecycleGeneration(t *testing.T) {
	f, _, l, m := startupFixture(t)
	// Deliberately corrupt only this disposable cluster to test defense against
	// inconsistent persisted state, beyond the normal migration constraints.
	if _, err := f.owner.Exec(context.Background(), `ALTER TABLE framework.auth_config_lifecycle DISABLE TRIGGER auth_config_lifecycle_guard`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.Exec(context.Background(), `UPDATE framework.auth_config_lifecycle SET generation=99 WHERE revision_id=$1`, m.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.Exec(context.Background(), `ALTER TABLE framework.auth_config_lifecycle ENABLE TRIGGER auth_config_lifecycle_guard`); err != nil {
		t.Fatal(err)
	}
	if runtime, err := l.Load(context.Background()); err == nil || runtime != nil {
		t.Fatal("inconsistent lifecycle accepted")
	}
}
