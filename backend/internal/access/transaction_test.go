package access

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/module"
)

type mutationAuth struct{}

func (mutationAuth) Authenticate(*http.Request) (auth.Identity, error) {
	return auth.Identity{Issuer: "https://issuer.test", Subject: "user", Provider: auth.OIDC}, nil
}

func TestMutationRequiresVerifiedPrincipal(t *testing.T) {
	s := New(nil)
	for _, authenticated := range []bool{false, true} {
		called := false
		var handler http.Handler = s.BindMutation("example.items.write", "account", module.AuditPolicy{}, func(http.ResponseWriter, *http.Request, module.TransactionManager) { called = true })
		want := 401
		if authenticated {
			handler = auth.Require(mutationAuth{}, handler)
			want = 403
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("POST", "/", nil))
		if w.Code != want || called {
			t.Fatal("missing authentication/principal accepted", w.Code)
		}
	}
}

func TestMutationContextAndCatalogCannotBeSubstituted(t *testing.T) {
	id := auth.Identity{Issuer: "https://issuer.test", Subject: "user", Provider: auth.OIDC}
	actor := User{ID: "12345678-1234-1234-1234-123456789012", Issuer: id.Issuer, Subject: id.Subject, Active: true}
	s, err := New(nil).WithModulePermissions([]string{"example.items.write"})
	if err != nil {
		t.Fatal(err)
	}
	fn := func(context.Context, module.Transaction) (string, module.AuditDetails, error) {
		t.Fatal("unauthorized callback executed")
		return "", nil, nil
	}
	// Only auth.Require can install the private authentication context key.
	auth.Require(mutationAuth{}, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		for _, tc := range []struct {
			name       string
			permission string
			change     func(context.Context) context.Context
			want       error
		}{
			{"missing principal", "example.items.write", func(ctx context.Context) context.Context { return ctx }, module.ErrUnauthenticated},
			{"forged actor", "example.items.write", func(ctx context.Context) context.Context {
				other := actor
				other.ID = "22345678-1234-1234-1234-123456789012"
				return context.WithValue(ctx, principalKey{}, other)
			}, module.ErrUnauthenticated},
			{"forged identity association", "example.items.write", func(ctx context.Context) context.Context {
				other := actor
				other.Subject = "admin"
				return context.WithValue(ctx, principalKey{}, other)
			}, module.ErrUnauthenticated},
			{"unknown permission", "unknown.write", func(ctx context.Context) context.Context { return context.WithValue(ctx, principalKey{}, actor) }, module.ErrPermissionDenied},
			{"undeclared permission", "example.settings.write", func(ctx context.Context) context.Context { return context.WithValue(ctx, principalKey{}, actor) }, module.ErrPermissionDenied},
			{"core permission", "admin.manage", func(ctx context.Context) context.Context { return context.WithValue(ctx, principalKey{}, actor) }, module.ErrPermissionDenied},
		} {
			t.Run(tc.name, func(t *testing.T) {
				m := &boundMutation{store: s, actor: actor, identity: id, permission: tc.permission, request: r.Context()}
				ctx := context.WithValue(tc.change(r.Context()), mutationBindingKey{}, m)
				if err := m.MutateGlobal(ctx, fn); !errors.Is(err, tc.want) {
					t.Fatal(err)
				}
			})
		}
		t.Run("another route manager", func(t *testing.T) {
			m := &boundMutation{store: s, actor: actor, identity: id, permission: "example.items.write", request: r.Context()}
			ctx := context.WithValue(context.WithValue(r.Context(), principalKey{}, actor), mutationBindingKey{}, &boundMutation{})
			if err := m.MutateGlobal(ctx, fn); !errors.Is(err, module.ErrScope) {
				t.Fatal(err)
			}
		})
		t.Run("disabled catalog", func(t *testing.T) {
			m := &boundMutation{store: New(nil), actor: actor, identity: id, permission: "example.items.write", request: r.Context()}
			ctx := context.WithValue(context.WithValue(r.Context(), principalKey{}, actor), mutationBindingKey{}, m)
			if err := m.MutateGlobal(ctx, fn); !errors.Is(err, module.ErrPermissionDenied) {
				t.Fatal(err)
			}
		})
	})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/", nil))
}

func TestAuditSchemaAndPayload(t *testing.T) {
	id := "12345678-1234-1234-1234-123456789012"
	p := module.AuditPolicy{Action: "example.item.updated", Fields: map[string]module.AuditField{"item_id": {Kind: module.AuditUUID}, "status": {Kind: module.AuditEnum, Values: []string{"open", "closed"}}, "count": {Kind: module.AuditInteger}, "changed": {Kind: module.AuditBool}}}
	frozen, err := CopyAuditPolicy("example", p)
	if err != nil {
		t.Fatal(err)
	}
	p.Fields["status"].Values[0] = "secret"
	valid := module.AuditDetails{"item_id": id, "status": "open", "count": int64(2), "changed": true}
	if _, err := auditPayload(frozen, id, id, valid); err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{"secret", nil, map[string]any{"password": "secret"}, []string{"open"}} {
		invalid := module.AuditDetails{"item_id": id, "status": value, "count": 1, "changed": true}
		if _, err := auditPayload(frozen, id, id, invalid); !errors.Is(err, module.ErrAudit) {
			t.Fatal("invalid audit accepted", err)
		}
	}
	for name, policy := range map[string]module.AuditPolicy{
		"foreign action": {Action: "other.item.updated"}, "empty action": {}, "unnamespaced action": {Action: "example.updated"},
		"password":             {Action: "example.item.updated", Fields: map[string]module.AuditField{"password": {Kind: module.AuditUUID}}},
		"scope override":       {Action: "example.item.updated", Fields: map[string]module.AuditField{"account_id": {Kind: module.AuditUUID}}},
		"free text":            {Action: "example.item.updated", Fields: map[string]module.AuditField{"value": {Kind: "string"}}},
		"empty enum":           {Action: "example.item.updated", Fields: map[string]module.AuditField{"state": {Kind: module.AuditEnum}}},
		"oversized enum label": {Action: "example.item.updated", Fields: map[string]module.AuditField{"state": {Kind: module.AuditEnum, Values: []string{strings.Repeat("x", 513)}}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := CopyAuditPolicy("example", policy); !errors.Is(err, module.ErrAudit) {
				t.Fatal("unsafe audit schema accepted")
			}
		})
	}
}
