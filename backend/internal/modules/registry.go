// Package modules validates an explicit catalog and mounts only enabled modules.
package modules

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/module"
)

var identifier = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)
var relativePath = regexp.MustCompile(`^/[a-z][a-z0-9_-]*(/([a-z][a-z0-9_-]*|\{[a-z][a-z0-9_]*\}))*$`)

func validID(id string) bool {
	return identifier.MatchString(id) && !slices.Contains([]string{"admin", "accounts", "auth", "access", "health", "modules", "framework", "public"}, id)
}

type route struct {
	pattern, permission, accountParameter string
	handler                               http.HandlerFunc
	mutation                              module.MutationHandler
	audit                                 module.AuditPolicy
}

// Registry is immutable after New; callers receive copies of its enabled IDs.
type Registry struct {
	ids         []string
	permissions []string
	routes      []route
}

// New accepts only a literal comma-separated allowlist. Empty means no modules.
// Catalog manifests are validated even when disabled; Register runs only for
// enabled modules. No registration hooks, external clients or database writes
// are needed to discover the catalog.
func New(catalog []module.Module, enabled string) (*Registry, error) {
	known := make(map[string]module.Module)
	manifests := make(map[string]module.Manifest)
	for _, m := range catalog {
		if m == nil {
			return nil, errors.New("nil module in catalog")
		}
		manifest := m.Manifest()
		if !validID(manifest.ID) {
			return nil, errors.New("invalid or reserved module ID")
		}
		if _, exists := known[manifest.ID]; exists {
			return nil, fmt.Errorf("duplicate module ID %q", manifest.ID)
		}
		permissions := make(map[module.Permission]bool)
		for _, permission := range manifest.Permissions {
			name := string(permission)
			if !strings.HasPrefix(name, manifest.ID+".") || !access.ValidModulePermission(name) || permissions[permission] {
				return nil, fmt.Errorf("invalid or duplicate permission for module %q", manifest.ID)
			}
			permissions[permission] = true
		}
		manifest.Permissions = slices.Clone(manifest.Permissions)
		known[manifest.ID], manifests[manifest.ID] = m, manifest
	}
	registry := &Registry{ids: []string{}}
	if enabled == "" {
		return registry, nil
	}
	selected := make(map[string]bool)
	for _, id := range strings.Split(enabled, ",") {
		if !validID(id) || known[id] == nil || selected[id] {
			return nil, errors.New("ENABLED_MODULES must contain unique, known lowercase IDs separated by commas, without whitespace")
		}
		selected[id] = true
		registry.ids = append(registry.ids, id)
	}
	slices.Sort(registry.ids)
	validator := http.NewServeMux()
	for _, id := range registry.ids {
		manifest := manifests[id]
		collector := &registrar{id: id, declared: make(map[module.Permission]bool), validator: validator}
		for _, permission := range manifest.Permissions {
			collector.declared[permission] = true
			registry.permissions = append(registry.permissions, string(permission))
		}
		err := known[id].Register(collector)
		collector.closed = true
		if err != nil || collector.err != nil {
			return nil, fmt.Errorf("invalid routes for module %q", id)
		}
		registry.routes = append(registry.routes, collector.routes...)
	}
	return registry, nil
}

func (r *Registry) Enabled() []string { return append([]string{}, r.ids...) }

type registrar struct {
	id        string
	declared  map[module.Permission]bool
	validator *http.ServeMux
	routes    []route
	err       error
	closed    bool
}

func (r *registrar) GlobalRoute(method, path string, permission module.Permission, handler http.HandlerFunc) error {
	return r.add(method, path, permission, handler, false)
}
func (r *registrar) AccountRoute(method, path string, permission module.Permission, handler http.HandlerFunc) error {
	return r.add(method, path, permission, handler, true)
}
func (r *registrar) add(method, path string, permission module.Permission, handler http.HandlerFunc, account bool) error {
	if r.closed {
		return errors.New("module registration is closed")
	}
	if r.err != nil {
		return r.err
	}
	if !slices.Contains([]string{"GET", "POST", "PUT", "PATCH", "DELETE"}, method) || !relativePath.MatchString(path) ||
		strings.Contains(path, "{account}") || !r.declared[permission] || handler == nil ||
		(!account && (path == "/accounts" || strings.HasPrefix(path, "/accounts/"))) {
		r.err = errors.New("invalid module route, handler or permission")
		return r.err
	}
	prefix, parameter := "/api/modules/"+r.id, ""
	if account {
		prefix += "/accounts/{account}"
		parameter = "account"
	}
	pattern := method + " " + prefix + path
	if err := mount(r.validator, pattern, handler); err != nil {
		r.err = err
		return err
	}
	r.routes = append(r.routes, route{pattern: pattern, permission: string(permission), accountParameter: parameter, handler: handler})
	return nil
}

// Mutation routes bind their permission, scope and audit schema at registration.
func (r *registrar) GlobalMutation(method, path string, permission module.Permission, policy module.AuditPolicy, handler module.MutationHandler) error {
	return r.mutation(method, path, permission, policy, handler, false)
}
func (r *registrar) AccountMutation(method, path string, permission module.Permission, policy module.AuditPolicy, handler module.MutationHandler) error {
	return r.mutation(method, path, permission, policy, handler, true)
}
func (r *registrar) mutation(method, path string, permission module.Permission, policy module.AuditPolicy, handler module.MutationHandler, account bool) error {
	if r.closed {
		return errors.New("module registration is closed")
	}
	if r.err != nil {
		return r.err
	}
	frozen, err := access.CopyAuditPolicy(r.id, policy)
	if err != nil || handler == nil || method == "GET" {
		r.err = errors.New("invalid module mutation or audit policy")
		return r.err
	}
	if err := r.add(method, path, permission, func(http.ResponseWriter, *http.Request) {}, account); err != nil {
		return err
	}
	entry := &r.routes[len(r.routes)-1]
	entry.mutation, entry.audit = handler, frozen
	return nil
}

// ServeMux checks duplicate patterns and ambiguous wildcard precedence itself.
func mount(mux *http.ServeMux, pattern string, handler http.Handler) (err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("invalid or conflicting route %q", pattern)
		}
	}()
	mux.Handle(pattern, handler)
	return nil
}

// Handler builds a private mux. No handler can be served without the common
// authentication, write protection, permission and optional account checks.
func (r *Registry) Handler(provider auth.Authenticator, store *access.Store, origin string) (http.Handler, error) {
	if len(r.ids) != 0 && (provider == nil || store == nil || origin == "") {
		return nil, errors.New("enabled modules require authentication, RBAC and APP_ORIGIN")
	}
	if store != nil {
		var err error
		store, err = store.WithModulePermissions(r.permissions)
		if err != nil {
			return nil, err
		}
	}
	mux := http.NewServeMux()
	for _, route := range r.routes {
		var endpoint http.Handler = route.handler
		if route.mutation != nil {
			endpoint = store.BindMutation(route.permission, route.accountParameter, route.audit, route.mutation)
		}
		handler := auth.Require(provider, access.ProtectWrites(origin,
			store.Require(route.permission, route.accountParameter, endpoint)))
		if err := mount(mux, route.pattern, handler); err != nil {
			return nil, err
		}
	}
	// Availability only, not a permission grant. No RBAC lookup or user creation.
	mux.Handle("GET /api/modules", auth.Require(provider, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Modules []string `json:"modules"`
		}{Modules: r.Enabled()})
	})))
	return mux, nil
}
