// Package module defines the compile-time application module contract.
// Modules are trusted Go code, not sandboxed plugins. Only the framework owns
// the HTTP mux and constructs authentication and authorization middleware.
package module

import "net/http"

type Permission string

type Manifest struct {
	ID          string
	Permissions []Permission
	// Optional operator-facing descriptions, keyed only by declared permissions.
	PermissionDescriptions map[Permission]string
	Migrations             *MigrationSpec
}

// MigrationSpec is optional. Schema and directory must follow the module ID;
// journals are framework-derived, never module-configurable. RequiredVersion is
// an exact compatibility requirement, not a minimum. No startup SQL execution.
type MigrationSpec struct {
	Schema          string
	Directory       string // repository-relative database/modules/<id>/migrations
	RequiredVersion int64
}

type Module interface {
	Manifest() Manifest
	Register(Registrar) error
}

// Registrar exposes no public-route or arbitrary-middleware escape hatch.
// Paths are relative, start with a literal segment, and may contain single
// named parameters. AccountRoute supplies and checks {account} itself.
type Registrar interface {
	GlobalMutation(method, path string, permission Permission, audit AuditPolicy, handler MutationHandler) error
	AccountMutation(method, path string, permission Permission, audit AuditPolicy, handler MutationHandler) error
	GlobalRoute(method, path string, permission Permission, handler http.HandlerFunc) error
	AccountRoute(method, path string, permission Permission, handler http.HandlerFunc) error
}
