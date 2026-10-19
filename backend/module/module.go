// Package module defines the compile-time application module contract.
// Modules are trusted Go code, not sandboxed plugins. Only the framework owns
// the HTTP mux and constructs authentication and authorization middleware.
package module

import "net/http"

type Permission string

type Manifest struct {
	ID          string
	Permissions []Permission
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
