// Package example demonstrates registration without domain storage or integrations.
package example

import (
	"encoding/json"
	"net/http"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/module"
)

const Read module.Permission = "example.read"

type Module struct{}

func (Module) Manifest() module.Manifest {
	return module.Manifest{ID: "example", Permissions: []module.Permission{Read}}
}

func (Module) Register(routes module.Registrar) error {
	if err := routes.GlobalRoute("GET", "/info", Read, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"module": "example"})
	}); err != nil {
		return err
	}
	return routes.AccountRoute("GET", "/info", Read, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"module": "example", "account_id": r.PathValue("account")})
	})
}
