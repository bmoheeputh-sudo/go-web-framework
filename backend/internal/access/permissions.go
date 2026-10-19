package access

import (
	"regexp"
	"strings"
)

var modulePermission = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}\.[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`)

// ValidModulePermission validates catalog names, never permission grants.
func ValidModulePermission(name string) bool {
	return len(name) <= 160 && modulePermission.MatchString(name) &&
		!strings.HasPrefix(name, "admin.") && !strings.HasPrefix(name, "accounts.")
}

// WithModulePermissions returns a separate immutable catalog for the module mux.
// It neither changes the original Store nor inserts/grants database permissions.
func (s *Store) WithModulePermissions(permissions []string) (*Store, error) {
	if s == nil {
		return nil, ErrUnavailable
	}
	catalog := make(map[string]bool, len(permissions))
	for _, permission := range permissions {
		if !ValidModulePermission(permission) || catalog[permission] {
			return nil, ErrInvalid
		}
		catalog[permission] = true
	}
	copied := *s
	copied.modulePermissions = catalog
	return &copied, nil
}
