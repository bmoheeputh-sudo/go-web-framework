package access

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
)

// PermissionDefinition comes exclusively from the validated compile-time registry.
// It is metadata, not a permission grant or an authorization allowlist.
type PermissionDefinition struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Module      string `json:"module"`
	Enabled     bool   `json:"enabled"`
}
type CatalogPermission struct {
	PermissionDefinition
	Registered bool     `json:"registered"`
	Known      bool     `json:"known"`
	Roles      []string `json:"roles"`
}
type PermissionCatalog struct {
	Permissions []CatalogPermission `json:"permissions"`
	Roles       []string            `json:"roles"`
	Revision    string              `json:"revision"`
}
type PermissionChange struct {
	Permission string `json:"permission"`
	Role       string `json:"role"`
	Assigned   *bool  `json:"assigned"`
}
type permissionAudit struct {
	Permission string `json:"permission"`
	Role       string `json:"role"`
	Before     bool   `json:"before"`
	After      bool   `json:"after"`
}

func (s *Store) definitions() map[string]PermissionDefinition {
	result := map[string]PermissionDefinition{
		AdminManage:  {AdminManage, "Manage users, role assignments, accounts and associations", "framework", true},
		AccountRead:  {AccountRead, "Read explicitly linked active accounts", "framework", true},
		AccountWrite: {AccountWrite, "Update explicitly linked active accounts", "framework", true},
	}
	for name, definition := range s.permissionDefinitions {
		result[name] = definition
	}
	return result
}

func (s *Store) WithPermissionDefinitions(definitions []PermissionDefinition) (*Store, error) {
	if s == nil {
		return nil, ErrUnavailable
	}
	copied := *s
	copied.permissionDefinitions = make(map[string]PermissionDefinition, len(definitions))
	for _, definition := range definitions {
		if !ValidModulePermission(definition.Name) || strings.Split(definition.Name, ".")[0] != definition.Module ||
			definition.Module == "framework" || (definition.Description != "" && !validName(definition.Description)) {
			return nil, ErrInvalid
		}
		if _, exists := copied.permissionDefinitions[definition.Name]; exists {
			return nil, ErrInvalid
		}
		copied.permissionDefinitions[definition.Name] = definition
	}
	return &copied, nil
}

// One SQL statement obtains a consistent catalog, assignment and audit snapshot.
// The audit sequence prevents an intervening API edit-and-revert (ABA) from
// silently accepting an old revision. Neither reading nor startup provisions SQL.
func (s *Store) permissionCatalog(ctx context.Context, q querier) (PermissionCatalog, error) {
	var stored []struct {
		Name        string
		Description string
		Roles       []string
	}
	var data []byte
	var epoch int64
	result := PermissionCatalog{Permissions: []CatalogPermission{}}
	err := q.QueryRow(ctx, `SELECT
 COALESCE((SELECT jsonb_agg(jsonb_build_object('name',p.name,'description',p.description,
 'roles',ARRAY(SELECT role FROM framework.role_permissions WHERE permission=p.name ORDER BY role)) ORDER BY p.name)
 FROM framework.permissions p),'[]'::jsonb),
 COALESCE((SELECT max(id) FROM framework.audit_log WHERE action IN ('permission.register','role.permission')),0),
 ARRAY(SELECT name FROM framework.roles ORDER BY name)`).Scan(&data, &epoch, &result.Roles)
	if err != nil || json.Unmarshal(data, &stored) != nil {
		return result, ErrUnavailable
	}
	definitions := s.definitions()
	for _, row := range stored {
		definition, known := definitions[row.Name]
		if !known {
			definition = PermissionDefinition{Name: row.Name, Description: row.Description, Module: strings.Split(row.Name, ".")[0]}
		}
		result.Permissions = append(result.Permissions, CatalogPermission{definition, true, known, row.Roles})
		delete(definitions, row.Name)
	}
	for _, definition := range definitions {
		result.Permissions = append(result.Permissions, CatalogPermission{definition, false, true, []string{}})
	}
	slices.SortFunc(result.Permissions, func(a, b CatalogPermission) int { return strings.Compare(a.Name, b.Name) })
	encoded, err := json.Marshal(struct {
		Catalog PermissionCatalog
		Epoch   int64
	}{result, epoch})
	if err != nil {
		return result, ErrUnavailable
	}
	sum := sha256.Sum256(encoded)
	result.Revision = hex.EncodeToString(sum[:])
	return result, nil
}
func (s *Store) PermissionCatalog(ctx context.Context) (PermissionCatalog, error) {
	return s.permissionCatalog(ctx, s.pool)
}

func (s *Store) RegisterPermission(ctx context.Context, actor, name string) error {
	definition, known := s.definitions()[name]
	if !known || definition.Module == "framework" || !definition.Enabled {
		return ErrInvalid
	}
	return s.mutate(ctx, actor, AdminManage, "", func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM framework.permissions WHERE name=$1)`, name).Scan(&exists); err != nil {
			return ErrUnavailable
		}
		if exists {
			return ErrConflict
		}
		if _, err := tx.Exec(ctx, `INSERT INTO framework.permissions(name,description) VALUES($1,$2)`, name, definition.Description); err != nil {
			return dbError(err)
		}
		// Registration does not assign any role. Empty role denotes catalog metadata.
		return audit(ctx, tx, actor, "permission.register", name, permissionAudit{name, "", false, true})
	})
}

// A batch is atomic across roles. Only explicit changed cells are accepted, so
// disabled permissions can be revoked without granting them to another role.
func (s *Store) SetPermissions(ctx context.Context, actor, revision string, changes []PermissionChange) error {
	if len(revision) != 64 || len(changes) == 0 || len(changes) > 100 {
		return ErrInvalid
	}
	if _, err := hex.DecodeString(revision); err != nil {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, change := range changes {
		if change.Assigned == nil || !slices.Contains([]string{"Admin", "User", "Viewer"}, change.Role) || seen[change.Role+":"+change.Permission] {
			return ErrInvalid
		}
		seen[change.Role+":"+change.Permission] = true
		// No delegation/revocation of administrative authority in Phase 9.1.
		if change.Permission == AdminManage {
			return ErrDenied
		}
	}
	return s.mutate(ctx, actor, AdminManage, "", func(tx pgx.Tx) error {
		current, err := s.permissionCatalog(ctx, tx)
		if err != nil {
			return err
		}
		if revision != current.Revision {
			return ErrConflict
		}
		for _, change := range changes {
			index := slices.IndexFunc(current.Permissions, func(p CatalogPermission) bool { return p.Name == change.Permission })
			if index < 0 {
				return ErrInvalid
			}
			permission := current.Permissions[index]
			if !permission.Known || !permission.Registered || (!permission.Enabled && *change.Assigned) {
				return ErrInvalid
			}
			before := slices.Contains(permission.Roles, change.Role)
			if before == *change.Assigned {
				return ErrInvalid
			}
			if *change.Assigned {
				_, err = tx.Exec(ctx, `INSERT INTO framework.role_permissions(role,permission) VALUES($1,$2)`, change.Role, change.Permission)
			} else {
				_, err = tx.Exec(ctx, `DELETE FROM framework.role_permissions WHERE role=$1 AND permission=$2`, change.Role, change.Permission)
			}
			if err != nil {
				return dbError(err)
			}
			if err = audit(ctx, tx, actor, "role.permission", change.Role, permissionAudit{change.Permission, change.Role, before, *change.Assigned}); err != nil {
				return err
			}
		}
		return lastAdminGuard(ctx, tx)
	})
}
