package access

import "testing"

func TestModulePermissionCatalogValidation(t *testing.T) {
	base := New(nil)
	for _, names := range [][]string{{""}, {"unknown"}, {"Example.read"}, {"example..read"}, {"example.read.*"}, {"example.read "}, {"admin.manage"}, {"accounts.read"}, {"example.read", "example.read"}} {
		if _, err := base.WithModulePermissions(names); err == nil {
			t.Fatalf("accepted invalid catalog %v", names)
		}
	}
	permissions := []string{"example.read", "drive_audit.findings.read"}
	copy, err := base.WithModulePermissions(permissions)
	if err != nil {
		t.Fatal(err)
	}
	permissions[0] = "changed"
	if !copy.modulePermissions["example.read"] || len(base.modulePermissions) != 0 {
		t.Fatal("catalog is not isolated")
	}
}
