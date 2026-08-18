package auth

import "github.com/oast/oast/internal/storage"

// Permission is a capability an action requires.
type Permission string

const (
	PermManageUsers    Permission = "users.manage"
	PermManageDomains   Permission = "domains.manage"
	PermManageProjects  Permission = "projects.manage"
	PermManageTokens    Permission = "tokens.manage"
	PermViewAllInteractions Permission = "interactions.view_all"
	PermViewOwnInteractions Permission = "interactions.view_own"
	PermDeleteInteractions Permission = "interactions.delete"
	PermExportInteractions  Permission = "interactions.export"
	PermViewLogs       Permission = "logs.view"
)

// rolePermissions maps each role to the set of permissions it holds.
var rolePermissions = map[storage.Role]map[Permission]bool{
	storage.RoleAdmin: {
		PermManageUsers: true, PermManageDomains: true, PermManageProjects: true,
		PermManageTokens: true, PermViewAllInteractions: true, PermViewOwnInteractions: true,
		PermDeleteInteractions: true, PermExportInteractions: true, PermViewLogs: true,
	},
	storage.RoleAuditor: {
		PermViewAllInteractions: true, PermViewOwnInteractions: true,
		PermExportInteractions: true, PermViewLogs: true,
	},
	storage.RoleViewer: {
		PermViewOwnInteractions: true,
	},
}

// Can reports whether the role holds the given permission.
func Can(role storage.Role, perm Permission) bool {
	set, ok := rolePermissions[role]
	if !ok {
		return false
	}
	return set[perm]
}

// Missing returns the permissions from required that the role does NOT have.
func Missing(role storage.Role, required ...Permission) []Permission {
	var missing []Permission
	for _, p := range required {
		if !Can(role, p) {
			missing = append(missing, p)
		}
	}
	return missing
}
