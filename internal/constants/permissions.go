package constants

type Permission uint32

const (
	PermNone Permission = 0

	// user permissions (0-15)
	PermUserRead   Permission = 1 << 0 // 1
	PermUserWrite  Permission = 1 << 1 // 2
	PermUserDelete Permission = 1 << 2 // 4

	// admin permissions (16-31)
	PermAdminPanel Permission = 1 << 16 // 65536
	PermAuditRead  Permission = 1 << 17 // 131072

	// roles shortcuts
	PermRoleUser  Permission = PermUserRead
	PermRoleAdmin Permission = PermUserRead | PermUserWrite | PermUserDelete | PermAdminPanel | PermAuditRead
)

// HasPermission checks if permission present
func HasPermission(userPerms, required Permission) bool {
	return userPerms&required == required
}

// AddPermission adds permission
func AddPermission(userPerms, toAdd Permission) Permission {
	return userPerms | toAdd
}

// RemovePermission deletes permission
func RemovePermission(userPerms, toRemove Permission) Permission {
	return userPerms &^ toRemove
}
