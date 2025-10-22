package perms

import (
	"fmt"
	"strings"
)

// Role represents a role that can have multiple permissions
type Role struct {
	Name        string
	Permissions []Permission
}

// NewRole creates a new role with the given name
func NewRole(name string) *Role {
	return &Role{
		Name:        name,
		Permissions: make([]Permission, 0),
	}
}

// AddPermission adds a permission to the role
func (r *Role) AddPermission(permission Permission) {
	r.Permissions = append(r.Permissions, permission)
}

// AddPermissionString adds a permission from a string to the role
func (r *Role) AddPermissionString(permission string) {
	r.AddPermission(NewPermission(permission))
}

// AddPermissions adds multiple permissions to the role
func (r *Role) AddPermissions(permissions ...Permission) {
	r.Permissions = append(r.Permissions, permissions...)
}

// AddPermissionStrings adds multiple permissions from strings to the role
func (r *Role) AddPermissionStrings(permissions ...string) {
	for _, perm := range permissions {
		r.AddPermissionString(perm)
	}
}

// HasPermission checks if the role has a specific permission
func (r *Role) HasPermission(resource, action string) bool {
	for _, perm := range r.Permissions {
		if perm.Matches(resource, action) {
			return true
		}
	}
	return false
}

// HasRoute checks if the role has access to a specific route (ignoring action)
// This is useful for route-based authentication where the action is embedded in the route
func (r *Role) HasRoute(resource string) bool {
	for _, perm := range r.Permissions {
		if perm.HasRoute(resource) {
			return true
		}
	}
	return false
}

// String returns a string representation of the role
func (r *Role) String() string {
	var permStrings []string
	for _, perm := range r.Permissions {
		permStrings = append(permStrings, perm.String())
	}
	return fmt.Sprintf("Role(%s): [%s]", r.Name, strings.Join(permStrings, ", "))
}

// User represents a user that can have multiple roles
type User struct {
	ID    string
	Name  string
	Roles []*Role
}

// NewUser creates a new user with the given ID and name
func NewUser(id, name string) *User {
	return &User{
		ID:    id,
		Name:  name,
		Roles: make([]*Role, 0),
	}
}

// AddRole adds a role to the user
func (u *User) AddRole(role *Role) {
	u.Roles = append(u.Roles, role)
}

// AddRoles adds multiple roles to the user
func (u *User) AddRoles(roles ...*Role) {
	u.Roles = append(u.Roles, roles...)
}

// HasRole checks if the user has a specific role
func (u *User) HasRole(roleName string) bool {
	for _, role := range u.Roles {
		if role.Name == roleName {
			return true
		}
	}
	return false
}

// HasPermission checks if the user has a specific permission through any of their roles
func (u *User) HasPermission(resource, action string) bool {
	for _, role := range u.Roles {
		if role.HasPermission(resource, action) {
			return true
		}
	}
	return false
}

// HasRoute checks if the user has access to a specific route through any of their roles (ignoring action)
// This is useful for route-based authentication where the action is embedded in the route
func (u *User) HasRoute(resource string) bool {
	for _, role := range u.Roles {
		if role.HasRoute(resource) {
			return true
		}
	}
	return false
}

// GetPermissions returns all permissions the user has through their roles
func (u *User) GetPermissions() []Permission {
	var permissions []Permission
	for _, role := range u.Roles {
		permissions = append(permissions, role.Permissions...)
	}
	return permissions
}

// String returns a string representation of the user
func (u *User) String() string {
	var roleNames []string
	for _, role := range u.Roles {
		roleNames = append(roleNames, role.Name)
	}
	return fmt.Sprintf("User(%s): [%s]", u.Name, strings.Join(roleNames, ", "))
}
