package perms

import (
	"fmt"
	"sync"
)

// LoadUserCallback is a function type for loading user data from external storage
// It should return a User object with all roles and permissions loaded
type LoadUserCallback func(userID string) (*User, error)

// SaveUserCallback is a function type for saving user data to external storage
// It receives the User object and should persist it to the database
type SaveUserCallback func(user *User) error

// UserLookupCallback is a function type for looking up user permissions during authorization
// It should return the user's roles and permissions without loading the full user object
// This is more efficient for authorization checks as it doesn't require loading all user data
type UserLookupCallback func(userID string) ([]string, []string, error) // returns (roles, permissions, error)

// AuthManager manages roles, users, and authorization
type AuthManager struct {
	roles map[string]*Role
	users map[string]*User
	mutex sync.RWMutex
}

// NewAuthManager creates a new authorization manager
func NewAuthManager() *AuthManager {
	return &AuthManager{
		roles: make(map[string]*Role),
		users: make(map[string]*User),
	}
}

// CreateRole creates a new role with the given name
func (am *AuthManager) CreateRole(name string) (*Role, error) {
	if err := ValidateRoleName(name); err != nil {
		LogError("Invalid role name", "name", name, "error", err)
		return nil, err
	}
	
	am.mutex.Lock()
	defer am.mutex.Unlock()
	
	role := NewRole(name)
	am.roles[name] = role
	
	LogInfo("Role created", "name", name)
	return role, nil
}

// GetRole retrieves a role by name
func (am *AuthManager) GetRole(name string) (*Role, bool) {
	am.mutex.RLock()
	defer am.mutex.RUnlock()
	
	role, exists := am.roles[name]
	return role, exists
}

// CreateUser creates a new user with the given ID and name
func (am *AuthManager) CreateUser(id, name string) (*User, error) {
	if err := ValidateUserID(id); err != nil {
		LogError("Invalid user ID", "id", id, "error", err)
		return nil, err
	}
	
	if name == "" || len(name) > 200 {
		return nil, ValidationError{Field: "name", Message: "name cannot be empty or exceed 200 characters"}
	}
	
	am.mutex.Lock()
	defer am.mutex.Unlock()
	
	user := NewUser(id, name)
	am.users[id] = user
	
	LogInfo("User created", "id", id, "name", name)
	return user, nil
}

// GetUser retrieves a user by ID
// If the user is not in memory and a global load callback is set, it will attempt to load from external storage
func (am *AuthManager) GetUser(id string) (*User, bool) {
	am.mutex.RLock()
	user, exists := am.users[id]
	am.mutex.RUnlock()
	
	if exists {
		return user, true
	}
	
	// Try to load from external storage if global callback is set
	loadCallback := GetGlobalLoadUserCallback()
	if loadCallback != nil {
		loadedUser, err := loadCallback(id)
		if err == nil && loadedUser != nil {
			am.mutex.Lock()
			am.users[id] = loadedUser
			am.mutex.Unlock()
			return loadedUser, true
		}
	}
	
	return nil, false
}

// AssignRole assigns a role to a user
func (am *AuthManager) AssignRole(userID, roleName string) error {
	if err := ValidateUserID(userID); err != nil {
		LogError("Invalid user ID in AssignRole", "userID", userID, "error", err)
		return err
	}
	if err := ValidateRoleName(roleName); err != nil {
		LogError("Invalid role name in AssignRole", "roleName", roleName, "error", err)
		return err
	}
	
	am.mutex.Lock()
	defer am.mutex.Unlock()
	
	user, exists := am.users[userID]
	if !exists {
		LogError("User not found in AssignRole", "userID", userID)
		return fmt.Errorf("authorization failed")
	}
	
	role, exists := am.roles[roleName]
	if !exists {
		LogError("Role not found in AssignRole", "roleName", roleName)
		return fmt.Errorf("authorization failed")
	}
	
	user.AddRole(role)
	
	// Save user to external storage if global callback is set
	saveCallback := GetGlobalSaveUserCallback()
	if saveCallback != nil {
		if err := saveCallback(user); err != nil {
			globalLogger.LogCallbackError("save_user", userID, err)
			return fmt.Errorf("authorization failed")
		}
	}
	
	LogInfo("Role assigned to user", "userID", userID, "roleName", roleName)
	return nil
}

// RemoveRole removes a role from a user
func (am *AuthManager) RemoveRole(userID, roleName string) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()
	
	user, exists := am.users[userID]
	if !exists {
		return fmt.Errorf("user %s not found", userID)
	}
	
	// Find and remove the role
	for i, role := range user.Roles {
		if role.Name == roleName {
			user.Roles = append(user.Roles[:i], user.Roles[i+1:]...)
			
			// Save user to external storage if global callback is set
			saveCallback := GetGlobalSaveUserCallback()
			if saveCallback != nil {
				return saveCallback(user)
			}
			
			return nil
		}
	}
	
	return fmt.Errorf("role %s not assigned to user %s", roleName, userID)
}

// Authorize checks if a user has permission to perform an action on a resource
// If a global user lookup callback is set, it will use that for efficient authorization without loading the full user
func (am *AuthManager) Authorize(userID, resource, action string) bool {
	// Validate inputs
	if err := ValidateUserID(userID); err != nil {
		globalLogger.LogAuthFailure(userID, resource, action, "invalid user ID")
		return false
	}
	if err := ValidateResource(resource); err != nil {
		globalLogger.LogAuthFailure(userID, resource, action, "invalid resource")
		return false
	}
	if err := ValidateAction(action); err != nil {
		globalLogger.LogAuthFailure(userID, resource, action, "invalid action")
		return false
	}
	
	// Use global lookup callback if available (more efficient)
	userLookupCallback := GetGlobalUserLookupCallback()
	if userLookupCallback != nil {
		roles, permissions, err := userLookupCallback(userID)
		if err != nil {
			globalLogger.LogCallbackError("user_lookup", userID, err)
			globalLogger.LogAuthFailure(userID, resource, action, "callback error")
			return false
		}
		
		// Check direct permissions first
		for _, permStr := range permissions {
			perm := NewPermission(permStr)
			if perm.Matches(resource, action) {
				globalLogger.LogAuthAttempt(userID, resource, action, true, "direct permission")
				return true
			}
		}
		
		// Check role-based permissions - hold lock during entire check to prevent race conditions
		am.mutex.RLock()
		defer am.mutex.RUnlock()
		
		for _, roleName := range roles {
			role, exists := am.roles[roleName]
			if exists && role.HasPermission(resource, action) {
				globalLogger.LogAuthAttempt(userID, resource, action, true, "role permission")
				return true
			}
		}
		
		globalLogger.LogAuthAttempt(userID, resource, action, false, "no matching permissions")
		return false
	}
	
	// Fallback to in-memory user lookup
	am.mutex.RLock()
	defer am.mutex.RUnlock()
	
	user, exists := am.users[userID]
	if !exists {
		globalLogger.LogAuthFailure(userID, resource, action, "user not found")
		return false
	}
	
	allowed := user.HasPermission(resource, action)
	globalLogger.LogAuthAttempt(userID, resource, action, allowed, "in-memory check")
	return allowed
}

// AuthorizeUser checks if a user object has permission to perform an action on a resource
func (am *AuthManager) AuthorizeUser(user *User, resource, action string) bool {
	if user == nil {
		return false
	}
	
	return user.HasPermission(resource, action)
}

// HasRoute checks if a user has access to a specific route (ignoring action)
// This is useful for route-based authentication where the action is embedded in the route
// If a global user lookup callback is set, it will use that for efficient authorization without loading the full user
func (am *AuthManager) HasRoute(userID, resource string) bool {
	// Use global lookup callback if available (more efficient)
	userLookupCallback := GetGlobalUserLookupCallback()
	if userLookupCallback != nil {
		roles, permissions, err := userLookupCallback(userID)
		if err != nil {
			return false
		}
		
		// Check direct permissions first
		for _, permStr := range permissions {
			perm := NewPermission(permStr)
			if perm.HasRoute(resource) {
				return true
			}
		}
		
		// Check role-based permissions
		for _, roleName := range roles {
			am.mutex.RLock()
			role, exists := am.roles[roleName]
			am.mutex.RUnlock()
			
			if exists && role.HasRoute(resource) {
				return true
			}
		}
		
		return false
	}
	
	// Fallback to in-memory user lookup
	am.mutex.RLock()
	defer am.mutex.RUnlock()
	
	user, exists := am.users[userID]
	if !exists {
		return false
	}
	
	return user.HasRoute(resource)
}

// HasRouteUser checks if a user object has access to a specific route (ignoring action)
func (am *AuthManager) HasRouteUser(user *User, resource string) bool {
	if user == nil {
		return false
	}
	
	return user.HasRoute(resource)
}

// HasRole checks if a user has a specific role
// If a global user lookup callback is set, it will use that for efficient role checking without loading the full user
func (am *AuthManager) HasRole(userID, roleName string) bool {
	// Use global lookup callback if available (more efficient)
	userLookupCallback := GetGlobalUserLookupCallback()
	if userLookupCallback != nil {
		roles, _, err := userLookupCallback(userID)
		if err != nil {
			return false
		}
		
		// Check if user has the specified role
		for _, role := range roles {
			if role == roleName {
				return true
			}
		}
		
		return false
	}
	
	// Fallback to in-memory user lookup
	am.mutex.RLock()
	defer am.mutex.RUnlock()
	
	user, exists := am.users[userID]
	if !exists {
		return false
	}
	
	return user.HasRole(roleName)
}

// HasRoleUser checks if a user object has a specific role
func (am *AuthManager) HasRoleUser(user *User, roleName string) bool {
	if user == nil {
		return false
	}
	
	return user.HasRole(roleName)
}

// ListRoles returns all roles with pagination
func (am *AuthManager) ListRoles(limit, offset int) ([]*Role, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100 // Default limit
	}
	if offset < 0 {
		offset = 0
	}
	
	am.mutex.RLock()
	defer am.mutex.RUnlock()
	
	var roles []*Role
	count := 0
	skipped := 0
	
	for _, role := range am.roles {
		if skipped < offset {
			skipped++
			continue
		}
		if count >= limit {
			break
		}
		roles = append(roles, role)
		count++
	}
	
	LogInfo("Listed roles", "count", len(roles), "limit", limit, "offset", offset)
	return roles, nil
}

// ListUsers returns all users with pagination
func (am *AuthManager) ListUsers(limit, offset int) ([]*User, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100 // Default limit
	}
	if offset < 0 {
		offset = 0
	}
	
	am.mutex.RLock()
	defer am.mutex.RUnlock()
	
	var users []*User
	count := 0
	skipped := 0
	
	for _, user := range am.users {
		if skipped < offset {
			skipped++
			continue
		}
		if count >= limit {
			break
		}
		users = append(users, user)
		count++
	}
	
	LogInfo("Listed users", "count", len(users), "limit", limit, "offset", offset)
	return users, nil
}

// DeleteRole deletes a role (but doesn't remove it from users)
func (am *AuthManager) DeleteRole(name string) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()
	
	_, exists := am.roles[name]
	if !exists {
		return fmt.Errorf("role %s not found", name)
	}
	
	delete(am.roles, name)
	return nil
}

// DeleteUser deletes a user
func (am *AuthManager) DeleteUser(id string) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()
	
	_, exists := am.users[id]
	if !exists {
		return fmt.Errorf("user %s not found", id)
	}
	
	delete(am.users, id)
	return nil
}

// SaveUser manually saves a user to external storage using the global save callback
func (am *AuthManager) SaveUser(userID string) error {
	am.mutex.RLock()
	user, exists := am.users[userID]
	am.mutex.RUnlock()
	
	if !exists {
		return fmt.Errorf("user %s not found", userID)
	}
	
	saveCallback := GetGlobalSaveUserCallback()
	if saveCallback == nil {
		return fmt.Errorf("global save callback not set")
	}
	
	return saveCallback(user)
}

// LoadUserFromDB is a helper method for database integration
// This method loads a user with all their roles and permissions into the auth manager
func (am *AuthManager) LoadUserFromDB(user *User) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()
	
	// Create user in auth manager
	am.users[user.ID] = user
	
	// Create roles and assign permissions
	for _, role := range user.Roles {
		// Create role if it doesn't exist
		if _, exists := am.roles[role.Name]; !exists {
			am.roles[role.Name] = role
		}
		
		// Assign role to user
		user.AddRole(role)
	}
	
	// Save user to external storage if global callback is set
	saveCallback := GetGlobalSaveUserCallback()
	if saveCallback != nil {
		return saveCallback(user)
	}
	
	return nil
}

// ClearUser removes a user and all their roles from the auth manager
// Useful for logout or session cleanup
func (am *AuthManager) ClearUser(userID string) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()
	
	_, exists := am.users[userID]
	if !exists {
		return fmt.Errorf("user %s not found", userID)
	}
	
	delete(am.users, userID)
	return nil
}
