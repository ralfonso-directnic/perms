package perms

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPermission(t *testing.T) {
	tests := []struct {
		name           string
		permission     Permission
		resource       string
		action         string
		expectedMatch  bool
	}{
		{
			name:           "exact match",
			permission:     Permission{Resource: "/users", Action: "read"},
			resource:       "/users",
			action:         "read",
			expectedMatch:  true,
		},
		{
			name:           "wildcard action",
			permission:     Permission{Resource: "/users", Action: "*"},
			resource:       "/users",
			action:         "write",
			expectedMatch:  true,
		},
		{
			name:           "wildcard resource",
			permission:     Permission{Resource: "/*", Action: "read"},
			resource:       "/posts",
			action:         "read",
			expectedMatch:  true,
		},
		{
			name:           "resource prefix wildcard",
			permission:     Permission{Resource: "/users/*", Action: "read"},
			resource:       "/users/123",
			action:         "read",
			expectedMatch:  true,
		},
		{
			name:           "no action in permission",
			permission:     Permission{Resource: "/users", Action: ""},
			resource:       "/users",
			action:         "read",
			expectedMatch:  true,
		},
		{
			name:           "no match",
			permission:     Permission{Resource: "/posts", Action: "read"},
			resource:       "/users",
			action:         "read",
			expectedMatch:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.permission.Matches(tt.resource, tt.action)
			assert.Equal(t, tt.expectedMatch, result)
		})
	}
}

func TestNewPermission(t *testing.T) {
	tests := []struct {
		input          string
		expectedResource string
		expectedAction   string
		hasRegex        bool
	}{
		{
			input:            "/users:read",
			expectedResource: "/users",
			expectedAction:   "read",
			hasRegex:         false,
		},
		{
			input:            "/users/read",
			expectedResource: "/users",
			expectedAction:   "read",
			hasRegex:         false,
		},
		{
			input:            "/users",
			expectedResource: "/users",
			expectedAction:   "",
			hasRegex:         false,
		},
		{
			input:            "users:read",
			expectedResource: "users",
			expectedAction:   "read",
			hasRegex:         false,
		},
		{
			input:            "/admin/settings[0-9]+",
			expectedResource: "/admin/settings[0-9]+",
			expectedAction:   "",
			hasRegex:         true,
		},
		{
			input:            "/admin/[0-9]+:read",
			expectedResource: "/admin/[0-9]+",
			expectedAction:   "read",
			hasRegex:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			perm := NewPermission(tt.input)
			assert.Equal(t, tt.expectedResource, perm.Resource)
			assert.Equal(t, tt.expectedAction, perm.Action)
			if tt.hasRegex {
				assert.NotNil(t, perm.regexPattern, "Expected regex pattern to be compiled")
			} else {
				assert.Nil(t, perm.regexPattern, "Expected no regex pattern")
			}
		})
	}
}

func TestRegexPermissionMatching(t *testing.T) {
	tests := []struct {
		name           string
		permission     string
		resource       string
		action         string
		expectedMatch  bool
	}{
		{
			name:           "numeric ID pattern",
			permission:     "/admin/settings[0-9]+",
			resource:       "/admin/settings123",
			action:         "read",
			expectedMatch:  true,
		},
		{
			name:           "numeric ID pattern - no match",
			permission:     "/admin/settings[0-9]+",
			resource:       "/admin/settingsabc",
			action:         "read",
			expectedMatch:  false,
		},
		{
			name:           "numeric ID pattern with action",
			permission:     "/admin/[0-9]+:read",
			resource:       "/admin/123",
			action:         "read",
			expectedMatch:  true,
		},
		{
			name:           "numeric ID pattern with action - wrong action",
			permission:     "/admin/[0-9]+:read",
			resource:       "/admin/123",
			action:         "update",
			expectedMatch:  false,
		},
		{
			name:           "alphanumeric pattern",
			permission:     "/users/[a-zA-Z0-9]+",
			resource:       "/users/user123",
			action:         "read",
			expectedMatch:  true,
		},
		{
			name:           "alphanumeric pattern - no match",
			permission:     "/users/[a-zA-Z0-9]+",
			resource:       "/users/user-123",
			action:         "read",
			expectedMatch:  false,
		},
		{
			name:           "optional pattern",
			permission:     "/posts/[0-9]+?",
			resource:       "/posts/123",
			action:         "read",
			expectedMatch:  true,
		},
		{
			name:           "optional pattern - empty",
			permission:     "/posts/[0-9]*",
			resource:       "/posts/",
			action:         "read",
			expectedMatch:  true,
		},
		{
			name:           "complex pattern",
			permission:     "/api/v[0-9]+/users/[0-9]+",
			resource:       "/api/v1/users/123",
			action:         "read",
			expectedMatch:  true,
		},
		{
			name:           "complex pattern - no match",
			permission:     "/api/v[0-9]+/users/[0-9]+",
			resource:       "/api/v1/users/abc",
			action:         "read",
			expectedMatch:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perm := NewPermission(tt.permission)
			result := perm.Matches(tt.resource, tt.action)
			assert.Equal(t, tt.expectedMatch, result, 
				"Permission %s should match resource %s with action %s: %v", 
				tt.permission, tt.resource, tt.action, tt.expectedMatch)
		})
	}
}

func TestPermissionHasRoute(t *testing.T) {
	tests := []struct {
		name           string
		permission     Permission
		resource       string
		expectedMatch  bool
	}{
		{
			name:           "exact match",
			permission:     Permission{Resource: "/users", Action: "read"},
			resource:       "/users",
			expectedMatch:  true,
		},
		{
			name:           "wildcard action",
			permission:     Permission{Resource: "/users", Action: "*"},
			resource:       "/users",
			expectedMatch:  true,
		},
		{
			name:           "wildcard resource",
			permission:     Permission{Resource: "/*", Action: "read"},
			resource:       "/posts",
			expectedMatch:  true,
		},
		{
			name:           "resource prefix wildcard",
			permission:     Permission{Resource: "/users/*", Action: "read"},
			resource:       "/users/123",
			expectedMatch:  true,
		},
		{
			name:           "no action in permission",
			permission:     Permission{Resource: "/users", Action: ""},
			resource:       "/users",
			expectedMatch:  true,
		},
		{
			name:           "no match",
			permission:     Permission{Resource: "/posts", Action: "read"},
			resource:       "/users",
			expectedMatch:  false,
		},
		{
			name:           "regex pattern match",
			permission:     NewPermission("/admin/settings[0-9]+"),
			resource:       "/admin/settings123",
			expectedMatch:  true,
		},
		{
			name:           "regex pattern no match",
			permission:     NewPermission("/admin/settings[0-9]+"),
			resource:       "/admin/settingsabc",
			expectedMatch:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.permission.HasRoute(tt.resource)
			assert.Equal(t, tt.expectedMatch, result)
		})
	}
}

func TestRole(t *testing.T) {
	role := NewRole("admin")
	
	// Test adding permissions
	role.AddPermission(Permission{Resource: "/users", Action: "read"})
	role.AddPermissionString("/posts:create")
	role.AddPermissionStrings("/admin/*", "/logs:read")
	
	// Test permission checking
	assert.True(t, role.HasPermission("/users", "read"))
	assert.True(t, role.HasPermission("/posts", "create"))
	assert.True(t, role.HasPermission("/admin/settings", "read"))
	assert.True(t, role.HasPermission("/logs", "read"))
	assert.False(t, role.HasPermission("/users", "update"))
	assert.False(t, role.HasPermission("/posts", "read"))
	
	// Test route checking
	assert.True(t, role.HasRoute("/users"))
	assert.True(t, role.HasRoute("/posts"))
	assert.True(t, role.HasRoute("/admin/settings"))
	assert.True(t, role.HasRoute("/logs"))
	assert.False(t, role.HasRoute("/other"))
}

func TestUser(t *testing.T) {
	user := NewUser("user1", "John Doe")
	
	// Create roles
	adminRole := NewRole("admin")
	adminRole.AddPermissionStrings("/admin/*", "/users:update")
	
	userRole := NewRole("user")
	userRole.AddPermissionStrings("/users/self", "/posts:read")
	
	// Add roles to user
	user.AddRole(adminRole)
	user.AddRole(userRole)
	
	// Test role checking
	assert.True(t, user.HasRole("admin"))
	assert.True(t, user.HasRole("user"))
	assert.False(t, user.HasRole("guest"))
	
	// Test permission checking
	assert.True(t, user.HasPermission("/admin/settings", "read"))
	assert.True(t, user.HasPermission("/users", "update"))
	assert.True(t, user.HasPermission("/users/self", "read"))
	assert.True(t, user.HasPermission("/posts", "read"))
	assert.False(t, user.HasPermission("/admin", "update"))
	assert.False(t, user.HasPermission("/posts", "create"))
	
	// Test route checking
	assert.True(t, user.HasRoute("/admin/settings"))
	assert.True(t, user.HasRoute("/users"))
	assert.True(t, user.HasRoute("/users/self"))
	assert.True(t, user.HasRoute("/posts"))
	assert.False(t, user.HasRoute("/admin"))
	assert.False(t, user.HasRoute("/other"))
}

func TestAuthManager(t *testing.T) {
	am := NewAuthManager()
	
	// Create roles
	adminRole := am.CreateRole("admin")
	adminRole.AddPermissionStrings("/admin/*", "/users:update", "/posts:delete")
	
	userRole := am.CreateRole("user")
	userRole.AddPermissionStrings("/users/self", "/posts:read", "/posts:create")
	
	// Create users
	am.CreateUser("user1", "John Doe")
	am.CreateUser("user2", "Jane Smith")
	
	// Assign roles
	err := am.AssignRole("user1", "admin")
	require.NoError(t, err)
	
	err = am.AssignRole("user2", "user")
	require.NoError(t, err)
	
	// Test authorization
	assert.True(t, am.Authorize("user1", "/admin/settings", "read"))
	assert.True(t, am.Authorize("user1", "/users", "update"))
	assert.True(t, am.Authorize("user1", "/posts", "delete"))
	
	assert.True(t, am.Authorize("user2", "/users/self", "read"))
	assert.True(t, am.Authorize("user2", "/posts", "read"))
	assert.True(t, am.Authorize("user2", "/posts", "create"))
	
	assert.False(t, am.Authorize("user2", "/admin/settings", "read"))
	assert.False(t, am.Authorize("user2", "/users", "update"))
	assert.False(t, am.Authorize("user1", "/posts", "read"))
	
	// Test route checking
	assert.True(t, am.HasRoute("user1", "/admin/settings"))
	assert.True(t, am.HasRoute("user1", "/users"))
	assert.True(t, am.HasRoute("user1", "/posts"))
	assert.True(t, am.HasRoute("user2", "/users/self"))
	assert.True(t, am.HasRoute("user2", "/posts"))
	assert.False(t, am.HasRoute("user2", "/admin/settings"))
	assert.False(t, am.HasRoute("user1", "/other"))
	
	// Test role checking
	assert.True(t, am.HasRole("user1", "admin"))
	assert.True(t, am.HasRole("user2", "user"))
	assert.False(t, am.HasRole("user1", "user"))
	assert.False(t, am.HasRole("user2", "admin"))
	assert.False(t, am.HasRole("nonexistent", "admin"))
	
	// Test role checking with user objects
	user1, _ := am.GetUser("user1")
	user2, _ := am.GetUser("user2")
	assert.True(t, am.HasRoleUser(user1, "admin"))
	assert.True(t, am.HasRoleUser(user2, "user"))
	assert.False(t, am.HasRoleUser(user1, "user"))
	assert.False(t, am.HasRoleUser(user2, "admin"))
	assert.False(t, am.HasRoleUser(nil, "admin"))
	
	// Test role removal
	err = am.RemoveRole("user1", "admin")
	require.NoError(t, err)
	
	assert.False(t, am.Authorize("user1", "/admin/settings", "read"))
	assert.False(t, am.HasRoute("user1", "/admin/settings"))
	assert.False(t, am.HasRole("user1", "admin"))
}

func TestAuthManagerDatabaseIntegration(t *testing.T) {
	am := NewAuthManager()
	
	// Create a user with roles and permissions (simulating database load)
	user := NewUser("user1", "John Doe")
	
	adminRole := NewRole("admin")
	adminRole.AddPermissionStrings("/admin/*", "/users:update")
	user.AddRole(adminRole)
	
	userRole := NewRole("user")
	userRole.AddPermissionStrings("/posts:read", "/posts:create")
	user.AddRole(userRole)
	
	// Test LoadUserFromDB helper method
	err := am.LoadUserFromDB(user)
	require.NoError(t, err)
	
	// Verify user is loaded
	assert.True(t, am.HasRole("user1", "admin"))
	assert.True(t, am.HasRole("user1", "user"))
	assert.True(t, am.Authorize("user1", "/admin/settings", "read"))
	assert.True(t, am.Authorize("user1", "/posts", "read"))
	
	// Test ClearUser helper method
	err = am.ClearUser("user1")
	require.NoError(t, err)
	
	// Verify user is cleared
	assert.False(t, am.HasRole("user1", "admin"))
	assert.False(t, am.Authorize("user1", "/admin/settings", "read"))
	
	// Test clearing nonexistent user
	err = am.ClearUser("nonexistent")
	assert.Error(t, err)
}

func TestAuthManagerCallbacks(t *testing.T) {
	am := NewAuthManager()
	
	// Track callback calls
	var loadCallCount int
	var saveCallCount int
	var lastSavedUser *User
	var lastLoadUserID string
	
	// Set up save callback
	SetGlobalSaveUserCallback(func(user *User) error {
		saveCallCount++
		lastSavedUser = user
		return nil
	})
	
	// Set up load callback
	SetGlobalLoadUserCallback(func(userID string) (*User, error) {
		loadCallCount++
		lastLoadUserID = userID
		
		// Return a mock user for testing
		user := NewUser(userID, "Loaded User")
		role := NewRole("admin")
		role.AddPermissionStrings("/admin/*")
		user.AddRole(role)
		return user, nil
	})
	
	// Test automatic save on role assignment
	am.CreateUser("user1", "John Doe")
	adminRole := am.CreateRole("admin")
	adminRole.AddPermissionStrings("/admin/*")
	
	// This should trigger save callback
	err := am.AssignRole("user1", "admin")
	require.NoError(t, err)
	assert.Equal(t, 1, saveCallCount)
	assert.Equal(t, "user1", lastSavedUser.ID)
	
	// Test automatic save on role removal
	err = am.RemoveRole("user1", "admin")
	require.NoError(t, err)
	assert.Equal(t, 2, saveCallCount)
	
	// Test load callback when user not in memory
	am.ClearUser("user1") // Remove from memory
	
	// This should trigger load callback
	loadedUser, exists := am.GetUser("user1")
	require.True(t, exists)
	assert.Equal(t, 1, loadCallCount)
	assert.Equal(t, "user1", lastLoadUserID)
	assert.Equal(t, "Loaded User", loadedUser.Name)
	assert.True(t, loadedUser.HasRole("admin"))
	
	// Test manual save
	err = am.SaveUser("user1")
	require.NoError(t, err)
	assert.Equal(t, 3, saveCallCount)
	
	// Test save callback error handling
	SetGlobalSaveUserCallback(func(user *User) error {
		return fmt.Errorf("save error")
	})
	
	err = am.AssignRole("user1", "admin")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "save error")
	
	// Test load callback error handling
	SetGlobalLoadUserCallback(func(userID string) (*User, error) {
		return nil, fmt.Errorf("load error")
	})
	
	am.ClearUser("user1")
	_, exists = am.GetUser("user1")
	assert.False(t, exists)
}

func TestAuthManagerAuthorizationCallbacks(t *testing.T) {
	am := NewAuthManager()
	
	// Create roles with permissions
	adminRole := am.CreateRole("admin")
	adminRole.AddPermissionStrings("/admin/*", "/users:update")
	
	userRole := am.CreateRole("user")
	userRole.AddPermissionStrings("/posts:read", "/posts:create")
	
	// Set up authorization lookup callback
	SetGlobalUserLookupCallback(func(userID string) ([]string, []string, error) {
		switch userID {
		case "admin1":
			return []string{"admin"}, []string{"/admin/settings:read"}, nil
		case "user1":
			return []string{"user"}, []string{"/posts:read"}, nil
		case "moderator1":
			return []string{"admin", "user"}, []string{}, nil
		case "error_user":
			return nil, nil, fmt.Errorf("database error")
		default:
			return []string{}, []string{}, nil
		}
	})
	
	// Test authorization with callback
	assert.True(t, am.Authorize("admin1", "/admin/settings", "read"))
	assert.True(t, am.Authorize("admin1", "/users", "update"))
	assert.False(t, am.Authorize("admin1", "/posts", "create"))
	
	assert.True(t, am.Authorize("user1", "/posts", "read"))
	assert.False(t, am.Authorize("user1", "/admin/settings", "read"))
	
	// Test user with multiple roles
	assert.True(t, am.Authorize("moderator1", "/admin/settings", "read"))
	assert.True(t, am.Authorize("moderator1", "/posts", "read"))
	
	// Test route checking with callback
	assert.True(t, am.HasRoute("admin1", "/admin/settings"))
	assert.True(t, am.HasRoute("user1", "/posts"))
	assert.False(t, am.HasRoute("user1", "/admin/settings"))
	
	// Test role checking with callback
	assert.True(t, am.HasRole("admin1", "admin"))
	assert.True(t, am.HasRole("user1", "user"))
	assert.True(t, am.HasRole("moderator1", "admin"))
	assert.True(t, am.HasRole("moderator1", "user"))
	assert.False(t, am.HasRole("user1", "admin"))
	
	// Test error handling
	assert.False(t, am.Authorize("error_user", "/admin/settings", "read"))
	assert.False(t, am.HasRoute("error_user", "/admin/settings"))
	assert.False(t, am.HasRole("error_user", "admin"))
	
	// Test nonexistent user
	assert.False(t, am.Authorize("nonexistent", "/admin/settings", "read"))
	assert.False(t, am.HasRoute("nonexistent", "/admin/settings"))
	assert.False(t, am.HasRole("nonexistent", "admin"))
	
	// Test fallback to in-memory when callback is nil
	SetGlobalUserLookupCallback(nil)
	
	// Create user in memory
	user := am.CreateUser("memory_user", "Memory User")
	user.AddRole(adminRole)
	
	assert.True(t, am.Authorize("memory_user", "/admin/settings", "read"))
	assert.True(t, am.HasRoute("memory_user", "/admin/settings"))
	assert.True(t, am.HasRole("memory_user", "admin"))
}

func TestGlobalCallbacks(t *testing.T) {
	// Clear any existing global callbacks
	ClearGlobalCallbacks()
	
	am := NewAuthManager()
	
	// Track callback calls
	var loadCallCount int
	var saveCallCount int
	var lookupCallCount int
	var lastSavedUser *User
	var lastLoadUserID string
	
	// Set up global save callback
	SetGlobalSaveUserCallback(func(user *User) error {
		saveCallCount++
		lastSavedUser = user
		return nil
	})
	
	// Set up global load callback
	SetGlobalLoadUserCallback(func(userID string) (*User, error) {
		loadCallCount++
		lastLoadUserID = userID
		
		// Return a mock user for testing
		user := NewUser(userID, "Loaded User")
		role := NewRole("admin")
		role.AddPermissionStrings("/admin/*")
		user.AddRole(role)
		return user, nil
	})
	
	// Set up global authorization lookup callback
	SetGlobalUserLookupCallback(func(userID string) ([]string, []string, error) {
		lookupCallCount++
		
		switch userID {
		case "admin1":
			return []string{"admin"}, []string{"/admin/settings:read"}, nil
		case "user1":
			return []string{"user"}, []string{"/posts:read"}, nil
		default:
			return []string{}, []string{}, nil
		}
	})
	
	// Test global save callback
	am.CreateUser("user1", "John Doe")
	adminRole := am.CreateRole("admin")
	adminRole.AddPermissionStrings("/admin/*")
	
	err := am.AssignRole("user1", "admin")
	require.NoError(t, err)
	assert.Equal(t, 1, saveCallCount)
	assert.Equal(t, "user1", lastSavedUser.ID)
	
	// Test global load callback
	am.ClearUser("user1")
	loadedUser, exists := am.GetUser("user1")
	require.True(t, exists)
	assert.Equal(t, 1, loadCallCount)
	assert.Equal(t, "user1", lastLoadUserID)
	assert.Equal(t, "Loaded User", loadedUser.Name)
	
	// Test global authorization lookup callback
	assert.True(t, am.Authorize("admin1", "/admin/settings", "read"))
	assert.True(t, am.HasRole("admin1", "admin"))
	assert.True(t, am.HasRoute("admin1", "/admin/settings"))
	
	assert.True(t, am.Authorize("user1", "/posts", "read"))
	assert.False(t, am.Authorize("user1", "/admin/settings", "read"))
	
	assert.Equal(t, 5, lookupCallCount) // 5 calls: Authorize (2), HasRole (2), HasRoute (1)
	
	// Test global callback getters
	assert.NotNil(t, GetGlobalSaveUserCallback())
	assert.NotNil(t, GetGlobalLoadUserCallback())
	assert.NotNil(t, GetGlobalUserLookupCallback())
	assert.True(t, HasGlobalCallbacks())
	
	// Test clearing global callbacks
	ClearGlobalCallbacks()
	assert.Nil(t, GetGlobalSaveUserCallback())
	assert.Nil(t, GetGlobalLoadUserCallback())
	assert.Nil(t, GetGlobalUserLookupCallback())
	assert.False(t, HasGlobalCallbacks())
	
	// Test fallback to in-memory when global callbacks are cleared
	user2 := am.CreateUser("user2", "Jane Doe")
	user2.AddRole(adminRole)
	
	assert.True(t, am.Authorize("user2", "/admin/settings", "read"))
	assert.True(t, am.HasRole("user2", "admin"))
	assert.True(t, am.HasRoute("user2", "/admin/settings"))
}

func TestAuthManagerWithRegexPermissions(t *testing.T) {
	am := NewAuthManager()
	
	// Create role with regex permissions
	adminRole := am.CreateRole("admin")
	adminRole.AddPermissionStrings(
		"/admin/settings[0-9]+",  // Access to numbered settings
		"/users/[0-9]+:update",  // Update users by ID
		"/api/v[0-9]+/posts",    // Access to versioned API posts
	)
	
	// Create user
	am.CreateUser("admin1", "Admin User")
	am.AssignRole("admin1", "admin")
	
	// Test regex permission matching
	assert.True(t, am.Authorize("admin1", "/admin/settings123", "read"))
	assert.True(t, am.Authorize("admin1", "/admin/settings456", "read"))
	assert.False(t, am.Authorize("admin1", "/admin/settingsabc", "read"))
	assert.False(t, am.Authorize("admin1", "/admin/settings", "read"))
	
	assert.True(t, am.Authorize("admin1", "/users/123", "update"))
	assert.True(t, am.Authorize("admin1", "/users/456", "update"))
	assert.False(t, am.Authorize("admin1", "/users/abc", "update"))
	assert.False(t, am.Authorize("admin1", "/users/123", "read"))
	
	assert.True(t, am.Authorize("admin1", "/api/v1/posts", "read"))
	assert.True(t, am.Authorize("admin1", "/api/v2/posts", "read"))
	assert.False(t, am.Authorize("admin1", "/api/vbeta/posts", "read"))
	assert.False(t, am.Authorize("admin1", "/api/v1/users", "read"))
	
	// Test route checking with regex patterns
	assert.True(t, am.HasRoute("admin1", "/admin/settings123"))
	assert.True(t, am.HasRoute("admin1", "/admin/settings456"))
	assert.False(t, am.HasRoute("admin1", "/admin/settingsabc"))
	assert.False(t, am.HasRoute("admin1", "/admin/settings"))
	
	assert.True(t, am.HasRoute("admin1", "/users/123"))
	assert.True(t, am.HasRoute("admin1", "/users/456"))
	assert.False(t, am.HasRoute("admin1", "/users/abc"))
	
	assert.True(t, am.HasRoute("admin1", "/api/v1/posts"))
	assert.True(t, am.HasRoute("admin1", "/api/v2/posts"))
	assert.False(t, am.HasRoute("admin1", "/api/vbeta/posts"))
	assert.False(t, am.HasRoute("admin1", "/api/v1/users"))
}

func TestHTTPMiddleware(t *testing.T) {
	am := NewAuthManager()
	
	// Create role and user
	adminRole := am.CreateRole("admin")
	adminRole.AddPermissionStrings("/admin/*", "/users:update")
	
	am.CreateUser("user1", "John Doe")
	am.AssignRole("user1", "admin")
	
	// Create middleware
	middleware := NewHTTPAuthMiddleware(am)
	
	// Test handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})
	
	t.Run("RequirePermission - success", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/admin/settings", nil)
		req.Header.Set("X-User-ID", "user1")
		w := httptest.NewRecorder()
		
		middleware.RequirePermission("/admin/settings", "read")(handler).ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "success", w.Body.String())
	})
	
	t.Run("RequirePermission - unauthorized", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/admin/settings", nil)
		req.Header.Set("X-User-ID", "user2") // user2 doesn't exist
		w := httptest.NewRecorder()
		
		middleware.RequirePermission("/admin/settings", "read")(handler).ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
	
	t.Run("RequireDynamicPermission - success", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/admin/settings", nil)
		req.Header.Set("X-User-ID", "user1")
		w := httptest.NewRecorder()
		
		middleware.RequireDynamicPermission()(handler).ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
	})
	
	t.Run("RequireRole - success", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/admin/settings", nil)
		req.Header.Set("X-User-ID", "user1")
		w := httptest.NewRecorder()
		
		middleware.RequireRole("admin")(handler).ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
	})
	
	t.Run("RequireRole - unauthorized", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/admin/settings", nil)
		req.Header.Set("X-User-ID", "user1")
		w := httptest.NewRecorder()
		
		middleware.RequireRole("guest")(handler).ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}
