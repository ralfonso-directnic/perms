package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/ralfonso-directnic/perms"
)

func main() {
	// Create authorization manager
	authManager := perms.NewAuthManager()

	// Create roles with permissions using standard CRUD actions and regex patterns
	adminRole := authManager.CreateRole("admin")
	adminRole.AddPermissionStrings(
		"/admin/*",                    // Access to all admin routes
		"/users:update",               // Can update users
		"/posts:delete",              // Can delete posts
		"/logs:read",                 // Can read logs
		"/admin/settings[0-9]+",      // Access to numbered settings (regex)
		"/users/[0-9]+:update",       // Update users by ID (regex)
	)

	userRole := authManager.CreateRole("user")
	userRole.AddPermissionStrings(
		"/users/self",                // Can access own user data
		"/posts:read",               // Can read posts
		"/posts:create",             // Can create posts
		"/comments:read",            // Can read comments
		"/comments:create",          // Can create comments
		"/posts/[0-9]+:read",        // Read specific posts by ID (regex)
	)

	moderatorRole := authManager.CreateRole("moderator")
	moderatorRole.AddPermissionStrings(
		"/posts:read",               // Can read posts
		"/posts:update",             // Can update posts
		"/comments:read",            // Can read comments
		"/comments:delete",          // Can delete comments
		"/reports:read",             // Can read reports
		"/api/v[0-9]+/posts",        // Access to versioned API posts (regex)
	)

	// Create users
	authManager.CreateUser("admin1", "Admin User")
	authManager.CreateUser("user1", "Regular User")
	authManager.CreateUser("moderator1", "Moderator User")

	// Assign roles to users
	authManager.AssignRole("admin1", "admin")
	authManager.AssignRole("user1", "user")
	authManager.AssignRole("moderator1", "moderator")

	// Test authorization
	fmt.Println("=== Authorization Tests ===")
	
	// Admin tests
	fmt.Printf("Admin can access /admin/settings: %v\n", 
		authManager.Authorize("admin1", "/admin/settings", "read"))
	fmt.Printf("Admin can update users: %v\n", 
		authManager.Authorize("admin1", "/users", "update"))
	fmt.Printf("Admin can delete posts: %v\n", 
		authManager.Authorize("admin1", "/posts", "delete"))

	// User tests
	fmt.Printf("User can access own profile: %v\n", 
		authManager.Authorize("user1", "/users/self", "read"))
	fmt.Printf("User can read posts: %v\n", 
		authManager.Authorize("user1", "/posts", "read"))
	fmt.Printf("User can create posts: %v\n", 
		authManager.Authorize("user1", "/posts", "create"))
	fmt.Printf("User cannot access admin: %v\n", 
		authManager.Authorize("user1", "/admin/settings", "read"))

	// Moderator tests
	fmt.Printf("Moderator can read posts: %v\n", 
		authManager.Authorize("moderator1", "/posts", "read"))
	fmt.Printf("Moderator can update posts: %v\n", 
		authManager.Authorize("moderator1", "/posts", "update"))
	fmt.Printf("Moderator can delete comments: %v\n", 
		authManager.Authorize("moderator1", "/comments", "delete"))
	
	fmt.Println("\n=== Regex Permission Tests ===")
	
	// Admin regex tests
	fmt.Printf("Admin can access numbered settings: %v\n", 
		authManager.Authorize("admin1", "/admin/settings123", "read"))
	fmt.Printf("Admin can update user by ID: %v\n", 
		authManager.Authorize("admin1", "/users/456", "update"))
	fmt.Printf("Admin cannot access non-numeric settings: %v\n", 
		authManager.Authorize("admin1", "/admin/settingsabc", "read"))
	
	// User regex tests
	fmt.Printf("User can read specific post: %v\n", 
		authManager.Authorize("user1", "/posts/789", "read"))
	fmt.Printf("User cannot read non-numeric post: %v\n", 
		authManager.Authorize("user1", "/posts/abc", "read"))
	
	// Moderator regex tests
	fmt.Printf("Moderator can access versioned API: %v\n", 
		authManager.Authorize("moderator1", "/api/v1/posts", "read"))
	fmt.Printf("Moderator can access different API version: %v\n", 
		authManager.Authorize("moderator1", "/api/v2/posts", "read"))
	fmt.Printf("Moderator cannot access non-numeric API version: %v\n", 
		authManager.Authorize("moderator1", "/api/vbeta/posts", "read"))
	
	fmt.Println("\n=== Route-Only Authorization Tests ===")
	
	// Test route-only checking (ignoring action)
	fmt.Printf("Admin has route access to /admin/settings: %v\n", 
		authManager.HasRoute("admin1", "/admin/settings"))
	fmt.Printf("Admin has route access to /users: %v\n", 
		authManager.HasRoute("admin1", "/users"))
	fmt.Printf("Admin has route access to /posts: %v\n", 
		authManager.HasRoute("admin1", "/posts"))
	
	fmt.Printf("User has route access to /posts: %v\n", 
		authManager.HasRoute("user1", "/posts"))
	fmt.Printf("User has route access to /admin/settings: %v\n", 
		authManager.HasRoute("user1", "/admin/settings"))
	
	// Test route-only checking with regex patterns
	fmt.Printf("Admin has route access to numbered settings: %v\n", 
		authManager.HasRoute("admin1", "/admin/settings123"))
	fmt.Printf("Admin has route access to user by ID: %v\n", 
		authManager.HasRoute("admin1", "/users/456"))
	fmt.Printf("Moderator has route access to versioned API: %v\n", 
		authManager.HasRoute("moderator1", "/api/v1/posts"))
	
	fmt.Println("\n=== Role Checking Tests ===")
	
	// Test role checking
	fmt.Printf("Admin user has admin role: %v\n", 
		authManager.HasRole("admin1", "admin"))
	fmt.Printf("Admin user has user role: %v\n", 
		authManager.HasRole("admin1", "user"))
	fmt.Printf("Regular user has admin role: %v\n", 
		authManager.HasRole("user1", "admin"))
	fmt.Printf("Regular user has user role: %v\n", 
		authManager.HasRole("user1", "user"))
	fmt.Printf("Moderator has moderator role: %v\n", 
		authManager.HasRole("moderator1", "moderator"))
	fmt.Printf("Nonexistent user has admin role: %v\n", 
		authManager.HasRole("nonexistent", "admin"))
	
	fmt.Println("\n=== Callback Integration Example ===")
	
	// Set up save callback (simulating database save)
	authManager.SetSaveUserCallback(func(user *perms.User) error {
		fmt.Printf("Saving user %s to database...\n", user.Name)
		return nil
	})
	
	// Set up load callback (simulating database load)
	authManager.SetLoadUserCallback(func(userID string) (*perms.User, error) {
		fmt.Printf("Loading user %s from database...\n", userID)
		// Return a mock user for demonstration
		user := perms.NewUser(userID, "Loaded User")
		role := perms.NewRole("admin")
		role.AddPermissionStrings("/admin/*")
		user.AddRole(role)
		return user, nil
	})
	
	// Test automatic save on role assignment
	fmt.Println("Assigning role (should trigger save callback):")
	authManager.AssignRole("user1", "admin")
	
	// Test automatic save on role removal
	fmt.Println("Removing role (should trigger save callback):")
	authManager.RemoveRole("user1", "admin")
	
	// Test load callback when user not in memory
	fmt.Println("Clearing user from memory and loading (should trigger load callback):")
	authManager.ClearUser("user1")
	loadedUser, exists := authManager.GetUser("user1")
	if exists {
		fmt.Printf("Loaded user: %s with %d roles\n", loadedUser.Name, len(loadedUser.Roles))
	}
	
	fmt.Println("\n=== Authorization Callback Example ===")
	
	// Set up authorization lookup callback (simulating database lookup)
	authManager.SetUserLookupCallback(func(userID string) ([]string, []string, error) {
		fmt.Printf("Looking up roles and permissions for user %s...\n", userID)
		
		// Simulate database lookup
		switch userID {
		case "user1":
			return []string{"user"}, []string{"/posts:read"}, nil
		case "admin1":
			return []string{"admin"}, []string{"/admin/settings:read"}, nil
		case "moderator1":
			return []string{"admin", "user"}, []string{}, nil
		default:
			return []string{}, []string{}, nil
		}
	})
	
	// Test efficient authorization without loading users into memory
	fmt.Println("Testing authorization callbacks:")
	fmt.Printf("User1 can read posts: %v\n", 
		authManager.Authorize("user1", "/posts", "read"))
	fmt.Printf("User1 has admin role: %v\n", 
		authManager.HasRole("user1", "admin"))
	fmt.Printf("Admin1 can access admin settings: %v\n", 
		authManager.Authorize("admin1", "/admin/settings", "read"))
	fmt.Printf("Moderator1 has multiple roles: %v\n", 
		authManager.HasRole("moderator1", "admin") && authManager.HasRole("moderator1", "user"))

	fmt.Println("\n=== HTTP Middleware Example ===")

	// Create HTTP middleware
	middleware := perms.NewHTTPAuthMiddleware(authManager)

	// Create handlers
	adminHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Admin area accessed successfully"))
	})

	userHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("User area accessed successfully"))
	})

	postsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Posts accessed successfully"))
	})

	// Set up routes with middleware
	http.Handle("/admin/", middleware.RequireRole("admin")(adminHandler))
	http.Handle("/users/self", middleware.RequirePermission("/users/self", "read")(userHandler))
	http.Handle("/posts", middleware.RequireDynamicPermission()(postsHandler))

	// Start server
	fmt.Println("Server starting on :8080")
	fmt.Println("Test with:")
	fmt.Println("  curl -H 'X-User-ID: admin1' http://localhost:8080/admin/settings")
	fmt.Println("  curl -H 'X-User-ID: user1' http://localhost:8080/users/self")
	fmt.Println("  curl -H 'X-User-ID: user1' http://localhost:8080/posts")
	
	log.Fatal(http.ListenAndServe(":8080", nil))
}
