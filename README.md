# Perms - Go Authorization Library

A flexible and easy-to-use authorization library for Go applications that supports role-based access control (RBAC) with permissions.

## Features

- **Role-based Access Control**: Define roles and assign permissions to them
- **Standard CRUD Actions**: Uses create, read, update, delete as standard permission actions
- **Flexible Permission System**: Support for route-based and action-based permissions
- **Wildcard Support**: Use `*` and `/*` for flexible permission matching
- **Regex Pattern Matching**: Support for regex patterns like `/admin/settings[0-9]+` or `/users/[0-9]+:read`
- **Route-Only Checking**: Check route access without specifying actions using `HasRoute()` methods
- **HTTP Middleware**: Ready-to-use middleware with automatic HTTP method to CRUD mapping
- **Thread-safe**: Safe for concurrent use
- **Simple API**: Easy to integrate into existing applications

## Installation

```bash
go get github.com/ralfonso-directnic/perms
```

## Quick Start

### Basic Usage

```go
package main

import (
    "fmt"
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
        "/admin/settings[0-9]+",      // Access to numbered settings (regex)
        "/users/[0-9]+:update",       // Update users by ID (regex)
    )

    userRole := authManager.CreateRole("user")
    userRole.AddPermissionStrings(
        "/users/self",                // Can access own user data
        "/posts:read",               // Can read posts
        "/posts:create",             // Can create posts
        "/posts/[0-9]+:read",        // Read specific posts by ID (regex)
    )

    // Create users
    adminUser := authManager.CreateUser("admin1", "Admin User")
    regularUser := authManager.CreateUser("user1", "Regular User")

    // Assign roles
    authManager.AssignRole("admin1", "admin")
    authManager.AssignRole("user1", "user")

// Check authorization
canAccess := authManager.Authorize("admin1", "/admin/settings", "read")
fmt.Printf("Admin can access admin settings: %v\n", canAccess)

canUpdate := authManager.Authorize("admin1", "/users", "update")
fmt.Printf("Admin can update users: %v\n", canUpdate)

// Check route access (ignoring action)
hasRoute := authManager.HasRoute("admin1", "/admin/settings")
fmt.Printf("Admin has route access to admin settings: %v\n", hasRoute)
}
```

### HTTP Middleware

```go
package main

import (
    "net/http"
    "github.com/ralfonso-directnic/perms"
)

func main() {
    authManager := perms.NewAuthManager()
    
    // Setup roles and users (see basic usage above)
    
    // Create middleware
    middleware := perms.NewHTTPAuthMiddleware(authManager)
    
    // Protect routes
    http.Handle("/admin/", middleware.RequireRole("admin")(adminHandler))
    http.Handle("/posts", middleware.RequireDynamicPermission()(postsHandler))
    
    http.ListenAndServe(":8080", nil)
}
```

## Permission Formats

The library uses standard CRUD actions (create, read, update, delete) and supports multiple permission formats:

### Standard CRUD Actions
- `create` - Create new resources (maps to HTTP POST)
- `read` - Read/view resources (maps to HTTP GET)
- `update` - Update existing resources (maps to HTTP PUT/PATCH)
- `delete` - Delete resources (maps to HTTP DELETE)

### Route-based Permissions
- `/users` - Access to users resource (any action)
- `/users/123` - Access to specific user (any action)
- `/users/*` - Access to all user sub-resources (any action)
- `/*` - Access to all resources (any action)

### Action-based Permissions
- `/users:read` - Read access to users
- `/posts:create` - Create posts
- `/admin:update` - Update admin resources
- `/posts:delete` - Delete posts

### Combined Formats
- `/users/self:read` - Read access to own user data
- `/posts:create` - Create posts
- `/admin/*:update` - Update access to all admin resources

### Regex Pattern Formats
- `/admin/settings[0-9]+` - Access to numbered settings (e.g., `/admin/settings123`)
- `/users/[0-9]+:read` - Read access to users by ID (e.g., `/users/456`)
- `/api/v[0-9]+/posts` - Access to versioned API posts (e.g., `/api/v1/posts`)
- `/posts/[a-zA-Z0-9]+:update` - Update posts with alphanumeric IDs
- `/files/[0-9]*` - Access to files with optional numeric suffix

## Route-Only Authorization

For cases where the action is embedded in the route or you only need to check route access regardless of action, use the `HasRoute()` methods:

```go
// Check if user has access to a route (ignoring action)
hasAccess := authManager.HasRoute("user1", "/admin/settings")
fmt.Printf("User has route access: %v\n", hasAccess)

// Works with all permission types
hasWildcard := authManager.HasRoute("user1", "/admin/settings")  // matches /admin/*
hasRegex := authManager.HasRoute("user1", "/admin/settings123")  // matches /admin/settings[0-9]+
hasExact := authManager.HasRoute("user1", "/users")             // matches /users:read
```

## Role Checking

Check if users have specific roles using the `HasRole()` methods:

```go
// Check if user has a specific role
hasAdmin := authManager.HasRole("user1", "admin")
hasUser := authManager.HasRole("user1", "user")

// Check multiple roles
if authManager.HasRole("user1", "admin") || authManager.HasRole("user1", "moderator") {
    // User has admin or moderator privileges
}

// Works with user objects too
user, _ := authManager.GetUser("user1")
hasAdmin := authManager.HasRoleUser(user, "admin")
```

## API Reference

### AuthManager

The main authorization manager that handles roles, users, and permissions.

```go
// Create a new authorization manager
authManager := perms.NewAuthManager()

// Create roles
role := authManager.CreateRole("admin")

// Create users
user := authManager.CreateUser("user1", "John Doe")

// Assign roles to users
authManager.AssignRole("user1", "admin")

// Check authorization
authorized := authManager.Authorize("user1", "/admin/settings", "read")

// Check route access (ignoring action)
hasRoute := authManager.HasRoute("user1", "/admin/settings")

// Check if user has specific role
hasAdminRole := authManager.HasRole("user1", "admin")
```

### Permission

Represents a single permission with resource and action.

```go
// Create permission from string
perm := perms.NewPermission("/users:read")

// Create permission directly
perm := perms.Permission{
    Resource: "/users",
    Action:   "read",
}

// Check if permission matches
matches := perm.Matches("/users", "read")
```

### Role

A role that can have multiple permissions.

```go
role := perms.NewRole("admin")
role.AddPermissionString("/admin/*")
role.AddPermissionStrings("/users:write", "/posts:delete")

// Check if role has permission
hasPerm := role.HasPermission("/admin/settings", "read")
```

### User

A user that can have multiple roles.

```go
user := perms.NewUser("user1", "John Doe")
user.AddRole(adminRole)

// Check if user has role
hasRole := user.HasRole("admin")

// Check if user has permission
hasPerm := user.HasPermission("/admin/settings", "read")
```

### HTTP Middleware

Middleware for protecting HTTP routes.

```go
middleware := perms.NewHTTPAuthMiddleware(authManager)

// Require specific permission
http.Handle("/admin", middleware.RequirePermission("/admin", "read")(handler))

// Require specific role
http.Handle("/admin", middleware.RequireRole("admin")(handler))

// Require any of multiple roles
http.Handle("/admin", middleware.RequireAnyRole("admin", "moderator")(handler))

// Dynamic permission extraction from request
http.Handle("/posts", middleware.RequireDynamicPermission()(handler))
```

## Database Integration with GORM

For applications that store user state in a database, here's a complete example using GORM to load user roles and permissions after login verification:

### Database Models

```go
package main

import (
    "gorm.io/gorm"
    "github.com/ralfonso-directnic/perms"
)

// User model for database
type User struct {
    ID       uint   `gorm:"primaryKey"`
    Username string `gorm:"uniqueIndex"`
    Email    string `gorm:"uniqueIndex"`
    Password string // hashed password
    
    // GORM relationships
    UserRoles []UserRole `gorm:"foreignKey:UserID"`
}

// Role model for database
type Role struct {
    ID          uint   `gorm:"primaryKey"`
    Name        string `gorm:"uniqueIndex"`
    Description string
    
    // GORM relationships
    UserRoles    []UserRole    `gorm:"foreignKey:RoleID"`
    RolePermissions []RolePermission `gorm:"foreignKey:RoleID"`
}

// Permission model for database
type Permission struct {
    ID       uint   `gorm:"primaryKey"`
    Resource string `gorm:"index"`
    Action   string `gorm:"index"`
    
    // GORM relationships
    RolePermissions []RolePermission `gorm:"foreignKey:PermissionID"`
}

// Junction table for users and roles
type UserRole struct {
    ID     uint `gorm:"primaryKey"`
    UserID uint `gorm:"index"`
    RoleID uint `gorm:"index"`
    
    User User `gorm:"foreignKey:UserID"`
    Role Role `gorm:"foreignKey:RoleID"`
}

// Junction table for roles and permissions
type RolePermission struct {
    ID           uint `gorm:"primaryKey"`
    RoleID       uint `gorm:"index"`
    PermissionID uint `gorm:"index"`
    
    Role       Role       `gorm:"foreignKey:RoleID"`
    Permission Permission `gorm:"foreignKey:PermissionID"`
}
```

### Database Loading Functions

```go
// LoadUserFromDB loads a user with all roles and permissions from database
func LoadUserFromDB(db *gorm.DB, username string) (*perms.User, error) {
    var dbUser User
    
    // Load user with all relationships
    err := db.Preload("UserRoles.Role.RolePermissions.Permission").
        Where("username = ?", username).
        First(&dbUser).Error
    if err != nil {
        return nil, err
    }
    
    // Create perms.User
    user := perms.NewUser(fmt.Sprintf("%d", dbUser.ID), dbUser.Username)
    
    // Add roles and permissions
    for _, userRole := range dbUser.UserRoles {
        role := perms.NewRole(userRole.Role.Name)
        
        // Add permissions to role
        for _, rolePerm := range userRole.Role.RolePermissions {
            perm := perms.NewPermission(fmt.Sprintf("%s:%s", 
                rolePerm.Permission.Resource, 
                rolePerm.Permission.Action))
            role.AddPermission(perm)
        }
        
        user.AddRole(role)
    }
    
    return user, nil
}

// LoadUserRolesFromDB loads roles for a specific user
func LoadUserRolesFromDB(db *gorm.DB, userID string) ([]*perms.Role, error) {
    var userRoles []UserRole
    
    err := db.Preload("Role.RolePermissions.Permission").
        Where("user_id = ?", userID).
        Find(&userRoles).Error
    if err != nil {
        return nil, err
    }
    
    var roles []*perms.Role
    for _, userRole := range userRoles {
        role := perms.NewRole(userRole.Role.Name)
        
        for _, rolePerm := range userRole.Role.RolePermissions {
            perm := perms.NewPermission(fmt.Sprintf("%s:%s", 
                rolePerm.Permission.Resource, 
                rolePerm.Permission.Action))
            role.AddPermission(perm)
        }
        
        roles = append(roles, role)
    }
    
    return roles, nil
}
```

### Complete Login and Authorization Example

```go
package main

import (
    "fmt"
    "log"
    "net/http"
    
    "gorm.io/driver/sqlite"
    "gorm.io/gorm"
    "github.com/ralfonso-directnic/perms"
)

func main() {
    // Initialize database
    db, err := gorm.Open(sqlite.Open("auth.db"), &gorm.Config{})
    if err != nil {
        log.Fatal("Failed to connect to database:", err)
    }
    
    // Auto-migrate the schema
    db.AutoMigrate(&User{}, &Role{}, &Permission{}, &UserRole{}, &RolePermission{})
    
    // Seed some data
    seedDatabase(db)
    
    // Create authorization manager
    authManager := perms.NewAuthManager()
    
    // Login handler
    http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
        username := r.FormValue("username")
        password := r.FormValue("password")
        
        // Verify credentials (implement your own verification logic)
        if !verifyCredentials(db, username, password) {
            http.Error(w, "Invalid credentials", http.StatusUnauthorized)
            return
        }
        
        // Load user with roles and permissions
        user, err := LoadUserFromDB(db, username)
        if err != nil {
            http.Error(w, "Failed to load user", http.StatusInternalServerError)
            return
        }
        
        // Add user to auth manager (simplified with helper method)
        authManager.LoadUserFromDB(user)
        
        // Set user ID in session/cookie for subsequent requests
        http.SetCookie(w, &http.Cookie{
            Name:  "user_id",
            Value: user.ID,
            Path:  "/",
        })
        
        fmt.Fprintf(w, "Login successful! User: %s", user.Name)
    })
    
    // Logout handler
    http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
        cookie, err := r.Cookie("user_id")
        if err != nil {
            http.Error(w, "Not authenticated", http.StatusUnauthorized)
            return
        }
        
        userID := cookie.Value
        
        // Clear user from auth manager
        authManager.ClearUser(userID)
        
        // Clear session cookie
        http.SetCookie(w, &http.Cookie{
            Name:   "user_id",
            Value:  "",
            Path:   "/",
            MaxAge: -1,
        })
        
        fmt.Fprintf(w, "Logout successful!")
    })
    
    // Protected route handler
    http.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
        // Get user ID from session/cookie
        cookie, err := r.Cookie("user_id")
        if err != nil {
            http.Error(w, "Not authenticated", http.StatusUnauthorized)
            return
        }
        
        userID := cookie.Value
        
        // Check authorization
        if !authManager.HasRole(userID, "admin") {
            http.Error(w, "Access denied", http.StatusForbidden)
            return
        }
        
        fmt.Fprintf(w, "Welcome to admin area, user %s!", userID)
    })
    
    // Dynamic permission check
    http.HandleFunc("/posts/", func(w http.ResponseWriter, r *http.Request) {
        cookie, err := r.Cookie("user_id")
        if err != nil {
            http.Error(w, "Not authenticated", http.StatusUnauthorized)
            return
        }
        
        userID := cookie.Value
        resource := r.URL.Path
        action := getActionFromMethod(r.Method)
        
        if !authManager.Authorize(userID, resource, action) {
            http.Error(w, "Access denied", http.StatusForbidden)
            return
        }
        
        fmt.Fprintf(w, "Access granted to %s %s", action, resource)
    })
    
    log.Println("Server starting on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

// Helper functions
func verifyCredentials(db *gorm.DB, username, password string) bool {
    var user User
    err := db.Where("username = ? AND password = ?", username, password).First(&user).Error
    return err == nil
}

func getActionFromMethod(method string) string {
    switch method {
    case "GET":
        return "read"
    case "POST":
        return "create"
    case "PUT", "PATCH":
        return "update"
    case "DELETE":
        return "delete"
    default:
        return "read"
    }
}

func seedDatabase(db *gorm.DB) {
    // Create permissions
    permissions := []Permission{
        {Resource: "/admin/*", Action: ""},
        {Resource: "/users", Action: "read"},
        {Resource: "/users", Action: "update"},
        {Resource: "/posts", Action: "read"},
        {Resource: "/posts", Action: "create"},
        {Resource: "/posts", Action: "update"},
        {Resource: "/posts", Action: "delete"},
    }
    
    for _, perm := range permissions {
        db.Create(&perm)
    }
    
    // Create roles
    roles := []Role{
        {Name: "admin", Description: "Administrator role"},
        {Name: "user", Description: "Regular user role"},
        {Name: "moderator", Description: "Moderator role"},
    }
    
    for _, role := range roles {
        db.Create(&role)
    }
    
    // Assign permissions to roles
    rolePermissions := []RolePermission{
        // Admin gets all permissions
        {RoleID: 1, PermissionID: 1}, // /admin/*
        {RoleID: 1, PermissionID: 2}, // /users:read
        {RoleID: 1, PermissionID: 3}, // /users:update
        {RoleID: 1, PermissionID: 4}, // /posts:read
        {RoleID: 1, PermissionID: 5}, // /posts:create
        {RoleID: 1, PermissionID: 6}, // /posts:update
        {RoleID: 1, PermissionID: 7}, // /posts:delete
        
        // User gets limited permissions
        {RoleID: 2, PermissionID: 4}, // /posts:read
        {RoleID: 2, PermissionID: 5}, // /posts:create
        
        // Moderator gets moderate permissions
        {RoleID: 3, PermissionID: 4}, // /posts:read
        {RoleID: 3, PermissionID: 6}, // /posts:update
        {RoleID: 3, PermissionID: 7}, // /posts:delete
    }
    
    for _, rp := range rolePermissions {
        db.Create(&rp)
    }
    
    // Create users
    users := []User{
        {Username: "admin", Email: "admin@example.com", Password: "admin123"},
        {Username: "user1", Email: "user1@example.com", Password: "user123"},
        {Username: "moderator1", Email: "mod@example.com", Password: "mod123"},
    }
    
    for _, user := range users {
        db.Create(&user)
    }
    
    // Assign roles to users
    userRoles := []UserRole{
        {UserID: 1, RoleID: 1}, // admin user gets admin role
        {UserID: 2, RoleID: 2}, // user1 gets user role
        {UserID: 3, RoleID: 3}, // moderator1 gets moderator role
    }
    
    for _, ur := range userRoles {
        db.Create(&ur)
    }
}
```

### Usage

1. **Login**: POST to `/login` with username/password
2. **Access protected routes**: Use the session cookie for authorization
3. **Check permissions**: The system automatically loads and caches user permissions

This example shows how to:
- Store users, roles, and permissions in a database
- Load user permissions after login verification
- Use the authorization library with database-backed data
- Handle session-based authentication
- Implement dynamic permission checking

## Save/Load Callback Integration

For more flexible database integration, you can use save/load callbacks to automatically persist user data:

### Setting Up Callbacks

```go
package main

import (
    "fmt"
    "log"
    
    "gorm.io/driver/sqlite"
    "gorm.io/gorm"
    "github.com/ralfonso-directnic/perms"
)

func main() {
    // Initialize database
    db, err := gorm.Open(sqlite.Open("auth.db"), &gorm.Config{})
    if err != nil {
        log.Fatal("Failed to connect to database:", err)
    }
    
    // Create authorization manager
    authManager := perms.NewAuthManager()
    
    // Set up save callback
    authManager.SetSaveUserCallback(func(user *perms.User) error {
        return saveUserToDB(db, user)
    })
    
    // Set up load callback
    authManager.SetLoadUserCallback(func(userID string) (*perms.User, error) {
        return loadUserFromDB(db, userID)
    })
    
    // Now all user operations will automatically save/load from database
    user := authManager.CreateUser("user1", "John Doe")
    adminRole := authManager.CreateRole("admin")
    adminRole.AddPermissionStrings("/admin/*", "/users:update")
    
    // This will automatically save to database
    authManager.AssignRole("user1", "admin")
    
    // This will automatically load from database if not in memory
    loadedUser, exists := authManager.GetUser("user1")
    if exists {
        fmt.Printf("Loaded user: %s\n", loadedUser.Name)
    }
}
```

### Database Save/Load Functions

```go
// Save user to database
func saveUserToDB(db *gorm.DB, user *perms.User) error {
    // Convert perms.User to database User
    dbUser := User{
        Username: user.Name,
        Email:    fmt.Sprintf("%s@example.com", user.Name),
    }
    
    // Save or update user
    if err := db.Where("username = ?", user.Name).FirstOrCreate(&dbUser).Error; err != nil {
        return err
    }
    
    // Clear existing roles
    db.Where("user_id = ?", dbUser.ID).Delete(&UserRole{})
    
    // Add new roles
    for _, role := range user.Roles {
        var dbRole Role
        if err := db.Where("name = ?", role.Name).First(&dbRole).Error; err != nil {
            return err
        }
        
        userRole := UserRole{
            UserID: dbUser.ID,
            RoleID: dbRole.ID,
        }
        
        if err := db.Create(&userRole).Error; err != nil {
            return err
        }
    }
    
    return nil
}

// Load user from database
func loadUserFromDB(db *gorm.DB, userID string) (*perms.User, error) {
    var dbUser User
    
    // Load user with all relationships
    err := db.Preload("UserRoles.Role.RolePermissions.Permission").
        Where("id = ?", userID).
        First(&dbUser).Error
    if err != nil {
        return nil, err
    }
    
    // Create perms.User
    user := perms.NewUser(fmt.Sprintf("%d", dbUser.ID), dbUser.Username)
    
    // Add roles and permissions
    for _, userRole := range dbUser.UserRoles {
        role := perms.NewRole(userRole.Role.Name)
        
        // Add permissions to role
        for _, rolePerm := range userRole.Role.RolePermissions {
            perm := perms.NewPermission(fmt.Sprintf("%s:%s", 
                rolePerm.Permission.Resource, 
                rolePerm.Permission.Action))
            role.AddPermission(perm)
        }
        
        user.AddRole(role)
    }
    
    return user, nil
}
```

### Automatic Persistence Features

With callbacks configured, the following operations automatically persist to the database:

```go
// Create user (saved automatically)
user := authManager.CreateUser("user1", "John Doe")

// Assign role (saved automatically)
authManager.AssignRole("user1", "admin")

// Remove role (saved automatically)
authManager.RemoveRole("user1", "admin")

// Load user (loaded automatically if not in memory)
user, exists := authManager.GetUser("user1")

// Manual save
authManager.SaveUser("user1")
```

### Benefits of Callback Integration

- **Automatic Persistence**: All user changes are automatically saved
- **Lazy Loading**: Users are loaded from database when needed
- **Memory Efficiency**: Only active users are kept in memory
- **Flexible Storage**: Works with any database or storage backend
- **Transparent Operation**: Existing code works without changes

## Authorization Callback Integration

For maximum efficiency and scalability, you can use authorization callbacks to perform authorization checks without loading users into memory. This is especially useful for applications with many users where you don't want to store every user in memory.

### Setting Up Authorization Callbacks

```go
package main

import (
    "fmt"
    "log"
    
    "gorm.io/driver/sqlite"
    "gorm.io/gorm"
    "github.com/ralfonso-directnic/perms"
)

func main() {
    // Initialize database
    db, err := gorm.Open(sqlite.Open("auth.db"), &gorm.Config{})
    if err != nil {
        log.Fatal("Failed to connect to database:", err)
    }
    
    // Create authorization manager
    authManager := perms.NewAuthManager()
    
    // Set up authorization lookup callback
    authManager.SetUserLookupCallback(func(userID string) ([]string, []string, error) {
        return getUserRolesAndPermissions(db, userID)
    })
    
    // Now authorization checks are performed efficiently without loading users into memory
    canAccess := authManager.Authorize("user1", "/admin/settings", "read")
    hasRoute := authManager.HasRoute("user1", "/admin/settings")
    hasRole := authManager.HasRole("user1", "admin")
    
    fmt.Printf("User can access admin settings: %v\n", canAccess)
    fmt.Printf("User has route access: %v\n", hasRoute)
    fmt.Printf("User has admin role: %v\n", hasRole)
}
```

### Database Authorization Lookup Function

```go
// getUserRolesAndPermissions returns user roles and permissions from database
func getUserRolesAndPermissions(db *gorm.DB, userID string) ([]string, []string, error) {
    var roles []string
    var permissions []string
    
    // Get user roles
    var userRoles []UserRole
    err := db.Preload("Role").
        Where("user_id = ?", userID).
        Find(&userRoles).Error
    if err != nil {
        return nil, nil, err
    }
    
    for _, userRole := range userRoles {
        roles = append(roles, userRole.Role.Name)
    }
    
    // Get direct user permissions (if you have a user_permissions table)
    var userPermissions []UserPermission
    err = db.Preload("Permission").
        Where("user_id = ?", userID).
        Find(&userPermissions).Error
    if err != nil {
        return nil, nil, err
    }
    
    for _, userPerm := range userPermissions {
        permStr := fmt.Sprintf("%s:%s", userPerm.Permission.Resource, userPerm.Permission.Action)
        permissions = append(permissions, permStr)
    }
    
    return roles, permissions, nil
}

// Alternative: Get permissions from roles only
func getUserRolesAndPermissionsFromRoles(db *gorm.DB, userID string) ([]string, []string, error) {
    var roles []string
    var permissions []string
    
    // Get user roles with their permissions
    var userRoles []UserRole
    err := db.Preload("Role.RolePermissions.Permission").
        Where("user_id = ?", userID).
        Find(&userRoles).Error
    if err != nil {
        return nil, nil, err
    }
    
    for _, userRole := range userRoles {
        roles = append(roles, userRole.Role.Name)
        
        // Add role permissions
        for _, rolePerm := range userRole.Role.RolePermissions {
            permStr := fmt.Sprintf("%s:%s", rolePerm.Permission.Resource, rolePerm.Permission.Action)
            permissions = append(permissions, permStr)
        }
    }
    
    return roles, permissions, nil
}
```

### Benefits of Authorization Callbacks

- **Memory Efficiency**: No need to load users into memory
- **Scalability**: Works with millions of users
- **Database Agnostic**: Works with any database backend
- **Performance**: Direct database queries for authorization
- **Flexibility**: Custom permission logic per application

### Authorization Callback vs Load Callback

| Feature | Load Callback | Authorization Callback |
|---------|---------------|----------------------|
| **Purpose** | Load full user object | Get roles/permissions only |
| **Memory Usage** | High (full user objects) | Low (just strings) |
| **Performance** | Slower (full object creation) | Faster (minimal data) |
| **Use Case** | User management operations | Authorization checks |
| **Scalability** | Limited by memory | Scales to millions of users |

### Complete Example with Both Callbacks

```go
func main() {
    db, _ := gorm.Open(sqlite.Open("auth.db"), &gorm.Config{})
    authManager := perms.NewAuthManager()
    
    // For user management operations (load full user)
    authManager.SetLoadUserCallback(func(userID string) (*perms.User, error) {
        return loadUserFromDB(db, userID)
    })
    
    // For authorization checks (get roles/permissions only)
    authManager.SetUserLookupCallback(func(userID string) ([]string, []string, error) {
        return getUserRolesAndPermissions(db, userID)
    })
    
    // For saving user changes
    authManager.SetSaveUserCallback(func(user *perms.User) error {
        return saveUserToDB(db, user)
    })
    
    // Efficient authorization without loading users
    canAccess := authManager.Authorize("user1", "/admin/settings", "read")
    
    // Full user loading when needed for management
    user, exists := authManager.GetUser("user1")
    if exists {
        // Perform user management operations
    }
}
```

## Examples

See the `example/` directory for complete working examples.

## Testing

Run the tests:

```bash
go test ./...
```

## License

MIT License
