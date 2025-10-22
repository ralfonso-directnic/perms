package perms

import (
	"net/http"
	"strings"
)

// HTTPAuthMiddleware provides HTTP middleware for authorization
type HTTPAuthMiddleware struct {
	authManager *AuthManager
	// UserExtractor extracts user ID from HTTP request
	UserExtractor func(r *http.Request) string
	// ResourceExtractor extracts resource path from HTTP request
	ResourceExtractor func(r *http.Request) string
	// ActionExtractor extracts action from HTTP request
	ActionExtractor func(r *http.Request) string
	// UnauthorizedHandler handles unauthorized requests
	UnauthorizedHandler http.HandlerFunc
}

// NewHTTPAuthMiddleware creates a new HTTP authorization middleware
func NewHTTPAuthMiddleware(authManager *AuthManager) *HTTPAuthMiddleware {
	return &HTTPAuthMiddleware{
		authManager: authManager,
		UserExtractor: func(r *http.Request) string {
			// Default: extract from X-User-ID header
			return r.Header.Get("X-User-ID")
		},
		ResourceExtractor: func(r *http.Request) string {
			// Default: use request path
			return r.URL.Path
		},
		ActionExtractor: func(r *http.Request) string {
			// Default: map HTTP methods to standard CRUD actions
			switch strings.ToUpper(r.Method) {
			case "GET":
				return "read"
			case "POST":
				return "create"
			case "PUT", "PATCH":
				return "update"
			case "DELETE":
				return "delete"
			default:
				return "read" // Default to read for unknown methods
			}
		},
		UnauthorizedHandler: func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		},
	}
}

// RequirePermission creates middleware that requires a specific permission
func (m *HTTPAuthMiddleware) RequirePermission(resource, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID := m.UserExtractor(r)
			if userID == "" {
				m.UnauthorizedHandler(w, r)
				return
			}
			
			if !m.authManager.Authorize(userID, resource, action) {
				m.UnauthorizedHandler(w, r)
				return
			}
			
			next.ServeHTTP(w, r)
		})
	}
}

// RequireDynamicPermission creates middleware that extracts permission from request
func (m *HTTPAuthMiddleware) RequireDynamicPermission() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID := m.UserExtractor(r)
			if userID == "" {
				m.UnauthorizedHandler(w, r)
				return
			}
			
			resource := m.ResourceExtractor(r)
			action := m.ActionExtractor(r)
			
			if !m.authManager.Authorize(userID, resource, action) {
				m.UnauthorizedHandler(w, r)
				return
			}
			
			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole creates middleware that requires a specific role
func (m *HTTPAuthMiddleware) RequireRole(roleName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID := m.UserExtractor(r)
			if userID == "" {
				m.UnauthorizedHandler(w, r)
				return
			}
			
			user, exists := m.authManager.GetUser(userID)
			if !exists || !user.HasRole(roleName) {
				m.UnauthorizedHandler(w, r)
				return
			}
			
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyRole creates middleware that requires any of the specified roles
func (m *HTTPAuthMiddleware) RequireAnyRole(roleNames ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID := m.UserExtractor(r)
			if userID == "" {
				m.UnauthorizedHandler(w, r)
				return
			}
			
			user, exists := m.authManager.GetUser(userID)
			if !exists {
				m.UnauthorizedHandler(w, r)
				return
			}
			
			hasRole := false
			for _, roleName := range roleNames {
				if user.HasRole(roleName) {
					hasRole = true
					break
				}
			}
			
			if !hasRole {
				m.UnauthorizedHandler(w, r)
				return
			}
			
			next.ServeHTTP(w, r)
		})
	}
}

// SetUserExtractor sets a custom user extractor function
func (m *HTTPAuthMiddleware) SetUserExtractor(extractor func(r *http.Request) string) {
	m.UserExtractor = extractor
}

// SetResourceExtractor sets a custom resource extractor function
func (m *HTTPAuthMiddleware) SetResourceExtractor(extractor func(r *http.Request) string) {
	m.ResourceExtractor = extractor
}

// SetActionExtractor sets a custom action extractor function
func (m *HTTPAuthMiddleware) SetActionExtractor(extractor func(r *http.Request) string) {
	m.ActionExtractor = extractor
}

// SetUnauthorizedHandler sets a custom unauthorized handler
func (m *HTTPAuthMiddleware) SetUnauthorizedHandler(handler http.HandlerFunc) {
	m.UnauthorizedHandler = handler
}
