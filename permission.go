package perms

import (
	"fmt"
	"regexp"
	"strings"
)

// Permission represents a single permission that can be granted to a role
type Permission struct {
	// Resource is the resource path (e.g., "/users", "/posts/123", "/admin/*")
	Resource string
	// Action is the action being performed (e.g., "read", "write", "delete", "*")
	Action string
	// regexPattern is the compiled regex pattern for resource matching (if applicable)
	regexPattern *regexp.Regexp
}

// String returns a string representation of the permission
func (p Permission) String() string {
	if p.Action == "" {
		return p.Resource
	}
	return fmt.Sprintf("%s:%s", p.Resource, p.Action)
}

// NewPermission creates a new permission from a string
// Supports formats: "/resource/action", "/resource", "resource:action"
// Also supports regex patterns like "/admin/settings[0-9]+" or "/admin/[0-9]+"
func NewPermission(permission string) Permission {
	// Validate permission string first
	if err := ValidatePermission(permission); err != nil {
		LogError("Invalid permission string", "permission", permission, "error", err)
		return Permission{} // Return empty permission for invalid input
	}
	
	var resource, action string
	var regexPattern *regexp.Regexp
	
	// Handle colon-separated format
	if strings.Contains(permission, ":") {
		parts := strings.SplitN(permission, ":", 2)
		resource = parts[0]
		action = parts[1]
	} else if strings.HasPrefix(permission, "/") {
		// Handle slash-separated format
		// Check if it contains wildcards - if so, treat as resource pattern
		if strings.Contains(permission, "*") {
			resource = permission
			action = ""
		} else {
			parts := strings.Split(permission, "/")
			if len(parts) >= 3 {
				// Check if the last part looks like an action (standard CRUD actions)
				lastPart := parts[len(parts)-1]
				crudActions := map[string]bool{
					"create": true, "read": true, "update": true, "delete": true,
				}
				
				if crudActions[lastPart] {
					// Format: /resource/action
					resource = strings.Join(parts[:len(parts)-1], "/")
					action = lastPart
				} else {
					// Format: /resource
					resource = permission
					action = ""
				}
			} else {
				// Format: /resource
				resource = permission
				action = ""
			}
		}
	} else {
		// Default: treat as resource only
		resource = permission
		action = ""
	}
	
	// Validate resource and action
	if err := ValidateResource(resource); err != nil {
		LogError("Invalid resource in permission", "resource", resource, "error", err)
		return Permission{}
	}
	if action != "" {
		if err := ValidateAction(action); err != nil {
			LogError("Invalid action in permission", "action", action, "error", err)
			return Permission{}
		}
	}
	
	// Check if resource contains regex patterns
	if containsRegexPattern(resource) {
		// Use safe regex compilation
		if compiled, err := SafeCompileRegex(resource); err == nil {
			regexPattern = compiled
		} else {
			LogError("Failed to compile regex pattern", "pattern", resource, "error", err)
			// Continue without regex pattern - will fall back to wildcard matching
		}
	}
	
	return Permission{
		Resource:     resource,
		Action:       action,
		regexPattern: regexPattern,
	}
}

// Matches checks if this permission matches the given resource and action
func (p Permission) Matches(resource, action string) bool {
	// Check if resource matches (supports wildcards)
	if !p.matchesResource(resource) {
		return false
	}
	
	// If no action specified in permission, it matches any action
	if p.Action == "" {
		return true
	}
	
	// Check if action matches (supports wildcards)
	return p.matchesAction(action)
}

// HasRoute checks if this permission matches the given resource (ignoring action)
// This is useful for route-based authentication where the action is embedded in the route
func (p Permission) HasRoute(resource string) bool {
	return p.matchesResource(resource)
}

// containsRegexPattern checks if a string contains regex patterns
func containsRegexPattern(s string) bool {
	// Skip simple wildcard patterns
	if s == "*" || s == "/*" || strings.HasSuffix(s, "/*") {
		return false
	}
	
	// Look for regex character classes and quantifiers
	regexIndicators := []string{"[", "]", "(", ")", "{", "}", "+", "?", "^", "$", "\\"}
	for _, indicator := range regexIndicators {
		if strings.Contains(s, indicator) {
			return true
		}
	}
	return false
}

// matchesResource checks if the resource matches the permission's resource pattern
func (p Permission) matchesResource(resource string) bool {
	// If we have a compiled regex pattern, use it
	if p.regexPattern != nil {
		return p.regexPattern.MatchString(resource)
	}
	
	// Handle wildcard patterns
	if p.Resource == "*" || p.Resource == "/*" {
		return true
	}
	
	// Handle wildcard at the end
	if strings.HasSuffix(p.Resource, "/*") {
		prefix := strings.TrimSuffix(p.Resource, "/*")
		// Must be a sub-path, not exact match
		return strings.HasPrefix(resource, prefix+"/")
	}
	
	// Exact match
	return p.Resource == resource
}

// matchesAction checks if the action matches the permission's action pattern
func (p Permission) matchesAction(action string) bool {
	if p.Action == "*" {
		return true
	}
	
	return p.Action == action
}
