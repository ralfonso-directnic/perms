package perms

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// SecurityConfig holds security-related configuration
type SecurityConfig struct {
	MaxUserIDLength     int
	MaxRoleNameLength    int
	MaxResourceLength    int
	MaxActionLength      int
	MaxPermissionLength  int
	RegexTimeout         time.Duration
	AllowedRegexPatterns []string
}

// DefaultSecurityConfig returns a secure default configuration
func DefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		MaxUserIDLength:     100,
		MaxRoleNameLength:   50,
		MaxResourceLength:   500,
		MaxActionLength:     20,
		MaxPermissionLength: 1000,
		RegexTimeout:        100 * time.Millisecond,
		AllowedRegexPatterns: []string{
			`^[a-zA-Z0-9/\[\](){}*+?^$|\\-_.]+$`, // Basic safe patterns
		},
	}
}

// Global security configuration
var securityConfig = DefaultSecurityConfig()

// SetSecurityConfig sets the global security configuration
func SetSecurityConfig(config *SecurityConfig) {
	if config == nil {
		panic("security config cannot be nil")
	}
	securityConfig = config
}

// GetSecurityConfig returns the current security configuration
func GetSecurityConfig() *SecurityConfig {
	return securityConfig
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("validation error for field '%s': %s", e.Field, e.Message)
}

// ValidateUserID validates a user ID
func ValidateUserID(userID string) error {
	if userID == "" {
		return ValidationError{Field: "userID", Message: "cannot be empty"}
	}
	if len(userID) > securityConfig.MaxUserIDLength {
		return ValidationError{Field: "userID", Message: fmt.Sprintf("exceeds maximum length of %d", securityConfig.MaxUserIDLength)}
	}
	// Allow alphanumeric, hyphens, underscores, and dots
	if matched, _ := regexp.MatchString(`^[a-zA-Z0-9._-]+$`, userID); !matched {
		return ValidationError{Field: "userID", Message: "contains invalid characters"}
	}
	return nil
}

// ValidateRoleName validates a role name
func ValidateRoleName(roleName string) error {
	if roleName == "" {
		return ValidationError{Field: "roleName", Message: "cannot be empty"}
	}
	if len(roleName) > securityConfig.MaxRoleNameLength {
		return ValidationError{Field: "roleName", Message: fmt.Sprintf("exceeds maximum length of %d", securityConfig.MaxRoleNameLength)}
	}
	// Allow alphanumeric, hyphens, underscores
	if matched, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, roleName); !matched {
		return ValidationError{Field: "roleName", Message: "contains invalid characters"}
	}
	return nil
}

// ValidateResource validates a resource path
func ValidateResource(resource string) error {
	if resource == "" {
		return ValidationError{Field: "resource", Message: "cannot be empty"}
	}
	if len(resource) > securityConfig.MaxResourceLength {
		return ValidationError{Field: "resource", Message: fmt.Sprintf("exceeds maximum length of %d", securityConfig.MaxResourceLength)}
	}
	// Allow alphanumeric, slashes, hyphens, underscores, dots, and regex characters
	// Note: This is more permissive to allow regex patterns
	if matched, _ := regexp.MatchString(`^[a-zA-Z0-9/\[\](){}*?^$|\\-_.+\-]+$`, resource); !matched {
		return ValidationError{Field: "resource", Message: "contains invalid characters"}
	}
	return nil
}

// ValidateAction validates an action
func ValidateAction(action string) error {
	if action == "" {
		return ValidationError{Field: "action", Message: "cannot be empty"}
	}
	if len(action) > securityConfig.MaxActionLength {
		return ValidationError{Field: "action", Message: fmt.Sprintf("exceeds maximum length of %d", securityConfig.MaxActionLength)}
	}
	// Allow alphanumeric, hyphens, underscores
	if matched, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, action); !matched {
		return ValidationError{Field: "action", Message: "contains invalid characters"}
	}
	return nil
}

// ValidatePermission validates a permission string
func ValidatePermission(permission string) error {
	if permission == "" {
		return ValidationError{Field: "permission", Message: "cannot be empty"}
	}
	if len(permission) > securityConfig.MaxPermissionLength {
		return ValidationError{Field: "permission", Message: fmt.Sprintf("exceeds maximum length of %d", securityConfig.MaxPermissionLength)}
	}
	return nil
}

// Dangerous regex patterns that can cause ReDoS
var dangerousRegexPatterns = []string{
	`(a+)+`, `(a*)*`, `(a|a)*`, `(a+)*`, `(a*)+`,
	`(a+)+b`, `(a*)*b`, `(a|a)*b`, `(a+)*b`, `(a*)+b`,
	`(a+)+$`, `(a*)*$`, `(a|a)*$`, `(a+)*$`, `(a*)+$`,
	`(a+)+b$`, `(a*)*b$`, `(a|a)*b$`, `(a+)*b$`, `(a*)+b$`,
	`(a+)+.*`, `(a*)*.*`, `(a|a)*.*`, `(a+)*.*`, `(a*)+.*`,
	`(a+)+b.*`, `(a*)*b.*`, `(a|a)*b.*`, `(a+)*b.*`, `(a*)+b.*`,
}

// ValidateRegexPattern validates a regex pattern for security
func ValidateRegexPattern(pattern string) error {
	// Check for dangerous patterns
	for _, dangerous := range dangerousRegexPatterns {
		if strings.Contains(pattern, dangerous) {
			globalLogger.LogSecurityEvent("DANGEROUS_REGEX_DETECTED", map[string]interface{}{
				"pattern": pattern,
				"dangerous": dangerous,
			})
			return ValidationError{Field: "regex", Message: fmt.Sprintf("dangerous regex pattern detected: %s", dangerous)}
		}
	}
	
	// Check for excessive quantifiers
	quantifierCount := 0
	for _, char := range pattern {
		if char == '+' || char == '*' || char == '?' {
			quantifierCount++
		}
	}
	if quantifierCount > 10 {
		globalLogger.LogSecurityEvent("EXCESSIVE_QUANTIFIERS", map[string]interface{}{
			"pattern": pattern,
			"count": quantifierCount,
		})
		return ValidationError{Field: "regex", Message: "excessive quantifiers detected"}
	}
	
	// Check pattern length
	if len(pattern) > 200 {
		return ValidationError{Field: "regex", Message: "regex pattern too long"}
	}
	
	return nil
}

// SafeCompileRegex safely compiles a regex pattern with timeout protection
func SafeCompileRegex(pattern string) (*regexp.Regexp, error) {
	// Validate the pattern first
	if err := ValidateRegexPattern(pattern); err != nil {
		return nil, err
	}
	
	// Compile with timeout protection
	done := make(chan bool, 1)
	var compiled *regexp.Regexp
	var compileErr error
	
	go func() {
		defer func() {
			if r := recover(); r != nil {
				compileErr = fmt.Errorf("regex compilation panic: %v", r)
			}
			done <- true
		}()
		
		compiled, compileErr = regexp.Compile("^" + pattern + "$")
	}()
	
	select {
	case <-done:
		if compileErr != nil {
			globalLogger.LogSecurityEvent("REGEX_COMPILATION_ERROR", map[string]interface{}{
				"pattern": pattern,
				"error": compileErr.Error(),
			})
			return nil, ValidationError{Field: "regex", Message: "invalid regex pattern"}
		}
		return compiled, nil
	case <-time.After(securityConfig.RegexTimeout):
		globalLogger.LogSecurityEvent("REGEX_COMPILATION_TIMEOUT", map[string]interface{}{
			"pattern": pattern,
			"timeout": securityConfig.RegexTimeout,
		})
		return nil, ValidationError{Field: "regex", Message: "regex compilation timeout"}
	}
}
