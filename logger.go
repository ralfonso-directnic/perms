package perms

import (
	"fmt"
	"log"
	"os"
)

// LogLevel represents the severity level of a log message
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
)

// String returns the string representation of the log level
func (l LogLevel) String() string {
	switch l {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARN:
		return "WARN"
	case ERROR:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// Logger interface for logging security events and operations
type Logger interface {
	Debug(msg string, fields ...interface{})
	Info(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
	LogAuthAttempt(userID, resource, action string, allowed bool, reason string)
	LogAuthFailure(userID, resource, action string, reason string)
	LogCallbackError(operation string, userID string, err error)
	LogSecurityEvent(event string, details map[string]interface{})
}

// DefaultLogger is a simple logger implementation
type DefaultLogger struct {
	logger *log.Logger
	level  LogLevel
}

// NewDefaultLogger creates a new default logger
func NewDefaultLogger(level LogLevel) *DefaultLogger {
	return &DefaultLogger{
		logger: log.New(os.Stdout, "[PERMS] ", log.LstdFlags|log.Lshortfile),
		level:  level,
	}
}

// Debug logs a debug message
func (l *DefaultLogger) Debug(msg string, fields ...interface{}) {
	if l.level <= DEBUG {
		l.logger.Printf("[DEBUG] %s %v", msg, fields)
	}
}

// Info logs an info message
func (l *DefaultLogger) Info(msg string, fields ...interface{}) {
	if l.level <= INFO {
		l.logger.Printf("[INFO] %s %v", msg, fields)
	}
}

// Warn logs a warning message
func (l *DefaultLogger) Warn(msg string, fields ...interface{}) {
	if l.level <= WARN {
		l.logger.Printf("[WARN] %s %v", msg, fields)
	}
}

// Error logs an error message
func (l *DefaultLogger) Error(msg string, fields ...interface{}) {
	if l.level <= ERROR {
		l.logger.Printf("[ERROR] %s %s", msg, fields)
	}
}

// LogAuthAttempt logs an authorization attempt
func (l *DefaultLogger) LogAuthAttempt(userID, resource, action string, allowed bool, reason string) {
	status := "DENIED"
	if allowed {
		status = "ALLOWED"
	}
	l.Info(fmt.Sprintf("AUTH_ATTEMPT: user=%s resource=%s action=%s status=%s reason=%s", 
		userID, resource, action, status, reason))
}

// LogAuthFailure logs an authorization failure
func (l *DefaultLogger) LogAuthFailure(userID, resource, action string, reason string) {
	l.Warn(fmt.Sprintf("AUTH_FAILURE: user=%s resource=%s action=%s reason=%s", 
		userID, resource, action, reason))
}

// LogCallbackError logs a callback error
func (l *DefaultLogger) LogCallbackError(operation string, userID string, err error) {
	l.Error(fmt.Sprintf("CALLBACK_ERROR: operation=%s user=%s error=%v", 
		operation, userID, err))
}

// LogSecurityEvent logs a security event
func (l *DefaultLogger) LogSecurityEvent(event string, details map[string]interface{}) {
	l.Warn(fmt.Sprintf("SECURITY_EVENT: event=%s details=%v", event, details))
}

// NullLogger is a no-op logger implementation that discards all log messages
type NullLogger struct{}

// NewNullLogger creates a new null logger that discards all messages
func NewNullLogger() *NullLogger {
	return &NullLogger{}
}

// Debug logs a debug message (no-op)
func (l *NullLogger) Debug(msg string, fields ...interface{}) {}

// Info logs an info message (no-op)
func (l *NullLogger) Info(msg string, fields ...interface{}) {}

// Warn logs a warning message (no-op)
func (l *NullLogger) Warn(msg string, fields ...interface{}) {}

// Error logs an error message (no-op)
func (l *NullLogger) Error(msg string, fields ...interface{}) {}

// LogAuthAttempt logs an authorization attempt (no-op)
func (l *NullLogger) LogAuthAttempt(userID, resource, action string, allowed bool, reason string) {}

// LogAuthFailure logs an authorization failure (no-op)
func (l *NullLogger) LogAuthFailure(userID, resource, action string, reason string) {}

// LogCallbackError logs a callback error (no-op)
func (l *NullLogger) LogCallbackError(operation string, userID string, err error) {}

// LogSecurityEvent logs a security event (no-op)
func (l *NullLogger) LogSecurityEvent(event string, details map[string]interface{}) {}

// Global logger instance
var globalLogger Logger = NewDefaultLogger(INFO)

// SetLogger sets the global logger
func SetLogger(logger Logger) {
	if logger == nil {
		panic("logger cannot be nil")
	}
	globalLogger = logger
}

// SetNullLogger sets a null logger that discards all messages
func SetNullLogger() {
	globalLogger = NewNullLogger()
}

// GetLogger returns the global logger
func GetLogger() Logger {
	return globalLogger
}

// LogDebug logs a debug message using the global logger
func LogDebug(msg string, fields ...interface{}) {
	globalLogger.Debug(msg, fields...)
}

// LogInfo logs an info message using the global logger
func LogInfo(msg string, fields ...interface{}) {
	globalLogger.Info(msg, fields...)
}

// LogWarn logs a warning message using the global logger
func LogWarn(msg string, fields ...interface{}) {
	globalLogger.Warn(msg, fields...)
}

// LogError logs an error message using the global logger
func LogError(msg string, fields ...interface{}) {
	globalLogger.Error(msg, fields...)
}
