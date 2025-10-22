package perms

import (
	"sync"
)

// Global callback registry for database operations
type CallbackRegistry struct {
	loadUserCallback      LoadUserCallback
	saveUserCallback      SaveUserCallback
	userLookupCallback    UserLookupCallback
	mutex                 sync.RWMutex
}

// Global instance
var globalCallbacks = &CallbackRegistry{}

// SetGlobalLoadUserCallback sets the global callback for loading user data
func SetGlobalLoadUserCallback(callback LoadUserCallback) error {
	if callback == nil {
		return ValidationError{Field: "callback", Message: "load user callback cannot be nil"}
	}
	
	globalCallbacks.mutex.Lock()
	defer globalCallbacks.mutex.Unlock()
	globalCallbacks.loadUserCallback = callback
	
	LogInfo("Global load user callback set")
	return nil
}

// SetGlobalSaveUserCallback sets the global callback for saving user data
func SetGlobalSaveUserCallback(callback SaveUserCallback) error {
	if callback == nil {
		return ValidationError{Field: "callback", Message: "save user callback cannot be nil"}
	}
	
	globalCallbacks.mutex.Lock()
	defer globalCallbacks.mutex.Unlock()
	globalCallbacks.saveUserCallback = callback
	
	LogInfo("Global save user callback set")
	return nil
}

// SetGlobalUserLookupCallback sets the global callback for user authorization lookup
func SetGlobalUserLookupCallback(callback UserLookupCallback) error {
	// Allow nil to clear the callback
	globalCallbacks.mutex.Lock()
	defer globalCallbacks.mutex.Unlock()
	globalCallbacks.userLookupCallback = callback
	
	if callback != nil {
		LogInfo("Global user lookup callback set")
	} else {
		LogInfo("Global user lookup callback cleared")
	}
	return nil
}

// GetGlobalLoadUserCallback returns the global load user callback
func GetGlobalLoadUserCallback() LoadUserCallback {
	globalCallbacks.mutex.RLock()
	defer globalCallbacks.mutex.RUnlock()
	return globalCallbacks.loadUserCallback
}

// GetGlobalSaveUserCallback returns the global save user callback
func GetGlobalSaveUserCallback() SaveUserCallback {
	globalCallbacks.mutex.RLock()
	defer globalCallbacks.mutex.RUnlock()
	return globalCallbacks.saveUserCallback
}

// GetGlobalUserLookupCallback returns the global user lookup callback
func GetGlobalUserLookupCallback() UserLookupCallback {
	globalCallbacks.mutex.RLock()
	defer globalCallbacks.mutex.RUnlock()
	return globalCallbacks.userLookupCallback
}

// ClearGlobalCallbacks clears all global callbacks (useful for testing)
func ClearGlobalCallbacks() {
	globalCallbacks.mutex.Lock()
	defer globalCallbacks.mutex.Unlock()
	globalCallbacks.loadUserCallback = nil
	globalCallbacks.saveUserCallback = nil
	globalCallbacks.userLookupCallback = nil
}

// HasGlobalCallbacks returns true if any global callbacks are set
func HasGlobalCallbacks() bool {
	globalCallbacks.mutex.RLock()
	defer globalCallbacks.mutex.RUnlock()
	return globalCallbacks.loadUserCallback != nil ||
		globalCallbacks.saveUserCallback != nil ||
		globalCallbacks.userLookupCallback != nil
}
