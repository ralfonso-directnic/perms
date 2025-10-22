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
func SetGlobalLoadUserCallback(callback LoadUserCallback) {
	globalCallbacks.mutex.Lock()
	defer globalCallbacks.mutex.Unlock()
	globalCallbacks.loadUserCallback = callback
}

// SetGlobalSaveUserCallback sets the global callback for saving user data
func SetGlobalSaveUserCallback(callback SaveUserCallback) {
	globalCallbacks.mutex.Lock()
	defer globalCallbacks.mutex.Unlock()
	globalCallbacks.saveUserCallback = callback
}

// SetGlobalUserLookupCallback sets the global callback for user authorization lookup
func SetGlobalUserLookupCallback(callback UserLookupCallback) {
	globalCallbacks.mutex.Lock()
	defer globalCallbacks.mutex.Unlock()
	globalCallbacks.userLookupCallback = callback
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
