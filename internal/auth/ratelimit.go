package auth

import (
	"sync"
	"time"
)

// RateLimiter tracks failed login attempts per client IP.
type RateLimiter struct {
	mu           sync.Mutex
	attempts     map[string][]time.Time
	lockouts     map[string]time.Time
	maxAttempts  int
	window       time.Duration
	lockoutDuration time.Duration
}

// NewRateLimiter creates a RateLimiter instance.
func NewRateLimiter(maxAttempts int, window, lockoutDuration time.Duration) *RateLimiter {
	return &RateLimiter{
		attempts:        make(map[string][]time.Time),
		lockouts:        make(map[string]time.Time),
		maxAttempts:     maxAttempts,
		window:          window,
		lockoutDuration: lockoutDuration,
	}
}

// IsLockedOut checks if the given IP is currently locked out.
func (rl *RateLimiter) IsLockedOut(ip string) (bool, time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	if lockUntil, ok := rl.lockouts[ip]; ok {
		if now.Before(lockUntil) {
			return true, lockUntil.Sub(now)
		}
		delete(rl.lockouts, ip)
		delete(rl.attempts, ip)
	}
	return false, 0
}

// RecordFailure records a failed login attempt for the IP.
// Returns true if this attempt triggered a new lockout.
func (rl *RateLimiter) RecordFailure(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	// Clean old attempts
	var recent []time.Time
	for _, t := range rl.attempts[ip] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	recent = append(recent, now)
	rl.attempts[ip] = recent

	if len(recent) >= rl.maxAttempts {
		rl.lockouts[ip] = now.Add(rl.lockoutDuration)
		return true
	}
	return false
}

// Reset clears failure history for an IP upon successful login.
func (rl *RateLimiter) Reset(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.attempts, ip)
	delete(rl.lockouts, ip)
}
