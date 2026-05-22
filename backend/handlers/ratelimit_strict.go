package handlers

import (
	"sync"
	"time"
)

// newStrictRateLimiter creates a token-bucket limiter for the registration endpoint.
// Parameters: burst=3 (3 immediate attempts allowed), 1 request per hour sustained.
// Much more restrictive than the analytics limiter (10 burst / 60 rpm).
func newStrictRateLimiter() *StrictRateLimiter {
	rl := &StrictRateLimiter{
		clients:     make(map[string]*strictClient),
		maxBurst:    3,
		ratePerSec:  1.0 / 3600.0, // 1 token per hour
	}
	go rl.cleanup()
	return rl
}

// StrictRateLimiter is a per-key token-bucket limiter intended for
// low-volume, high-security endpoints like device registration.
type StrictRateLimiter struct {
	mu         sync.Mutex
	clients    map[string]*strictClient
	maxBurst   float64
	ratePerSec float64 // tokens added per second
}

type strictClient struct {
	tokens   float64
	lastSeen time.Time
}

// Allow returns true if the given key (IP or device_id) is within rate limits.
func (rl *StrictRateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	c, exists := rl.clients[key]
	if !exists {
		c = &strictClient{tokens: rl.maxBurst, lastSeen: now}
		rl.clients[key] = c
	}

	// Refill tokens based on elapsed time
	elapsed := now.Sub(c.lastSeen).Seconds()
	c.lastSeen = now
	c.tokens += elapsed * rl.ratePerSec
	if c.tokens > rl.maxBurst {
		c.tokens = rl.maxBurst
	}

	if c.tokens < 1 {
		return false
	}
	c.tokens--
	return true
}

// cleanup removes idle entries every 2 hours (entries idle > 25 hours are dropped).
func (rl *StrictRateLimiter) cleanup() {
	ticker := time.NewTicker(2 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-25 * time.Hour)
		rl.mu.Lock()
		for key, c := range rl.clients {
			if c.lastSeen.Before(cutoff) {
				delete(rl.clients, key)
			}
		}
		rl.mu.Unlock()
	}
}
