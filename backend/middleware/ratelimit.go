package middleware

import (
	"sync"
	"time"
)

// tokenBucket implements a simple token-bucket rate limiter for one client.
type tokenBucket struct {
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens per second
	lastRefill time.Time
	mu         sync.Mutex
}

func newBucket(maxTokens, refillRate float64) *tokenBucket {
	return &tokenBucket{
		tokens:     maxTokens,
		maxTokens:  maxTokens,
		refillRate: refillRate,
		lastRefill: time.Now(),
	}
}

// allow returns true if a request is permitted (consumes 1 token).
func (b *tokenBucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.lastRefill = now

	// Refill tokens based on elapsed time
	b.tokens += elapsed * b.refillRate
	if b.tokens > b.maxTokens {
		b.tokens = b.maxTokens
	}

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// RateLimiter manages per-IP token buckets.
type RateLimiter struct {
	mu       sync.Mutex
	clients  map[string]*clientEntry
	maxBurst float64
	ratePerS float64
}

type clientEntry struct {
	bucket   *tokenBucket
	lastSeen time.Time
}

// NewRateLimiter creates a limiter.
//   - maxBurst: max requests in a burst (e.g. 10)
//   - perMinute: sustained requests per minute (e.g. 60)
func NewRateLimiter(maxBurst, perMinute float64) *RateLimiter {
	rl := &RateLimiter{
		clients:  make(map[string]*clientEntry),
		maxBurst: maxBurst,
		ratePerS: perMinute / 60.0,
	}
	// Background cleanup — evict idle entries every 5 minutes
	go rl.cleanup()
	return rl
}

// Allow checks whether the given IP is within rate limits.
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	entry, exists := rl.clients[ip]
	if !exists {
		entry = &clientEntry{bucket: newBucket(rl.maxBurst, rl.ratePerS)}
		rl.clients[ip] = entry
	}
	entry.lastSeen = time.Now()
	rl.mu.Unlock()

	return entry.bucket.allow()
}

// cleanup removes client entries that have been idle for >10 minutes.
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-10 * time.Minute)
		rl.mu.Lock()
		for ip, entry := range rl.clients {
			if entry.lastSeen.Before(cutoff) {
				delete(rl.clients, ip)
			}
		}
		rl.mu.Unlock()
	}
}
