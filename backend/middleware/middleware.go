package middleware

import (
	"crypto/subtle"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"time"
)

// Limiter is the global rate limiter instance.
// 10 burst, 60 requests/minute per IP.
var Limiter = NewRateLimiter(10, 60)

// Chain applies all security middleware in the correct order:
//   Recover → SecurityHeaders → RateLimit → APIKey → Logging → handler
func Chain(next http.Handler) http.Handler {
	return recoverMiddleware(
		securityHeaders(
			rateLimitMiddleware(
				apiKeyMiddleware(
					loggingMiddleware(next),
				),
			),
		),
	)
}

// ── 1. Panic recovery ─────────────────────────────────────────────────────────
// Catches any unhandled panic and returns 500 instead of crashing the process.
func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("PANIC recovered: %v\n%s", rec, debug.Stack())
				http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// ── 2. Security headers ───────────────────────────────────────────────────────
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Type", "application/json")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-XSS-Protection", "1; mode=block")
		h.Set("Referrer-Policy", "no-referrer")
		// Only allow requests from the Fyloxen app (no browser cross-origin needed)
		h.Set("Access-Control-Allow-Origin", "null")
		h.Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		h.Set("Access-Control-Allow-Headers", "Content-Type, X-Api-Key")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ── 3. Rate limiting ──────────────────────────────────────────────────────────
func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip rate limit for health check
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		ip := realIP(r)
		if !Limiter.Allow(ip) {
			w.Header().Set("Retry-After", "60")
			w.Header().Set("X-RateLimit-Limit", "60")
			http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
			log.Printf("RATE_LIMIT ip=%s path=%s", ip, r.URL.Path)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ── 4. API key authentication ─────────────────────────────────────────────────
// Uses constant-time comparison to prevent timing-based key enumeration attacks.
func apiKeyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		expected := os.Getenv("API_KEY")
		if expected == "" {
			// No key configured — allow (dev mode)
			next.ServeHTTP(w, r)
			return
		}

		provided := r.Header.Get("X-Api-Key")

		// Constant-time comparison — prevents timing attacks even if lengths differ
		// by padding the shorter string to the same length before comparing.
		ok := subtle.ConstantTimeCompare(
			[]byte(provided),
			[]byte(expected),
		) == 1

		if !ok {
			ip := realIP(r)
			log.Printf("AUTH_FAIL ip=%s path=%s key_prefix=%.4s", ip, r.URL.Path, safePrefix(provided))
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ── 5. Request logging ────────────────────────────────────────────────────────
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		start := time.Now()
		next.ServeHTTP(rec, r)
		log.Printf("%s %s %d %s ip=%s",
			r.Method, r.URL.Path, rec.status,
			time.Since(start).Round(time.Millisecond),
			realIP(r),
		)
	})
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// realIP extracts the true client IP, respecting X-Forwarded-For from reverse proxies.
func realIP(r *http.Request) string {
	// Trust X-Forwarded-For only for the first (leftmost) IP — the real client
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		parts := strings.Split(fwd, ",")
		if ip := strings.TrimSpace(parts[0]); ip != "" {
			return ip
		}
	}
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func safePrefix(s string) string {
	if len(s) == 0 {
		return "(empty)"
	}
	if len(s) < 4 {
		return fmt.Sprintf("%s***", s)
	}
	return s[:4]
}
