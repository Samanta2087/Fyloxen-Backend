package middleware

import (
	"context"
	"crypto/subtle"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ── Context keys ──────────────────────────────────────────────────────────────

type contextKey string

const (
	// deviceIDKey holds the verified device_id extracted from a valid Bearer JWT.
	// Empty string means no valid token was present.
	deviceIDKey contextKey = "device_id"
)

// DeviceID retrieves the authenticated device_id from the request context.
// Returns "" if no valid JWT was presented (unauthenticated or expired token).
func DeviceID(r *http.Request) string {
	v, _ := r.Context().Value(deviceIDKey).(string)
	return v
}

// ── Rate limiters ─────────────────────────────────────────────────────────────

// IPLimiter: 10 burst, 60 rpm — global per-IP limit for all endpoints.
var IPLimiter = NewRateLimiter(10, 60)

// DeviceLimiter: 30 burst, 120 rpm per device_id — applied to analytics
// endpoints only. Generous enough for normal use (batch queuing) but catches
// a device submitting events in a tight loop (app bug / abuse).
// NOT applied to /api/v1/auth/refresh — refresh must always succeed.
var DeviceLimiter = NewRateLimiter(30, 120)

// ── Middleware chain ──────────────────────────────────────────────────────────

// Chain applies all security middleware in the correct order:
//
//	Recover → SecurityHeaders → JWT → RateLimit → APIKey → Logging → handler
//
// JWT runs before RateLimit so device_id is available for per-device limiting.
func Chain(next http.Handler) http.Handler {
	return recoverMiddleware(
		securityHeaders(
			jwtMiddleware(
				rateLimitMiddleware(
					apiKeyMiddleware(
						loggingMiddleware(next),
					),
				),
			),
		),
	)
}

// ── 1. Panic recovery ─────────────────────────────────────────────────────────

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
		h.Set("Access-Control-Allow-Origin", "null")
		h.Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		// Phase 3+: include Authorization so the app can send Bearer tokens
		h.Set("Access-Control-Allow-Headers", "Content-Type, X-Api-Key, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ── 3. JWT extraction ─────────────────────────────────────────────────────────
//
// Parses the `Authorization: Bearer <token>` header and, if valid, injects
// the verified device_id into the request context.
//
// This middleware is PERMISSIVE — it never blocks a request. A missing or
// invalid/expired token simply results in an empty device_id in context:
//   - No token → device_id = "" (no device-level rate limit applied)
//   - Expired token → device_id = "" (app will refresh and retry; don't block)
//   - Invalid signature → device_id = "" + warning logged
//
// Phase 5 will make token presence MANDATORY for analytics endpoints.
func jwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deviceID := extractVerifiedDeviceID(r)
		ctx := context.WithValue(r.Context(), deviceIDKey, deviceID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// extractVerifiedDeviceID parses and verifies the Bearer JWT, returning the
// device_id claim on success or "" on any failure.
// Uses MapClaims to avoid a dependency on the handlers package struct.
func extractVerifiedDeviceID(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	tokenStr := strings.TrimPrefix(auth, "Bearer ")

	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		// Dev mode: no JWT_SECRET set — skip verification, don't extract device_id
		return ""
	}

	token, err := jwt.Parse(
		tokenStr,
		func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return []byte(secret), nil
		},
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		// Expired tokens are normal — app will call /auth/refresh.
		// Only log unexpected errors (wrong signature, malformed).
		if !strings.Contains(err.Error(), "token is expired") {
			log.Printf("JWT_INVALID ip=%s path=%s err=%v", realIP(r), r.URL.Path, err)
		}
		return ""
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return ""
	}
	deviceID, _ := claims["device_id"].(string)
	return deviceID
}

// ── 4. Dual rate limiting ─────────────────────────────────────────────────────
//
// Applies two independent rate limits in sequence:
//
//  1. Per-IP limit (IPLimiter): all endpoints, 10 burst / 60 rpm.
//     Guards against unauthenticated floods and scraping.
//
//  2. Per-device_id limit (DeviceLimiter): analytics endpoints only,
//     30 burst / 120 rpm. Guards against a single device hammering analytics.
//
// Exemptions (no device_id limit):
//   - /api/v1/register → has its own strict limiter in the handler
//   - /api/v1/auth/refresh → must never be device-limited; app needs this
//     to renew an expired token before retrying analytics
//   - /health → always unlimited
func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		ip := realIP(r)

		// ── Layer 1: IP rate limit (all endpoints) ────────────────────────────
		if !IPLimiter.Allow(ip) {
			w.Header().Set("Retry-After", "60")
			w.Header().Set("X-RateLimit-Limit", "60")
			http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
			log.Printf("RATE_LIMIT_IP ip=%s path=%s", ip, r.URL.Path)
			return
		}

		// ── Layer 2: Device rate limit (analytics endpoints only) ─────────────
		if isAnalyticsEndpoint(r.URL.Path) {
			deviceID := DeviceID(r) // injected by jwtMiddleware above
			if deviceID != "" {
				if !DeviceLimiter.Allow(deviceID) {
					w.Header().Set("Retry-After", "60")
					w.Header().Set("X-RateLimit-Device-Limit", "120")
					http.Error(w, `{"error":"device rate limit exceeded"}`, http.StatusTooManyRequests)
					log.Printf("RATE_LIMIT_DEVICE device_id=%s ip=%s path=%s",
						deviceID, ip, r.URL.Path)
					return
				}
			}
			// device_id == "" means no valid token yet — only IP-limited (permissive)
		}

		next.ServeHTTP(w, r)
	})
}

// isAnalyticsEndpoint returns true for endpoints that receive device telemetry.
// These are the only endpoints subject to per-device_id rate limiting.
func isAnalyticsEndpoint(path string) bool {
	switch path {
	case "/api/v1/app-open", "/api/v1/feature", "/api/v1/crash":
		return true
	}
	return false
}

// ── 5. API key authentication ─────────────────────────────────────────────────

func apiKeyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		expected := os.Getenv("API_KEY")
		if expected == "" {
			next.ServeHTTP(w, r)
			return
		}

		provided := r.Header.Get("X-Api-Key")
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

// ── 6. Request logging ────────────────────────────────────────────────────────

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// loggingMiddleware logs every request with method, path, status, duration,
// IP, and device_id (if a valid JWT was presented — from context).
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		start := time.Now()
		next.ServeHTTP(rec, r)

		deviceID := DeviceID(r)
		if deviceID == "" {
			deviceID = "-"
		}
		log.Printf("%s %s %d %s ip=%s device=%s",
			r.Method, r.URL.Path, rec.status,
			time.Since(start).Round(time.Millisecond),
			realIP(r), deviceID,
		)
	})
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func realIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		parts := strings.Split(fwd, ",")
		if ip := strings.TrimSpace(parts[0]); ip != "" {
			return ip
		}
	}
	if ri := r.Header.Get("X-Real-IP"); ri != "" {
		return ri
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
