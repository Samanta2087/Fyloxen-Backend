package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"fyloxen/analytics/db"
)

// regLimiter: burst=3, 1 per hour sustained — set in ratelimit_strict.go
// var regLimiter = newStrictRateLimiter()  (defined in ratelimit_strict.go)

// ── Register handler ──────────────────────────────────────────────────────────

type RegisterRequest struct {
	DeviceID       string `json:"device_id"`
	PublicKey      string `json:"public_key"`
	KeyFingerprint string `json:"key_fingerprint"`
	AppVersion     string `json:"app_version"`
}

type RegisterResponse struct {
	Status       string `json:"status"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// POST /api/v1/register
//
// Registers the device and issues initial JWT access + refresh tokens.
// Rate limited aggressively: 3 burst, 1 per hour per IP.
//
// Flow:
//  1. Validate request fields
//  2. Check IP rate limit (strict)
//  3. Parse + validate EC P-256 public key
//  4. Verify key_fingerprint matches public_key
//  5. UPSERT device record (first_seen / last_seen / key_version++)
//  6. Issue access token + refresh token
//  7. Store hashed refresh token in auth_tokens
//  8. Return tokens to client
func Register(w http.ResponseWriter, r *http.Request) {
	// ── Rate limit by IP ──────────────────────────────────────────────────────
	ip := clientIP(r)
	if !regLimiter.Allow(ip) {
		log.Printf("register: rate limited IP=%s", ip)
		w.Header().Set("Retry-After", "3600")
		fail(w, http.StatusTooManyRequests, "registration rate limit exceeded — try again in 1 hour")
		return
	}

	// ── Decode + validate request ─────────────────────────────────────────────
	var req RegisterRequest
	r.Body = http.MaxBytesReader(w, r.Body, 8*1024) // 8 KB max for registration
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "invalid json")
		return
	}

	req.DeviceID       = strings.TrimSpace(req.DeviceID)
	req.PublicKey      = strings.TrimSpace(req.PublicKey)
	req.KeyFingerprint = strings.TrimSpace(req.KeyFingerprint)
	req.AppVersion     = strings.TrimSpace(req.AppVersion)

	switch {
	case req.DeviceID == "":
		fail(w, http.StatusBadRequest, "device_id required"); return
	case req.PublicKey == "":
		fail(w, http.StatusBadRequest, "public_key required"); return
	case req.KeyFingerprint == "":
		fail(w, http.StatusBadRequest, "key_fingerprint required"); return
	case !validateLen(req.DeviceID, 64):
		fail(w, http.StatusBadRequest, "device_id too long"); return
	case !validateLen(req.PublicKey, 512):
		fail(w, http.StatusBadRequest, "public_key too long"); return
	case !validateLen(req.KeyFingerprint, 64):
		fail(w, http.StatusBadRequest, "key_fingerprint too long"); return
	case !validateLen(req.AppVersion, 20):
		fail(w, http.StatusBadRequest, "app_version too long"); return
	}

	// ── Validate EC P-256 public key ──────────────────────────────────────────
	pubKey, err := parseECPublicKey(req.PublicKey)
	if err != nil {
		log.Printf("register: invalid public key device=%s err=%v", req.DeviceID, err)
		fail(w, http.StatusBadRequest, "public_key is not a valid EC P-256 key")
		return
	}

	// ── Verify fingerprint matches the submitted public key ───────────────────
	computedFingerprint, err := fingerprintKey(pubKey)
	if err != nil {
		fail(w, http.StatusInternalServerError, "fingerprint computation failed")
		return
	}
	if computedFingerprint != req.KeyFingerprint {
		log.Printf("register: fingerprint mismatch device=%s", req.DeviceID)
		fail(w, http.StatusBadRequest, "key_fingerprint does not match public_key")
		return
	}

	// ── UPSERT device record ──────────────────────────────────────────────────
	// On conflict (same device_id, same public_key): update last_seen only.
	// On key change (same device_id, new public_key): increment key_version.
	var keyVersion int
	err = db.DB.QueryRow(`
		INSERT INTO devices (device_id, public_key, key_fingerprint, app_version, key_version)
		VALUES ($1, $2, $3, $4, 1)
		ON CONFLICT (device_id) DO UPDATE SET
			public_key      = EXCLUDED.public_key,
			key_fingerprint = EXCLUDED.key_fingerprint,
			app_version     = EXCLUDED.app_version,
			key_version     = CASE
				WHEN devices.public_key != EXCLUDED.public_key
				THEN devices.key_version + 1
				ELSE devices.key_version
			END,
			last_seen = NOW()
		RETURNING key_version
	`, req.DeviceID, req.PublicKey, req.KeyFingerprint, req.AppVersion).Scan(&keyVersion)
	if err != nil {
		log.Printf("register: upsert error device=%s err=%v", req.DeviceID, err)
		fail(w, http.StatusInternalServerError, "registration failed")
		return
	}

	// ── Check device is not revoked ───────────────────────────────────────────
	var revoked bool
	_ = db.DB.QueryRow(
		`SELECT revoked FROM devices WHERE device_id = $1`, req.DeviceID,
	).Scan(&revoked)
	if revoked {
		log.Printf("register: revoked device=%s", req.DeviceID)
		fail(w, http.StatusForbidden, "device has been revoked")
		return
	}

	// ── Issue JWT access token ────────────────────────────────────────────────
	accessToken, err := issueAccessToken(req.DeviceID, req.KeyFingerprint, keyVersion)
	if err != nil {
		log.Printf("register: access token error device=%s err=%v", req.DeviceID, err)
		fail(w, http.StatusInternalServerError, "token issuance failed")
		return
	}

	// ── Generate + store hashed refresh token ─────────────────────────────────
	rawRefresh, hashRefresh, err := generateRefreshToken()
	if err != nil {
		log.Printf("register: refresh token generation error: %v", err)
		fail(w, http.StatusInternalServerError, "token generation failed")
		return
	}

	// Revoke any existing refresh tokens for this device before issuing a new one
	_, _ = db.DB.Exec(
		`UPDATE auth_tokens SET revoked = TRUE WHERE device_id = $1 AND revoked = FALSE`,
		req.DeviceID,
	)
	_, err = db.DB.Exec(`
		INSERT INTO auth_tokens (device_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`, req.DeviceID, hashRefresh, time.Now().Add(refreshTokenTTL))
	if err != nil {
		log.Printf("register: auth_token insert error device=%s err=%v", req.DeviceID, err)
		fail(w, http.StatusInternalServerError, "token storage failed")
		return
	}

	log.Printf("register: ✅ device=%s key_version=%d ip=%s", req.DeviceID, keyVersion, ip)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(RegisterResponse{
		Status:       "registered",
		AccessToken:  accessToken,
		RefreshToken: rawRefresh,
	})
}

// ── Refresh handler ───────────────────────────────────────────────────────────

type RefreshRequest struct {
	DeviceID     string `json:"device_id"`
	RefreshToken string `json:"refresh_token"`
}

// POST /api/v1/auth/refresh
//
// Validates the refresh token and issues a new access + refresh token pair.
// Implements refresh token rotation: the used refresh token is deleted and a
// new one is inserted — prevents replay attacks.
func Refresh(w http.ResponseWriter, r *http.Request) {
	var req RefreshRequest
	r.Body = http.MaxBytesReader(w, r.Body, 2*1024)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "invalid json")
		return
	}

	req.DeviceID     = strings.TrimSpace(req.DeviceID)
	req.RefreshToken = strings.TrimSpace(req.RefreshToken)

	if req.DeviceID == "" || req.RefreshToken == "" {
		fail(w, http.StatusBadRequest, "device_id and refresh_token required")
		return
	}

	// ── Look up hashed refresh token ──────────────────────────────────────────
	tokenHash := hashRefreshToken(req.RefreshToken)
	var (
		tokenID   int64
		expiresAt time.Time
		revoked   bool
	)
	err := db.DB.QueryRow(`
		SELECT id, expires_at, revoked FROM auth_tokens
		WHERE token_hash = $1 AND device_id = $2
	`, tokenHash, req.DeviceID).Scan(&tokenID, &expiresAt, &revoked)
	if err != nil {
		log.Printf("refresh: token not found device=%s", req.DeviceID)
		fail(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}
	if revoked || time.Now().After(expiresAt) {
		fail(w, http.StatusUnauthorized, "refresh token expired or revoked")
		return
	}

	// ── Check device is not revoked ───────────────────────────────────────────
	var (
		keyFingerprint string
		keyVersion     int
		deviceRevoked  bool
	)
	err = db.DB.QueryRow(`
		SELECT key_fingerprint, key_version, revoked FROM devices WHERE device_id = $1
	`, req.DeviceID).Scan(&keyFingerprint, &keyVersion, &deviceRevoked)
	if err != nil || deviceRevoked {
		fail(w, http.StatusForbidden, "device not found or revoked")
		return
	}

	// ── Rotate: delete used token, issue new pair ─────────────────────────────
	_, _ = db.DB.Exec(`DELETE FROM auth_tokens WHERE id = $1`, tokenID)

	accessToken, err := issueAccessToken(req.DeviceID, keyFingerprint, keyVersion)
	if err != nil {
		fail(w, http.StatusInternalServerError, "token issuance failed")
		return
	}

	rawRefresh, hashRefresh, err := generateRefreshToken()
	if err != nil {
		fail(w, http.StatusInternalServerError, "token generation failed")
		return
	}
	_, err = db.DB.Exec(`
		INSERT INTO auth_tokens (device_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`, req.DeviceID, hashRefresh, time.Now().Add(refreshTokenTTL))
	if err != nil {
		fail(w, http.StatusInternalServerError, "token storage failed")
		return
	}

	log.Printf("refresh: ✅ device=%s key_version=%d", req.DeviceID, keyVersion)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(RegisterResponse{
		Status:       "refreshed",
		AccessToken:  accessToken,
		RefreshToken: rawRefresh,
	})
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// clientIP extracts the real client IP, honouring X-Forwarded-For from the
// reverse proxy (Nginx/Caddy) sitting in front of the Go server.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For may contain a comma-separated list — take the first
		parts := strings.SplitN(xff, ",", 2)
		return strings.TrimSpace(parts[0])
	}
	return r.RemoteAddr
}
