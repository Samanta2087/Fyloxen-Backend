package middleware

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"fyloxen/analytics/db"
)

// ── Public key cache ──────────────────────────────────────────────────────────
//
// Caches device public keys in memory to avoid a DB lookup on every request.
// TTL: 5 minutes — balances performance with key rotation visibility.
// Revoked devices are cached too (revoked=true), preventing repeated DB hits.

type cachedKey struct {
	key     *ecdsa.PublicKey
	revoked bool
	expiry  time.Time
}

var (
	pkCache    sync.Map        // map[device_id string] → *cachedKey
	pkCacheTTL = 5 * time.Minute
)

// lookupPublicKey returns the verified EC P-256 public key for a device_id.
// Uses the in-memory cache; falls back to DB on miss or TTL expiry.
// Returns (nil, false, nil) if the device is not found.
// Returns (nil, true, nil) if the device is revoked.
func lookupPublicKey(deviceID string) (pub *ecdsa.PublicKey, revoked bool, err error) {
	// Cache hit?
	if v, ok := pkCache.Load(deviceID); ok {
		entry := v.(*cachedKey)
		if time.Now().Before(entry.expiry) {
			return entry.key, entry.revoked, nil
		}
		// TTL expired — evict and re-fetch
		pkCache.Delete(deviceID)
	}

	// DB lookup (primary key — always fast)
	var pubKeyB64 string
	dbErr := db.DB.QueryRow(
		`SELECT public_key, revoked FROM devices WHERE device_id = $1`, deviceID,
	).Scan(&pubKeyB64, &revoked)
	if dbErr != nil {
		return nil, false, nil // device not found
	}

	// Parse the EC P-256 public key
	pub, err = parseECPublicKey(pubKeyB64)
	if err != nil {
		return nil, revoked, fmt.Errorf("public key parse failed for device %s: %w", deviceID, err)
	}

	// Store in cache (revoked devices cached too — prevents repeated DB hits)
	pkCache.Store(deviceID, &cachedKey{
		key:     pub,
		revoked: revoked,
		expiry:  time.Now().Add(pkCacheTTL),
	})
	return pub, revoked, nil
}

// InvalidatePubKeyCache removes a device's public key from the cache.
// Call this after a key rotation (device re-registration with a new key).
func InvalidatePubKeyCache(deviceID string) {
	pkCache.Delete(deviceID)
}

// ── Signature middleware ───────────────────────────────────────────────────────
//
// Verifies the ECDSA SHA-256 signature on the request body for analytics
// endpoints. Enforces that every analytics POST was signed by the device's
// hardware-backed private key (Android Keystore, Phase 1).
//
// Applies to:  /api/v1/app-open, /api/v1/feature, /api/v1/crash
// Exempt:      /api/v1/register (no key yet), /api/v1/auth/refresh (refresh token flow)
//
// Required headers (added by Android AnalyticsManager in Phase 5):
//   Authorization: Bearer <access_token>   ← device_id extracted by jwtMiddleware
//   X-Signature:   <Base64 DER ECDSA sig>  ← SHA256withECDSA over raw body bytes
//
// Signature algorithm:
//   Android:  Signature.getInstance("SHA256withECDSA") → sign(body bytes)
//             This computes ECDSA(SHA-256(body)), producing a DER-encoded signature.
//   Backend:  sha256.Sum256(body) → ecdsa.VerifyASN1(pubKey, digest, sigDER)
//
// On failure: returns 401 with a structured error and logs for abuse visibility.
// On success: body is restored via io.NopCloser so handlers can decode it normally.
func signatureMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only enforce signature on analytics endpoints
		if !isAnalyticsEndpoint(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		ip := realIP(r)

		// ── Require a verified device identity ────────────────────────────────
		// device_id is set by jwtMiddleware from a verified (non-expired) Bearer token.
		// Empty device_id means no valid JWT was presented → Phase 5 requires auth.
		deviceID := DeviceID(r)
		if deviceID == "" {
			http.Error(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
			log.Printf("SIG_NO_AUTH ip=%s path=%s", ip, r.URL.Path)
			return
		}

		// ── Read + buffer the request body ────────────────────────────────────
		// Read once here, restore for handler below.
		bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 32*1024))
		if err != nil {
			http.Error(w, `{"error":"failed to read body"}`, http.StatusBadRequest)
			return
		}
		_ = r.Body.Close()
		// Restore body so the downstream handler can decode it normally
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		// ── Require X-Signature header ────────────────────────────────────────
		sigB64 := r.Header.Get("X-Signature")
		if sigB64 == "" {
			http.Error(w, `{"error":"X-Signature header required"}`, http.StatusUnauthorized)
			log.Printf("SIG_MISSING device_id=%s ip=%s path=%s", deviceID, ip, r.URL.Path)
			return
		}

		// ── Load device public key (cached) ───────────────────────────────────
		pubKey, revoked, err := lookupPublicKey(deviceID)
		if err != nil {
			log.Printf("SIG_KEYLOAD_ERR device_id=%s ip=%s err=%v", deviceID, ip, err)
			http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
			return
		}
		if pubKey == nil {
			http.Error(w, `{"error":"device not registered"}`, http.StatusForbidden)
			log.Printf("SIG_NO_DEVICE device_id=%s ip=%s", deviceID, ip)
			return
		}
		if revoked {
			http.Error(w, `{"error":"device revoked"}`, http.StatusForbidden)
			log.Printf("SIG_REVOKED device_id=%s ip=%s", deviceID, ip)
			return
		}

		// ── Verify ECDSA signature ────────────────────────────────────────────
		valid, err := verifyECDSASignature(bodyBytes, sigB64, pubKey)
		if err != nil || !valid {
			http.Error(w, `{"error":"invalid signature"}`, http.StatusUnauthorized)
			log.Printf("SIG_INVALID device_id=%s ip=%s path=%s err=%v", deviceID, ip, r.URL.Path, err)
			return
		}

		// ── Signature verified ✅ ─────────────────────────────────────────────
		next.ServeHTTP(w, r)
	})
}

// ── ECDSA verification ────────────────────────────────────────────────────────

// verifyECDSASignature verifies a SHA256withECDSA signature produced by the
// Android Keystore against [data] using the device's EC P-256 public key.
//
// The Android Signature.getInstance("SHA256withECDSA") call internally:
//   1. Computes SHA-256 of the input data
//   2. Produces a DER-encoded ECDSA signature over that digest
//
// We replicate this server-side:
//   1. sha256.Sum256(data) → digest
//   2. ecdsa.VerifyASN1(pubKey, digest, sigDER) → bool
func verifyECDSASignature(data []byte, sigB64 string, pubKey *ecdsa.PublicKey) (bool, error) {
	sigDER, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false, fmt.Errorf("sig base64 decode: %w", err)
	}
	digest := sha256.Sum256(data)
	return ecdsa.VerifyASN1(pubKey, digest[:], sigDER), nil
}

// parseECPublicKey decodes a Base64 DER SubjectPublicKeyInfo and asserts it is
// an EC P-256 key. Mirrors the logic in handlers/auth.go (kept here to avoid
// a handlers → middleware import cycle).
func parseECPublicKey(b64 string) (*ecdsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("DER parse: %w", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an EC key")
	}
	if ec.Curve.Params().Name != "P-256" {
		return nil, fmt.Errorf("expected P-256, got %s", ec.Curve.Params().Name)
	}
	return ec, nil
}
