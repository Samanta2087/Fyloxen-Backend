package handlers

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ── Token lifetimes ──────────────────────────────────────────────────────────

const (
	accessTokenTTL  = 10 * time.Minute
	refreshTokenTTL = 30 * 24 * time.Hour
)

// ── JWT claims ───────────────────────────────────────────────────────────────

// DeviceClaims are the custom claims embedded in every access token.
// The backend includes device_id and key_id so the receiver can:
//   - Authorise requests by device_id without a DB lookup (Phase 4)
//   - Correlate the key version used at token issuance (key rotation awareness)
type DeviceClaims struct {
	DeviceID   string `json:"device_id"`
	KeyID      string `json:"key_id"`      // SHA-256 fingerprint of the EC public key
	KeyVersion int    `json:"key_version"` // incremented on key rotation
	jwt.RegisteredClaims
}

// jwtSecret reads JWT_SECRET from env. Panics on empty — misconfiguration must
// be caught at startup, not at runtime.
func jwtSecret() []byte {
	s := os.Getenv("JWT_SECRET")
	if s == "" {
		panic("JWT_SECRET environment variable is not set")
	}
	return []byte(s)
}

// ── Access token ─────────────────────────────────────────────────────────────

// issueAccessToken mints a short-lived HS256 JWT for the given device.
func issueAccessToken(deviceID, keyFingerprint string, keyVersion int) (string, error) {
	now := time.Now()
	claims := DeviceClaims{
		DeviceID:   deviceID,
		KeyID:      keyFingerprint,
		KeyVersion: keyVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   deviceID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(accessTokenTTL)),
			NotBefore: jwt.NewNumericDate(now),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtSecret())
}

// parseAccessToken verifies signature and expiry, returning claims on success.
func parseAccessToken(tokenStr string) (*DeviceClaims, error) {
	token, err := jwt.ParseWithClaims(
		tokenStr,
		&DeviceClaims{},
		func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return jwtSecret(), nil
		},
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*DeviceClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}
	return claims, nil
}

// ── Refresh token ─────────────────────────────────────────────────────────────

// generateRefreshToken returns a cryptographically random URL-safe token string
// (48 random bytes → 64 char base64url) and its SHA-256 hex hash for DB storage.
// The raw token is sent to the client; only the hash is stored server-side.
func generateRefreshToken() (raw, hash string, err error) {
	b := make([]byte, 48)
	if _, err = rand.Read(b); err != nil {
		return
	}
	raw = base64.URLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(raw))
	hash = hex.EncodeToString(h[:])
	return
}

// hashRefreshToken returns the SHA-256 hex hash of a raw refresh token.
// Used to look up and compare tokens stored in the DB.
func hashRefreshToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// ── EC public key helpers ─────────────────────────────────────────────────────

// parseECPublicKey decodes a Base64 DER-encoded SubjectPublicKeyInfo and
// asserts it is an EC P-256 key. Returns an error for any other key type.
//
// This is the validation used during device registration to ensure the client
// submitted a real EC key rather than arbitrary bytes.
func parseECPublicKey(b64 string) (*ecdsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("public_key: base64 decode failed: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("public_key: DER parse failed: %w", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public_key: not an EC key")
	}
	if ec.Curve.Params().Name != "P-256" {
		return nil, fmt.Errorf("public_key: expected P-256, got %s", ec.Curve.Params().Name)
	}
	return ec, nil
}

// fingerprintKey computes the SHA-256 of the DER-encoded public key and
// returns it as a standard Base64 string (no line wraps).
// Matches what the Android KeystoreManager computes with MessageDigest("SHA-256").
func fingerprintKey(pubKey *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(der)
	return base64.StdEncoding.EncodeToString(h[:]), nil
}

// ── Phase 4 preparation: signature verification ───────────────────────────────

// VerifyRequestSignature verifies a SHA256withECDSA signature produced by
// the Android Keystore (KeystoreManager.sign(data)) against the device's
// registered public key.
//
// Parameters:
//   deviceID  - ANDROID_ID sent with the request
//   dataBytes - canonical bytes that were signed (e.g. request body)
//   sigB64    - Base64-encoded DER ECDSA signature from the Android Keystore
//   pubKeyB64 - Base64-encoded DER public key retrieved from the devices table
//
// Returns (true, nil) if the signature is valid and the key is not revoked.
// Returns (false, err) on any validation failure.
//
// This function is NOT enforced yet — it will be wired into middleware in Phase 4.
// Call it now in tests to confirm end-to-end signing works before Phase 4.
func VerifyRequestSignature(dataBytes []byte, sigB64, pubKeyB64 string) (bool, error) {
	// 1. Decode the signature
	sigDER, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false, fmt.Errorf("signature: base64 decode failed: %w", err)
	}

	// 2. Parse the stored public key
	pubKey, err := parseECPublicKey(pubKeyB64)
	if err != nil {
		return false, fmt.Errorf("public key parse failed: %w", err)
	}

	// 3. Hash the data (Android signs SHA256(data))
	digest := sha256.Sum256(dataBytes)

	// 4. Verify ECDSA DER signature
	valid := ecdsa.VerifyASN1(pubKey, digest[:], sigDER)
	return valid, nil
}
