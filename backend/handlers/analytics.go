package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"fyloxen/analytics/db"
)

// ── Request models ─────────────────────────────────────────────────────────────

type AppOpenRequest struct {
	DeviceID   string `json:"device_id"`
	AppVersion string `json:"app_version"`
	OsVersion  string `json:"os_version"`
}

type FeatureRequest struct {
	DeviceID    string `json:"device_id"`
	FeatureName string `json:"feature_name"`
	Screen      string `json:"screen"`
	Extra       string `json:"extra"`
}

type CrashRequest struct {
	DeviceID     string `json:"device_id"`
	AppVersion   string `json:"app_version"`
	OsVersion    string `json:"os_version"`
	ErrorMessage string `json:"error_message"`
	StackTrace   string `json:"stack_trace"`
}

// ── Response helpers ───────────────────────────────────────────────────────────

func ok(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

func fail(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func decode(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 32*1024) // 32 KB max per request
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields() // reject unexpected JSON keys
	return d.Decode(v)
}

// validateLen rejects strings longer than maxLen to prevent DB oversizing.
func validateLen(s string, maxLen int) bool { return len(s) <= maxLen }

// ── Handlers ───────────────────────────────────────────────────────────────────

// POST /api/v1/app-open
func AppOpen(w http.ResponseWriter, r *http.Request) {
	var req AppOpenRequest
	if err := decode(w, r, &req); err != nil {
		fail(w, http.StatusBadRequest, "invalid json")
		return
	}

	req.DeviceID   = strings.TrimSpace(req.DeviceID)
	req.AppVersion = strings.TrimSpace(req.AppVersion)
	req.OsVersion  = strings.TrimSpace(req.OsVersion)

	if req.DeviceID == "" {
		fail(w, http.StatusBadRequest, "device_id required")
		return
	}
	if !validateLen(req.DeviceID, 64) || !validateLen(req.AppVersion, 32) || !validateLen(req.OsVersion, 64) {
		fail(w, http.StatusBadRequest, "field too long")
		return
	}

	_, err := db.DB.Exec(
		`INSERT INTO app_opens (device_id, app_version, os_version) VALUES ($1, $2, $3)`,
		req.DeviceID, req.AppVersion, req.OsVersion,
	)
	if err != nil {
		log.Printf("app_open insert error: %v", err)
		fail(w, http.StatusInternalServerError, "db error")
		return
	}

	ok(w)
}

// POST /api/v1/feature
func FeatureUsage(w http.ResponseWriter, r *http.Request) {
	var req FeatureRequest
	if err := decode(w, r, &req); err != nil {
		fail(w, http.StatusBadRequest, "invalid json")
		return
	}

	req.DeviceID     = strings.TrimSpace(req.DeviceID)
	req.FeatureName  = strings.TrimSpace(req.FeatureName)
	req.Screen       = strings.TrimSpace(req.Screen)
	req.Extra        = strings.TrimSpace(req.Extra)

	if req.DeviceID == "" || req.FeatureName == "" {
		fail(w, http.StatusBadRequest, "device_id and feature_name required")
		return
	}
	if !validateLen(req.DeviceID, 64) || !validateLen(req.FeatureName, 100) ||
		!validateLen(req.Screen, 100) || !validateLen(req.Extra, 255) {
		fail(w, http.StatusBadRequest, "field too long")
		return
	}

	_, err := db.DB.Exec(
		`INSERT INTO feature_usage (device_id, feature_name, screen, extra) VALUES ($1, $2, $3, $4)`,
		req.DeviceID, req.FeatureName, req.Screen, req.Extra,
	)
	if err != nil {
		log.Printf("feature_usage insert error: %v", err)
		fail(w, http.StatusInternalServerError, "db error")
		return
	}

	ok(w)
}

// POST /api/v1/crash
func CrashLog(w http.ResponseWriter, r *http.Request) {
	var req CrashRequest
	if err := decode(w, r, &req); err != nil {
		fail(w, http.StatusBadRequest, "invalid json")
		return
	}

	req.DeviceID      = strings.TrimSpace(req.DeviceID)
	req.AppVersion    = strings.TrimSpace(req.AppVersion)
	req.OsVersion     = strings.TrimSpace(req.OsVersion)
	req.ErrorMessage  = strings.TrimSpace(req.ErrorMessage)

	if req.DeviceID == "" {
		fail(w, http.StatusBadRequest, "device_id required")
		return
	}
	if !validateLen(req.DeviceID, 64) || !validateLen(req.AppVersion, 32) ||
		!validateLen(req.OsVersion, 64) || !validateLen(req.ErrorMessage, 512) ||
		!validateLen(req.StackTrace, 8000) {
		fail(w, http.StatusBadRequest, "field too long")
		return
	}

	_, err := db.DB.Exec(
		`INSERT INTO crash_logs (device_id, app_version, os_version, error_message, stack_trace) VALUES ($1, $2, $3, $4, $5)`,
		req.DeviceID, req.AppVersion, req.OsVersion, req.ErrorMessage, req.StackTrace,
	)
	if err != nil {
		log.Printf("crash_log insert error: %v", err)
		fail(w, http.StatusInternalServerError, "db error")
		return
	}

	ok(w)
}
