package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"

	"fyloxen/analytics/db"
	"fyloxen/analytics/handlers"
	"fyloxen/analytics/middleware"
)

func main() {
	// Load .env (ignored in production where env vars are set directly)
	_ = godotenv.Load()

	// Connect to PostgreSQL and run migrations
	db.Init()
	defer db.Close()

	// ── Routes ────────────────────────────────────────────────────────────────
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/v1/app-open", handlers.AppOpen)
	mux.HandleFunc("POST /api/v1/feature",  handlers.FeatureUsage)
	mux.HandleFunc("POST /api/v1/crash",    handlers.CrashLog)

	// Phase 3: Device registration + JWT token refresh
	// Register: burst=3, 1/hr per IP — strict rate limited
	mux.HandleFunc("POST /api/v1/register",      handlers.Register)
	mux.HandleFunc("POST /api/v1/auth/refresh",  handlers.Refresh)

	// Health — unauthenticated, not rate-limited
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	// ── Server ────────────────────────────────────────────────────────────────
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: middleware.Chain(mux),

		// Strict timeouts — prevent Slowloris and slow-body attacks
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,

		// Limit total request body to 128 KB at the transport level
		// (each handler also calls MaxBytesReader for defence-in-depth)
		MaxHeaderBytes: 4 << 10, // 4 KB header limit
	}

	log.Printf("🚀 Fyloxen Analytics  →  http://localhost:%s", port)
	log.Printf("🔒 Security: rate-limit=10burst/60rpm  register=3burst/1hr  auth=X-Api-Key+JWT  panic-recover=on")
	log.Fatal(srv.ListenAndServe())
}
