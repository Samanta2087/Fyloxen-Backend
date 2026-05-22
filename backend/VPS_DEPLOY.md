# 🚀 Fyloxen Analytics Backend — VPS Deployment Guide

Complete guide to deploy the Go + PostgreSQL backend on a Linux VPS (Ubuntu 22.04).

---

## 📋 Requirements

| Item | Recommended |
|---|---|
| OS | Ubuntu 22.04 LTS |
| RAM | 512 MB minimum (1 GB recommended) |
| CPU | 1 vCPU minimum |
| Storage | 10 GB SSD |
| Port | 443 (HTTPS) open in firewall |
| VPS Providers | DigitalOcean, Hetzner, Vultr, AWS Lightsail |

> **Cheapest option:** Hetzner CX11 = ~€3.29/month (2 GB RAM, 1 vCPU)

---

## 🔑 Step 1 — Initial Server Setup

SSH into your new VPS as root:

```bash
ssh root@YOUR_SERVER_IP
```

Create a non-root user and give it sudo:

```bash
adduser fyloxen
usermod -aG sudo fyloxen
# Switch to new user
su - fyloxen
```

Update the system:

```bash
sudo apt update && sudo apt upgrade -y
```

---

## 🔥 Step 2 — Configure Firewall (UFW)

```bash
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
sudo ufw status
```

> ⚠️ **Never expose port 8080/8081 directly.** Use Nginx as a reverse proxy on 443.

---

## 🐘 Step 3 — Install PostgreSQL

```bash
sudo apt install -y postgresql postgresql-contrib
sudo systemctl enable postgresql
sudo systemctl start postgresql
```

Create the database and user:

```bash
sudo -u postgres psql
```

Inside the PostgreSQL shell:

```sql
-- Create a dedicated DB user (replace 'YOUR_STRONG_PASSWORD')
CREATE USER fyloxen_user WITH PASSWORD 'YOUR_STRONG_PASSWORD';

-- Create the database
CREATE DATABASE fyloxen OWNER fyloxen_user;

-- Grant all privileges
GRANT ALL PRIVILEGES ON DATABASE fyloxen TO fyloxen_user;

-- Exit
\q
```

Test the connection:

```bash
psql -U fyloxen_user -d fyloxen -h localhost
# Should connect successfully — type \q to exit
```

---

## 🐹 Step 4 — Install Go

```bash
# Download Go 1.22 (check https://go.dev/dl/ for latest)
wget https://go.dev/dl/go1.22.4.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.4.linux-amd64.tar.gz
rm go1.22.4.linux-amd64.tar.gz

# Add Go to PATH
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# Verify
go version
# Expected: go version go1.22.4 linux/amd64
```

---

## 📦 Step 5 — Deploy the Backend Code

### Option A — Copy from your PC (simple)

On your **Windows PC**, run:

```powershell
# From d:\Mt Manger Backup\backend
scp -r . fyloxen@YOUR_SERVER_IP:/home/fyloxen/analytics/
```

### Option B — Git (recommended for updates)

On the server:

```bash
sudo apt install -y git
git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git /home/fyloxen/analytics
cd /home/fyloxen/analytics/backend
```

### Build the binary

```bash
cd /home/fyloxen/analytics
go mod download
go build -o fyloxen-analytics .
ls -lh fyloxen-analytics   # Should show ~8-12 MB binary
```

---

## ⚙️ Step 6 — Configure Environment

Create the production `.env` file:

```bash
nano /home/fyloxen/analytics/.env
```

Paste and edit:

```env
# Database
DB_HOST=localhost
DB_PORT=5432
DB_USER=fyloxen_user
DB_PASSWORD=YOUR_STRONG_PASSWORD
DB_NAME=fyloxen
DB_SSLMODE=disable

# Server — listen on localhost only (Nginx will proxy to this)
PORT=8080

# API Key — change this to a long random string!
API_KEY=CHANGE_THIS_TO_A_LONG_RANDOM_SECRET
```

> 💡 Generate a strong API key:
> ```bash
> openssl rand -hex 32
> # Example: a3f9b2c1d4e5f67890abcdef1234567890abcdef1234567890abcdef12345678
> ```

Secure the file so only your user can read it:

```bash
chmod 600 /home/fyloxen/analytics/.env
```

> ⚠️ **Update `API_KEY` in `AnalyticsManager.kt`** in your Android app to match!

---

## 🔄 Step 7 — Create a systemd Service

This keeps the server running automatically and restarts it on crash:

```bash
sudo nano /etc/systemd/system/fyloxen-analytics.service
```

Paste:

```ini
[Unit]
Description=Fyloxen Analytics Backend
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=fyloxen
WorkingDirectory=/home/fyloxen/analytics
EnvironmentFile=/home/fyloxen/analytics/.env
ExecStart=/home/fyloxen/analytics/fyloxen-analytics
Restart=on-failure
RestartSec=5s

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/home/fyloxen/analytics

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=fyloxen-analytics

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable fyloxen-analytics
sudo systemctl start fyloxen-analytics

# Check status
sudo systemctl status fyloxen-analytics
# Should show: Active: active (running)
```

View live logs:

```bash
sudo journalctl -u fyloxen-analytics -f
```

---

## 🌐 Step 8 — Install Nginx (Reverse Proxy)

```bash
sudo apt install -y nginx
sudo systemctl enable nginx
```

Create a config for your domain:

```bash
sudo nano /etc/nginx/sites-available/fyloxen-analytics
```

Paste (replace `api.yourdomain.com` with your actual domain):

```nginx
server {
    listen 80;
    server_name api.yourdomain.com;

    # Redirect HTTP → HTTPS
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name api.yourdomain.com;

    # SSL (Certbot will fill this in Step 9)
    ssl_certificate     /etc/letsencrypt/live/api.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.yourdomain.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options    "nosniff" always;
    add_header X-Frame-Options           "DENY" always;

    # Limit request body (defence-in-depth alongside Go handler limits)
    client_max_body_size 64k;

    location / {
        proxy_pass         http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_read_timeout 10s;
        proxy_send_timeout 10s;
    }

    # Block all paths except our API
    location ~* ^/(?!api/v1/|health) {
        return 404;
    }
}
```

Enable the site:

```bash
sudo ln -s /etc/nginx/sites-available/fyloxen-analytics /etc/nginx/sites-enabled/
sudo nginx -t          # Test config — should say "syntax is ok"
sudo systemctl reload nginx
```

---

## 🔐 Step 9 — Free HTTPS with Let's Encrypt

> **Requirement:** Your domain must point to your VPS IP via DNS A record before this step.

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d api.yourdomain.com

# Follow the prompts:
# - Enter email
# - Agree to terms
# - Certbot will auto-configure Nginx for HTTPS ✅

# Test auto-renewal
sudo certbot renew --dry-run
```

---

## 📱 Step 10 — Update Android App

In `AnalyticsManager.kt`, change:

```kotlin
// BEFORE (local dev)
private const val BASE_URL = "http://192.168.1.101:8081"
private const val API_KEY  = "Samanta1"

// AFTER (production VPS)
private const val BASE_URL = "https://api.yourdomain.com"
private const val API_KEY  = "YOUR_LONG_RANDOM_SECRET_FROM_STEP_6"
```

Also remove `android:usesCleartextTraffic="true"` from `AndroidManifest.xml` since you now use HTTPS.

Rebuild and install:

```powershell
.\gradlew assembleRelease
```

---

## ✅ Step 11 — Test Everything

From your PC, test all 3 endpoints:

```bash
# Health check (no API key needed)
curl https://api.yourdomain.com/health

# App open (replace with your actual API key)
curl -X POST https://api.yourdomain.com/api/v1/app-open \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: YOUR_API_KEY" \
  -d '{"device_id":"test-device","app_version":"1.0","os_version":"Android 14"}'

# Feature usage
curl -X POST https://api.yourdomain.com/api/v1/feature \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: YOUR_API_KEY" \
  -d '{"device_id":"test-device","feature_name":"folder_open","screen":"main"}'

# Rate limit test (should get 429 after 10 rapid requests)
for i in {1..12}; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    https://api.yourdomain.com/health
done
```

Check the database:

```bash
sudo -u postgres psql -d fyloxen
SELECT count(*) FROM app_opens;
SELECT count(*) FROM feature_usage;
\q
```

---

## 🔄 Updating the Backend

When you make code changes, deploy the update:

```bash
# On your PC — copy new files
scp -r d:\Mt\ Manger\ Backup\backend\* fyloxen@YOUR_SERVER_IP:/home/fyloxen/analytics/

# On the server — rebuild and restart
ssh fyloxen@YOUR_SERVER_IP
cd /home/fyloxen/analytics
go build -o fyloxen-analytics .
sudo systemctl restart fyloxen-analytics
sudo systemctl status fyloxen-analytics
```

---

## 📊 Useful Commands

```bash
# View live server logs
sudo journalctl -u fyloxen-analytics -f

# Check how many requests received
sudo journalctl -u fyloxen-analytics --since "today" | grep "POST /api" | wc -l

# PostgreSQL — view recent app opens
sudo -u postgres psql -d fyloxen -c "SELECT * FROM app_opens ORDER BY created_at DESC LIMIT 10;"

# PostgreSQL — top features used
sudo -u postgres psql -d fyloxen -c "SELECT feature_name, count(*) FROM feature_usage GROUP BY feature_name ORDER BY count DESC;"

# PostgreSQL — crash reports
sudo -u postgres psql -d fyloxen -c "SELECT device_id, error_message, created_at FROM crash_logs ORDER BY created_at DESC LIMIT 5;"

# Check server memory / CPU
htop

# Check Nginx error log
sudo tail -f /var/log/nginx/error.log

# Restart everything
sudo systemctl restart fyloxen-analytics nginx postgresql
```

---

## 🏗️ Architecture Overview

```
Android App (Fyloxen)
        │
        │ HTTPS POST  X-Api-Key: ***
        ▼
   Nginx (port 443)
   - SSL termination
   - client_max_body: 64k
   - Forwards X-Forwarded-For
        │
        │ HTTP proxy  127.0.0.1:8080
        ▼
   Go Backend
   - Panic recovery
   - Rate limit: 10 burst / 60 rpm per IP
   - Constant-time API key check
   - Field length validation
   - 32 KB body limit
        │
        ▼
   PostgreSQL
   - app_opens
   - feature_usage
   - crash_logs
```

---

## 🔒 Security Checklist

- [ ] PostgreSQL not exposed to internet (localhost only)
- [ ] Go backend not exposed to internet (localhost only, behind Nginx)
- [ ] HTTPS enabled (Let's Encrypt)
- [ ] API key is long random string (not "Samanta1")
- [ ] `.env` file has `chmod 600`
- [ ] UFW firewall enabled (only 22, 80, 443 open)
- [ ] `android:usesCleartextTraffic` removed from `AndroidManifest.xml`
- [ ] Rate limiting tested (returns 429 after burst)
- [ ] systemd service set to `Restart=on-failure`
