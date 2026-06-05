# Artisan Gem Works — Private Admin Credentials

> **PRIVATE — Do not commit to a public repository or share externally.**
> All credentials below are for demo and testing purposes only.

---

## Demo User Accounts (All Projects)

| Role | Email | Password |
|------|-------|----------|
| Admin | admin@artisangemworks.com | Admin!2024Secure |
| Customer | customer@demo.com | Customer!2024Demo |

---

## Two-Factor Authentication (2FA)

All projects implement TOTP-based 2FA (RFC 6238 — compatible with Google Authenticator and Authy).

**Setup flow:**
1. Log in as admin.
2. Navigate to **Admin → Security**.
3. Scan the displayed QR code with your authenticator app.
4. Enter the 6-digit code to confirm setup.
5. Save the one-time backup codes shown — each code can only be used once.

In development mode, the TOTP secret is seeded deterministically from the database. In production (P6), the secret is stored in AWS Secrets Manager and rotated every 30 days by a Lambda function.

---

## Stripe Test Cards

| Card Number | Result |
|-------------|--------|
| 4242 4242 4242 4242 | Payment succeeds |
| 4000 0000 0000 9995 | Declined (insufficient funds) |
| 4000 0025 0000 3155 | Requires 3D Secure authentication |

Use any future expiry date (e.g., `12/29`), any 3-digit CVV, and any billing ZIP code.

---

## Project 1 — Local Store
**Repo/Branch:** `cloud-migration-project` → `demo/project-1-local-store`

- **Stack:** Node.js 20 + Express + SQLite (WAL mode), no Redis, no CDN.
- **Local start:** `docker compose up` — app at http://localhost:3000
- **Admin URL:** http://localhost:3000/admin.html
- **JWT secret (dev default):** `dev-secret-change-in-production` (set via `JWT_SECRET` env var)
- **Rate limiting:** in-process memory (resets on restart)

---

## Project 2 — CDN-Enhanced
**Repo/Branch:** `cloud-migration-project` → `demo/project-2-cdn-enhanced`

- **Stack:** Node.js 20 + Express + SQLite + Redis 7 + AWS CloudFront + WAF.
- **Local start:** `docker compose up` — app at http://localhost:3000, Redis at localhost:6379
- **Admin URL:** http://localhost:3000/admin.html
- **JWT secret (dev default):** `dev-secret-change-in-production`
- **CloudFront cookie whitelist:** `__Host-agw_token`

---

## Project 3 — Secure Local
**Repo/Branch:** `cloud-migration-project` → `demo/project-3-secure-local`

- **Stack:** Node.js 20 + Express + SQLite + Redis + full hardening (Helmet, CSP, audit log, JWT blocklist, 2FA).
- **Local start:** `docker compose up` — app at http://localhost:3000
- **Admin URL:** http://localhost:3000/admin.html
- **JWT secret (dev default):** `dev-secret-change-in-production`
- **bcrypt rounds:** 12 (password hashing)
- **2FA:** enabled from first login

---

## Project 4 — Franchise HA
**Repo/Branch:** `cloud-deployment-project` → `demo/project-4-franchise-ha`

- **Stack:** Node.js 20 + PostgreSQL 15 (RDS Multi-AZ) + Redis (ElastiCache) + CloudFront + WAF.
- **Locations:** Portland (PDX, store_id=1) and Seattle (SEA, store_id=2).
- **Local start:** `docker compose up` — app at http://localhost:3000, Postgres at localhost:5432, Redis at localhost:6379
- **Admin URL:** http://localhost:3000/admin.html
- **Local Postgres:** `postgresql://postgres:postgres@localhost:5432/artisangemworks`
- **JWT secret (dev default):** `dev-secret-change-in-production`
- **Location selector:** click the location banner at the top of the page (Portland / Seattle)

---

## Project 5 — Franchise Kubernetes
**Repo/Branch:** `cloud-deployment-project` → `demo/project-5-franchise-k8s`

- **Stack:** P4 stack + EKS 1.29 + ArgoCD GitOps + HPA + PDB + NetworkPolicy.
- **Local start:** `docker compose up` (same ports as P4; EKS features not active locally)
- **Admin URL:** http://localhost:3000/admin.html
- **Production deploy:** triggered by push to `main` via `.github/workflows/deploy.yml`
- **ArgoCD dashboard:** `kubectl port-forward svc/argocd-server -n argocd 8080:443`
- **ArgoCD initial admin password:**
  ```bash
  kubectl get secret argocd-initial-admin-secret -n argocd \
    -o jsonpath="{.data.password}" | base64 -d
  ```

---

## Project 6 — Zero Trust
**Repo/Branch:** `secure-cloud-comms-project` → `demo/project-6-franchise-zerotrust`

- **Stack:** P5 stack + Istio mTLS (STRICT) + Falco + External Secrets Operator + GuardDuty + Security Hub + CloudTrail + IMDSv2.
- **Local start:** `docker compose up` (Istio sidecar not active locally; set `NODE_ENV=development`)
- **Admin URL:** http://localhost:3000/admin.html
- **Production deploy:** `./deploy.sh` (one-time bootstrap); subsequent deploys via ArgoCD auto-sync.

**AWS Secrets Manager paths (production):**

| Path | Keys |
|------|------|
| `artisan-gem-works/production/jwt` | `secret` (rotates every 30 days) |
| `artisan-gem-works/production/database` | `username`, `password`, `host` (rotates every 90 days) |
| `artisan-gem-works/production/redis` | `auth_token`, `host` (rotates every 90 days) |
| `artisan-gem-works/production/stripe` | `secret_key` |

**Useful diagnostic commands:**
```bash
# Live Falco alerts
kubectl logs -n falco -l app.kubernetes.io/name=falco -f

# Confirm mTLS is STRICT
kubectl get peerauthentication -n artisan-gem-works

# Check ExternalSecret sync status
kubectl get externalsecret -n artisan-gem-works

# Tail application logs
kubectl logs -n artisan-gem-works -l app=agw-app -f

# Security Hub findings: AWS Console → Security Hub → Findings
# GuardDuty findings:   AWS Console → GuardDuty → Findings
```

---

## Local Development Quick Start (P4–P6)

```bash
cp .env.example .env          # fill in your values
docker compose up             # starts app + postgres + redis
docker compose exec app node scripts/seed.js  # first run only

# Admin login
# URL:      http://localhost:3000/admin.html
# Email:    admin@artisangemworks.com
# Password: Admin!2024Secure
```
