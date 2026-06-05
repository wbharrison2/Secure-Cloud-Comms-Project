# Project 6: Artisan Gem Works Franchise — Zero-Trust Security Platform

**Artisan Gem Works** — Fine handcrafted jewelry, Portland and Seattle.

| | |
|---|---|
| **Portland Flagship** | 2847 NW Thurman St, Portland, OR 97210 |
| **Seattle Location** | 412 Pine St, Seattle, WA 98101 |
| **Owner** | Mira Chen |
| **Acquired by** | Meridian Jewelry Group (January 2026) |
| **Website** | https://artisangemworks.com |

## What Changed from Project 5

Project 5 ran on EKS with GitHub Actions + ArgoCD. In January 2026, Artisan Gem Works
was acquired by Meridian Jewelry Group. Meridian’s security team ran a 3-week audit
and found 7 critical security findings. This project implements the required remediations:

| Finding | Severity | Remediation |
|---------|----------|-------------|
| No mTLS between pods | CRITICAL | Istio service mesh, STRICT mode |
| Secrets never rotated | CRITICAL | External Secrets + AWS Secrets Manager |
| No runtime threat detection | CRITICAL | Falco with custom rules |
| No centralized security monitoring | CRITICAL | Security Hub + GuardDuty |
| No EKS audit trail | CRITICAL | CloudTrail + control plane logs |
| No container vulnerability scanning | CRITICAL | Trivy in CI/CD pipeline |
| IMDSv2 not enforced (SSRF risk) | CRITICAL | IMDSv2 + IRSA for pod IAM |

## Security Architecture

```
[Customers]
    │ HTTPS (TLS 1.2+)
    ▼
[CloudFront + WAF]
    │ HTTPS → origin-only
    ▼
[Istio Ingress Gateway]
    │ mTLS (Envoy proxy)
    ▼
[agw-production namespace] ← PeerAuthentication: STRICT mTLS
    │                       ← AuthorizationPolicy: allowlisted sources only
    ├── Pod: agw-app (Envoy sidecar, mTLS on all traffic)
    │   ├── livenessProbe:  GET /api/health
    │   ├── readinessProbe: GET /api/ready (DB + Redis check)
    │   └── Credentials: from External Secrets (AWS Secrets Manager)
    │
    └── Falco DaemonSet (syscall-level runtime monitoring)

[Security & Compliance]
├── AWS Security Hub (findings aggregation: CRITICAL/HIGH auto-alert)
├── AWS GuardDuty (threat intelligence: DNS exfil, unusual API calls)
├── AWS CloudTrail (EKS audit: every kubectl command logged to S3)
├── AWS Config (compliance rules: encryption, logging enabled)
└── Trivy (CI: blocks deploy if CRITICAL CVE found in image)

[Secrets Lifecycle]
AWS Secrets Manager → External Secrets Operator → Kubernetes Secret
    └── JWT_SECRET: rotated every 30 days (auto)
    └── DATABASE_URL: rotated every 90 days (Lambda rotation function)
    └── REDIS_URL: rotated every 90 days
```

## Istio mTLS

All traffic between pods in the `agw-production` namespace is encrypted with mutual TLS.
Pods without a valid Istio certificate cannot communicate with `agw-app`.

```yaml
# PeerAuthentication: enforce mTLS
kind: PeerAuthentication
spec:
  mtls:
    mode: STRICT  # No plaintext allowed

# AuthorizationPolicy: allow only Istio Ingress Gateway
kind: AuthorizationPolicy
spec:
  action: ALLOW
  rules:
    - from:
        - source:
            principals: ["cluster.local/ns/istio-system/sa/istio-ingressgateway-service-account"]
```

## Falco Runtime Security

Falco runs as a DaemonSet on every EKS node, monitoring system calls in real time.
Custom rules detect AGW-specific threats:

| Rule | Trigger | Alert |
|------|---------|-------|
| `agw_shell_in_container` | `bash` or `sh` exec in agw-app pod | CRITICAL |
| `agw_unexpected_outbound` | TCP connection to non-RDS/Redis port | WARNING |
| `agw_write_to_etc` | Write to `/etc` directory | ERROR |
| `agw_read_secrets` | Access to `/proc` filesystem | WARNING |
| `agw_crypto_mining` | CPU > 95% + external network | WARNING |

## External Secrets (Rotation Schedule)

| Secret | AWS Secrets Manager Name | Rotation |
|--------|--------------------------|----------|
| JWT_SECRET | `agw/production/jwt-secret` | 30 days (Lambda) |
| DATABASE_URL | `agw/production/database-url` | 90 days (RDS managed) |
| REDIS_URL | `agw/production/redis-url` | 90 days (Lambda) |
| STRIPE_SECRET_KEY | `agw/production/stripe-key` | Manual |
| CLOUDFRONT_DISTRIBUTION_ID | `agw/production/cloudfront-id` | Static |

External Secrets Operator polls AWS Secrets Manager every 1 hour and automatically
rotates the Kubernetes Secret when the AWS secret version changes.

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /api/health | None | Liveness probe |
| GET | /api/ready | None | Readiness probe (DB + Redis) |
| GET | /api/locations | None | Store locations |
| GET | /api/products | None | Products (location filter) |
| GET | /api/products/:slug | None | Product detail |
| POST | /api/auth/login | None | Login |
| POST | /api/auth/logout | Cookie | Logout |
| GET | /api/auth/me | Cookie | Current user |
| POST | /api/auth/2fa/setup | Cookie+Admin | Setup TOTP |
| POST | /api/auth/2fa/enable | Cookie+Admin | Enable TOTP |
| POST | /api/auth/2fa/disable | Cookie+Admin | Disable TOTP |
| GET | /api/orders | Cookie | User orders |
| POST | /api/orders | Cookie | Place order |
| GET | /api/admin/products | Cookie+Admin | All products |
| POST | /api/admin/products | Cookie+Admin | Create product |
| PUT | /api/admin/products/:id | Cookie+Admin | Update product |
| DELETE | /api/admin/products/:id | Cookie+Admin | Delete product |
| GET | /api/admin/orders | Cookie+Admin | All orders |
| PUT | /api/admin/orders/:id/status | Cookie+Admin | Update order status |
| POST | /api/admin/cache/clear | Cookie+Admin | Clear Redis + CloudFront |
| GET | /api/admin/audit-log | Cookie+Admin | Audit log (paginated) |

## Security Controls (Full Stack)

### Application Layer
- **httpOnly cookies** — JWT never accessible to JavaScript (`__Host-agw_token`)
- **Helmet.js** — X-Frame-Options, HSTS (63072000s), strict CSP
- **Rate limiting** — 200 req/15min API, 5 req/15min auth/admin
- **TOTP 2FA** — RFC 6238 admin authentication
- **Redis JWT blocklist** — session revocation on logout
- **bcryptjs rounds=12** — password hashing

### Network Layer
- **Istio mTLS STRICT** — all pod-to-pod traffic encrypted
- **Istio AuthorizationPolicy** — allowlist-only ingress to agw-app
- **Kubernetes NetworkPolicy** — pod-level egress restrictions
- **WAF** — OWASP CRS + IP rate limit 2000/IP (CloudFront scope)

### Infrastructure Layer
- **External Secrets + AWS Secrets Manager** — automatic rotation
- **IMDSv2** — enforced on all EKS nodes (no SSRF credential theft)
- **IRSA** — pod-level IAM (no node-level credential access)
- **Trivy CI scan** — blocks deploy on CRITICAL CVEs

### Monitoring & Response
- **Falco** — runtime syscall threat detection
- **AWS GuardDuty** — DNS exfiltration, unusual API calls, port scanning
- **AWS Security Hub** — CRITICAL/HIGH findings → SNS → PagerDuty
- **AWS CloudTrail** — every Kubernetes API call logged (90-day retention, S3)
- **AWS Config** — compliance rules, drift detection

## Local Development

```bash
cp .env.example .env
# Edit .env with your values
docker-compose up -d
# App:   http://localhost:3000
# Admin: http://localhost:3000/admin.html
```

## Demo Credentials

See `PRIVATE-ADMIN-GUIDE.md` for all credentials.

| Role | Email | Password |
|------|-------|----------|
| Admin | admin@artisangemworks.com | Admin!2024Secure |
| Customer | customer@demo.com | Customer!2024Demo |

**Note**: In production, credentials are managed by AWS Secrets Manager and rotated
automatically. The credentials above are for local development and demo only.

**Stripe Test Cards**: `4242 4242 4242 4242` (success), `4000 0000 0000 9995` (decline)
