# Project 6 Summary

## Problem

Following acquisition by Meridian Jewelry Group in January 2026, a third-party
security audit found 7 critical vulnerabilities in the EKS platform (Project 5):
plaintext pod-to-pod traffic, never-rotated secrets, no runtime threat detection,
no centralized security monitoring, no audit trail, no vulnerability scanning,
and SSRF-exploitable instance metadata access.

## Solution

Implemented a zero-trust security platform: Istio mTLS STRICT (encrypted pod
communication), External Secrets with automatic rotation (no long-lived credentials),
Falco DaemonSet (runtime threat detection), Security Hub + GuardDuty (centralized
monitoring), CloudTrail EKS audit logging, Trivy in CI/CD (blocks on CRITICAL CVEs),
and IMDSv2 enforcement with IRSA.

## Before vs. After

| Dimension | Project 5 (EKS+ArgoCD) | Project 6 (Zero-Trust) |
|-----------|------------------------|------------------------|
| **Pod-to-pod traffic** | Plaintext | mTLS STRICT (Istio) |
| **Secret rotation** | Never | 30–90 days (AWS Secrets Manager) |
| **Runtime detection** | None | Falco (syscall-level) |
| **Threat intelligence** | None | GuardDuty (DNS, VPC, CloudTrail) |
| **Security findings** | Siloed | Security Hub (aggregated) |
| **K8s audit trail** | None | CloudTrail + control plane logs |
| **CVE scanning** | None | Trivy (blocks CRITICAL) |
| **Instance metadata** | IMDSv1 (SSRF risk) | IMDSv2 + IRSA |
| **Pod network auth** | NetworkPolicy only | + AuthorizationPolicy (Istio) |
| **Ingress** | NGINX Ingress | Istio Gateway + VirtualService |
| **Compliance** | None | CIS + PCI DSS (Security Hub) |
| **Incident response** | Manual, ad-hoc | SNS → PagerDuty (CRITICAL auto-alert) |

## Security Findings Resolution

| Finding | Status | Implementation |
|---------|--------|----------------|
| CRITICAL-001: No mTLS | ✓ Closed | Istio STRICT mode |
| CRITICAL-002: Never-rotated secrets | ✓ Closed | External Secrets + Secrets Manager |
| CRITICAL-003: No runtime detection | ✓ Closed | Falco DaemonSet |
| CRITICAL-004: No security monitoring | ✓ Closed | Security Hub + GuardDuty |
| CRITICAL-005: No audit trail | ✓ Closed | CloudTrail + EKS control plane logs |
| CRITICAL-006: No CVE scanning | ✓ Closed | Trivy in CI/CD |
| CRITICAL-007: IMDSv1 SSRF | ✓ Closed | IMDSv2 + IRSA |

## Additional Finding (Discovered During Remediation)

Falco detected a rogue process on Day 1 of deployment: a transitive npm
dependency (`agw-analytics-helper`) phoning home to an external IP. This
would have been undetectable without runtime monitoring. Removed, CVE filed.

## Architecture Diagram

```
[Customers]
    │ HTTPS
[CloudFront + WAF]
    │ HTTPS
[Istio Ingress Gateway]
    │ mTLS
[agw-production] PeerAuthentication: STRICT
    ├── agw-app Pod (Envoy sidecar)
    └── Falco (DaemonSet, syscall monitor)

[Secrets] AWS Secrets Manager → External Secrets → K8s Secret
[Security] GuardDuty + Security Hub + CloudTrail → SNS → PagerDuty
[CI/CD] GitHub Actions + Trivy scan + ArgoCD
```

## Audit Outcome

Meridian re-assessment on March 14, 2026: **All 7 findings closed**.
Security posture: **Satisfactory**. Acquisition integration proceeded.
