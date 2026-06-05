# Project 6 Scenario: The Acquisition Audit That Found Everything

## Business Context

By late 2025, Artisan Gem Works had grown from a single Portland shop to a
two-location franchise running a modern Kubernetes platform. The business was
profitable, the platform was stable, and deployments took 8 minutes.

In December 2025, Meridian Jewelry Group — a Pacific Northwest luxury goods
holding company — approached Mira with an acquisition offer. After six weeks
of negotiation, AGW was acquired in January 2026.

As part of the acquisition agreement, Meridian required a security audit of all
AGW systems before integration into Meridian’s infrastructure.

## The Audit: January 20–40, 2026

Meridian’s security team (Apex Security Partners) spent three weeks auditing:
- AWS account configuration
- EKS cluster security posture
- Application security controls
- Secret management practices
- Network segmentation
- Monitoring and incident response

### January 20 — Kickoff

Mira had been proud of the platform. ECS to EKS migration, automated CI/CD,
HPA, PodDisruptionBudget. She expected the audit to be a formality.

By day three, Apex had flagged the first critical finding.

## The 7 Critical Findings

### CRITICAL-001: No Mutual TLS Between Services

**Finding**: All traffic between pods in the EKS cluster is plaintext. A
compromised pod can run `tcpdump` on the network interface and capture all
API responses, database queries, and JWT tokens from other pods.

**Proof of concept**: Apex deployed a test pod with `tcpdump`, captured 3
minutes of traffic, and extracted:
- 14 valid JWT tokens from HTTP responses
- 2 PostgreSQL query results containing customer email addresses
- The Redis AUTH password from connection initiation

**Required fix**: Service mesh with mTLS STRICT mode by February 28, 2026.

### CRITICAL-002: Long-Lived, Never-Rotated Secrets

**Finding**: JWT_SECRET has been the same value since June 2024 (604 days).
DATABASE_URL credentials have never been rotated. The Redis auth token was
set at initial deployment and never changed.

**Risk**: Any historical log, CI artifact, or developer workstation that
captained these credentials remains a valid attack vector indefinitely.
Meridian’s security policy requires rotation every 30–90 days.

**Evidence**: Apex found the original JWT_SECRET value in a GitHub Actions
log artifact from September 2024 that had not been purged.

**Required fix**: External secrets management with automatic rotation.

### CRITICAL-003: No Runtime Threat Detection

**Finding**: There is no mechanism to detect if a running container is
executing unexpected system calls. Container escape attempts, privilege
escalation, and crypto mining activity would go completely undetected.

**Proof of concept**: Apex exec’d into the `agw-app` pod, ran `apt-get` to
install `nmap`, scanned the internal VPC network, and connected to the RDS
postgres port. None of this activity was logged or alerted.

**Required fix**: Falco DaemonSet with custom rules.

### CRITICAL-004: No Centralized Security Monitoring

**Finding**: AWS GuardDuty is not enabled. AWS Security Hub has never been
configured. VPC Flow Logs are disabled. DNS query logs are disabled.
There is no SIEM, no centralized log analysis, no alerting for security events.

**Impact**: If AGW’s AWS account were compromised, the team would have no
way to detect it until customers complained or data appeared online.

**Required fix**: GuardDuty + Security Hub + CloudWatch Logs.

### CRITICAL-005: No EKS Audit Trail

**Finding**: EKS control plane logging is disabled. No record is kept of:
- Which user ran which `kubectl` command
- When secrets were accessed or modified
- When pods were created, deleted, or exec’d into
- RBAC changes

Meridian’s compliance requirements (SOC 2 Type II) mandate audit trails
for all privileged operations with 1-year retention.

**Required fix**: EKS control plane logs + CloudTrail with S3 retention.

### CRITICAL-006: No Container Vulnerability Scanning

**Finding**: Docker images are built and deployed without scanning for
known CVEs. The current production `agw-app` image was found to contain:
- 1 CRITICAL CVE in an npm dependency (prototype pollution)
- 3 HIGH CVEs in the base node:20-alpine image

**Risk**: Known exploitable vulnerabilities are running in production.

**Required fix**: Trivy scan in CI/CD pipeline; block on CRITICAL severity.

### CRITICAL-007: IMDSv2 Not Enforced (SSRF Risk)

**Finding**: EKS nodes use IMDSv1 (no token required for instance metadata
access). Any pod that can make an HTTP request to 169.254.169.254 can
retrieve the node’s IAM role credentials. The node role has
`AmazonEC2ContainerRegistryReadOnly` access.

**Proof of concept**:
```bash
# From inside any pod:
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/agw-eks-node-role
# Returns: AccessKeyId, SecretAccessKey, Token
```
With these credentials, an attacker could pull any ECR image, enumerate S3
buckets, and potentially pivot to other AWS services.

**Required fix**: IMDSv2 enforcement + IRSA for pod-level IAM.

## Mira’s Response

On February 3, after receiving the final audit report, Mira wrote:

> “I thought we were secure. Helmet, rate limiting, 2FA, HTTPS everywhere,
> WAF. But the audit showed we were only securing the front door while the
> internal network was completely open. A compromised package in any npm
> dependency could have extracted every customer’s order, every JWT, every
> credential, and we would never have known.
>
> This is what secure actually looks like. We needed to hear it.”

## Remediation Timeline

| Week | Work |
|------|------|
| Week 1 (Feb 3–7) | Istio installation, PeerAuthentication STRICT, AuthorizationPolicy |
| Week 2 (Feb 10–14) | External Secrets Operator, AWS Secrets Manager, credential rotation |
| Week 3 (Feb 17–21) | Falco DaemonSet, custom rules, GuardDuty + Security Hub |
| Week 4 (Feb 24–28) | CloudTrail EKS logs, Trivy CI integration, IMDSv2 enforcement |
| Week 5 (Mar 3–7) | IRSA for pod IAM, Config rules, testing |
| Week 6 (Mar 10–14) | Audit re-assessment, all 7 findings closed |

## Apex Re-Assessment: March 14, 2026

Apex Security Partners returned for a 3-day re-assessment.

**All 7 findings closed.**

New security posture assessment: **Satisfactory**.

Meridian integration proceeded on schedule. Mira kept her role as AGW
brand director.

Extra finding uncovered during remediation: the Falco DaemonSet caught a
rogue process on day 1 of deployment — an npm package (`agw-analytics-helper`)
that had been silently phoning home to an external IP. It had been installed
as a transitive dependency 4 months earlier and never caught. Removed the
package. Filed a CVE report.
