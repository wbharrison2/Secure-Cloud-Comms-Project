# Changes: Project 5 → Project 6

This document describes what changed from the EKS+ArgoCD platform (Project 5)
to the Zero-Trust security platform (Project 6), implementing remediations for
7 critical findings from the Meridian Jewelry Group acquisition audit.

## Change 1: No mTLS → Istio Service Mesh (STRICT mTLS)

**Finding addressed**: CRITICAL-001 (plaintext pod-to-pod traffic)

**What changed**: Installed Istio service mesh. All pods in `agw-production`
namespace have Envoy sidecar injected automatically. PeerAuthentication set to
STRICT mode: only mTLS-authenticated traffic is accepted. AuthorizationPolicy
allows only the Istio Ingress Gateway to reach `agw-app` pods.

**Files added**: `istio/peer-authentication.yaml`, `istio/authorization-policy.yaml`,
`istio/gateway.yaml`, `istio/virtual-service.yaml`

**Files changed**: `k8s/deployment.yaml` (Istio annotations + preStop hook for
graceful Envoy shutdown), `k8s/namespace.yaml` (istio-injection label)

## Change 2: kubectl Secrets → External Secrets + AWS Secrets Manager

**Finding addressed**: CRITICAL-002 (long-lived, never-rotated secrets)

**What changed**: Replaced manually-created Kubernetes secrets with External
Secrets Operator. All credentials are stored in AWS Secrets Manager with
automatic rotation (JWT_SECRET: 30 days, DB/Redis: 90 days). The Kubernetes
secret is automatically updated when the AWS secret version changes.

**Files added**: `external-secrets/secret-store.yaml`,
`external-secrets/external-secret.yaml`

**Files changed**: `k8s/secret.yaml` (replaced with ExternalSecret reference)

## Change 3: No Runtime Detection → Falco DaemonSet

**Finding addressed**: CRITICAL-003 (no runtime threat detection)

**What changed**: Deployed Falco as a Kubernetes DaemonSet on all nodes.
Custom rules detect: shell execution in agw-app containers, unexpected outbound
connections, writes to sensitive directories, access to /proc filesystem.
Alerts forwarded to CloudWatch Logs and Security Hub.

**Files added**: `falco/falco-values.yaml`, `falco/custom-rules.yaml`

## Change 4: No Monitoring → Security Hub + GuardDuty + CloudTrail

**Finding addressed**: CRITICAL-004 + CRITICAL-005

**What changed**: Enabled AWS GuardDuty (threat intelligence across DNS, VPC
Flow Logs, CloudTrail). Configured AWS Security Hub with CIS AWS Foundations
and PCI DSS standards. CloudTrail enabled for all management events including
EKS Kubernetes API calls. Retention: 90 days in CloudWatch, 1 year in S3.

**Files added**: `terraform/security.tf` (GuardDuty, Security Hub, CloudTrail,
Config rules, SNS alert topic)

## Change 5: No Vulnerability Scanning → Trivy in CI/CD

**Finding addressed**: CRITICAL-006 (no container vulnerability scanning)

**What changed**: Added Trivy scan step to GitHub Actions pipeline, after
build and before push to ECR. If any CRITICAL CVE is found, the pipeline
fails and the image is not deployed. HIGH CVEs generate a warning comment
on the PR but do not block.

**Files changed**: `.github/workflows/deploy.yml` (Trivy scan step added)

## Change 6: IMDSv1 → IMDSv2 + IRSA

**Finding addressed**: CRITICAL-007 (SSRF via IMDSv1)

**What changed**: EKS managed node groups now have `http_tokens = required`
(IMDSv2). Pods that need AWS API access use IRSA (IAM Roles for Service
Accounts) — a pod-specific IAM role bound via service account annotation,
not inherited from the node role. The node role has had all non-essential
policies removed.

**Files changed**: `terraform/main.tf` (node group metadata options),
`k8s/service-account.yaml` (IRSA annotation)

## Change 7: Kubernetes Ingress → Istio Gateway + VirtualService

**What changed**: Replaced NGINX Ingress with Istio Ingress Gateway. TLS
termination handled by Istio Gateway using ACM certificate via AWS integration.
VirtualService defines routing rules and traffic policies (retries, timeouts).

**Files added**: `istio/gateway.yaml`, `istio/virtual-service.yaml`

**Files removed**: `k8s/ingress.yaml` (replaced by Istio resources)

## Change 8: Graceful Istio Shutdown

**What changed**: Added `preStop` lifecycle hook to the agw-app deployment.
When a pod is terminated, Istio’s Envoy sidecar stops accepting new
connections. Without the preStop hook, the application container may exit
before Envoy has drained in-flight requests.

```yaml
lifecycle:
  preStop:
    exec:
      command: ["/bin/sh", "-c", "sleep 5"]
```

**Files changed**: `k8s/deployment.yaml`
