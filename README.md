# Project 3 — Secure Cloud-to-Cloud Communication
**Author:** Wilton B. Harrison  
**Stack:** Terraform · AWS VPC Peering · KMS · IAM STS · Python · Boto3  
**Tier:** Cloud Security Engineer Portfolio Project

---

## Overview

This project establishes **encrypted, authenticated, zero-trust communication between two isolated AWS VPCs** — simulating secure connectivity between a production environment (VPC A) and a security operations center (VPC B). No traffic traverses the public internet. All data is encrypted at rest and in transit using AWS KMS. All cross-VPC access is controlled via IAM role assumption with ExternalId conditions.

This pattern is used in real enterprises to connect separate cloud environments, business units, accounts, or compliance zones without exposing sensitive data to public routing.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                    AWS Account (Single Region)                        │
│                                                                      │
│   VPC A — PRODUCTION (10.10.0.0/16)                                 │
│   ┌──────────────────────────────────┐                              │
│   │  Private Subnet 10.10.1.0/24     │                              │
│   │  ┌───────────────────────────┐   │                              │
│   │  │ EC2 / ECS Production App  │   │                              │
│   │  │  - Runs secure_log_       │   │                              │
│   │  │    forwarder.py           │   │                              │
│   │  │  - Assumes cross-VPC role │   │                              │
│   │  │  - Sends KMS-encrypted    │   │                              │
│   │  │    logs via VPC Peering   │   │                              │
│   │  └───────────────────────────┘   │                              │
│   │  SG: allow egress 5044/443       │                              │
│   │       to VPC B CIDR only         │                              │
│   └────────────┬─────────────────────┘                              │
│                │                                                     │
│         VPC Peering Connection                                       │
│         (private, no internet)                                       │
│         VPC Flow Logs → CloudWatch                                   │
│                │                                                     │
│   VPC B — SECURITY OPERATIONS (10.20.0.0/16)                       │
│   ┌──────────────────────────────────┐                              │
│   │  Private Subnet 10.20.1.0/24     │                              │
│   │  SG: allow ingress 5044/443      │                              │
│   │       from VPC A CIDR only       │                              │
│   │                                  │                              │
│   │  ┌───────────────────────────┐   │                              │
│   │  │ S3 SecOps Log Bucket      │   │                              │
│   │  │  - KMS SSE-KMS encrypted  │   │                              │
│   │  │  - HTTPS-only policy      │   │                              │
│   │  │  - Versioned              │   │                              │
│   │  │  - 90-day flow log audit  │   │                              │
│   │  └───────────────────────────┘   │                              │
│   └──────────────────────────────────┘                              │
│                                                                      │
│   ┌──────────────────────────────────┐                              │
│   │  KMS Key (alias/wbh-secure-comms)│                              │
│   │  - AES-256, auto-rotation ON     │                              │
│   │  - Encrypts: S3, CloudWatch Logs │                              │
│   └──────────────────────────────────┘                              │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Security Controls — Defense in Depth

| Layer | Control | Implementation |
|---|---|---|
| **Network** | VPC Peering (no public internet) | `aws_vpc_peering_connection` |
| **Network** | Zero Trust SGs (deny all by default) | Explicit ingress/egress CIDR rules only |
| **Network** | VPC Flow Logs (ALL traffic) | CloudWatch Logs, 90-day KMS-encrypted retention |
| **Identity** | STS AssumeRole with ExternalId | Prevents confused deputy attacks |
| **Identity** | Least-privilege IAM policy | Only `s3:PutObject` to specific prefix |
| **Data at Rest** | KMS SSE-KMS on S3 | AES-256, customer-managed, auto-rotate |
| **Data in Transit** | S3 HTTPS-only bucket policy | `aws:SecureTransport: false → Deny` |
| **Data in Transit** | VPC Peering (private AWS backbone) | Never traverses public internet |
| **Integrity** | SHA-256 hash in S3 metadata | Verifies payload integrity post-upload |
| **Monitoring** | CloudWatch alarm on rejected traffic | Detects lateral movement / misconfiguration |
| **Audit** | S3 object versioning | Full log history, tamper evidence |

---

## Components

| Resource | Description |
|---|---|
| `aws_kms_key` | Customer-managed encryption key, auto-rotation enabled |
| `aws_vpc` (x2) | Production and SecOps VPCs, fully isolated |
| `aws_vpc_peering_connection` | Private encrypted channel between VPCs |
| `aws_route` (x2) | Bidirectional routing through peering only |
| `aws_security_group` (x2) | Zero Trust SGs — deny all, explicit CIDR allows |
| `aws_flow_log` (x2) | ALL traffic captured to CloudWatch (KMS encrypted) |
| `aws_iam_role` | Cross-VPC role with ExternalId + least-privilege policy |
| `aws_s3_bucket` | SecOps log bucket: KMS, HTTPS-only, versioned, private |
| `aws_cloudwatch_metric_alarm` | Alert on rejected traffic spikes |

---

## Prerequisites

| Tool | Source |
|---|---|
| Terraform >= 1.6 | https://developer.hashicorp.com/terraform/install |
| AWS CLI >= 2.x | https://aws.amazon.com/cli/ |
| Python >= 3.9 | https://python.org |
| boto3, cryptography | `pip install boto3 cryptography` |

---

## Quick Start

```bash
# 1. Deploy infrastructure
cd project3-secure-cloud-comms
terraform init
terraform plan -out=tfplan
terraform apply tfplan

# 2. Get outputs
terraform output

# 3. Run the secure log forwarder (from a VPC A workload)
python secure_log_forwarder.py \
  --role-arn $(terraform output -raw cross_vpc_role_arn) \
  --bucket   $(terraform output -raw secops_log_bucket) \
  --kms-key-id $(terraform output -raw kms_key_id) \
  --verify

# 4. Verify logs arrived in SecOps bucket
aws s3 ls s3://$(terraform output -raw secops_log_bucket)/prod-logs/ --recursive

# 5. Check VPC Flow Logs for traffic evidence
aws logs describe-log-streams \
  --log-group-name /aws/vpc/wbh-secure-comms/vpc-a/flow-logs
```

---

## Key Learning Outcomes

- VPC Peering: private cross-VPC routing without internet exposure
- KMS customer-managed keys: creation, rotation, key policies
- IAM STS AssumeRole with ExternalId (confused deputy prevention)
- Least-privilege IAM policies scoped to S3 key prefixes
- VPC Flow Logs for full traffic audit and threat detection
- S3 bucket policies enforcing HTTPS-only access
- SHA-256 integrity verification for data in transit
- CloudWatch alarms for anomaly detection on network reject events

---

## Open-Source References

- [AWS VPC Peering Guide](https://docs.aws.amazon.com/vpc/latest/peering/what-is-vpc-peering.html)
- [AWS KMS Developer Guide](https://docs.aws.amazon.com/kms/latest/developerguide/)
- [STS AssumeRole ExternalId Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html)
- [VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
- [S3 Security Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
- [NIST 800-53 SC Family (System & Comms Protection)](https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_0/home)
