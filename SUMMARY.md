# SUMMARY — Project 3: Secure Cloud-to-Cloud Communication

**Author:** Wilton B. Harrison  
**Date:** 2026  
**Classification:** Portfolio / Professional Development

---

## What This Project Does

Project 3 builds a **zero-trust encrypted communication channel between two isolated AWS VPCs** — simulating the security architecture required when separate cloud environments need to share data without public internet exposure. A Production VPC (VPC A) securely forwards encrypted security event logs to a Security Operations VPC (VPC B) using VPC Peering, AWS KMS encryption, IAM role assumption via STS, and strict security group enforcement.

Nothing is accessible from the public internet. Every byte is encrypted. Every access requires explicit IAM authorization. Every packet is logged.

---

## Why It Matters for Cloud Security Engineering Roles

This project addresses the **hardest problem in enterprise cloud security**: how do you connect systems that need to communicate, without introducing attack surface? It demonstrates:

- **Zero Trust network design** — deny all by default, explicit allow only at the CIDR and port level
- **End-to-end encryption** — KMS customer-managed keys for at-rest, HTTPS enforcement for in-transit
- **Identity-based access** — IAM roles and STS AssumeRole instead of network-based trust
- **Full observability** — VPC Flow Logs capture every packet, CloudWatch alarms on anomalies
- **Confusion-resistant IAM** — ExternalId condition prevents confused deputy attacks

This is the pattern used in regulated industries (healthcare, defense, finance) where data must cross environment boundaries without violating compliance boundaries.

---

## NIST 800-53 Controls Addressed

| Control | Description | Implementation |
|---|---|---|
| SC-8 | Transmission Confidentiality | VPC Peering + HTTPS-only S3 policy |
| SC-28 | Protection of Information at Rest | KMS SSE-KMS on S3 + CloudWatch Logs |
| SC-7 | Boundary Protection | Security Groups (deny-all + explicit allow) |
| AU-9 | Protection of Audit Information | KMS-encrypted, versioned flow logs |
| AC-6 | Least Privilege | IAM policy scoped to single S3 prefix |
| SI-7 | Software & Information Integrity | SHA-256 hash verification post-upload |
| CA-7 | Continuous Monitoring | CloudWatch alarm on rejected traffic |

---

## Architecture Decision Highlights

| Decision | Rationale |
|---|---|
| VPC Peering over VPN/internet | Lower latency, no encryption overhead, fully private AWS backbone |
| STS AssumeRole with ExternalId | Prevents third-party confused deputy — required in multi-tenant environments |
| KMS auto-rotation enabled | Limits key compromise blast radius — industry standard |
| Flow logs on ALL traffic | ACCEPT-only logs miss rejected probes — critical for threat detection |
| S3 DenyNonHTTPS policy | Blocks any misconfigured client using HTTP — data exposure prevention |
| Versioned S3 bucket | Tamper detection + recovery — required for log integrity in compliance audits |

---

## Tools & Open-Source Stack

| Tool | Role | License |
|---|---|---|
| Terraform | Infrastructure provisioning | MPL 2.0 |
| AWS KMS | Envelope encryption | N/A (AWS managed) |
| Python 3 | Log forwarder application | PSF |
| Boto3 | AWS API (STS, S3, KMS) | Apache 2.0 |
| AWS VPC | Network isolation layer | N/A (AWS managed) |
| CloudWatch | Log storage + alerting | N/A (AWS managed) |

---

## Skills Demonstrated

`VPC Peering` · `Zero Trust Network Design` · `AWS KMS` · `Customer-Managed Keys` · `Key Rotation` · `IAM STS AssumeRole` · `ExternalId Condition` · `Least-Privilege IAM` · `VPC Flow Logs` · `CloudWatch Alarms` · `S3 Bucket Policies` · `SSE-KMS Encryption` · `HTTPS Enforcement` · `SHA-256 Integrity Verification` · `Python Boto3` · `NIST 800-53 Mapping` · `Cross-Environment Security Architecture`
