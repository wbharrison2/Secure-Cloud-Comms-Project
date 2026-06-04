# Enterprise Project 6 — Executive Summary
## Zero-Trust Security Operations Platform

**Author:** Wilton B. Harrison | **Stack:** Terraform · AWS Security · OpenSearch · Python | **Based on:** Project 3

---

## What This Project Proves

This project demonstrates the ability to architect and deploy an **enterprise-grade Security Operations Center (SecOps)** using zero-trust principles, open-source SIEM, automated threat response, and multi-standard compliance.

---

## Before vs. After

| | Project 3 (Baseline) | Enterprise Project 6 |
|---|---|---|
| **Network topology** | 2-VPC peering | 4-VPC Transit Gateway hub-and-spoke |
| **Environments monitored** | 2 | 4 (production + dev + staging + hub) |
| **Log destination** | CloudWatch | OpenSearch SIEM (full-text searchable) |
| **Log pipeline** | Direct write | Kinesis Firehose with Lambda enrichment |
| **Audit trail** | VPC Flow Logs only | CloudTrail (all events) + Flow Logs (all 4 VPCs) |
| **Compliance checks** | None | AWS Config 6 managed rules (continuous) |
| **Security standards** | Custom | CIS 1.4 + AWS FSBP + PCI-DSS 3.2.1 |
| **Threat detection** | 1 CloudWatch alarm | GuardDuty (malware, K8s, S3) + Security Hub |
| **Incident response** | Manual (email alert) | Automated Lambda quarantine in < 60 seconds |
| **Monitoring type** | Passive only | Passive (SIEM/dashboards) + Active (auto-response) |

---

## Architecture Decision Highlights

1. **Transit Gateway over peering mesh** — 4 VPCs with peering requires 6 connections; TGW requires 4 and enforces hub-only routing
2. **OpenSearch over CloudWatch Logs Insights** — open-source, richer query capabilities, Kibana-compatible dashboards, no per-query cost
3. **Kinesis Firehose with Lambda enrichment** — enriches logs before storage; prevents retroactive enrichment issues during incidents
4. **Security Hub 3 standards simultaneously** — CIS + FSBP + PCI-DSS gives comprehensive coverage across compliance frameworks
5. **Auto-rotation KMS CMK** — meets NIST 800-57 recommendation for annual key rotation without manual scheduling

---

## Open-Source Tools Used

| Tool | License | Purpose |
|---|---|---|
| Terraform >= 1.6 | MPL-2.0 | Infrastructure as code |
| OpenSearch 2.11 | Apache-2.0 | Open-source SIEM and log analytics |
| Python 3.12 (Lambda) | PSF | Log enrichment + incident response |
| AWS Provider >= 5.0 | MPL-2.0 | AWS resource management |

*Estimated cost: ~$100-200/month (OpenSearch t3.small × 2 nodes is largest cost driver).*
