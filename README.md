# Enterprise Project 6 — Zero-Trust Security Operations Platform
**Author:** Wilton B. Harrison
**Stack:** Terraform · AWS Transit Gateway · Security Hub · OpenSearch · Kinesis · GuardDuty · Lambda · Config
**Tier:** Enterprise Cloud Security Engineer Portfolio Project
**Source Project:** [Project 3 — Secure Cloud-to-Cloud Communication](https://github.com/wbharrison2/Secure-Cloud-Comms-Project)

---

## Overview

This project builds an **enterprise zero-trust security operations center (SecOps)** across multiple VPCs. It evolves Project 3's two-VPC peering pattern into a full hub-and-spoke topology with Transit Gateway, centralized SIEM (OpenSearch), Kinesis log streaming pipeline, continuous compliance (AWS Config), Security Hub consolidated findings, and automated incident response via EventBridge + Lambda.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Zero-Trust Network Perimeter                             │
│                                                                             │
│  Production VPC        Dev VPC         Staging VPC                         │
│  (10.20.0.0/16)       (10.30.0.0/16)  (10.40.0.0/16)                      │
│       │                    │                │                               │
│       └──────────┬─────────┘                │                               │
│                  │              ┌──────────┘                               │
│                  └──────────────┤                                            │
│                           ┌────▼─────────────────────────┐                    │
│                           │  Transit Gateway (Hub)     │                    │
│                           │  - Spoke→Hub routing ONLY  │                    │
│                           │  - No spoke-to-spoke       │                    │
│                           └────┬──────────────────────┘                    │
│                                │                                            │
│                    ┌───────────▼────────────────────────────────┐    │
│                    │  SecOps Hub VPC (10.10.0.0/16)                   │    │
│                    │                                                   │    │
│                    │  ┌─────────────┐  ┌──────────────────────────┐   │    │
│                    │  │  OpenSearch  │  │  Kinesis Firehose         │   │    │
│                    │  │  SIEM        │◄─│  Log Pipeline             │   │    │
│                    │  │ (open-source)│  │  VPC Flow Logs + Trail    │   │    │
│                    │  └─────────────┘  └──────────────────────────┘   │    │
│                    │                                                   │    │
│                    │  ┌─────────────────────────────────────────────┐ │    │
│                    │  │  Security Services (account-wide)           │ │    │
│                    │  │  GuardDuty │ Security Hub │ Config          │ │    │
│                    │  │  CloudTrail (all regions, all events)       │ │    │
│                    │  └─────────────────────────────────────────────┘ │    │
│                    │                                                   │    │
│                    │  ┌─────────────────────────────────────────────┐ │    │
│                    │  │  Automated Incident Response                │ │    │
│                    │  │  GuardDuty HIGH → EventBridge               │ │    │
│                    │  │  → Lambda auto-quarantine → SNS alert       │ │    │
│                    │  └─────────────────────────────────────────────┘ │    │
│                    └───────────────────────────────────────────────────┘    │
│                                                                             │
│  KMS CMK ────────────────────────────────────────────────────────────────► │
│  Encrypts: S3, CloudWatch Logs, OpenSearch, SNS, CloudTrail, Firehose      │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Enterprise Upgrades Over Project 3

| Capability | Project 3 (Baseline) | Enterprise Project 6 |
|---|---|---|
| **Network topology** | 2-VPC peering (peer-to-peer) | 4-VPC Transit Gateway hub-and-spoke |
| **Traffic isolation** | SG rules (CIDR-based) | TGW route tables: spokes cannot reach each other |
| **Log collection** | VPC Flow Logs → CloudWatch | All 4 VPCs + CloudTrail → Kinesis Firehose → OpenSearch |
| **SIEM** | None | OpenSearch (open-source, 2-node HA cluster) |
| **Compliance** | Manual review | AWS Config continuous recording + 6 managed rules |
| **Threat detection** | CloudWatch alarm on rejections | GuardDuty (malware, S3, K8s audit) + Security Hub |
| **Security standards** | Custom | CIS Benchmark 1.4, AWS FSBP, PCI-DSS 3.2.1 |
| **Incident response** | Manual | EventBridge + Lambda auto-quarantine within 60s |
| **Audit trail** | VPC Flow Logs (2 VPCs) | CloudTrail multi-region + data events + Insights |
| **Log enrichment** | Raw logs | Lambda enrichment: account_id, region, timestamp |
| **Encryption** | KMS SSE-KMS (S3 only) | KMS CMK + custom key policy for CW Logs + Firehose |

---

## Prerequisites

| Tool | Version | Source |
|---|---|---|
| Terraform | >= 1.6 | https://developer.hashicorp.com/terraform/install |
| AWS CLI | >= 2.x | https://aws.amazon.com/cli/ |
| Python | >= 3.9 | https://python.org |
| boto3 | latest | `pip install boto3` |
| jq | any | `yum install jq` / `brew install jq` |

---

## Quick Start

```bash
# 1. Navigate to project directory
cd enterprise-project-6-zerotrust-secops

# 2. Initialize Terraform
terraform init

# 3. Preview the security operations infrastructure
terraform plan -out=tfplan

# 4. Deploy (~10-15 min; OpenSearch takes longest)
terraform apply tfplan

# 5. Run the incident response verification script
chmod +x remediate.sh
./remediate.sh --verify --region us-east-1

# 6. Verify OpenSearch SIEM is receiving logs
terraform output opensearch_dashboard_url

# 7. Check Security Hub compliance score
aws securityhub get-findings \
  --filters '{"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}],"SeverityLabel":[{"Value":"CRITICAL","Comparison":"EQUALS"}]}' \
  --region us-east-1 | jq '.Findings | length'

# 8. View GuardDuty findings
aws guardduty list-findings \
  --detector-id $(terraform output -raw guardduty_detector_id) \
  --finding-criteria '{"Criterion":{"severity":{"Gte":7}}}' \
  --region us-east-1

# 9. Open CloudWatch SecOps dashboard
terraform output cw_dashboard
```

---

## Key Learning Outcomes

- AWS Transit Gateway: hub-and-spoke topology replacing VPC peering mesh
- Transit Gateway route tables: enforcing zero spoke-to-spoke traffic without individual rules
- OpenSearch (open-source Elasticsearch): SIEM data ingestion, index management, dashboards
- Kinesis Firehose log pipeline: VPC Flow Logs + CloudTrail → enrichment → OpenSearch
- AWS Config continuous compliance: 6 managed rules with delivery channel
- Security Hub aggregation: CIS Benchmark 1.4, AWS FSBP, PCI-DSS 3.2.1 simultaneously
- GuardDuty advanced configuration: malware scanning, K8s audit, finding publication to S3
- EventBridge + Lambda: automated incident response under 60 seconds
- KMS CMK custom key policies: granting CloudWatch Logs and Firehose encryption access
- CloudTrail Insights: API call rate anomaly detection

---

## Open-Source References

- [AWS Transit Gateway Documentation](https://docs.aws.amazon.com/vpc/latest/tgw/)
- [OpenSearch Documentation](https://opensearch.org/docs/latest/)
- [AWS Security Hub User Guide](https://docs.aws.amazon.com/securityhub/latest/userguide/)
- [AWS Config Managed Rules](https://docs.aws.amazon.com/config/latest/developerguide/managed-rules-by-aws-config.html)
- [GuardDuty User Guide](https://docs.aws.amazon.com/guardduty/latest/ug/)
- [CIS AWS Foundations Benchmark v1.4](https://www.cisecurity.org/benchmark/amazon_web_services)
