# ADR-0003: AWS Security Hub for Centralized Security Monitoring

**Date**: 2026-02-17  
**Status**: Accepted  
**Deciders**: Mira Chen, senior developer, Meridian security team

## Context

CRITICAL-004 requires centralized security monitoring with automated alerting
for critical and high severity findings. CRITICAL-005 requires audit trail
retention with 1-year minimum. Meridian also requires compliance reporting
against CIS and PCI DSS standards.

## Decision

Enable AWS Security Hub with CIS AWS Foundations Benchmark and PCI DSS standards.
Enable AWS GuardDuty as the primary threat detection source. Forward findings
to SNS → PagerDuty for CRITICAL/HIGH severity. Store audit logs in S3 for
1-year retention.

## Options Considered

### Option A: Datadog

**Pros**: Excellent dashboards, APM integration, log management, unified platform

**Cons**: High cost (~$800/month at AGW’s scale), requires separate log shipper
agent on every node, Meridian uses AWS-native tools

**Rejected**: Cost and Meridian standardization.

### Option B: Elastic SIEM (self-hosted)

**Pros**: Full control, no vendor lock-in, powerful KQL queries

**Cons**: Requires running and maintaining Elasticsearch cluster, significant
ops burden, indexing costs, Meridian doesn’t run Elasticsearch

**Rejected**: Operational complexity.

### Option C: AWS Security Hub + GuardDuty + CloudTrail

**Pros**: Native AWS integration (no agents beyond GuardDuty),
GuardDuty analyzes VPC Flow Logs, DNS logs, CloudTrail events automatically
(no manual log shipping), Security Hub aggregates findings from GuardDuty,
Config, Inspector, and Falco (via custom provider), compliance standards
built-in (CIS, PCI DSS, AWS Foundational), Meridian already uses Security Hub
across their portfolio

**Cons**: AWS-only (acceptable for AGW), finding format less flexible than Datadog,
no APM or business metrics (use CloudWatch for those)

**Accepted**.

## Alert Routing

```
Finding Sources:
├── GuardDuty (threat intelligence)
├── AWS Config (compliance drift)
├── Falco → CloudWatch → Lambda → Security Hub (runtime threats)
└── Inspector (container CVEs)
         │
         ▼
    Security Hub
         │
    EventBridge Rule: severity = CRITICAL or HIGH
         │
         ▼
        SNS Topic
         │
    PagerDuty (on-call rotation)
```

## Consequences

**Positive**:
- Single pane of glass for all security findings
- GuardDuty threat detection requires no agents (uses existing VPC/DNS/CloudTrail data)
- CIS and PCI DSS compliance scores visible at a glance
- Meridian security team can access findings across all acquired companies

**Negative**:
- GuardDuty cost: ~$30/month for AGW’s VPC/DNS/CloudTrail volume
- Security Hub cost: ~$20/month for checks across resources
- False positives from GuardDuty require tuning (suppression rules)
