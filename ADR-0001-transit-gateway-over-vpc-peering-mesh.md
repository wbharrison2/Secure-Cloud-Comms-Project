# ADR-0001: AWS Transit Gateway Over Full-Mesh VPC Peering

**Status:** Accepted
**Date:** 2026-06-04
**Author:** Wilton B. Harrison
**Project:** Enterprise Project 6 — Zero-Trust Security Operations Platform

---

## Context

Project 3 (Secure Cloud-to-Cloud Communication) established secure connectivity between two VPCs using VPC Peering. This project extends that pattern to four VPCs: SecOps Hub, Production, Development, and Staging.

When scaling beyond two VPCs, the choice of connectivity mechanism has significant operational and security implications. Two architectural options exist:

1. **Full-mesh VPC Peering** — direct peer-to-peer connections between each pair of VPCs
2. **Transit Gateway Hub-and-Spoke** — all VPCs connect to a central TGW; routing is centrally controlled

---

## Decision

**Use AWS Transit Gateway with a hub-and-spoke topology.** The SecOps Hub VPC is the hub. Production, Development, and Staging are spokes. Two separate Transit Gateway route tables enforce that spokes can only reach the hub — not each other.

---

## Rationale

### Scaling complexity

With N VPCs, full-mesh peering requires N×(N-1)/2 peering connections and N×(N-1) sets of route table entries:
- 4 VPCs: 6 peering connections, 12 route table entries
- 6 VPCs: 15 peering connections, 30 route table entries
- 10 VPCs: 45 peering connections, 90 route table entries

Transit Gateway requires N attachments (one per VPC) and N route table entries per route table. For 10 VPCs: 10 attachments, ~20 route table entries total. The growth is linear rather than quadratic.

### Zero-trust spoke isolation

The core security requirement of this project is that environments cannot accidentally or intentionally communicate with each other — only with the SecOps Hub. Full-mesh peering requires explicit security group rules and routing decisions to prevent cross-spoke communication; mistakes lead to data leakage between Production and Development.

Transit Gateway's route tables make this architecturally impossible: the spoke route table contains only one route (to the Hub CIDR). There is no route that would allow Production to reach Development, even if an administrator accidentally misconfigures a security group.

### Centralized routing control

Transit Gateway is a single control plane for all routing changes. Adding a new VPC means adding one attachment and one route table entry per route table. With full-mesh peering, adding one new VPC means adding N peering connections and updating every existing VPC's route tables.

### Project 3 compatibility

The hub-and-spoke TGW pattern is a direct evolution of Project 3's two-VPC peering concept. Project 3 showed point-to-point secure connectivity. This project shows the enterprise generalization: centralized hub, controlled spoke routing, zero spoke-to-spoke traffic. The security principles (KMS encryption, IAM ExternalId, HTTPS-only S3 policies, flow logs) are preserved and extended.

---

## Positive Consequences

- Spoke-to-spoke isolation is architecturally enforced, not policy-dependent
- Adding a fifth VPC requires 1 attachment + 2 route table entries (not N new peering connections)
- Single pane of glass for all inter-VPC routing in the AWS console
- TGW VPC Flow Logs capture cross-VPC traffic at the transit layer
- TGW supports future expansion to Direct Connect and VPN without re-architecting

---

## Negative Consequences / Trade-offs

- **Cost:** Transit Gateway charges $0.05/attachment-hour (~$36/month for 4 VPCs) plus $0.02/GB of data processed. VPC Peering costs only per data transfer.
- **Latency:** Transit Gateway adds ~1ms of latency vs. VPC Peering's direct path. Negligible for SecOps log forwarding.
- **Complexity:** TGW with separate hub and spoke route tables with explicit propagation and association is more complex to reason about than simple VPC Peering.

---

## OpenSearch vs. Elasticsearch vs. CloudWatch Logs Insights

A secondary decision in this project is the SIEM destination. Three options were evaluated:

| Option | Cost | Query Power | Dashboards | License |
|---|---|---|---|---|
| CloudWatch Logs Insights | Pay per query | Limited | Basic | AWS proprietary |
| Elasticsearch (Elastic Cloud) | $95/month minimum | Excellent | Excellent | Elastic (non-OSS) |
| OpenSearch | Free (self-hosted on AWS) | Excellent | Excellent (Kibana-compatible) | Apache-2.0 |

**OpenSearch** is selected because:
- Apache-2.0 license — fully open-source
- Kibana-compatible dashboards work natively in OpenSearch Dashboards
- AWS manages the cluster when deployed as `aws_opensearch_domain`
- No per-query cost (unlike CloudWatch Logs Insights)
- Supports index lifecycle management, alerting, anomaly detection as built-in plugins
- t3.small.search with 50GB is sufficient for a 30-day log window at enterprise scale

---

## Alternatives Considered

### Full-mesh VPC Peering
**Rejected:** Quadratic scaling complexity. Spoke-to-spoke isolation requires policy controls that can be misconfigured. Does not support routing to the same destination from multiple spokes without route conflicts.

### AWS PrivateLink
**Rejected:** PrivateLink is for service-to-service connectivity (NLB-backed endpoints), not network-level multi-VPC routing. Not appropriate for hub-and-spoke topology.

### AWS Cloud WAN
**Rejected:** More advanced than needed for 4 VPCs. Designed for multi-region, multi-account topologies at 100+ VPC scale. Transit Gateway is the right tool for this scope.

---

## Revisit Triggers

- Expanding to 10+ VPCs (Transit Gateway remains appropriate but cost analysis should be revisited)
- Multi-account architecture required (would add AWS Organizations + RAM for TGW sharing)
- Real-time streaming requirements replace batch log forwarding (would add Amazon MSK/Kafka in the pipeline)
- Data residency requirements force specific regions (OpenSearch domain and Firehose would need multi-region replication)
