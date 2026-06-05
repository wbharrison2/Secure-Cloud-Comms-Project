# ADR-0002: External Secrets Operator + AWS Secrets Manager

**Date**: 2026-02-10  
**Status**: Accepted  
**Deciders**: Mira Chen, senior developer, Meridian security team

## Context

CRITICAL-002 requires automatic secret rotation. JWT_SECRET must rotate every
30 days. Database credentials every 90 days. Meridian’s policy prohibits
long-lived credentials and requires that secret access be auditable.

## Decision

Install External Secrets Operator (ESO). Store all production secrets in AWS
Secrets Manager with rotation enabled. ESO synchronizes AWS secret versions to
Kubernetes Secrets automatically.

## Options Considered

### Option A: Manual kubectl rotation

**Pros**: No additional tooling

**Cons**: Rotation is a manual step that will be forgotten. Doesn’t address
the root cause (secrets not rotating). Does not create audit trails for secret
access. CRITICAL-002 explicitly requires automatic rotation.

**Rejected**: Doesn’t meet Meridian’s policy requirement.

### Option B: HashiCorp Vault + Vault Agent Injector

**Pros**: Industry-leading secrets management, dynamic credentials, fine-grained
ACL policies, comprehensive audit trail

**Cons**: Requires running and maintaining Vault cluster (high ops burden for
small team), significant learning curve, overkill for AGW’s secret count
(<10 secrets), Meridian doesn’t run Vault

**Rejected**: Operational complexity disproportionate to team size.

### Option C: External Secrets Operator + AWS Secrets Manager

**Pros**: AWS-native (no additional infrastructure to operate), Secrets Manager
has built-in Lambda rotation for RDS credentials, ESO polls and auto-updates
Kubernetes secrets, audit trail via CloudTrail (every Secrets Manager API call
logged), Meridian already uses AWS Secrets Manager for other services

**Cons**: ESO is an additional cluster component, secret update causes pod
restart (brief rolling restart on rotation — acceptable given HPA/PDB)

**Accepted**.

## Rotation Implementation

**JWT_SECRET (30-day rotation)**:
- Lambda function generates new 64-byte random key
- Updates Secrets Manager version
- ESO syncs to Kubernetes Secret within 1 hour
- ArgoCD triggers rolling restart (new pods get new JWT_SECRET)
- Old tokens still valid until they expire (7d TTL)

**DATABASE_URL (90-day rotation)**:
- AWS RDS managed rotation (built-in Lambda for PostgreSQL)
- Updates Secrets Manager version with new password + connection string
- ESO syncs to Kubernetes Secret
- App reconnects via pg.Pool connection retry

## Consequences

**Positive**:
- No long-lived credentials in Kubernetes secrets or CI artifacts
- AWS CloudTrail logs every Secrets Manager GetSecretValue call (full audit trail)
- Rotation is automatic and tested (Lambda rotation function)
- ESO polls every hour; max exposure window for a rotated credential: 1 hour

**Negative**:
- Secret rotation triggers a rolling restart of agw-app pods
- If ESO fails, Kubernetes secrets fall back to cached values (no immediate outage)
- JWT rotation invalidates all active sessions at rotation time (users must re-login)
