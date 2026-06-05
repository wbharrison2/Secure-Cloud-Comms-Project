# ADR-0001: Istio Service Mesh for mTLS

**Date**: 2026-02-03  
**Status**: Accepted  
**Deciders**: Mira Chen, senior developer, Meridian security team

## Context

CRITICAL-001 requires that all pod-to-pod traffic be encrypted with mutual TLS.
The solution must be transparent to the application (no code changes) and must
enforce mTLS rather than just offering it as an option.

## Decision

Install Istio service mesh. Enable sidecar injection in `agw-production` namespace.
Set PeerAuthentication to STRICT mode. Use AuthorizationPolicy to restrict ingress
to the Istio Ingress Gateway service account.

## Options Considered

### Option A: Manual TLS in the application (Node.js https module)

**Pros**: No additional infrastructure

**Cons**: Requires certificate management code in the application, certificate
rotation disrupts pods, no mutual authentication (server can’t verify client
identity), high implementation burden

**Rejected**: Doesn’t address mutual authentication; high ongoing maintenance.

### Option B: Linkerd

**Pros**: Simpler than Istio, lighter resource footprint, automatic mTLS,
good Kubernetes integration

**Cons**: Less mature AuthorizationPolicy, no built-in Ingress Gateway (needs
separate NGINX Ingress), smaller ecosystem, Meridian’s existing infrastructure
uses Istio

**Rejected**: Meridian standardization requirement.

### Option C: Istio

**Pros**: Industry standard, mature AuthorizationPolicy and traffic management,
Istio Ingress Gateway replaces NGINX Ingress (one fewer component), SPIFFE/SVID
identity for pods, Envoy proxy gives visibility into all traffic metrics,
Meridian’s teams already operate Istio

**Cons**: Complex, resource overhead (~50MB RAM per Envoy sidecar), adds 2ms
latency per hop, longer learning curve

**Accepted**.

## Consequences

**Positive**:
- All pod-to-pod traffic is mTLS without any application code changes
- PeerAuthentication STRICT rejects any plaintext connection attempt
- AuthorizationPolicy provides service-identity-based access control
- Envoy sidecar provides free traffic metrics (request rate, latency, error rate)
- Istio Ingress Gateway consolidates TLS termination and routing

**Negative**:
- Each pod uses ~50MB more RAM for Envoy sidecar
- Deployment YAML must include `preStop` hook for graceful Envoy shutdown
- Debugging requires `istioctl` knowledge
- Mesh upgrades require careful coordination
