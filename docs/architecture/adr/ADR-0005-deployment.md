# ADR-0005 — Deployment: Docker/Compose first, Kubernetes validated but smoke-test blocked

- **Status:** proposed
- **Date:** 2026-10-08
- **Deciders:** architecture lead (proposal), platform engineer, orchestrator
- **Milestone:** M4 (CI/CD + containers + deployment)

## Context

A hardened single-container definition already exists (`Dockerfile`): exact pins
from `requirements.lock`, non-root UID 10001, port 8080, no privileged settings.
Docker 29.6.2 and Compose v5.3.1 are available locally, but `kind` is **not**, so
no Kubernetes cluster can be started here. A live Docker-engine run has not yet
been verified in this environment.

The milestone needs a deployment story that is honest about what is verified.

## Decision

Make **Docker Compose the supported deployment unit**: the service plus
PostgreSQL (ADR-0001) plus Prometheus and Grafana (ADR-0003), wired with health
checks, read-only root filesystems where possible, dropped capabilities and
no-new-privileges.

Provide **Kubernetes manifests as a validated-but-unverified artifact**: they are
schema-validated (`kubeconform`/`kubectl --dry-run=server`), but a live cluster
smoke test is **blocked** until `kind` is available. The manifest directory
carries a README stating exactly this, and no "works on Kubernetes" claim is made
until the smoke test passes on a real cluster.

## Alternatives

1. **Kubernetes-first.** Highest operational realism, but unverifiable here; it
   would force unverifiable claims, which this project forbids.
2. **Bare systemd.** Lightweight, but no clean multi-service story (PostgreSQL,
   Prometheus, Grafana) and no reproducible local stack.
3. **Serverless container platform.** Convenient, but ties the audit store and
   long-lived connections to a vendor and hides the network controls we need.
4. **No orchestration (single container, external services).** Viable for a demo;
   leaves the multi-service stack unexercised and the schema/auth/telemetry
   integration untested.

## Consequences

- **Positive:** one command brings up the whole platform locally; the deployment
  matches what tests exercise; the Kubernetes gap is explicit rather than
  papered over.
- **Negative:** Compose hides some production scheduling realities; the
  Kubernetes path stays unverified and therefore cannot be presented as working.
- **Neutral:** the legacy single-container `Dockerfile` is preserved; Compose
  composes it rather than replacing it.
- **Blocked:** cluster smoke test needs `kind`
  (`kind create cluster --name aegisgraph && kubectl apply -k deploy/k8s`).
  Report this cell as `blocked`.
