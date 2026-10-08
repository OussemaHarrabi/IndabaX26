# Architecture decision records

Every ADR is a **proposal** until the orchestrator and owner approve it. An
accepted ADR is never edited to hide its original decision: supersede it with a
new ADR that references it.

| ADR | Title | Status | Milestone |
| --- | --- | --- | --- |
| [0001](ADR-0001-persistence.md) | Persistence: PostgreSQL + SQLAlchemy 2 + Alembic | proposed | M2 |
| [0002](ADR-0002-authentication.md) | Authentication: OIDC/JWT + scoped service tokens | proposed | M3 |
| [0003](ADR-0003-telemetry.md) | Telemetry: OpenTelemetry + Prometheus + Grafana | proposed | M4 |
| [0004](ADR-0004-evaluation-framework.md) | Evaluation: native schema + legacy adapter + optional Inspect AI | proposed | M5 |
| [0005](ADR-0005-deployment.md) | Deployment: Docker/Compose first, Kubernetes validated-but-blocked | proposed | M7 |
| [0006](ADR-0006-enforcement-binding.md) | Enforcement binding by exact action digest | proposed | M1/M6 |

## Template

```markdown
# ADR-000N — <title>

- **Status:** proposed | accepted | superseded by ADR-00MX | rejected
- **Date:** YYYY-MM-DD
- **Deciders:** <roles>
- **Milestone:** M<n>

## Context
## Decision
## Alternatives
## Consequences
```
