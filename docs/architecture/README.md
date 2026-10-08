# Architecture

Documents in this directory describe the platform as it is, plus the decisions
that shape where it is going. Every statement about current behaviour cites a
`path:line` anchor that was opened while writing it. Capabilities are labelled
`implemented`, `partial` or `proposed`.

| Document | Contents |
| --- | --- |
| [system-context.md](system-context.md) | Components, boundaries, maturity, code anchors |
| [threat-model.md](threat-model.md) | Assets, trust boundaries, attacker capabilities, misuse cases, fail-closed behaviour |
| [roadmap.md](roadmap.md) | Milestones M0–M8, dependency graph, entry/exit criteria, single-writer map, blocked-by-tooling ledger |
| [adr/](adr/README.md) | Architecture decision records |

Related:

- [`AGENTS.md`](../../AGENTS.md) — operating guide, role boundaries, quality gates.
- [`PRODUCT.md`](../../PRODUCT.md) — product register.
- [`../evidence/ledger.md`](../evidence/ledger.md) — claim → status → artifact → digest.
- [`../legacy/sentinel-challenge.md`](../legacy/sentinel-challenge.md) — preserved challenge record.
