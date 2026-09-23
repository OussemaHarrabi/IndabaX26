# Product

## Register

product

## Users

The project owner and hackathon judges use the observability dashboard while reviewing SENTINEL runs. They need to inspect what the agent proposed, what the defense decided, why it decided that, and what happened after the decision.

## Product Purpose

AegisGraph is a deterministic decision gateway and evidence surface for the SENTINEL agent-security challenge. The dashboard makes run outcomes and policy decisions inspectable, so a reviewer can follow the evidence chain instead of trusting an aggregate score or opaque security claim.

## Brand Personality

Calm, forensic, evidence-first. The interface should feel precise and legible under scrutiny, with failures and uncertainty shown plainly.

## Anti-references

- Flashy “hacker” styling, neon-on-black clichés, or decorative threat animations.
- Opaque scores without the observations and decision reasons behind them.
- Hiding failed or incomplete runs, or presenting development mock results as Qwen results.
- Color as the only way to distinguish allow, block, escalate, error, or attack outcome.

## Design Principles

1. Show the event and decision evidence before summarizing the score.
2. Keep the causal chain visible: candidate action → defense verdict/reasons → tool effect → task and security outcome.
3. Preserve provenance and trust labels; never imply that untrusted text became trusted.
4. Make incomplete, failed, unreachable, and mock-only evidence explicit.
5. Support fast judge review without sacrificing keyboard access or readable detail.

## Accessibility & Inclusion

Target WCAG 2.2 AA. Support keyboard navigation, visible focus, readable text, reduced motion, and state labels/icons in addition to color. Use accessible names for interactive controls and ensure the timeline and decision details remain understandable to screen readers.
