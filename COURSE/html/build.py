"""Assemble the single-file interactive course.

    python COURSE/html/build.py

Reads:  COURSE/html/_course.css, COURSE/html/_course.js,
        COURSE/html/data-scenarios.json, COURSE/html/NN-*.html
Writes: COURSE/aegisgraph-course.html
"""

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE.parent / "aegisgraph-course.html"

FRAGMENTS = [
    "00-start.html",
    "01-basics.html",
    "02-challenge.html",
    "03-arena.html",
    "04-attacks.html",
    "05-baselines.html",
    "06-architecture.html",
    "07-kernel.html",
    "08-evidence.html",
    "09-audit.html",
    "10-labs.html",
    "11-glossary.html",
]

HERO = """
<section class="hero">
  <div class="hero-mark">
    <span class="pill gold">SENTINEL · IndabaX Tunisia 2026</span>
    <span class="pill">Agent security</span>
    <span class="pill">Defence only</span>
  </div>
  <h1>AegisGraph, explained from zero</h1>
  <p class="hero-sub">A provenance-aware decision gateway for tool-using agents — the project, the attacks it faced, the defences it tried, what it measured, and what is still broken.</p>
  <div class="callout hero-question">
    <div class="callout-title">The question the challenge asks</div>
    <p>Can an autonomous AI agent stay useful while its environment is actively trying to manipulate it?</p>
  </div>
  <div class="card-grid hero-numbers">
    <div class="card"><h4>22 / 22</h4><p class="dim">attacks a real model reaches and completes when nothing defends</p></div>
    <div class="card"><h4>0 / 22</h4><p class="dim">the same attacks, with AegisGraph v5 installed</p></div>
    <div class="card"><h4>0.86 %</h4><p class="dim">false-block rate · 4 of 9 benign tasks still complete</p></div>
    <div class="card"><h4>9.3 ms</h4><p class="dim">p95 decision latency, deterministic, no model in the loop</p></div>
  </div>
  <p class="hero-note">Every number here was recomputed from the repository's own evaluation artifacts during this audit. The
  run is one seeded public-suite self-test with Qwen3-8B, not a jury score — and the kit's own gate still marks it
  <code>eligible=false</code> because benign utility (4/9) sits under its 0.5 threshold.</p>
</section>
"""

SHELL = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AegisGraph — interactive course</title>
<meta name="description" content="An interactive course on AegisGraph: an agent-security defence gateway built for the SENTINEL challenge, IndabaX Tunisia 2026.">
<style>
{css}
</style>
</head>
<body>
<header class="topbar">
  <button class="menu-btn" type="button" aria-label="Toggle contents">☰</button>
  <div class="brand">Aegis<span>Graph</span> · course</div>
  <div class="meta">SENTINEL · IndabaX Tunisia 2026</div>
  <div class="search">
    <input id="search" type="search" placeholder="search the course…" aria-label="Search the course">
    <span class="hint">/</span>
  </div>
  <div class="progress"></div>
</header>
<div class="layout">
  <aside class="sidebar">
    <h2>Contents</h2>
    <ul id="nav-list" class="nav-list"></ul>
    <div class="side-foot">
      <p>Twelve chapters, fourteen interactive widgets, one honest verdict.</p>
      <p><a href="#ch-09">Jump to the audit verdict →</a></p>
    </div>
  </aside>
  <main>
{hero}
{body}
    <footer class="chapter" style="border-top:1px solid var(--hair);margin-top:40px">
      <h3 style="margin-top:24px">Colophon</h3>
      <p class="dim">Course generated from the repository's own sources: the eleven Markdown modules in <code>COURSE/</code>,
      the audit notes in <code>COURSE/notes/</code>, and the artifacts under <code>evaluation/</code>. Numbers are from the
      pinned public suite at <code>Skan22/Sentinel_Starter_Kit@dd2e5fe0</code>; the defence source is commit
      <code>53472e5</code>. Design follows the IndabaX Tunisia 2026 specification book. Single file, no external
      requests: it works offline, and prints cleanly.</p>
    </footer>
  </main>
</div>
<script>
window.__SCENARIOS__ = {scenarios};
</script>
<script>
{js}
</script>
</body>
</html>
"""

EXTRA_CSS = """
.hero { padding: 26px 0 6px; border-bottom: 1px solid var(--hair); margin-bottom: 34px; }
.hero-mark { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 14px; }
.hero h1 { font-size: 46px; line-height: 1.06; margin: 6px 0 12px; color: var(--ink); font-weight: 800; letter-spacing: -0.02em; }
.hero-sub { font-size: 19px; color: #e6eefa; max-width: 62ch; }
.hero-question { margin-top: 20px; }
.hero-numbers { margin-top: 22px; }
.hero-numbers .card h4 { font-size: 27px; color: var(--gold); margin: 0 0 4px; letter-spacing: -0.01em; }
.hero-note { font-size: 14px; color: var(--muted); max-width: 78ch; }
@media print { .hero { border-bottom: 1px solid #ccc; } .hero h1 { color: #111; font-size: 30pt; } }
"""


def main() -> int:
    css = (HERE / "_course.css").read_text(encoding="utf-8") + EXTRA_CSS
    js = (HERE / "_course.js").read_text(encoding="utf-8")
    scenarios = json.loads((HERE / "data-scenarios.json").read_text(encoding="utf-8"))

    parts, missing = [], []
    for name in FRAGMENTS:
        path = HERE / name
        if not path.exists():
            missing.append(name)
            continue
        parts.append(f"<!-- {name} -->\n" + path.read_text(encoding="utf-8").rstrip())

    html = SHELL.format(
        css=css,
        js=js,
        hero=HERO,
        body="\n".join(parts),
        scenarios=json.dumps(scenarios, ensure_ascii=False, separators=(",", ":")),
    )
    OUT.write_text(html, encoding="utf-8")
    size = OUT.stat().st_size
    print(f"wrote {OUT} ({size:,} bytes, {html.count(chr(10)):,} lines)")
    print(f"chapters embedded: {len(parts)} / {len(FRAGMENTS)}")
    if missing:
        print("MISSING fragments: " + ", ".join(missing))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
