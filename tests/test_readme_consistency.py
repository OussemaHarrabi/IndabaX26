"""The README must describe the shipped platform, not the legacy prototype.

The README once said persistence, authentication, telemetry and the native
evaluation harness were "proposed and not yet built" long after those milestones
had shipped, and its API table listed endpoints that never existed. These
assertions fail when that class of drift returns: the documented endpoints are
checked against the application's own route table, every relative link is checked
against the tree, the three evidence classes must stay separated, and the exact
stale sentences are forbidden.
"""

from __future__ import annotations

import re
from pathlib import Path

from aegisgraph.app import app

REPO_ROOT = Path(__file__).resolve().parents[1]
README = REPO_ROOT / "README.md"

# Sentences that were true of the prototype and are false of this release. Each one
# shipped once, so a substring match is enough to catch a return.
STALE_CLAIMS = (
    "proposed and not yet built",
    "not yet built",
    "No persistence, auth or telemetry yet",
    "Platform evaluation is not built",
    "A live Docker-engine run has not yet been verified",
    "proposed (roadmap M2)",
)

# Endpoints a reader must be able to find, checked against the live route table.
REQUIRED_DOCUMENTED = {
    ("GET", "/healthz"),
    ("GET", "/readyz"),
    ("POST", "/api/v1/decisions"),
    ("POST", "/v1/decision"),
}

LINK = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
API_ROW = re.compile(r"^\|\s*`(GET|POST|PUT|PATCH|DELETE)`\s*\|\s*`([^`]+)`\s*\|", re.MULTILINE)


def _text() -> str:
    return README.read_text(encoding="utf-8")


def test_no_stale_claim_about_implemented_capabilities() -> None:
    present = [claim for claim in STALE_CLAIMS if claim in _text()]
    assert present == [], (
        "the README describes implemented capabilities as unbuilt: " + "; ".join(present)
    )


def test_every_relative_link_resolves() -> None:
    broken = []
    for target in LINK.findall(_text()):
        if target.startswith(("http://", "https://", "#", "mailto:")):
            continue
        path = target.split("#", 1)[0]
        if path and not (REPO_ROOT / path).exists():
            broken.append(target)
    assert broken == [], f"broken relative links in README.md: {broken}"


def test_the_documented_endpoints_exist_in_the_application() -> None:
    routes = {
        (method, route.path)
        for route in app.routes
        for method in (getattr(route, "methods", None) or ())
    }
    documented = set(API_ROW.findall(_text()))
    assert documented, "the README's API table did not parse"
    unknown = sorted(documented - routes)
    assert unknown == [], f"the README documents endpoints that do not exist: {unknown}"
    missing = sorted(REQUIRED_DOCUMENTED - documented)
    assert missing == [], f"the README omits required endpoints: {missing}"


def test_the_three_evidence_classes_stay_separated() -> None:
    text = _text()
    for heading in (
        "### 1. Native benchmark, scripted replay",
        "### 2. Historical legacy SENTINEL evidence",
        "### 3. Native real-model campaign — **not yet run**",
    ):
        assert heading in text, f"README lost the evidence-class heading: {heading!r}"
