from importlib.resources import files

from aegisgraph.app import app
from fastapi.testclient import TestClient

client = TestClient(app)


def _section(source: str, start: str, end: str) -> str:
    return source.split(start, maxsplit=1)[1].split(end, maxsplit=1)[0]


def test_dashboard_route_serves_product_shell_without_network_uploads() -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert response.headers["cache-control"] == "no-store"
    assert 'aria-label="Load SENTINEL artifacts"' in response.text
    assert "/assets/dashboard.css" in response.text
    assert "/assets/dashboard.js" in response.text


def test_dashboard_assets_are_served_from_the_local_package() -> None:
    css = client.get("/assets/dashboard.css")
    script = client.get("/assets/dashboard.js")

    assert css.status_code == 200
    assert css.headers["cache-control"] == "no-store"
    assert "@media" in css.text
    assert script.status_code == 200
    assert script.headers["cache-control"] == "no-store"
    assert "defense_decision" in script.text
    assert "textContent" in script.text


def test_dashboard_artifact_import_stays_in_the_browser() -> None:
    response = client.get("/")

    assert response.headers["content-security-policy"] == (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "connect-src 'none'; img-src 'self' data:; object-src 'none'; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    )
    response = client.post("/dashboard/import", files={"trace": ("trace.jsonl", "{}")})
    assert response.status_code == 404


def test_dashboard_assets_are_reachable_as_package_resources() -> None:
    package = files("aegisgraph").joinpath("static")

    assert package.joinpath("index.html").is_file()
    assert package.joinpath("dashboard.css").is_file()
    assert package.joinpath("dashboard.js").is_file()


def test_dashboard_distinguishes_reachability_from_attack_outcome_and_presence() -> None:
    script = files("aegisgraph").joinpath("static/dashboard.js").read_text(encoding="utf-8")
    summary = _section(script, "function renderSummary()", "function filteredEvents()")
    run_data = _section(script, "function deriveRun(run)", "function renderSummary()")
    trust = _section(script, "const getTrust =", "const currentRun =")

    assert '["Attack success", details.attackSuccess]' in summary
    assert '["Attack present", details.attackPresent]' in summary
    assert '["Attack reachability", typeof details.attackReached' in summary
    assert 'attackReached: typeof merged.attack_reached === "boolean"' in run_data
    assert 'attackSuccess: typeof merged.attack_success === "boolean"' in run_data
    assert 'attackPresent: typeof merged.attack_present === "boolean"' in run_data
    assert '"trusted", "trusted_internal", "authenticated_user", "system_policy"' in trust
    assert 'return "trusted"' in trust
    assert (
        '"untrusted", "untrusted_internal", "untrusted_external", "adversary_controlled"'
        in trust
    )
    assert 'return "untrusted"' in trust
    assert 'labels.some((label) => ["untrusted"' in trust
    assert 'includes(label))) return "untrusted"' in trust
    assert 'return "unknown"' in trust


def test_dashboard_requires_matching_step_ids_and_announces_file_progress() -> None:
    script = files("aegisgraph").joinpath("static/dashboard.js").read_text(encoding="utf-8")
    related = _section(script, "function matchingRelated(event)", "function renderInspector")
    comparison = _section(script, "function renderComparison()", "function formatMetric")
    selection = _section(script, "function selectEvent(event)", "function renderComparison")

    assert 'eventStep === undefined || eventStep === null || eventStep === ""' in related
    assert '(candidate.step_id ?? getPayload(candidate).step_id) === eventStep' in related
    assert "Reading ${file.name} locally" in script
    assert 'byId("import-status").textContent = message' in script
    assert "runtime_config" in comparison
    assert "configuration" in comparison
    assert "recordedMetadata.length" in comparison
    assert "Comparison metadata unavailable" in comparison
    assert "if (!state.visible.includes(event)) resetFilters()" in selection
    assert 'selectedRow?.focus()' in selection
    assert 'selectedRow?.scrollIntoView' in selection
