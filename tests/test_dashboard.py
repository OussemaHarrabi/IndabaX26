from aegisgraph.app import app
from fastapi.testclient import TestClient

client = TestClient(app)


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
    from importlib.resources import files

    package = files("aegisgraph").joinpath("static")

    assert package.joinpath("index.html").is_file()
    assert package.joinpath("dashboard.css").is_file()
    assert package.joinpath("dashboard.js").is_file()
