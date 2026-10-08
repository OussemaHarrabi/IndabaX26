"""Durable receipts, tenant scoping, idempotency and retention (finding F7, decisions D1, D4, D6).

The store-level tests here run against the in-process store, which implements the
same contract as PostgreSQL; ``tests/test_postgres_store.py`` proves the database
enforces it too. Nothing in this file needs a database.
"""

from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from aegisgraph.app import app
from aegisgraph.auth import SCOPE_POLICY_CONTEXT_OVERRIDE
from aegisgraph.settings import load_settings
from aegisgraph.store import (
    EVENT_RETENTION_APPLIED,
    ReceiptConflictError,
    ReceiptRecord,
    apply_retention,
    digest_of,
    open_store,
)
from fastapi.testclient import TestClient
from m2_support import AuthHarness, decision_payload, seed_policy_set

client = TestClient(app)

TENANT = "tenant-a"
OTHER_TENANT = "tenant-b"
POLICY = {
    "allowed_tools": ["document_search"],
    "confirmation_required_tools": [],
    "consequential_tools": [],
}


def _submit(auth: AuthHarness, *, tenant: str = TENANT, **overrides: Any) -> Any:
    return client.post(
        "/api/v1/decisions",
        json=decision_payload(**overrides),
        headers=auth.header(role="decision_client", tenant=tenant),
    )


def _receipt_record(
    *, request_id: str, tenant: str = TENANT, metadata: dict[str, Any] | None = None,
    created_at: datetime | None = None,
) -> ReceiptRecord:
    moment = created_at or datetime.now(UTC)
    return ReceiptRecord(
        tenant_id=tenant,
        request_id=request_id,
        receipt_id=f"receipt-{request_id}",
        surface="generic",
        principal_id="client-a",
        auth_method="jwt",
        policy_set_id="aegisgraph-default",
        policy_set_version="1",
        verdict="allow",
        risk_score=0.08,
        confidence=0.9,
        reason_codes=("POLICY_CHECKS_PASSED",),
        action_digest="a" * 24,
        execution_digest="b" * 24,
        payload_digest=digest_of({"request_id": request_id}),
        decided_at=moment,
        valid_until=moment + timedelta(seconds=60),
        created_at=moment,
        run_id="run-1",
        step_id=1,
        metadata=metadata,
    )


def test_the_receipt_read_surface_requires_the_receipt_scope(auth: AuthHarness) -> None:
    assert client.get("/api/v1/receipts").status_code == 401

    wrong_scope = auth.header(role="decision_client", tenant=TENANT)

    assert client.get("/api/v1/receipts", headers=wrong_scope).status_code == 403
    assert client.get("/api/v1/receipts", headers=wrong_scope).json()["code"] == (
        "INSUFFICIENT_SCOPE"
    )


def test_a_decision_is_persisted_and_readable_by_an_auditor(auth: AuthHarness) -> None:
    seed_policy_set(TENANT, document=POLICY)
    created = _submit(auth, request_id="persisted-1")
    assert created.status_code == 200

    listed = client.get("/api/v1/receipts", headers=auth.header(role="auditor", tenant=TENANT))

    assert listed.status_code == 200
    items = [item for item in listed.json()["items"] if item["request_id"] == "persisted-1"]
    assert len(items) == 1
    receipt = items[0]
    assert receipt["receipt_id"] == created.json()["receipt_id"]
    assert receipt["verdict"] == "allow"
    assert receipt["policy_set"] == {"id": "aegisgraph-default", "version": "1"}
    assert receipt["action_digest"] == created.json()["action_digest"]
    assert receipt["execution_digest"] == created.json()["execution_digest"]
    assert receipt["payload_digest"] is not None
    assert receipt["principal_id"] == "client-a"
    assert receipt["surface"] == "generic"
    single = client.get(
        f"/api/v1/receipts/{receipt['receipt_id']}",
        headers=auth.header(role="auditor", tenant=TENANT),
    )
    assert single.status_code == 200
    assert single.json()["request_id"] == "persisted-1"


def test_a_receipt_is_invisible_to_another_tenant(auth: AuthHarness) -> None:
    seed_policy_set(TENANT, document=POLICY)
    created = _submit(auth, request_id="scoped-1")
    other = auth.header(role="auditor", tenant=OTHER_TENANT)

    listed = client.get("/api/v1/receipts", headers=other)

    assert listed.status_code == 200
    assert all(item["request_id"] != "scoped-1" for item in listed.json()["items"])
    missing = client.get(f"/api/v1/receipts/{created.json()['receipt_id']}", headers=other)
    assert missing.status_code == 404


def test_a_duplicate_request_id_returns_the_stored_receipt(auth: AuthHarness) -> None:
    seed_policy_set(TENANT, document=POLICY)

    first = _submit(auth, request_id="idempotent-1")
    second = _submit(auth, request_id="idempotent-1")

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["receipt_id"] == second.json()["receipt_id"]
    assert first.json()["decided_at"] == second.json()["decided_at"]
    listed = client.get("/api/v1/receipts", headers=auth.header(role="auditor", tenant=TENANT))
    matching = [item for item in listed.json()["items"] if item["request_id"] == "idempotent-1"]
    assert len(matching) == 1


def test_a_reused_request_id_with_a_different_action_is_refused(auth: AuthHarness) -> None:
    seed_policy_set(TENANT, document=POLICY)
    assert _submit(auth, request_id="conflicting-1").status_code == 200

    conflicting = client.post(
        "/api/v1/decisions",
        json=decision_payload(request_id="conflicting-1", tool="document_read"),
        headers=auth.header(role="decision_client", tenant=TENANT),
    )

    assert conflicting.status_code == 409
    assert conflicting.json()["code"] == "REQUEST_ID_CONFLICT"
    events = client.get(
        "/api/v1/audit-events", headers=auth.header(role="auditor", tenant=TENANT)
    ).json()["items"]
    assert any(item["event_type"] == "receipt_request_conflict" for item in events)


def test_the_receipt_page_is_bounded_and_cursor_paged(auth: AuthHarness) -> None:
    seed_policy_set(TENANT, document=POLICY)
    for index in range(3):
        assert _submit(auth, request_id=f"page-{index}").status_code == 200
    auditor = auth.header(role="auditor", tenant=TENANT)

    first = client.get("/api/v1/receipts?limit=2", headers=auditor)

    assert first.status_code == 200
    assert len(first.json()["items"]) == 2
    cursor = first.json()["next_cursor"]
    assert cursor is not None
    second = client.get(f"/api/v1/receipts?limit=2&cursor={cursor}", headers=auditor)
    assert second.status_code == 200
    first_ids = {item["receipt_id"] for item in first.json()["items"]}
    second_ids = {item["receipt_id"] for item in second.json()["items"]}
    assert first_ids.isdisjoint(second_ids)


def test_a_malformed_cursor_returns_an_empty_page(auth: AuthHarness) -> None:
    seed_policy_set(TENANT, document=POLICY)
    assert _submit(auth, request_id="cursor-1").status_code == 200

    response = client.get(
        "/api/v1/receipts?cursor=not-a-cursor", headers=auth.header(role="auditor", tenant=TENANT)
    )

    assert response.status_code == 200
    assert response.json()["items"] == []


@pytest.mark.parametrize("query", ["limit=0", "limit=101", "limit=abc"])
def test_the_receipt_page_bound_is_enforced(auth: AuthHarness, query: str) -> None:
    response = client.get(
        f"/api/v1/receipts?{query}", headers=auth.header(role="auditor", tenant=TENANT)
    )

    assert response.status_code == 422


def test_an_unknown_receipt_id_is_a_404(auth: AuthHarness) -> None:
    response = client.get(
        "/api/v1/receipts/00000000000000000000000000000000",
        headers=auth.header(role="auditor", tenant=TENANT),
    )

    assert response.status_code == 404
    assert response.json()["code"] == "RECEIPT_NOT_FOUND"


def test_concurrent_duplicate_receipt_writes_store_exactly_one_row() -> None:
    store = open_store(load_settings({"AEGISGRAPH_AUTH_MODE": "none"}))
    record = _receipt_record(request_id="concurrent-1")

    with ThreadPoolExecutor(max_workers=16) as pool:
        stored = list(pool.map(lambda _: store.store_receipt(record), range(32)))

    assert {item.receipt_id for item in stored} == {record.receipt_id}
    records, _ = store.list_receipts(TENANT, limit=100)
    assert [item.request_id for item in records] == ["concurrent-1"]


def test_a_conflicting_concurrent_write_is_refused() -> None:
    store = open_store(load_settings({"AEGISGRAPH_AUTH_MODE": "none"}))
    store.store_receipt(_receipt_record(request_id="concurrent-2"))
    different = replace(_receipt_record(request_id="concurrent-2"), action_digest="c" * 24)

    with pytest.raises(ReceiptConflictError):
        store.store_receipt(different)


def test_retention_redacts_payload_metadata_and_keeps_the_audit_row() -> None:
    """F7/D6 regression: the payload-adjacent half expires, the audit half does not."""

    store = open_store(load_settings({"AEGISGRAPH_AUTH_MODE": "none"}))
    now = datetime.now(UTC)
    old = _receipt_record(
        request_id="retention-old",
        metadata={"response_metadata": {"note": "payload-adjacent"}},
        created_at=now - timedelta(days=120),
    )
    fresh = _receipt_record(
        request_id="retention-fresh",
        metadata={"response_metadata": {"note": "still inside the window"}},
        created_at=now - timedelta(days=1),
    )
    store.store_receipt(old)
    store.store_receipt(fresh)

    report = apply_retention(store, now=now, days=90)

    assert report.payloads_redacted == 1
    assert report.tenants == (TENANT,)
    redacted = store.get_receipt(TENANT, old.receipt_id)
    assert redacted is not None
    assert redacted.metadata is None
    assert redacted.metadata_redacted_at is not None
    assert redacted.verdict == "allow"
    assert redacted.reason_codes == ("POLICY_CHECKS_PASSED",)
    assert redacted.action_digest == old.action_digest
    assert redacted.execution_digest == old.execution_digest
    assert redacted.payload_digest == old.payload_digest
    kept = store.get_receipt(TENANT, fresh.receipt_id)
    assert kept is not None and kept.metadata is not None

    events = store.list_audit_events(TENANT)
    retention_events = [event for event in events if event.event_type == EVENT_RETENTION_APPLIED]
    assert len(retention_events) == 1
    assert retention_events[0].details["payloads_redacted"] == 1
    assert retention_events[0].details["retention_days"] == 90


def test_retention_is_idempotent() -> None:
    store = open_store(load_settings({"AEGISGRAPH_AUTH_MODE": "none"}))
    now = datetime.now(UTC)
    store.store_receipt(
        _receipt_record(
            request_id="retention-twice",
            metadata={"note": "payload"},
            created_at=now - timedelta(days=10),
        )
    )

    first = apply_retention(store, now=now, days=1)
    second = apply_retention(store, now=now, days=1)

    assert first.payloads_redacted == 1
    assert second.payloads_redacted == 0
    assert second.tenants == ()


def test_retention_never_touches_another_tenants_rows() -> None:
    store = open_store(load_settings({"AEGISGRAPH_AUTH_MODE": "none"}))
    now = datetime.now(UTC)
    store.store_receipt(
        _receipt_record(
            request_id="retention-scoped",
            tenant=OTHER_TENANT,
            metadata={"note": "other tenant"},
            created_at=now - timedelta(days=10),
        )
    )

    report = apply_retention(store, now=now, days=1)

    assert report.tenants == (OTHER_TENANT,)
    kept = store.get_receipt(OTHER_TENANT, "receipt-retention-scoped")
    assert kept is not None and kept.metadata is None
    assert store.get_receipt(TENANT, "receipt-retention-scoped") is None


def test_the_decision_record_names_the_authenticated_caller(
    auth: AuthHarness, caplog: pytest.LogCaptureFixture
) -> None:
    """The decision record carries the caller identity, and no credential material."""

    seed_policy_set(TENANT, document=POLICY)
    token = auth.token(role="decision_client", tenant=TENANT)

    with caplog.at_level(logging.INFO, logger="aegisgraph.decision"):
        response = client.post(
            "/api/v1/decisions",
            json=decision_payload(request_id="caller-label"),
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 200
    records = [
        record
        for record in caplog.records
        if record.name == "aegisgraph.decision" and record.levelno == logging.INFO
    ]
    assert len(records) == 1
    event = json.loads(records[0].getMessage())
    assert event["caller"] == "client-a"
    assert token not in records[0].getMessage()


def test_an_unavailable_receipt_store_fails_closed_with_503(
    auth: AuthHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F7: a decision that cannot be persisted is not returned as if it were."""

    from aegisgraph import access

    class BrokenStore:
        durable = True

        def store_receipt(self, record: ReceiptRecord) -> ReceiptRecord:
            raise RuntimeError("the store is unavailable")

    monkeypatch.setattr(access, "open_store", lambda settings: BrokenStore())
    override = auth.header(
        role="decision_client", tenant=TENANT, scopes=(SCOPE_POLICY_CONTEXT_OVERRIDE,)
    )

    response = client.post(
        "/api/v1/decisions", json=decision_payload(request_id="store-down"), headers=override
    )

    assert response.status_code == 503
    assert response.json()["code"] == "RECEIPT_STORE_UNAVAILABLE"


def test_payload_metadata_is_stored_only_when_it_is_opted_in(
    auth: AuthHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D6: the default is digest-only; the opt-in keeps a redactable copy."""

    seed_policy_set(TENANT, document=POLICY)
    store = open_store(load_settings())

    digest_only = _submit(auth, request_id="digest-only")
    assert digest_only.status_code == 200
    stored = store.get_receipt(TENANT, digest_only.json()["receipt_id"])
    assert stored is not None
    assert stored.metadata is None
    assert len(stored.payload_digest) == 64

    monkeypatch.setenv("AEGISGRAPH_STORE_PAYLOAD_METADATA", "true")
    with_metadata = _submit(auth, request_id="with-metadata")
    assert with_metadata.status_code == 200
    kept = store.get_receipt(TENANT, with_metadata.json()["receipt_id"])
    assert kept is not None
    assert kept.metadata == dict(with_metadata.json()["metadata"])
    assert "least_trust" in kept.metadata


@pytest.mark.parametrize(
    "cursor",
    ["", "not-base64!!", "aGVsbG8", "MjAyNi0xMC0wOFQwOTowMDowMHx8"],
    ids=["empty", "not-base64", "no-separator", "no-request-id"],
)
def test_a_cursor_that_cannot_be_decoded_is_ignored(cursor: str) -> None:
    from aegisgraph.store import decode_cursor

    assert decode_cursor(cursor) is None


def test_a_naive_timestamp_cursor_is_refused() -> None:
    import base64

    from aegisgraph.store import decode_cursor, encode_cursor

    raw = base64.urlsafe_b64encode(b"2026-10-08T09:00:00|request-1").decode("ascii").rstrip("=")

    assert decode_cursor(raw) is None
    assert decode_cursor(encode_cursor(datetime.now(UTC), "request-1")) is not None


def test_the_in_process_store_pages_with_a_cursor() -> None:
    store = open_store(load_settings({"AEGISGRAPH_AUTH_MODE": "none"}))
    now = datetime.now(UTC)
    for index in range(3):
        store.store_receipt(
            _receipt_record(
                request_id=f"memory-page-{index}", created_at=now - timedelta(seconds=index)
            )
        )

    page, cursor = store.list_receipts(TENANT, limit=2)

    assert [item.request_id for item in page] == ["memory-page-0", "memory-page-1"]
    assert cursor is not None
    rest, cursor = store.list_receipts(TENANT, limit=2, cursor=cursor)
    assert [item.request_id for item in rest] == ["memory-page-2"]
    assert cursor is None


def test_the_in_process_store_administers_policies() -> None:
    from aegisgraph.store import PolicyRecord, UnknownPolicySetError

    store = open_store(load_settings({"AEGISGRAPH_AUTH_MODE": "none"}))
    now = datetime.now(UTC)
    record = PolicyRecord(
        tenant_id=TENANT,
        id="memory-policy",
        version="1",
        document=POLICY,
        checksum=digest_of(POLICY),
        active=False,
        created_by="admin",
        created_at=now,
    )

    created = store.create_policy_set(record)

    assert created.version == "1"
    assert store.create_policy_set(record).checksum == created.checksum
    assert store.get_policy_set(TENANT, "memory-policy", "1") is not None
    assert store.get_policy_set(TENANT, "memory-policy", "9") is None
    assert [item.version for item in store.list_policy_sets(TENANT)] == ["1"]
    assert store.active_policy_set(TENANT, "memory-policy") is None
    assert store.activate_policy_set(TENANT, "memory-policy", "1", now=now).active is True
    assert store.active_policy_set(TENANT, "memory-policy") is not None
    with pytest.raises(UnknownPolicySetError):
        store.activate_policy_set(TENANT, "memory-policy", "9", now=now)


def test_the_in_process_store_deactivates_the_previous_version() -> None:
    from aegisgraph.store import PolicyRecord

    store = open_store(load_settings({"AEGISGRAPH_AUTH_MODE": "none"}))
    now = datetime.now(UTC)
    for version in ("1", "2"):
        store.create_policy_set(
            PolicyRecord(
                tenant_id=TENANT,
                id="memory-policy",
                version=version,
                document=POLICY,
                checksum=digest_of(POLICY),
                active=False,
                created_by="admin",
                created_at=now,
            )
        )

    store.activate_policy_set(TENANT, "memory-policy", "1", now=now)
    store.activate_policy_set(TENANT, "memory-policy", "2", now=now)

    states = {item.version: item.active for item in store.list_policy_sets(TENANT)}
    assert states == {"1": False, "2": True}
