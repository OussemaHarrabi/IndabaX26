"""PostgreSQL-backed persistence: migrations, append-only proof, durability (F7, D1, D4, D6).

Every test here carries the ``db`` marker and skips cleanly unless
``AEGISGRAPH_TEST_DATABASE_URL`` points at a PostgreSQL database, so the rest of
the suite runs with no database at all.

    docker run --rm -d -e POSTGRES_PASSWORD=... -p 15532:5432 postgres:17
    AEGISGRAPH_TEST_DATABASE_URL=postgresql+psycopg://postgres:...@127.0.0.1:15532/postgres \\
        python -m pytest -m db -q
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from aegisgraph.app import app
from aegisgraph.models import Base
from aegisgraph.settings import load_settings
from aegisgraph.store import (
    EVENT_RETENTION_APPLIED,
    PolicyRecord,
    ReceiptRecord,
    SqlStore,
    apply_retention,
    digest_of,
    open_store,
    reset_store_cache,
)
from fastapi.testclient import TestClient
from m2_support import AuthHarness, alembic, decision_payload, require_database, seed_policy_set
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DatabaseError
from sqlalchemy.orm import Session

pytestmark = pytest.mark.db

client = TestClient(app)

TENANT = "tenant-a"
POLICY = {
    "allowed_tools": ["document_search"],
    "confirmation_required_tools": [],
    "consequential_tools": [],
}


@pytest.fixture(scope="module")
def database_url() -> str:
    return require_database()


@pytest.fixture
def store(database_url: str) -> SqlStore:
    """Return a store over a freshly created schema."""

    engine = create_engine(database_url)
    Base.metadata.drop_all(engine)
    fresh = SqlStore(database_url, engine=engine)
    fresh.create_schema()
    return fresh


def _record(
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


def test_the_migration_creates_the_schema_from_an_empty_database(database_url: str) -> None:
    engine = create_engine(database_url)
    Base.metadata.drop_all(engine)
    with engine.begin() as connection:
        # Alembic's own bookkeeping table is not part of the model metadata.
        connection.execute(text("DROP TABLE IF EXISTS alembic_version"))

    upgraded = alembic("upgrade", "head", database_url=database_url)

    assert upgraded.returncode == 0, upgraded.stderr
    assert "Running upgrade" in upgraded.stderr
    checked = alembic("check", database_url=database_url)
    assert checked.returncode == 0, checked.stderr
    assert "No new upgrade operations detected" in checked.stdout + checked.stderr

    with engine.connect() as connection:
        tables = set(
            connection.execute(
                text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
            ).scalars()
        )
        triggers = set(
            connection.execute(
                text("SELECT tgname FROM pg_trigger WHERE NOT tgisinternal")
            ).scalars()
        )
    assert {
        "receipts",
        "receipt_metadata",
        "policy_sets",
        "confirmation_grants",
        "audit_events",
        "evaluation_runs",
    } <= tables
    assert "aegisgraph_receipts_append_only" in triggers
    assert "aegisgraph_audit_events_append_only" in triggers
    assert "aegisgraph_policy_sets_immutable" in triggers


def test_append_only_tables_refuse_update_and_delete(store: SqlStore) -> None:
    """F7 regression: the audit trail cannot be rewritten or removed in place."""

    store.store_receipt(_record(request_id="append-only"))
    store.record_audit_event(
        # the event carries no payload-adjacent content, only identifiers
        _audit(store)
    )

    for statement in (
        "UPDATE receipts SET verdict = 'block' WHERE request_id = 'append-only'",
        "DELETE FROM receipts WHERE request_id = 'append-only'",
        "UPDATE audit_events SET event_type = 'tampered'",
        "DELETE FROM audit_events",
    ):
        with pytest.raises(DatabaseError) as error, store.engine.begin() as connection:
            connection.execute(text(statement))
        assert "append-only" in str(error.value)
        assert "55000" in str(error.value) or "ObjectNotInPrerequisiteState" in str(error.value)


def _audit(store: SqlStore) -> Any:
    from aegisgraph.store import AuditRecord

    return AuditRecord(
        tenant_id=TENANT,
        event_type="policy_set_created",
        actor_id="admin",
        subject="p:1",
        details={"checksum": "c" * 64},
        created_at=datetime.now(UTC),
    )


def test_policy_versions_are_immutable_while_the_activation_flag_may_change(
    store: SqlStore,
) -> None:
    document = dict(POLICY)
    store.create_policy_set(
        PolicyRecord(
            tenant_id=TENANT,
            id="p-1",
            version="1",
            document=document,
            checksum=digest_of(document),
            active=False,
            created_by="admin",
            created_at=datetime.now(UTC),
        )
    )

    for statement in (
        "UPDATE policy_sets SET document = '{\"allowed_tools\": []}'::jsonb",
        "UPDATE policy_sets SET checksum = repeat('e', 64)",
        "DELETE FROM policy_sets",
    ):
        with pytest.raises(DatabaseError) as error, store.engine.begin() as connection:
            connection.execute(text(statement))
        assert "policy_sets" in str(error.value)

    activated = store.activate_policy_set(TENANT, "p-1", "1", now=datetime.now(UTC))
    assert activated.active is True


def test_a_receipt_survives_a_restart(store: SqlStore, database_url: str) -> None:
    """F7's durable half: a new process (new engine) reads the stored receipt."""

    record = _record(request_id="durable-1")
    store.store_receipt(record)
    store.engine.dispose()

    restarted = SqlStore(database_url)

    loaded = restarted.get_receipt(TENANT, record.receipt_id)

    assert loaded is not None
    assert loaded.request_id == "durable-1"
    assert loaded.verdict == "allow"
    assert loaded.reason_codes == ("POLICY_CHECKS_PASSED",)
    assert loaded.action_digest == record.action_digest
    assert loaded.execution_digest == record.execution_digest
    assert loaded.payload_digest == record.payload_digest
    assert loaded.principal_id == "client-a"


def test_concurrent_duplicate_writes_store_exactly_one_row(store: SqlStore) -> None:
    record = _record(request_id="concurrent-db")

    with ThreadPoolExecutor(max_workers=8) as pool:
        stored = list(pool.map(lambda _: store.store_receipt(record), range(24)))

    assert {item.receipt_id for item in stored} == {record.receipt_id}
    with store.engine.connect() as connection:
        count = connection.execute(
            text("SELECT count(*) FROM receipts WHERE tenant_id = :tenant"),
            {"tenant": TENANT},
        ).scalar_one()
    assert count == 1


def test_grants_are_tenant_scoped_and_expire(store: SqlStore) -> None:
    from aegisgraph.store import GrantRecord

    now = datetime.now(UTC)
    store.issue_grant(
        GrantRecord(
            tenant_id=TENANT,
            run_id="run-1",
            step_id=2,
            execution_digest="d" * 24,
            issued_by="reviewer",
            issued_at=now,
            expires_at=now + timedelta(minutes=5),
        )
    )

    assert store.grant_exists(
        TENANT, run_id="run-1", step_id=2, execution_digest="d" * 24, now=now
    )
    assert not store.grant_exists(
        "tenant-b", run_id="run-1", step_id=2, execution_digest="d" * 24, now=now
    )
    assert not store.grant_exists(
        TENANT,
        run_id="run-1",
        step_id=2,
        execution_digest="d" * 24,
        now=now + timedelta(hours=1),
    )
    assert not store.grant_exists(
        TENANT, run_id="run-1", step_id=3, execution_digest="d" * 24, now=now
    )


def test_retention_redacts_the_payload_and_keeps_the_audit_row(store: SqlStore) -> None:
    now = datetime.now(UTC)
    store.store_receipt(
        _record(
            request_id="retention-db",
            metadata={"response_metadata": {"note": "payload-adjacent"}},
            created_at=now - timedelta(days=200),
        )
    )

    report = apply_retention(store, now=now, days=90)

    assert report.payloads_redacted == 1
    loaded = store.get_receipt(TENANT, "receipt-retention-db")
    assert loaded is not None
    assert loaded.metadata is None
    assert loaded.metadata_redacted_at is not None
    assert loaded.verdict == "allow"
    assert loaded.payload_digest == digest_of({"request_id": "retention-db"})
    events = [
        event
        for event in store.list_audit_events(TENANT)
        if event.event_type == EVENT_RETENTION_APPLIED
    ]
    assert len(events) == 1
    assert events[0].details["payloads_redacted"] == 1


def test_retention_redacts_evaluation_run_metadata_and_keeps_the_run(store: SqlStore) -> None:
    from aegisgraph.models import EvaluationRun

    now = datetime.now(UTC)
    with Session(store.engine) as session:
        session.add(
            EvaluationRun(
                tenant_id=TENANT,
                run_id="run-old",
                step_count=12,
                run_metadata={"note": "payload-adjacent"},
                created_at=now - timedelta(days=400),
            )
        )
        session.commit()

    report = apply_retention(store, now=now, days=90)

    assert report.runs_redacted == 1
    with Session(store.engine) as session:
        run = session.get(EvaluationRun, {"tenant_id": TENANT, "run_id": "run-old"})
        assert run is not None
        assert run.run_metadata is None
        assert run.redacted_at is not None
        assert run.step_count == 12


def test_the_api_persists_to_postgres_and_the_receipt_survives_a_restart(
    store: SqlStore,
    database_url: str,
    auth: AuthHarness,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """End-to-end: an authenticated decision lands in PostgreSQL and is re-readable."""

    monkeypatch.setenv("DATABASE_URL", database_url)
    reset_store_cache()
    seed_policy_set(TENANT, document=POLICY)

    with caplog.at_level(logging.INFO, logger="aegisgraph.decision"):
        created = client.post(
            "/api/v1/decisions",
            json=decision_payload(request_id="postgres-e2e"),
            headers=auth.header(role="decision_client", tenant=TENANT),
        )

    assert created.status_code == 200
    assert created.json()["decision"] == "allow"
    receipt_id = created.json()["receipt_id"]
    assert open_store(load_settings()).durable is True

    # A restart: the process cache is dropped and a new engine is built.
    reset_store_cache()
    auditor = auth.header(role="auditor", tenant=TENANT)
    read_back = client.get(f"/api/v1/receipts/{receipt_id}", headers=auditor)

    assert read_back.status_code == 200
    assert read_back.json()["request_id"] == "postgres-e2e"
    assert read_back.json()["verdict"] == "allow"
    assert read_back.json()["principal_id"] == "client-a"
    with store.engine.connect() as connection:
        rows = connection.execute(
            text("SELECT count(*) FROM receipts WHERE request_id = 'postgres-e2e'")
        ).scalar_one()
    assert rows == 1


def test_the_confirmation_channel_binds_grants_in_postgres(
    store: SqlStore, database_url: str, auth: AuthHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D4 through the API against the durable store: never-issued is refused."""

    monkeypatch.setenv("DATABASE_URL", database_url)
    reset_store_cache()
    seed_policy_set(
        TENANT,
        document={
            "allowed_tools": ["payment_execute"],
            "confirmation_required_tools": [],
            "consequential_tools": ["payment_execute"],
        },
    )
    submitter = auth.header(role="decision_client", tenant=TENANT)
    payload = decision_payload(run_id="pg-confirm", step_id=3, tool="payment_execute")
    payload["candidate_action"] = {
        "type": "tool_call",
        "tool": "payment_execute",
        "arguments": {"amount": 25},
    }

    unissued = client.post("/api/v1/decisions", json=payload, headers=submitter)
    assert unissued.status_code == 200
    assert unissued.json()["decision"] == "escalate"

    issued = client.post(
        "/api/v1/confirmations",
        json={
            "run_id": "pg-confirm",
            "step_id": 3,
            "execution_digest": unissued.json()["execution_digest"],
        },
        headers=auth.header(scopes=("confirmation:grant",), tenant=TENANT),
    )
    assert issued.status_code == 201
    confirmed = client.post(
        "/api/v1/decisions",
        json={**payload, "history_digest": {"confirmations_granted": [issued.json()["grant"]]}},
        headers=submitter,
    )

    assert confirmed.status_code == 200
    assert confirmed.json()["decision"] == "allow"
    assert confirmed.json()["reason_codes"] == ["CONFIRMATION_VERIFIED"]


def test_the_store_surface_is_complete_against_postgres(store: SqlStore) -> None:
    """Every read and write path of the durable store behaves as documented."""

    now = datetime.now(UTC)
    for index in range(3):
        store.store_receipt(
            _record(
                request_id=f"surface-{index}",
                metadata={"note": f"payload-{index}"},
                created_at=now - timedelta(seconds=index),
            )
        )
    store.store_receipt(_record(request_id="other-tenant", tenant="tenant-b"))

    # get_receipt: present, absent and tenant-scoped.
    first = store.get_receipt(TENANT, "receipt-surface-0")
    assert first is not None
    assert first.metadata == {"note": "payload-0"}
    assert store.get_receipt(TENANT, "receipt-missing") is None
    assert store.get_receipt("tenant-c", "receipt-surface-0") is None

    # list_receipts: newest first, bounded, cursor-paged, tenant-scoped.
    page, cursor = store.list_receipts(TENANT, limit=2)
    assert [item.request_id for item in page] == ["surface-0", "surface-1"]
    assert cursor is not None
    rest, cursor = store.list_receipts(TENANT, limit=2, cursor=cursor)
    assert [item.request_id for item in rest] == ["surface-2"]
    assert cursor is None
    assert store.list_receipts(TENANT, limit=2, cursor="not-a-cursor") == ([], None)
    assert store.list_receipts("tenant-b", limit=10)[0][0].request_id == "other-tenant"

    # store_receipt is idempotent and refuses a reused request_id for another action.
    duplicate = store.store_receipt(_record(request_id="surface-0"))
    assert duplicate.receipt_id == "receipt-surface-0"
    from aegisgraph.store import ReceiptConflictError

    with pytest.raises(ReceiptConflictError):
        store.store_receipt(replace(_record(request_id="surface-0"), action_digest="f" * 24))

    # policy versions: create, idempotent re-create, lookup, list, activate.
    document = dict(POLICY)
    record = PolicyRecord(
        tenant_id=TENANT,
        id="p-surface",
        version="1",
        document=document,
        checksum=digest_of(document),
        active=False,
        created_by="admin",
        created_at=now,
    )
    created = store.create_policy_set(record)
    assert created.version == "1"
    assert store.create_policy_set(record).checksum == created.checksum
    assert store.get_policy_set(TENANT, "p-surface", "1") is not None
    assert store.get_policy_set(TENANT, "p-surface", "9") is None
    assert [item.version for item in store.list_policy_sets(TENANT)] == ["1"]
    assert store.active_policy_set(TENANT, "p-surface") is None
    activated = store.activate_policy_set(TENANT, "p-surface", "1", now=now)
    assert activated.active is True
    assert store.active_policy_set(TENANT, "p-surface") is not None
    from aegisgraph.store import UnknownPolicySetError

    with pytest.raises(UnknownPolicySetError):
        store.activate_policy_set(TENANT, "p-surface", "9", now=now)

    # audit trail and readiness.
    store.record_audit_event(_audit(store))
    events = store.list_audit_events(TENANT)
    assert [event.event_type for event in events] == ["policy_set_created"]
    assert events[0].details == {"checksum": "c" * 64}
    assert store.ready() is True
    unreachable = SqlStore("postgresql+psycopg://nobody:nothing@127.0.0.1:1/absent?connect_timeout=1")
    assert unreachable.ready() is False


def test_the_administration_surfaces_read_and_write_postgres(
    store: SqlStore, database_url: str, auth: AuthHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same admin API drives the durable store, with tenant scoping intact."""

    monkeypatch.setenv("DATABASE_URL", database_url)
    reset_store_cache()
    admin = auth.header(role="policy_admin", tenant=TENANT)

    published = client.post(
        "/api/v1/policies",
        json={"id": "p-api", "version": "1", "document": POLICY, "activate": True},
        headers=admin,
    )
    assert published.status_code == 201
    assert published.json()["active"] is True
    listed = client.get("/api/v1/policies", headers=admin)
    assert [item["id"] for item in listed.json()["items"]] == ["p-api"]
    trail = client.get("/api/v1/audit-events", headers=admin)
    kinds = [item["event_type"] for item in trail.json()["items"]]
    assert kinds.count("policy_set_created") == 1
    assert kinds.count("policy_set_activated") == 1

    submitted = client.post(
        "/api/v1/decisions",
        json=decision_payload(
            request_id="admin-e2e", policy_set={"id": "p-api", "version": "1"}
        ),
        headers=auth.header(role="decision_client", tenant=TENANT),
    )
    assert submitted.status_code == 200
    auditor = auth.header(role="auditor", tenant=TENANT)
    page = client.get("/api/v1/receipts?limit=5", headers=auditor)
    assert page.status_code == 200
    assert any(item["request_id"] == "admin-e2e" for item in page.json()["items"])
    other = client.get(
        "/api/v1/receipts?limit=5", headers=auth.header(role="auditor", tenant="tenant-b")
    )
    assert other.json()["items"] == []
