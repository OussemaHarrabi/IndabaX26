# Migrations

Status: Milestone 2. PostgreSQL is the only supported database.

The schema lives in `backend/aegisgraph/models.py`; the migration that creates it is
`backend/migrations/versions/0001_initial.py`. Alembic configuration is at the
repository root (`alembic.ini`, `script_location = backend/migrations`).

## 1. Running a migration

The database URL is **never** stored in `alembic.ini`. It is read from
`DATABASE_URL`, so a migration run and the service always agree on the target:

```console
$ export DATABASE_URL='postgresql+psycopg://user:secret@host:5432/aegisgraph'
$ python -m alembic upgrade head
INFO  [alembic.runtime.migration] Context impl PostgresqlImpl.
INFO  [alembic.runtime.migration] Will assume transactional DDL.
INFO  [alembic.runtime.migration] Running upgrade  -> 0001_initial, Initial AegisGraph persistence schema (M2).
$ python -m alembic check
No new upgrade operations detected.
```

`alembic check` fails when the models and the database disagree, which makes it the
drift gate: run it after `upgrade head` in CI. `alembic upgrade head --sql` emits the
DDL without connecting. `alembic downgrade base` drops every table and the two
trigger functions.

A missing `DATABASE_URL` aborts with a non-zero exit and a one-line message rather
than connecting to a default.

## 2. Tables

| Table | Purpose | Mutability |
| --- | --- | --- |
| `receipts` | one durable decision record per `(tenant_id, request_id)` | **append-only**: `UPDATE` and `DELETE` raise |
| `receipt_metadata` | payload-adjacent copy, redacted by the retention window | `metadata` may be set to `NULL` once |
| `policy_sets` | immutable policy versions plus the activation flag | `DELETE` raises; only `active`/`activated_at` may change |
| `confirmation_grants` | issued confirmation grants (D4) | insert only |
| `audit_events` | administrative and security trail | **append-only** |
| `evaluation_runs` | run metadata reserved for the evaluation milestones | `metadata` may be redacted |

## 3. Append-only enforcement

Three triggers are installed by the migration from the single source of truth
`aegisgraph.models.APPEND_ONLY_STATEMENTS`:

```
aegisgraph_receipts_append_only      BEFORE UPDATE OR DELETE ON receipts
aegisgraph_audit_events_append_only  BEFORE UPDATE OR DELETE ON audit_events
aegisgraph_policy_sets_immutable     BEFORE UPDATE OR DELETE ON policy_sets
```

They raise SQLSTATE `55000` with a message naming the table and the operation:

```console
$ psql "$DATABASE_URL" -c "UPDATE receipts SET verdict = 'allow'"
ERROR:  aegisgraph: receipts is append-only; UPDATE is refused
```

`aegisgraph_policy_sets_immutable` allows exactly one mutation — flipping
`active`/`activated_at` — and refuses everything else, including `DELETE`.

### What the guarantee does not cover

`TRUNCATE` is a privileged DDL operation that row-level triggers do not intercept.
Purging an audit trail therefore requires a deliberate `TRUNCATE` (or a table drop)
by an operator with DDL rights; it cannot happen through the application, whose only
SQL is parameterized `INSERT`/`SELECT`/`UPDATE` on the allowed columns. Treat the
`TRUNCATE` privilege as break-glass and record it in the change log.

## 4. Migrating an empty database

```console
$ createdb aegisgraph
$ DATABASE_URL=postgresql+psycopg://user:secret@host:5432/aegisgraph python -m alembic upgrade head
$ DATABASE_URL=postgresql+psycopg://user:secret@host:5432/aegisgraph python -m alembic check
No new upgrade operations detected.
```

The test suite proves this path: `tests/test_postgres_store.py` drops every table
(including `alembic_version`), runs `upgrade head`, asserts `check` reports no
drift, and asserts the triggers exist.

```console
$ AEGISGRAPH_TEST_DATABASE_URL=postgresql+psycopg://user:secret@127.0.0.1:15532/postgres \
    python -m pytest -m db -q
```

The `db` marker is registered in `tests/conftest.py`. Tests that carry it skip
cleanly when `AEGISGRAPH_TEST_DATABASE_URL` is unset, so the rest of the suite runs
with no database at all.

## 5. Adding a migration

1. Change `backend/aegisgraph/models.py`.
2. `DATABASE_URL=... python -m alembic revision --autogenerate -m "short description"`.
3. Read the generated file: autogenerate does not emit triggers, so add any new
   append-only statement to `APPEND_ONLY_STATEMENTS` in `models.py` and apply it with
   `op.execute(statement)` — that keeps one source of truth.
4. Run `upgrade head` and `check` against an empty database, then the `db` tests.

## 6. The containerized development database

```console
$ docker run --rm -d --name aegisgraph-pg \
    -e POSTGRES_USER=aegisgraph -e POSTGRES_PASSWORD=local-only -e POSTGRES_DB=aegisgraph \
    -p 15532:5432 postgres:17
$ export DATABASE_URL='postgresql+psycopg://aegisgraph:local-only@127.0.0.1:15532/aegisgraph'
$ python -m alembic upgrade head
```

Choose a free host port: on Windows, parts of the ephemeral range are reserved and
`docker run -p` fails with "an attempt was made to access a socket in a way forbidden
by its access permissions".
