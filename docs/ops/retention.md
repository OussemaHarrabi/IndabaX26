# Retention and deletion

Status: Milestone 2. Implements decision **D6**: the audit trail is retained
indefinitely, payload-adjacent data is not.

## 1. What is kept and what expires

| Data | Table | Lifetime |
| --- | --- | --- |
| digests (`action_digest`, `execution_digest`, `payload_digest`) | `receipts` | **indefinitely** |
| verdicts, risk score, confidence, reason codes | `receipts` | **indefinitely** |
| policy identity (`policy_set_id`, `policy_set_version`) | `receipts` | **indefinitely** |
| actor identity (`principal_id`, `auth_method`) | `receipts` | **indefinitely** |
| decision identity (`receipt_id`, `request_id`, `run_id`, `step_id`, timestamps) | `receipts` | **indefinitely** |
| policy versions and the activation flag | `policy_sets` | **indefinitely** (immutable) |
| confirmation grants | `confirmation_grants` | **indefinitely** (they are authorization evidence) |
| audit events | `audit_events` | **indefinitely** (append-only) |
| response metadata (payload-adjacent) | `receipt_metadata.metadata` | `AEGISGRAPH_RETENTION_DAYS`, then redacted to `NULL` |
| evaluation-run metadata | `evaluation_runs.metadata` | `AEGISGRAPH_RETENTION_DAYS`, then redacted to `NULL` |

Payload-adjacent metadata is **digest-only by default**: unless
`AEGISGRAPH_STORE_PAYLOAD_METADATA=true`, the service stores
`receipts.payload_digest` and no copy of the metadata at all. The opt-in exists for
deployments that need the copy for a bounded time; the retention procedure is what
makes that safe.

## 2. The window

| Variable | Default | Meaning |
| --- | --- | --- |
| `AEGISGRAPH_RETENTION_DAYS` | `90` | age at which payload-adjacent data is redacted |
| `DATABASE_URL` | — | the durable store; the script refuses to run without it |

## 3. Running a retention pass

```console
$ export DATABASE_URL='postgresql+psycopg://user:secret@host:5432/aegisgraph'
$ python scripts/retention.py
{"cutoff": "2026-07-10T09:00:00+00:00", "payloads_redacted": 12, "retention_days": 90, "runs_redacted": 0, "tenants": ["tenant-a"]}
$ python scripts/retention.py --days 30
$ python scripts/retention.py --now 2026-10-08T00:00:00Z   # replay a pass at a fixed instant
```

* `--days` overrides `AEGISGRAPH_RETENTION_DAYS` for one pass; it must not be
  negative.
* `--now` accepts an ISO-8601 instant **with an offset**, which makes a pass
  reproducible and testable.
* The command is idempotent: a second pass with the same cutoff redacts nothing
  because the rows are already `NULL`.
* Every pass writes one `retention_applied` audit event per affected tenant,
  recording the cutoff, the window and the counts — never any content.

Schedule it (cron, Kubernetes `CronJob`, a task runner) at least as often as the
window: the window is a maximum age, not a guarantee of punctuality.

## 4. What a pass does, precisely

```sql
UPDATE receipt_metadata
   SET metadata = NULL, redacted_at = now()
 WHERE created_at < cutoff AND metadata IS NOT NULL;

UPDATE evaluation_runs
   SET metadata = NULL, redacted_at = now()
 WHERE created_at < cutoff AND metadata IS NOT NULL;
```

* The row itself survives, so `metadata_digest` (the digest) and every audit column
  remain readable.
* `redacted_at` records when the redaction happened.
* `receipts`, `audit_events`, `policy_sets` and `confirmation_grants` are never
  touched — the database refuses it anyway (see [migrations.md](migrations.md)).
* Nothing is deleted from a table that carries audit identity. "Deletion" here means
  the payload-adjacent field is destroyed, which is the behaviour D6 authorises
  ("digest-only **or** redacted").

## 5. Verifying a pass

```console
$ psql "$DATABASE_URL" -c \
  "SELECT count(*) FILTER (WHERE metadata IS NULL) AS redacted,
          count(*) AS total FROM receipt_metadata"
$ psql "$DATABASE_URL" -c \
  "SELECT event_type, details FROM audit_events WHERE event_type = 'retention_applied' ORDER BY id DESC LIMIT 1"
```

`tests/test_receipts_api.py` and `tests/test_postgres_store.py` assert the same
properties: after a pass, the payload is gone, `redacted_at` is set, and the verdict,
reason codes and every digest are intact and still readable through
`GET /api/v1/receipts/{receipt_id}`.

## 6. Purges and erasure requests

The append-only triggers refuse row-level `UPDATE` and `DELETE` on `receipts` and
`audit_events`. A genuine erasure (a legal request, a test-database reset) is a
privileged DDL operation:

```sql
TRUNCATE receipts, receipt_metadata, audit_events;
```

Row-level triggers do not fire on `TRUNCATE`, so this works — which is exactly why
it must be treated as break-glass: require a change record, prefer a scoped
`WHERE`-less purge on a copy, and note that `TRUNCATE` cannot be selective. Prefer
redaction (section 4) whenever the request is about payload content rather than about
the audit trail itself.

## 7. Retention and the trust boundary

Retention never changes a decision's meaning: it removes content that could be
payload-adjacent, and keeps the digests that let a caller re-verify an action
through `backend/aegisgraph/enforcement.py`. A receipt whose `metadata` was redacted
still enforces identically, because enforcement reads `receipt_id`, `policy_set`,
`action_digest`, `execution_digest` and `valid_until` — none of which expire.
