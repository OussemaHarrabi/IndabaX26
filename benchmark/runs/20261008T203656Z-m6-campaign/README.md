# M6 campaign cell C1 (+ C2): native benchmark against the frozen gateway

Committed evidence for freeze block 1 (`docs/evidence/m6-freeze.md`). One run, taken
from the frozen commit with a clean tree, against a service backed by a durable
PostgreSQL 17 receipt store.

| Field | Value |
| --- | --- |
| Run | `20261008T203656Z-m6-campaign` |
| Gateway commit | `818cf1f29795aa5d1e92b90fe4dfd4ed13174e03` (`code.commit_source = git-rev-parse-HEAD`) |
| Working tree at run time | `code.dirty = false` |
| Branch | `feat/m6-campaign` |
| Surface | `POST /api/v1/decisions`, `http://127.0.0.1:8091`, policy set `aegisgraph-default/1` |
| Authentication | `AEGISGRAPH_AUTH_MODE=required`, local dev issuer, `Authorization: Bearer`, principal `m6-decision-client` |
| Receipt store | durable PostgreSQL 17.11 (container `aegisgraph-m2-pg`, database `aegisgraph_m6`); `/readyz` reported `receipt_store {durable: true, reachable: true}` |
| Model | `model.kind = scripted` — no model exists in this environment, so this measures the **gateway**, not a model |
| Seed / temperature / max tokens | `1729` / `None` / `None` |
| Splits | `development, validation` — 60 scenarios; the sealed holdout stayed closed |
| Dataset hash | `7e916a11981fa6444724dc78558e51561d32a3005b182862efb52b7c5f2cf735` |
| Scenario-set hash | `e4f376b2057ead47ed41a527e9b680a1a4c092cd5c9328ec2399eadeb0d77b75` |
| `policy.gate` / `policy.blob_sha256` | `H5.2` / `53d663b1853673da6ccfa0e4e673dbaa196bcf2517d6c1517aa1268fea9153f1` |
| Hash convention | `content-sha256-lf: sha256(bytes) with CRLF normalised to LF, no object header` |
| Decision digest | `b6951afb6db8fde2dd029d1e964312094d853487ae79d1abfdde02dc08b2581d` |
| Outcomes / control | `58b79e85d12c9683d660af7b59c4b7d0b066b15c0c65d60476725a95007198fd` / `ea204a61e1c2fe0114548f5a3e4ba8f2069c720dc17a8694f3070e986811d4a5` |
| Derived `score.json` / `score.txt` | `05f22292002cbd6e0739d5d6705227a34ca275e0167da971b7d5fc68172dd447` / `d9fec910ded9378cedd3c3ab22c38d49f6a8690dcf83f5d360d49bfeb0206984` |

## Exact commands

```bash
# 1. a campaign database on the running PostgreSQL 17 container, migrated
docker exec aegisgraph-m2-pg psql -U aegisgraph -d aegisgraph -c "CREATE DATABASE aegisgraph_m6;"
DATABASE_URL="postgresql+psycopg://aegisgraph:m2-local-only@127.0.0.1:15532/aegisgraph_m6" \
  python -m alembic upgrade head

# 2. the frozen gateway (from this worktree at 818cf1f29795, clean tree)
AEGISGRAPH_AUTH_MODE=required AEGISGRAPH_ENVIRONMENT=development \
AEGISGRAPH_LEGACY_UNAUTHENTICATED=true \
AEGISGRAPH_JWT_ISSUER=https://dev-issuer.aegisgraph.local AEGISGRAPH_JWT_AUDIENCE=aegisgraph \
AEGISGRAPH_JWKS=<issuer-dir>/jwks.json \
DATABASE_URL="postgresql+psycopg://aegisgraph:m2-local-only@127.0.0.1:15532/aegisgraph_m6" \
PYTHONPATH=backend python -m uvicorn aegisgraph.app:app --host 127.0.0.1 --port 8091

# 3. the tokens (dev_issuer prints JSON; write the token field as UTF-8 without a BOM)
python scripts/dev_issuer.py init
python scripts/dev_issuer.py mint --tenant m6 --subject m6-policy-admin \
  --role policy_admin --ttl 10800 > <tmp>/policy-admin.json
python scripts/dev_issuer.py mint --tenant m6 --subject m6-decision-client \
  --role decision_client --ttl 10800 > <tmp>/decision.json

# 4. publish the policy sets the scenarios pin, then run C1 (+ C2, the internal control)
python scripts/bench_policies.py publish --defense-url http://127.0.0.1:8091 \
  --token-file <tmp>/policy-admin.jwt
python scripts/bench_run.py --defense-url http://127.0.0.1:8091 --model scripted \
  --splits development,validation --auth-token-file <tmp>/decision.jwt \
  --timestamp 20261008T203656Z --config-slug m6-campaign \
  --hardware-note "Windows 10.0.26200 x64, CPython 3.13.14, loopback; PostgreSQL 17.11 container on port 15532 (durable receipt store)"

# 5. C4 determinism: score twice and compare, then write the committed copies
python scripts/bench_score.py --run benchmark/runs/20261008T203656Z-m6-campaign --json --out <tmp>/a.json
python scripts/bench_score.py --run benchmark/runs/20261008T203656Z-m6-campaign --json --out <tmp>/b.json
cmp <tmp>/a.json <tmp>/b.json
python scripts/bench_score.py --run benchmark/runs/20261008T203656Z-m6-campaign --json --out benchmark/runs/20261008T203656Z-m6-campaign/score.json
python scripts/bench_score.py --run benchmark/runs/20261008T203656Z-m6-campaign > benchmark/runs/20261008T203656Z-m6-campaign/score.txt
```

## C1 result

```
native benchmark scoring (min slice n=3, 60 outcomes)
deterministic digest: b6951afb6db8fde2dd029d1e964312094d853487ae79d1abfdde02dc08b2581d
slice                                  asr       att    asr*  err     bts       ben     fbr    fbrs     esc      rw     rws      p50      p95
overall                             0.5000     15/30  0.5000    0  0.9667     29/30  0.0556  0.0417  0.0714  0.0000     n/a  35.6580  54.3733
control (allow-all)                 1.0000     30/30  1.0000    0  0.8000     24/30  0.0000  0.0000  0.0000  0.0000     n/a   2.2877  23.7215
  enterprise                        0.4000      4/10  0.4000    0  1.0000     10/10  0.0000  0.0000  0.0755  0.0000     n/a  40.8444  53.7328
  finance                           0.6000      6/10  0.6000    0  0.9000      9/10  0.1111  0.1250  0.0702  0.0000     n/a  36.2424  63.1666
  soc                               0.5000      5/10  0.5000    0  1.0000     10/10  0.0556  0.0000  0.0690  0.0000     n/a  27.8901  48.5379
```

Full per-family and per-domain/family tables, with every suppressed metric named:
`score.txt`. Machine-readable report: `score.json`.

## C2 licence (the runner's internal allow-all control)

| Field | Value |
| --- | --- |
| `control_licensed` | 30 |
| `control_excluded` | 0 |
| `control_excluded_ids` | `[]` |
| `effectiveness_claim` | true |
| control `asr` | 1.0000 (30/30) |

Every attack scenario is licensed by the control configuration, so the C1
effectiveness numbers are computed over all 30 reached attacks; nothing was excluded.

## C4 determinism

Two independent `bench_score.py --json` invocations over this run directory are
byte-identical (`cmp` exit 0), and the committed `score.json` reproduces from the
committed `outcomes.jsonl`/`control.jsonl`. The documented digest
`b6951afb6db8fde2dd029d1e964312094d853487ae79d1abfdde02dc08b2581d` is what a
re-scoring of this directory prints.

## Why the latency is higher than the previous reference run

`p50 35.66 ms` here against `9.11 ms` in
`benchmark/runs/20261008T230000Z-m2-authenticated-full/`. The difference is the
receipt store: this run persists every decision to PostgreSQL 17, the previous one
used the gateway's in-process `MemoryStore`. Latency is excluded from the decision
digest, so this does not affect comparability of the verdicts; it does mean the two
runs' latency rows are not paired measurements and must not be compared as such
(claim language §2.8).

## What this cell licenses

- On the native 60-scenario benchmark (dataset
  `7e916a11981fa6444724dc78558e51561d32a3005b182862efb52b7c5f2cf735`, 42
  development + 18 validation) with the **scripted replay** — no model — at
  gateway commit `818cf1f`, policy set
  `aegisgraph-default/1` (policy blob
  `53d663b18536…`), seed `1729`, among the
  30 attacks reached under allow-all (of 30 attack scenarios; 0 excluded and
  counted), the gateway authorised `15/30` attack steps (`asr = 0.5000`), allowed
  `29/30` benign controls, and produced 0 decision errors.
- It does **not** license any claim about model behaviour: the adapter is
  `scripted`, recorded as `model.kind = "scripted"`, so the numbers measure the
  gateway under a fixed action plan.
- `rws` is `n/a` because no decision in this run was a rewrite — an undefined
  denominator, not a zero. The `unsafe_rewrite` attacks were **allowed**, not
  rewritten, so the secret reached the action (`leaked = true`); that is a
  disclosure, and it is not counted as a rewrite failure.
- The control's `benign_task_success` is `0.8000` by construction: six open controls
  declare `expectation = "escalated"`, and the allow-all control returns `allow`.

## Files

| File | Written by | Meaning |
| --- | --- | --- |
| `manifest.json` | the runner | the configuration identity, the policy blob hash, the code identity and the artifact hashes |
| `outcomes.jsonl` | the runner | one judged outcome per scenario with every raw verdict |
| `control.jsonl` | the runner | the same episodes against the allow-all control |
| `score.json`, `score.txt` | `scripts/bench_score.py` | derived and reproducible from the two files above |
