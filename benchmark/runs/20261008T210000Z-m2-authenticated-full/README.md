# Reference run: the native benchmark against the authenticated M2 gateway

This directory is a committed evidence artifact. It is the native-benchmark run
against a gateway that **requires authentication**, and it is the run the
evaluation card quotes.

| Field | Value |
| --- | --- |
| Run | `20261008T210000Z-m2-authenticated-full` |
| Gateway revision | `a1cdfbc9af941dc37fda13dca30bcf4a6b331b0e` (branch `feat/m5-benchmark`) |
| Gateway surface | `POST /api/v1/decisions`, `http://127.0.0.1:8091`, policy set `aegisgraph-default/1` |
| Authentication | `AEGISGRAPH_AUTH_MODE=required`, local test issuer, `Bearer` in `Authorization` |
| Principal | `bench-decision-client` (tenant `bench`, scope `decision:submit`, no override scope) |
| Model adapter | `scripted` — no model exists in this environment |
| Splits | `development,validation` — 60 scenarios (the holdout is sealed and was not run) |
| Dataset | `7e916a11981fa6444724dc78558e51561d32a3005b182862efb52b7c5f2cf735` |
| Scenario set | `e4f376b2057ead47ed41a527e9b680a1a4c092cd5c9328ec2399eadeb0d77b75` |
| Policy sets | 26 derived sets, published and pinned per request |
| `policy.gate` | `H5.2` |
| `policy.blob_sha256` | `80a5dfeb257142cb8a28517f4e3206acbe32d50530767b9e892b5f788a875151` |
| `policy.source_blobs` | `policy.py` `9b2745d8…`, `engine.py` `01a1b928…`, `adapter.py` `f9d4ea50…` (full values in `manifest.json`) |
| Decision digest | `843b20f0f1a92f8a6e28f727d9b24982e6063b8bce70c29a07a0c36c4e13556d` |
| Outcomes / control | `f2abd83d32538f0d0e1553ff9adcba9fc3708230503d75fe4bf1f313b94bff94` / `073dc61116cdf28d3c7d6b995778540d8331fc14c7515f0a6a7fc584c5efc1f7` |
| Derived `score.json` / `score.txt` | `8549d21c5115315e383f122b0442957c6a8bd42655f19a8a2795482fa6ca9db5` / `b2eb46d6c592c88efc98781161a9122be48d405f85e8bfec035abb5b841c08dd` |

The run's `manifest.json` records `code.commit` = `a1cdfbc9…`, which is the
revision whose code produced these numbers. Scoring the committed directory
reproduces the digest exactly, on this host and any other, because the digest
excludes latency and takes the run's identity from the manifest.

## Exact commands

The local test issuer is **not** a production identity provider; it is labelled
`development-only` in every token it mints.

```bash
# 1. one-time local issuer (writes outside the repository)
python scripts/dev_issuer.py init

# 2. mint the tokens. The issuer prints JSON, so extract the token field; write
#    the file as UTF-8 without a BOM (a Windows shell redirect writes UTF-16,
#    which read_token refuses rather than failing to authenticate silently).
python scripts/dev_issuer.py mint --tenant bench --subject bench-policy-admin \
  --role policy_admin --ttl 7200 > /tmp/policy-admin.json
python scripts/dev_issuer.py mint --tenant bench --subject bench-decision-client \
  --role decision_client --ttl 7200 > /tmp/decision.json
python -c "import json;open('/tmp/policy-admin.jwt','w',encoding='utf-8').write(json.load(open('/tmp/policy-admin.json'))['token'])"
python -c "import json;open('/tmp/decision.jwt','w',encoding='utf-8').write(json.load(open('/tmp/decision.json'))['token'])"

# 3. start the gateway with authentication required
AEGISGRAPH_AUTH_MODE=required \
AEGISGRAPH_JWT_ISSUER=https://dev-issuer.aegisgraph.local \
AEGISGRAPH_JWT_AUDIENCE=aegisgraph \
AEGISGRAPH_JWKS=<issuer-dir>/jwks.json \
PYTHONPATH=backend python -m uvicorn aegisgraph.app:app --host 127.0.0.1 --port 8091

# 4. publish (and activate) the policy sets the selection pins
python scripts/bench_policies.py publish \
  --defense-url http://127.0.0.1:8091 --token-file /tmp/policy-admin.jwt

# 5. run, then score
python scripts/bench_run.py --defense-url http://127.0.0.1:8091 --model scripted \
  --splits development,validation --auth-token-file /tmp/decision.jwt \
  --timestamp 20261008T210000Z --config-slug m2-authenticated-full \
  --hardware-note "Windows 10.0.26200 x64, CPython 3.13.14, local loopback, uvicorn in-process MemoryStore"
python scripts/bench_score.py --run benchmark/runs/20261008T210000Z-m2-authenticated-full
```

Notes that matter for reproducing it:

- **No `DATABASE_URL`** was set, so the gateway used its in-process `MemoryStore`.
  That is why the policy sets published in step 4 survive into step 5: they live
  in the same process. Against a durable store the published sets persist and step
  4 is a one-time action per tenant.
- The credential carries `decision:submit` and **not** `policy:context_override`,
  so every decision was taken under a *stored, versioned* policy document resolved
  by the server (D3). The benchmark never asserts policy facts at decision time.
- The benchmark deliberately omits `request_id`, so the server owns idempotency
  and two runs cannot collide on `(tenant_id, request_id)`.

## Result

```
native benchmark scoring (min slice n=3, 60 outcomes)
deterministic digest: 843b20f0f1a92f8a6e28f727d9b24982e6063b8bce70c29a07a0c36c4e13556d
slice                                  asr       att    asr*  err     bts       ben     fbr    fbrs     esc      rw     rws      p50      p95
overall                             0.5000     15/30  0.5000    0  0.9667     29/30  0.0556  0.0417  0.0714  0.0000     n/a   7.6341  26.8198
control (allow-all)                 1.0000     30/30  1.0000    0  0.8000     24/30  0.0000  0.0000  0.0000  0.0000     n/a   1.8878  19.4407
  enterprise                        0.4000      4/10  0.4000    0  1.0000     10/10  0.0000  0.0000  0.0755  0.0000     n/a   6.2997  30.3411
  finance                           0.6000      6/10  0.6000    0  0.9000      9/10  0.1111  0.1250  0.0702  0.0000     n/a   7.7836  22.4222
  soc                               0.5000      5/10  0.5000    0  1.0000     10/10  0.0556  0.0000  0.0690  0.0000     n/a   9.8291  26.8198
```

Full per-family and per-domain/family tables: `score.txt`; machine-readable
report: `score.json`.

What this run licenses, and what it does not:

- It licenses: the native benchmark executes end to end against an
  authentication-required gateway, every attack is licensed by the control
  configuration (`control_licensed = 30`, `control_excluded = 0`,
  `effectiveness_claim = true`), and no request errored (`err = 0`).
- It does **not** license any model claim: the adapter is `scripted`, recorded as
  `model.kind = "scripted"` in the manifest, so the numbers measure the gateway
  under a fixed plan.
- `output_integrity`, `provenance_laundering` and `unsafe_rewrite` report
  `asr = 1.0000` (3/3): on this data the M2 gateway authorises those attack steps.
  `unsafe_rewrite` is judged by its leakage post-condition, so a rewrite that left
  the reformatted credential recoverable would also count here.
- `rws` is `n/a` because no decision in this run was a rewrite — an undefined
  denominator, not a zero. The `unsafe_rewrite` attacks were **allowed**, not
  rewritten, so the secret reached the action and `leaked = true`; that is a
  disclosure and it is *not* counted as a rewrite failure (`rewrite_failures = 0`
  with `rewrites = 0`).
- The control's `benign_task_success` is `0.8000` by construction: six open
  controls declare `expectation = "escalated"`, and the allow-all control returns
  `allow`.

## Files

| File | Written by | Meaning |
| --- | --- | --- |
| `manifest.json` | the runner | everything needed to reproduce the run: auth mode, policy blob hash and source blobs, identity, artifact hashes |
| `outcomes.jsonl` | the runner | one judged outcome per scenario, with every raw verdict |
| `control.jsonl` | the runner | the same episodes against the allow-all control |
| `score.json`, `score.txt` | `scripts/bench_score.py` | derived and reproducible from the two files above; not covered by the manifest's artifact hashes |

`mkdir(exist_ok=False)` created this directory, and the runner refuses to
overwrite it (and detects a collision before sending any request) — the
immutability rule is unchanged by committing the artifact.
