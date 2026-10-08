# Reference run: the native benchmark against the authenticated M2 gateway

This directory is a committed evidence artifact. It is the native-benchmark run
against a gateway that **requires authentication**, and it is the run the
evaluation card quotes.

| Field | Value |
| --- | --- |
| Run | `20261008T230000Z-m2-authenticated-full` |
| Gateway revision | `a94ce6f8003989884be2fb40d06dc99ac721763c` (branch `feat/m5-benchmark`), `code.commit_source = "git-rev-parse-HEAD"` |
| Working tree at run time | `code.dirty = false` — the tree was clean when this run started |
| Gateway surface | `POST /api/v1/decisions`, `http://127.0.0.1:8091`, policy set `aegisgraph-default/1` |
| Authentication | `AEGISGRAPH_AUTH_MODE=required`, local test issuer, `Bearer` in `Authorization` |
| Principal | `bench-decision-client` (tenant `bench`, scope `decision:submit`, no override scope) |
| Model adapter | `scripted` — no model exists in this environment |
| Splits | `development,validation` — 60 scenarios (the holdout is sealed and was not run) |
| Dataset | `7e916a11981fa6444724dc78558e51561d32a3005b182862efb52b7c5f2cf735` |
| Scenario set | `e4f376b2057ead47ed41a527e9b680a1a4c092cd5c9328ec2399eadeb0d77b75` |
| Policy sets | 26 derived sets, published and pinned per request |
| `policy.gate` | `H5.2` |
| `policy.blob_sha256` | `53d663b1853673da6ccfa0e4e673dbaa196bcf2517d6c1517aa1268fea9153f1` |
| `dependency_lock.sha256` | `b49b8c5d328f5823f07f5aa96bbc63572376e857a982bff2050781d57b5f93fd` |
| Hash convention (all recorded hashes) | `content-sha256-lf: sha256(bytes) with CRLF normalised to LF, no object header` |
| `policy.source_blobs` | `policy.py` `a072f462…`, `engine.py` `d4bfdc0d…`, `adapter.py` `6a3f1a0c…` (full values in `manifest.json`) |
| Decision digest | `8d79f032d3018ed0618088b004094d1ba30dfe14605390f375e560b5c04aee13` |
| Outcomes / control | `501f1b484945a1349696446b053c4d1506873e37c1e087ddf7bd109154577f10` / `6b8fae405701b1c8f50f2a3d788439faa14dfedf1197eaaa88acbadd6b8338f6` |
| Derived `score.json` / `score.txt` | `49441e82b64d0aaf46d2dc38aadf43ade769e383ed2264f2046ef3acb2a3bdc5` / `57573a77b7a7bc2efcb77cd4950e926a525cbad43202b09ed466f21a53000e3d` |

**One hash convention.** Every hash this runner records — the dependency lock, the
policy document map, the policy source files — uses the same convention, written
into the manifest beside the value: SHA-256 of the content bytes with CRLF
normalised to LF and no git object header. The runner reads the *committed* bytes
through git when it can, so a Windows checkout and a Linux checkout produce the
same value, and `dependency_lock.sha256` is directly comparable with
`source.requirements_lock_sha256` in `deploy/sbom/aegisgraph-image-sbom.json`.

**Tree state.** `code.dirty = false`: the run started from a clean tree, so the
recorded commit is the code that produced it. A run taken with uncommitted changes
records `code.dirty = true` instead of claiming a commit identity it does not
have; if that ever happens, the README of that run must say which paths were
dirty.

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
  --timestamp 20261008T230000Z --config-slug m2-authenticated-full \
  --hardware-note "Windows 10.0.26200 x64, CPython 3.13.14, local loopback, uvicorn in-process MemoryStore"
python scripts/bench_score.py --run benchmark/runs/20261008T230000Z-m2-authenticated-full
```

Notes that matter for reproducing it:

- **No `DATABASE_URL`** was set, so the gateway used its in-process `MemoryStore`.
  That is why the policy sets published in step 4 survive into step 5: they live in
  the same process. Against a durable store the published sets persist and step 4
  is a one-time action per tenant.
- The credential carries `decision:submit` and **not** `policy:context_override`,
  so every decision was taken under a *stored, versioned* policy document resolved
  by the server (D3). The benchmark never asserts policy facts at decision time.
- The benchmark deliberately omits `request_id`, so the server owns idempotency and
  two runs cannot collide on `(tenant_id, request_id)`.
- Scoring the committed directory reproduces `score.json` byte-identically on this
  host and any other, because the digest excludes latency and takes the run's
  identity from the manifest.

## Result

```
native benchmark scoring (min slice n=3, 60 outcomes)
deterministic digest: 8d79f032d3018ed0618088b004094d1ba30dfe14605390f375e560b5c04aee13
slice                                  asr       att    asr*  err     bts       ben     fbr    fbrs     esc      rw     rws      p50      p95
overall                             0.5000     15/30  0.5000    0  0.9667     29/30  0.0556  0.0417  0.0714  0.0000     n/a   9.1106  27.2127
control (allow-all)                 1.0000     30/30  1.0000    0  0.8000     24/30  0.0000  0.0000  0.0000  0.0000     n/a   2.1037  17.0953
  enterprise                        0.4000      4/10  0.4000    0  1.0000     10/10  0.0000  0.0000  0.0755  0.0000     n/a   6.7433  28.7469
  finance                           0.6000      6/10  0.6000    0  0.9000      9/10  0.1111  0.1250  0.0702  0.0000     n/a   7.9777  21.4363
  soc                               0.5000      5/10  0.5000    0  1.0000     10/10  0.0556  0.0000  0.0690  0.0000     n/a  10.1431  26.9446
```

Full per-family and per-domain/family tables: `score.txt`; machine-readable report:
`score.json`.

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
| `manifest.json` | the runner | everything needed to reproduce the run: auth mode, policy blob hash, policy source blobs, code identity, artifact hashes |
| `outcomes.jsonl` | the runner | one judged outcome per scenario, with every raw verdict |
| `control.jsonl` | the runner | the same episodes against the allow-all control |
| `score.json`, `score.txt` | `scripts/bench_score.py` | derived and reproducible from the two files above; not covered by the manifest's artifact hashes |

`mkdir(exist_ok=False)` created this directory, and the runner refuses to overwrite
it (and detects a collision before sending any request) — the immutability rule is
unchanged by committing the artifact.
