# M6 campaign freeze

Owner: orchestrator. **Status: prepared; not yet frozen.** Values marked `TBD-AT-FREEZE` are written at the
moment the campaign starts, and no gateway, policy, dataset or scoring change is permitted between that moment
and the recording of the results. If anything must change afterwards, the campaign is re-run under a new freeze
block appended to this file — the previous block is never edited.

## 1. What is frozen

| Element | Value |
| --- | --- |
| Gateway commit | `TBD-AT-FREEZE` (must be the integration tip, `code.dirty: false`) |
| Policy set identity | `TBD-AT-FREEZE` (`policy_set` id/version + `policy.blob_sha256` under the `content-sha256-lf` convention) |
| Native dataset hash | `7e916a11981fa6444724dc78558e51561d32a3005b182862efb52b7c5f2cf735` (60 scenarios: 42 development, 18 validation) |
| Scenario-set hash | `TBD-AT-FREEZE` (`scenario_set.sha256` from the run manifest) |
| Scoring code | `benchmark/scoring.py` + `docs/research/analysis.py` blobs, `TBD-AT-FREEZE` |
| Model configuration | `model.kind = scripted` (no model is available in this environment — see §4) |
| Seed / temperature / max tokens | `1729` / `null` / `null` (scripted replay has no sampling) |
| Splits | `development,validation` (the sealed holdout stays closed — §5) |
| Reachability control | the runner's internal allow-all control, `control_licensed` / `control_excluded` recorded per run |

## 2. Run matrix

| Cell | Configuration | Status |
| --- | --- | --- |
| C1 | Native benchmark, scripted model, development+validation, AegisGraph policy | runnable now |
| C2 | Native benchmark, scripted model, control (allow-all) | runnable now (the runner's internal control) |
| C3 | Legacy pinned suite, mock model, AegisGraph service | runnable now |
| C4 | Legacy pinned suite, mock model, allow-all + kit provenance baseline | frozen evidence already in `evaluation/**`; re-checked, not re-run as a campaign cell |
| C5 | Legacy pinned suite, real Qwen3-8B (5 revisions) | **blocked** — frozen historical evidence at `53472e5` etc.; not re-run |
| C6 | Native benchmark, real model (any family) | **blocked** — no `ollama`, no GPU, no paid API |
| C7 | Sealed holdout, any configuration | **not opened** — requires the freeze checklist in `docs/benchmark/holdout.md` §4 |

## 3. Exact commands

```bash
# 1. gateway under test (from the frozen commit, clean tree)
python -m uvicorn aegisgraph.app:app --app-dir backend --host 127.0.0.1 --port 8091 \
  # with AEGISGRAPH_AUTH_MODE=required, the local dev issuer, and DATABASE_URL set

# 2. publish the policy sets the scenarios pin
python scripts/bench_policies.py publish --defense-url http://127.0.0.1:8091 --token-file <policy_admin.jwt>

# 3. the campaign cell C1 (+ the runner's internal control C2)
python scripts/bench_run.py --defense-url http://127.0.0.1:8091 --model scripted \
  --splits development,validation --auth-token-file <decision_client.jwt> \
  --timestamp <UTC> --config-slug m6-campaign

# 4. scoring, twice, to prove determinism
python scripts/bench_score.py --run benchmark/runs/<timestamp>-m6-campaign --json --out <a>.json
python scripts/bench_score.py --run benchmark/runs/<timestamp>-m6-campaign --json --out <b>.json
cmp <a>.json <b>.json

# 5. legacy re-check (cell C3)
cd .sentinel_reference && uv run --no-sync sentinel eval public \
  --defense-url http://127.0.0.1:8092 --model mock --json --output <new artifact>

# 6. analysis with the preregistered correction
python docs/research/analysis.py --control <allow-all scorecard> --treatment <treatment scorecards> --by-domain --by-family
```

## 4. Why the model cells are blocked, and what unblocks them

No open-weight runtime is installed and no paid API is authorised. The exact unblocking steps:

- **Local open model:** install `ollama`, then `ollama pull qwen3:8b` (≈5 GB, 4-bit), and run
  `--model ollama:qwen3:8b` in place of `--model scripted`. The legacy kit path is
  `uv run sentinel run --scenario <path> --defense-url <url> --model ollama:qwen3:8b`.
- **Second backend:** any OpenAI-compatible endpoint, behind the runner's model-adapter interface; requires
  explicit owner authorisation because it incurs cost and leaves the machine.
- **Repeats:** at least three repeats per cell once a model is available, so the plan's variance requirement can
  be met rather than asserted.

A scripted cell measures the **gateway**, not a model: the scenario's authored action script is replayed
verbatim. The committed reference run's `limitations` field says exactly that, and the campaign report must
repeat it rather than letting a scripted table look like a model result.

## 5. Holdout

The seal stays closed. Opening requires the checklist in `docs/benchmark/holdout.md` §4 (policy freeze declared,
gateway commit recorded, data frozen and validator `PASS`, seal verified closed, evaluation command written down
first, single opening into a temporary directory, no tuning afterwards) and the custodian key at
`C:/Users/oussa/.aegisgraph/holdout-passphrase.txt` (see `docs/evidence/m5-seal-custody.md`). Comparing
`policy.source_blobs.blobs` between the freeze commit and the unseal commit is part of the procedure.

## 6. What the campaign may and may not claim

- **May:** on the native 60-scenario benchmark with the scripted replay, the gateway's verdicts are X; on the
  pinned legacy suite with the mock model, the scorecard reproduces digest Y; the components' contributions as
  measured by the recorded ablations; latency/throughput from the M3 load report on the recorded hardware.
- **May not:** any claim about model behaviour; any claim about the sealed holdout; any universal security
  statement; any comparison between the scripted native run and the real-Qwen legacy run as if they were the
  same measurement.
- Every table in the campaign report carries its configuration identity (commit, dataset hash, policy hash,
  model config, seed) or it is not published.

## 7. Freeze block 1

| Field | Value |
| --- | --- |
| Declared by | _not yet declared_ |
| Declared at | _not yet declared_ |
| Gateway commit | _not yet declared_ |
| Dataset / scenario-set / policy hashes | _not yet declared_ |
| Run directories | _not yet declared_ |
| Known deviations from this document | _none yet_ |
