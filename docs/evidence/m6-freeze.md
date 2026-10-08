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


## 8. Freeze block 1 — recorded results

Appended by the campaign runner after the cells ran. This section records results;
the block above is unchanged.

| Field | Value |
| --- | --- |
| Run directories | `benchmark/runs/20261008T203656Z-m6-campaign/` (C1 + C2, committed with its README), `evaluation/m6-recheck/aegisgraph-mock-m6-818cf1f.json` (C3) |
| Gateway commit observed | `818cf1f29795aa5d1e92b90fe4dfd4ed13174e03` (`code.commit_source = git-rev-parse-HEAD`, `code.dirty = false`) |
| Scenario-set hash recorded | `e4f376b2057ead47ed41a527e9b680a1a4c092cd5c9328ec2399eadeb0d77b75` |
| Policy set identity recorded | `aegisgraph-default/1`, `policy.blob_sha256 = 53d663b1853673da6ccfa0e4e673dbaa196bcf2517d6c1517aa1268fea9153f1` (26 derived sets pinned per request) |
| Policy source blobs recorded | `policy.py a072f462da4a9dc0e2a2ea5468a536f16b4391a9cb7af62958af2287222cb1be`, `engine.py 011111e10254d8cf148116e39a918216ca58bb7ba95cf217b39b1ea8bc1c4af2`, `adapter.py 7a4a28c8bd224415c924a4d18a962ee3e8601948636b4d20c3b322b32c979400` |
| Receipt store | durable PostgreSQL 17.11 (container `aegisgraph-m2-pg`, database `aegisgraph_m6`); `/readyz` = `receipt_store {durable: true, reachable: true}` |
| C1 decision digest | `b6951afb6db8fde2dd029d1e964312094d853487ae79d1abfdde02dc08b2581d` (reproduces from the committed run directory) |
| C2 licence | `control_licensed = 30`, `control_excluded = 0`, `control_excluded_ids = []`, `effectiveness_claim = true` |
| C3 digest | `8669aadb87e94652645ae8ed1f454f6f103c21bc8960cc65bf6e051de3043dfa` — byte-identical to the M0 and M1 re-checks; the committed scorecard's `3233dfc5…` is not reproduced, unchanged since M0 |
| C4 determinism | two independent scorings byte-identical; the documented digest reproduces |
| Delta vs `benchmark/runs/20261008T230000Z-m2-authenticated-full/` (`8d79f032…`) | 0 of 60 verdicts changed, 0 judged outcomes changed, every aggregate metric identical; the digest moved only because `code_commit` is part of it (`a94ce6f` → `818cf1f`). Neither H3-01 nor H3-04 is reachable from this suite under this configuration — the credential's ceiling is `trusted_internal` and the most-trusted declared level is `trusted_internal`, and the credential holds no `policy:context_override` |
| Blocked cells | C5 (real Qwen3-8B), C6 (native real model), C7 (sealed holdout), second backend — enabling commands in `docs/evidence/m6-campaign.md` §6 |
| Report | `docs/evidence/m6-campaign.md` |

Artifact hashes: `manifest.json` `4a2b377fa6d36101f8764dc6501cb1434a8cad1d94d330f9d737554ca2df96bd`,
`outcomes.jsonl` `58b79e85d12c9683d660af7b59c4b7d0b066b15c0c65d60476725a95007198fd`,
`control.jsonl` `ea204a61e1c2fe0114548f5a3e4ba8f2069c720dc17a8694f3070e986811d4a5`,
`score.json` `05f22292002cbd6e0739d5d6705227a34ca275e0167da971b7d5fc68172dd447`, `score.txt` `d9fec910ded9378cedd3c3ab22c38d49f6a8690dcf83f5d360d49bfeb0206984`,
`README.md` `94b8aed58f05abdeac1d17dad2b130c2f9cf431fee899cdcec6fbc51eb242c71`,
C3 artifact `2af5e8473f60bdeefc4a76227cf2b7744df7f01de782b5a164eeeca223a744d6`.
