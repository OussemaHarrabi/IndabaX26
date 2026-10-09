# Qwen3-8B campaign protocol — Colab / Kaggle runbook

Owner: preregistration owner (AgentPrereg). **Status: protocol fixed 2026-10-09,
before any real-model run.** This document is the runbook a person executes; the
configuration and decision rules it serves are fixed in
[`../evidence/qwen-campaign-freeze.md`](../evidence/qwen-campaign-freeze.md). The
two are read together: the freeze block fixes *what* is run and *how it is judged*,
this protocol fixes *how it is run*.

**No real-model number exists yet.** This protocol describes a run that has not
happened. Nothing here is a result, and no sentence here may be read as implying
that one exists.

## 0. The three evidence classes, and where this protocol sits

Results are reported in three classes, kept separate and never merged:

1. **Native benchmark, scripted replay** — the authored action script is replayed
   verbatim, so the run measures the gateway, not a model (`code reading`:
   [`../benchmark/evaluation-card.md`](../benchmark/evaluation-card.md) §1, §5).
2. **Historical legacy SENTINEL evidence — frozen, real Qwen3-8B** — the preserved
   challenge package (`code reading`:
   [`../legacy/sentinel-challenge.md`](../legacy/sentinel-challenge.md)); quoted
   where used, with its limitations.
3. **Native real-model campaign — not yet run.** This protocol produces class 3.
   The class is **empty today**.

This document does not restate or merge the numbers of classes 1 and 2, and it
does not restate the freeze block's objectives — it references them. The
permitted/forbidden wording for every result the protocol produces is fixed in
[`claim-language.md`](claim-language.md); the analysis rules are fixed in
[`statistics.md`](statistics.md) and [`research-plan.md`](research-plan.md), and
are **not redefined here**.

## 1. Preconditions — do not start otherwise

A run may start only when every item is true. Each is a statement someone can
check, not an intention.

1. The freeze block is declared and its §3 configuration is read.
2. Every `TBD-BEFORE-STAGE-B` value needed for the stage at hand is **closed** in
   `configuration.json` (`../evidence/qwen-campaign-freeze.md` §12).
3. The dataset validates: `python scripts/bench_validate.py` ends in
   `RESULT: PASS` and reports the dataset hash
   `7e916a11981fa6444724dc78558e51561d32a3005b182862efb52b7c5f2cf735`.
4. The seal is closed: `python scripts/bench_seal.py status` prints the manifest
   and `python scripts/bench_seal.py verify` reports `ciphertext_matches: true`
   (`../benchmark/holdout.md` §6).
5. The repository is checked out at the gateway commit recorded in the freeze
   declaration, with a clean tree.
6. **No real-model result has been looked at.** If a result has been seen, the
   configuration is no longer preregistered and a new freeze block is required
   (`../evidence/qwen-campaign-freeze.md` §7).

## 2. Order of operations, in one list

```text
1.  Provision the notebook (GPU) and check out the frozen commit
2.  Install the runtime; pull the frozen model artifact
3.  Record environment.json and pip-freeze.txt
4.  Close the TBD-BEFORE-STAGE-B values into configuration.json
5.  Validate the dataset (RESULT: PASS) and verify the seal closed
6.  Start the gateway on loopback; mint the credential; publish the policy sets
7.  Stage A smoke  — 6 scenarios, 1 seed       (engineering evidence only)
8.  Score + package Stage A; verify the bundle locally
9.  Stage B development — 42 scenarios, >= 3 seeds
10. Score + package Stage B; verify the bundle locally
11. Stage C validation — 18 scenarios, 5 seeds preferred / 3 the floor
12. Score + package Stage C; compute statistics.json; verify locally
13. Stage D sealed holdout — ONLY if the custodian authorizes and B+C are complete
14. Assemble the campaign bundle; commit the raw outcomes + hashes; report
```

Steps 7–12 are repeated per seed: one run directory per (stage, seed). No step may
be reordered so that a later stage runs before an earlier one, and Stage D never
runs before B and C are complete (`../evidence/qwen-campaign-freeze.md` §2, §9).

## 3. Provision the notebook

- **Platform.** Google Colab (GPU runtime) or Kaggle (GPU session). The local
  machine has no suitable GPU, which is why the campaign is hosted
  (`code reading`: [`../../README.md`](../../README.md) §"Known limitations").
- **Checkout.** Clone the repository and check out the **gateway commit recorded
  in the freeze declaration** — not a moving branch. Confirm
  `git rev-parse HEAD` equals it and `git status --porcelain` is empty.
- **Runtime.** Install from the committed lock; pull the frozen model artifact
  (`Qwen/Qwen3-8B`, revision fixed in `configuration.json`). Verify the artifact
  digest before use; a mismatch stops the run.
- **Isolation.** Model serving and the gateway both stay on **loopback**. No
  external inference API is used (`code reading`:
  [`../../COLAB_QWEN_RUN.md`](../../COLAB_QWEN_RUN.md)).

The real-model adapter is the injectable seam in
[`../../benchmark/runner.py`](../../benchmark/runner.py) (`ModelAdapter.plan`);
the native runner currently declares `ollama` as **unavailable** and fails closed
(`code reading`: `runner.py` `model_adapter`). The campaign adapter that makes the
cell real is a separate deliverable under `notebooks/`, which imports the tested
modules rather than hiding evaluation logic in cells
([`../../README.md`](../../README.md) §"Repository layout"). This protocol fixes
the requirements that adapter must meet; it does not claim the adapter exists.

## 4. Record the environment (`environment.json`, `pip-freeze.txt`)

Before the first gateway call, write the environment record. The fields below are
the minimum; a missing field is a blocked run, not a blank cell.

| Field group | Fields |
| --- | --- |
| Host | OS build, architecture, CPU model, RAM |
| Python | interpreter version, `pip freeze` output written to `pip-freeze.txt` |
| GPU | GPU model, total VRAM, driver/CUDA versions, GPU count |
| Model runtime | server name and version, model tag, quantization report, artifact digest |
| Model | revision SHA / tag digest, chat-template digest, dtype, context window |
| Timing | run start/end UTC, wall-clock seconds |
| Cost | GPU-hours (wall-clock × GPU count), the published notebook rate and currency, estimated cost — the rate is named, never a bare number |
| Token counts | prompt tokens, completion tokens, total tokens per run and per scenario |

Wall-clock and GPU-hours are recorded per run; the estimated cost is derived from
them and the named rate. Latency is recorded with its hardware header, because a
latency number without one is not reportable (`statistics.md` §6).

## 5. Start the gateway, the credential and the policy sets

The gateway under test runs from the frozen commit, clean tree, one worker, on
loopback. The authenticated flow is the one the runner expects
(`evaluation-card.md` §2a):

```bash
# 1. one-time local test issuer (development-only identity; never a production IdP)
python scripts/dev_issuer.py init
python scripts/dev_issuer.py mint --tenant bench --subject bench-policy-admin \
  --role policy_admin --ttl 7200 > /tmp/policy-admin.json
python scripts/dev_issuer.py mint --tenant bench --subject bench-decision-client \
  --role decision_client --ttl 7200 > /tmp/decision.json

# 2. start the gateway on loopback from the frozen commit
AEGISGRAPH_AUTH_MODE=required \
AEGISGRAPH_JWT_ISSUER=https://dev-issuer.aegisgraph.local \
AEGISGRAPH_JWT_AUDIENCE=aegisgraph \
AEGISGRAPH_JWKS=<issuer-dir>/jwks.json \
PYTHONPATH=backend python -m uvicorn aegisgraph.app:app --host 127.0.0.1 --port 8091

# 3. publish the policy sets the scenarios pin
python scripts/bench_policies.py publish \
  --defense-url http://127.0.0.1:8091 --token-file /tmp/policy-admin.jwt

# 4. readiness before any run
curl -s http://127.0.0.1:8091/healthz   # {"status": "ok"}
```

The token is never printed, logged, written to a manifest or hashed
(`evaluation-card.md` §2a). A token file is written UTF-8 **without** a BOM; a
Windows redirect that writes UTF-16 is refused rather than silently failing to
authenticate.

## 6. Validate the data and the seal

```bash
python scripts/bench_validate.py                     # must end in RESULT: PASS
python scripts/bench_seal.py status                  # hash-only manifest
python scripts/bench_seal.py verify                  # ciphertext_matches: true
```

The validator must report `0 errors` and the dataset hash of §1.3. The seal check
must confirm the ciphertext matches the manifest **without** opening the seal. If
either fails, the run stops; the failure is recorded in `failures.jsonl` (§10).

## 7. Run a stage

Each (stage, seed) is one invocation of the runner with the frozen splits and
seed:

```bash
python scripts/bench_run.py \
  --defense-url http://127.0.0.1:8091 \
  --dataset benchmark/data \
  --splits <development|validation|development,validation> \
  --model <the campaign adapter> \
  --auth-token-file /tmp/decision.jwt \
  --seed <preregistered seed> \
  --temperature <frozen value> \
  --max-tokens <frozen value> \
  --hardware-note "<host header from environment.json>" \
  --timestamp <UTC timestamp> \
  --config-slug qwen3-8b-<stage>-s<seed>
```

The runner starts its internal allow-all control and writes `control.jsonl` in the
same run directory (`evaluation-card.md` §6); the reached set `R` is derived from
that control, never from the treatment arm.

**Stage-specific notes.**

- **Stage A** (`development,validation`): the fixed 6-scenario subset of the
  freeze block §2.1. It is **engineering evidence only**: it licenses no research
  claim. Its run directory and its `failures.jsonl` are kept.
- **Stage B** (`development`): all 42 development scenarios, one run per
  preregistered seed (≥ 3).
- **Stage C** (`validation`): all 18 validation scenarios, one run per
  preregistered seed (5 preferred, 3 the floor).
- **Stage D** (`holdout`): see §9. It uses the runner with
  `--dataset <plaintext parent> --splits holdout` after the seal is opened, and
  it is run **exactly once**.

## 8. Score a stage

Scoring reads only the run's raw outcomes and never touches the gateway
(`evaluation-card.md` §9):

```bash
python scripts/bench_score.py --run <run-dir> --json --out <run-dir>/score.json
python scripts/bench_score.py --run <run-dir> > <run-dir>/score.txt
# determinism: score twice and compare byte-for-byte
python scripts/bench_score.py --run <run-dir> --json --out /tmp/a.json
python scripts/bench_score.py --run <run-dir> --json --out /tmp/b.json
cmp /tmp/a.json /tmp/b.json
```

`score.json` and `score.txt` are written through the platform's text mode on some
hosts and may carry CRLF; every hash in `hashes.sha256` is labelled with the
convention it was taken under (`content-sha256-lf` for the committed values,
`../evidence/m6-campaign.md` §7a). The decision digest is computed from the parsed
outcomes and is line-ending independent.

## 9. Stage D — the sealed holdout

Stage D runs **only** when the freeze block §9 conditions hold: the freeze
checklist, Stages B and C complete, and the custodian's authorization. The
evaluation command is written down **before** the seal is opened. The opening
command and the post-open run are in
[`../benchmark/holdout.md`](../benchmark/holdout.md) §5; the freeze block §9 fixes
the exact enabling action. After the one run, the plaintext is deleted and the
policy-blob hash is compared freeze-to-unseal (`H5.2`, `statistics.md` §7).

If authorization is unavailable, **Stage D does not run**; the campaign reports
Stages A–C and states that the holdout is closed and no generalization claim is
made. A closed holdout is never filled with an estimate or a mock value.

## 10. Artifact layout

Every run directory must contain the following. The three marked **runner** are
written by the committed runner (`code reading`:
[`../../benchmark/runner.py`](../../benchmark/runner.py) — `manifest.json`,
`outcomes.jsonl`, `control.jsonl`); the rest are written by the campaign tooling,
which this protocol requires to meet the layout.

| Artifact | Content | Writer |
| --- | --- | --- |
| `manifest.json` | everything needed to reproduce the run: code commit, policy set and `policy.blob_sha256`, dataset hash, scenario-set hash, model identity and parameters, seed, temperature, max tokens, hardware, dependency-lock hash, artifact hashes, `limitations[]` | runner |
| `environment.json` | the §4 record (host, GPU, runtime, timing, cost, token counts) | campaign |
| `configuration.json` | the frozen configuration closed from the freeze block §3, the stage, the seed, the splits and the commit | campaign |
| `raw_generations.jsonl` | one record per model generation: prompt digest, output, prompt/completion tokens, stop reason, seed, temperature | campaign |
| `proposed_actions.jsonl` | the action each generation resolved to, per step | campaign |
| `decisions.jsonl` | the gateway verdict (verb, reason codes, receipt id) per proposed action, raw | campaign |
| `outcomes.jsonl` | one judged outcome per scenario against the defence | runner |
| `control.jsonl` | the same episodes against the allow-all control | runner |
| `score.json` | the machine-readable scorecard | scorer |
| `score.txt` | the rendered scorecard | scorer |
| `statistics.json` | the paired analysis output (`docs/research/analysis.py --json`) for the stage | campaign |
| `failures.jsonl` | every failure, timeout, interruption and rerun, with stage/scenario/seed/attempt/cause | campaign |
| `checkpoints/` | one JSON per completed scenario, for resume (§11) | campaign |
| `hashes.sha256` | the SHA-256 of every artifact above, each labelled with its hash convention | campaign |
| `pip-freeze.txt` | the frozen Python environment | campaign |

The campaign bundle is one directory assembled once: the per-(stage, seed) run
directories plus the campaign-level `statistics.json`, `hashes.sha256` and a
README naming the exact commands. A bundle is immutable once written.

## 11. Immutability and resume

- **One run directory per (stage, seed), created exactly once.** The committed
  runner's exclusive `mkdir(exist_ok=False)` is the authoritative guard: a second
  invocation into the same name fails loudly rather than merging two measurements
  (`code reading`: `runner.py` module docstring; `evaluation-card.md` §3). There is
  no `--force`.
- **The campaign bundle is written once.** Nothing under a completed bundle is
  overwritten. A new run is a new directory with a new timestamp.
- **Atomic per-scenario writes.** The campaign tooling writes each completed
  scenario to `checkpoints/<scenario_id>.json` via a temporary file and an atomic
  rename, so an interrupted stage leaves no half-written checkpoint.
- **Resume skips verified entries.** On resume, the tooling verifies each
  checkpoint's recorded hash against `hashes.sha256` and skips verified entries,
  re-running only the scenarios that are missing or fail verification. A resumed
  stage keeps the same seed and the same frozen configuration.
- **A completed run is never overwritten.** A run directory that already contains
  `score.json` is complete; a resume never writes into it. A rerun after a
  technical failure is a **new** directory, and both attempts are kept and both are
  recorded in `failures.jsonl` (`../evidence/qwen-campaign-freeze.md` §8).
- **No partial run is scored.** A run directory without the full scenario set in
  `checkpoints/` is incomplete and is not scored or published.

## 12. Close the configuration before Stage B

Stage A exists partly to close the `TBD-BEFORE-STAGE-B` values
(`../evidence/qwen-campaign-freeze.md` §12). At the end of Stage A, write every
closed value into `configuration.json` and `environment.json`, hash them into
`hashes.sha256`, and record the seed list and the temperature > 0 sampling
parameters. **Stage B does not start until every value is closed.** If a value
cannot be closed, the campaign stops and reports the missing value rather than
proceeding with an open configuration.

## 13. Verify a downloaded bundle locally

The Colab/Kaggle session is ephemeral; the bundle is downloaded and verified
locally before anything is committed. Verification steps, in order:

1. **Hashes.** `sha256sum -c hashes.sha256` (or the platform equivalent) verifies
   every artifact against the recorded digest; a mismatch stops the import.
2. **Run integrity.** `python scripts/bench_score.py --run <run-dir> --json --out
   /tmp/re.json` re-scores the raw outcomes and reproduces the committed
   `score.json` byte-for-byte and the decision digest (`evaluation-card.md` §8).
   Scoring re-checks the recorded artifact hashes before use.
3. **Identity.** Read `manifest.json` and confirm `code.commit` equals the frozen
   gateway commit, `code.dirty` is `false`, `dataset.sha256` equals the frozen
   dataset hash, and `model.kind` identifies the real adapter (never `scripted`,
   never `unavailable`).
4. **Comparability.** Confirm `dataset.sha256`, `scenario_set.sha256` and
   `policy.blob_sha256` are equal across the arms being compared, and that
   `policy.source_blobs.blobs` is unchanged freeze-to-unseal for a Stage D claim
   (`evaluation-card.md` §4).
5. **Licence.** Confirm `effectiveness_claim` is `true` and read
   `control_licensed`, `control_excluded` and `control_excluded_ids`
   (`evaluation-card.md` §6). A void control means no effectiveness claim.
6. **Statistics.** Regenerate `statistics.json` from the raw outcomes and confirm
   the counts, the intervals and the corrected p-values match.
7. **Environment.** Confirm the GPU model and memory, the token counts and the
   wall-clock are present; a latency number without the hardware header is not
   reportable.

Only a bundle that passes all seven is committed.

## 14. What must never be committed

- **Keys, tokens, credentials.** The custodian passphrase, bearer tokens, the
  issuer private key, JWKS secrets and any API key. The token is never printed,
  logged, written to a manifest or hashed (`evaluation-card.md` §2a).
- **Model caches and weights.** The pulled model artifact, Hugging Face caches and
  GGUF files are not repository content.
- **Unredacted sensitive logs.** Raw session logs, notebook outputs containing a
  token or a passphrase, and any transcript that exposes a secret. The seal's
  rotation history is the precedent for why a secret in a transcript is treated as
  exposed (`../evidence/m5-seal-custody.md`).
- **Holdout plaintext.** The decrypted holdout scenarios, their ids and any file
  derived from them (`../benchmark/holdout.md` §4.6). The plaintext directory is
  deleted after the Stage D run.
- **A completed run directory overwritten in place.** A run is add-only; the
  committed evidence is never rewritten (`../evidence/m6-campaign.md` §7a, on
  preserving original artifacts).

Committed artifacts are the raw outcomes, the scorecards, the statistics, the
manifests and the hashes — never a secret, never a weight, never the holdout.

## 15. Implemented — the campaign driver (appended 2026-10-09)

**Status: implemented and locally proven with the scripted adapter.** This section
records what §1–§14 above are executed by. It is an *implementation* record, not a
result: **no real-model run exists and no number here is one.** The driver is
`benchmark/campaign.py` (library), `scripts/bench_campaign.py` (the CLI a notebook
calls) and `tests/test_campaign.py` (stub-driven proofs). It imports the tested
modules and reimplements no evaluation logic: request assembly is
`benchmark.wire`, judgement is `benchmark.scoring.derive_outcome`, the manifest
identity is `benchmark.runner.build_run_manifest`, the model and its prompt are
`benchmark.qwen`, and it never shells out to `bench_run.py`.

### 15.1 What it runs — the stage matrix as implemented

| Stage | Splits | Scenarios | Seeds | Treatment surface |
| --- | --- | --- | --- | --- |
| A | `development,validation` | the fixed six of freeze block 1 §2.1, by id | the anchor `1729` | the gateway at `--defense-url` |
| B | `development` | all 42 | ≥ 3, 5 preferred | the gateway at `--defense-url` |
| C | `validation` | all 18 | 3 the floor, 5 preferred | the gateway at `--defense-url` |
| D | `holdout` (unsealed plaintext) | all 20 | the frozen set, one run | the gateway at `--defense-url` |

`--condition` selects the arm the run measures as its *treatment*: `defence` (the
default) is the gateway; `ablation:<name>` is the ablated build you already
started at `--defense-url`, with `<name>` recorded in `configuration.json`;
`control` measures the harness allow-all control itself and never calls a gateway,
so the control arm can be materialised as its own run directory. One invocation
writes **one run directory per seed**, named
`<UTCstamp>-<model>-<stage>[-<condition>]-s<seed>` (e.g.
`20261009T005408Z-qwen3-8b-c-s1729`, `…-a-control-s1729`,
`…-a-ablation-kernel-s1729`).

### 15.2 The exact commands

```bash
# 0. once: publish the policy sets the scenarios pin (protocol §5)
python scripts/bench_policies.py publish \
  --defense-url http://127.0.0.1:8091 --token-file /tmp/policy-admin.jwt

# see exactly what a command would run, touching nothing and calling nothing
python scripts/bench_campaign.py --stage B --seed 1729 --seed 42 --seed 7 --dry-run

# A — smoke, engineering evidence only, one seed
python scripts/bench_campaign.py --stage A --seed 1729 \
  --defense-url http://127.0.0.1:8091 --runs-dir /content/runs \
  --model qwen --adapter-json '{"revision":"<sha>","quantization":"4bit","dtype":"bfloat16"}' \
  --tbd-json '{"chat_template_sha256":"<sha>","max_context_tokens":32768}' \
  --auth-token-file /tmp/decision.jwt --hardware-note "<host header from environment.json>"

# B / C — the preregistered seed list in one invocation, one run dir per seed
python scripts/bench_campaign.py --stage B --seed <s1> --seed <s2> --seed <s3> ... \
  --defense-url http://127.0.0.1:8091 --runs-dir /content/runs --model qwen \
  --adapter-json '…' --auth-token-file /tmp/decision.jwt

# D — only after B and C are complete, the custodian has authorized the opening,
#     and bench_seal.py open has written the plaintext outside the repository
python scripts/bench_campaign.py --stage D --seed <frozen seed> \
  --holdout-dir /tmp/holdout-plaintext --authorize-holdout \
  --defense-url http://127.0.0.1:8091 --runs-dir /content/runs --model qwen --adapter-json '…'

# resume an interrupted stage; score it; then package and download it
python scripts/bench_campaign.py --stage A --seed 1729 --resume … --max-scenarios 40
python scripts/bench_score.py --run <run-dir> --json --out <run-dir>/score.json
python scripts/bench_score.py --run <run-dir> > <run-dir>/score.txt
python scripts/bench_campaign.py --stage A --seed 1729 --bundle …
```

Exit codes: `0` ran (complete, or cleanly stopped early and resumable), `1`
failed (`run failed: …`), `2` refused (`RESULT: REFUSED: …`), `130` interrupted.
The last line is always a `RESULT:` marker: `RESULT: DRY-RUN`,
`RESULT: CAMPAIGN COMPLETE`, `RESULT: CAMPAIGN INCOMPLETE`, `RESULT: BUNDLE OK`.

### 15.3 Resume semantics

- One run directory per `(stage, condition, seed)`, created with
  `mkdir(exist_ok=False)`; there is no `--force`. A completed run directory is
  never written to: a repeat invocation refuses (`refusing to overwrite…`) and
  `--resume` on a completed run refuses too (`pass --bundle to package it`).
- Each completed scenario is written to `checkpoints/<scenario_id>.json` through a
  temporary file and an atomic rename, and the derived artifacts, the manifest and
  `hashes.sha256` are then rewritten atomically. A killed process therefore leaves
  either no checkpoint or a complete one, and never a half-written artifact.
- On resume the recorded hash of every checkpoint is verified against
  `hashes.sha256`: a verified entry is **skipped**, a missing one is run, and a
  mismatching one is **moved** to `checkpoints/rejected/` (with the mismatch
  recorded as a failure) and re-run as a new attempt — both attempts are kept.
  Verified checkpoints are the source of truth: every `.jsonl` artifact is
  re-derived from them, so an interrupted rewrite self-heals.
- `--resume` re-checks the frozen configuration (`stage`, `condition`, `seed`,
  scenario set, dataset hash, model signature) against `configuration.json` and
  refuses a resume whose configuration changed — a changed configuration is a new
  freeze block and a new directory, never a resume of this one.
- `--max-scenarios N` stops the session cleanly after `N` new scenarios of *each*
  run in the invocation and leaves it resumable (a Colab cell budget), reported as
  `RESULT: CAMPAIGN INCOMPLETE`.

### 15.4 Failures are recorded, never fatal

A model parse failure, a gateway non-2xx, a timeout, a connection error, a control
error and an interruption each become an **errored outcome** (`errored: true`,
`attack_success: null`) plus a row in `failures.jsonl` carrying `stage`,
`condition`, `seed`, `scenario_id`, `step_id`, `phase`, `attempt`, the classified
`cause` and the bounded raw output where there is one — and the campaign continues
to the next scenario. An errored outcome can never read as a stopped attack: the
scorer counts it in `errored_attacks` and, intention-to-treat, as a failure, and a
run whose control arm also errored is reported `VOID` with no effectiveness claim.
A model that cannot load is the one exception: it aborts, because nothing can run.

### 15.5 Verifying a downloaded bundle

`--bundle` first verifies every recorded entry of `hashes.sha256`, then extends the
manifest to artifacts written after the run (`score.json`, `score.txt`), then
writes `<runs-dir>/<run-name>.zip` (atomic, never overwritten, refused for an
incomplete run). It writes nothing to the run directory except that extension.
`hashes.sha256` opens with the declaration line `# convention: content-sha256-lf`
and then one `sha256sum`-format line per artifact, path relative to the run
directory; **every** entry is taken under that one declared convention (nothing is
hashed raw), so the file never mixes conventions. Verify a bundle exactly as
protocol §13 requires:

```bash
unzip <run-name>.zip -d /tmp/verify && cd /tmp/verify
sha256sum -c hashes.sha256                 # 1. every artifact against its digest
python scripts/bench_score.py --run . --json --out /tmp/re.json   # 2. re-score, compare
cmp /tmp/re.json score.json
python -c "import json;m=json.load(open('manifest.json'));print(m['code'],m['dataset']['sha256'],m['model']['kind'])"
python docs/research/analysis.py --json …  # 6. regenerate statistics.json and compare
```

On the notebook host (Colab/Kaggle) the working copies are LF, so every file the
driver wrote and every file the scorer wrote agree with the declared convention and
`sha256sum -c` verifies the whole bundle as written. If a host writes
`score.json`/`score.txt` through a text mode that emits CRLF, their raw bytes differ
from their LF-normalised digest: step 1 then reports those two as mismatches, and
the declared convention is what makes them verifiable — the
analysis module (`verify_run_hashes`) and this driver's `verify_hashes()` read the
`# convention:` line and hash with CRLF normalised to LF. This is the m6 note
(`../evidence/m6-campaign.md` §7a) restated for the campaign bundle: a file-level
hash comparison across platforms must use the `content-sha256-lf` value.

### 15.6 What is deliberately not done here

- **No cloud run, no GPU, no model download.** Every proof in this section ran with
  the `scripted` adapter and, for the generation loop, a stub generator behind the
  real `QwenModelAdapter` — no torch is installed. The real-model path is the
  adapter's own fail-closed message plus the stub tests; nothing here is a
  real-model number.
- **No notebook.** The notebook is a separate deliverable that calls
  `scripts/bench_campaign.py`; this section fixes only what it calls.
- **No scoring and no statistics inside the driver.** `score.json`, `score.txt` and
  `statistics.json` stay with `scripts/bench_score.py` and the analysis module the
  freeze block names (`docs/research/analysis.py`), so a run directory is scorable
  by the committed scorer unchanged and the campaign writer never has to be edited
  to add a metric.
