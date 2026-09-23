# Colab runbook: real Qwen3-8B evaluation (no mock)

This is an execution checklist, not evidence that a Colab run has happened. The repository currently contains deterministic **mock development** scorecards only. Do not label them Qwen results or use them as the final demonstration. The organizer explicitly allows an open-weight model hosted on your own cloud GPU; the reference agent must remain Qwen/Qwen3-8B with the starter kit's tools and prompt unchanged. Runtime settings may change. Do not add safety instructions to the reference agent.

## 0. Freeze the artifacts first

Before starting a notebook, record the AegisGraph Git commit (or archive SHA-256 if using an upload), and retain `benchmark.lock` unchanged. The benchmark source is `Skan22/Sentinel_Starter_Kit` at `dd2e5fe0979d0781a4bfe6d0849cd80cf69ef4a2`; it declares 40 scenarios: 31 attacks and 9 benign. The challenge PDF has an earlier count; the pinned starter kit is the operational evaluation source and the discrepancy must be noted in the report.

Use a fresh Colab notebook with a GPU runtime. Record the date, runtime type, GPU model and memory, Python version, package/commit versions, model identifier, precision/quantization, token budget, thinking mode, and random seed (if configurable). Do not put Hugging Face tokens, private repository credentials, or other secrets in notebook outputs or submitted artifacts. Qwen is open-weight and can be downloaded from Hugging Face; inference must not go through an external inference API.

## 1. Install pinned benchmark and defense

In the notebook, clone and pin the organizer kit:

```bash
git clone https://github.com/Skan22/Sentinel_Starter_Kit.git
cd Sentinel_Starter_Kit
git checkout dd2e5fe0979d0781a4bfe6d0849cd80cf69ef4a2
git rev-parse HEAD
uv sync --extra hf
```

Make the AegisGraph source snapshot for the exact commit available in the notebook (for example, a GitHub archive of that commit if the repository is pushed, or a zip upload). Extract it to a sibling directory named `aegisgraph`; verify its recorded commit/archive SHA-256 against the one frozen above. Do not silently use a different working tree.

```bash
cd /content/aegisgraph
python -m pip install .
python -m uvicorn aegisgraph.app:app --app-dir backend --host 127.0.0.1 --port 8080
```

Keep the service bound to loopback in the notebook. In a second cell, verify `GET http://127.0.0.1:8080/healthz` returns healthy. AegisGraph is the decision gateway; it does not load Qwen or invoke tools itself. The SENTINEL evaluator runs the reference agent and calls this local defense endpoint.

## 2. Confirm the reference model works

Download/use the organizer's `Qwen/Qwen3-8B` weights through the starter's Hugging Face adapter. The starter guide documents `--model qwen3-8b`; its `hf` extra installs Transformers and PyTorch. In Colab, first run a single baseline scenario to confirm the model initializes and returns valid tool actions:

```bash
cd /content/Sentinel_Starter_Kit
uv run sentinel run \
  --scenario scenarios/public/finance/finance_false_approval.yaml \
  --defense allow_all --model qwen3-8b
```

Do not change the prompt, tool set, or agent identity. Record any allowed runtime changes such as GPU, dtype/quantization, `max_new_tokens`, and thinking setting. If the full-precision configuration cannot fit, use an allowed supported runtime configuration and record it. Do not change settings between the allow-all and defense comparisons unless you rerun and record both sides under the new configuration.

## 3. Reachability gate: allow-all for every demonstrated attack

**Before interpreting a defense result or recording an attack, run that exact scenario with `allow_all` on the same Qwen runtime. It must report `attack_success=True`.** This proves the attack reached and affected the undefended reference agent. A failed gate is not defense evidence. Adjust only permitted runtime settings and retry. Do not proceed with that attack as a claimed Qwen demonstration if the gate remains false. The organizer permits mock mode when the real reference agent cannot trigger an attack, but this project does not want a mock final demo: disclose the limitation and choose a different reachable attack or pause the Qwen claim rather than silently substituting mock.

For the complete public suite, run allow-all and preserve the complete JSON output, including per-scenario outcomes:

```bash
cd /content/Sentinel_Starter_Kit
mkdir -p /content/aegisgraph-results
uv run sentinel eval public --defense allow_all --model qwen3-8b --json \
  --output /content/aegisgraph-results/allow-all-qwen3-8b.json
```

Inspect all 31 attack outcomes in the resulting artifact, not just the aggregate ASR. If the CLI's JSON envelope changes, use its emitted per-scenario outcomes and explicitly record any attacks with `attack_success != true`. For a scenario planned for the video, the condition is mandatory individually. Only interpret defense outcomes for scenarios that passed their reachability check under the same fixed configuration. Save the raw evaluator artifact; never hand-edit it.

## 4. Baselines, defense, and repeatability

On the same starter-kit commit, model/runtime configuration, scenario set, and seed, run each required comparison and save separate raw files:

```bash
uv run sentinel eval public --defense provenance --model qwen3-8b --json \
  --output /content/aegisgraph-results/provenance-qwen3-8b.json
uv run sentinel eval public --defense-url http://127.0.0.1:8080 --model qwen3-8b --json \
  --output /content/aegisgraph-results/aegisgraph-qwen3-8b.json
```

Run `allow_all` first, then `provenance`, then AegisGraph. Preserve stderr/logs, command lines, timestamps, service commit, starter-kit commit, model/runtime configuration, and resulting scorecard digest. Never overwrite mock artifacts or one run with another. If doing a rerun, use a new filename and explain what changed. Record both successful and failed runs; do not cherry-pick only favorable results.

For the named video scenario(s), also preserve the full individual run artifact and replay it:

```bash
uv run sentinel run --scenario scenarios/public/finance/finance_false_approval.yaml \
  --defense-url http://127.0.0.1:8080 --model qwen3-8b
uv run sentinel replay artifacts/<group>/<run>.jsonl
```

Select only a scenario whose allow-all reachability gate succeeded. The video must show the attack reaching AegisGraph and being stopped, a benign task completing normally, and an observability explanation of decisions and outcomes. Do not edit away failed actions or imply that a trace used Qwen if the artifact says otherwise.

## 5. Store and report results safely

Download `/content/aegisgraph-results` and the relevant replay artifacts before the Colab runtime expires. Add raw result files only if repository size and licensing permit; otherwise keep them in a versioned release/artifact location and commit a small manifest containing filenames, SHA-256, run metadata, and digests. Never upload credentials, user data, or secrets. The benchmark uses synthetic data.

In the report, state exactly which scenarios passed allow-all reachability and which did not; list `attack_success=True` for each showcased attack. Compare allow-all, provenance, and AegisGraph. Report the organizer's component metrics as self-test evidence, not an official score. Include domain and attack-family breakdowns, at least one ablation, failure analysis, calibration/latency/error behavior, and the model/runtime details. Current mock numbers in `evaluation/README.md` remain labelled development-only until replaced or supplemented by a real, reproducible Qwen run.

## Stop conditions

- If Colab cannot obtain/load Qwen3-8B, stop and report the environment error; do not substitute a mock result under a Qwen label.
- If a showcased attack fails the allow-all gate, remove it from the Qwen demo or change a permitted runtime setting and rerun both baseline and defense.
- If the defense endpoint fails health/contract checks, stop benchmark interpretation until it is repaired and rerun.
- If outputs omit per-scenario reachability, preserve raw output and inspect the evaluator artifact/code before drawing conclusions; do not infer reachability from aggregate metrics.
