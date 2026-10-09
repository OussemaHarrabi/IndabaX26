# The Qwen3-8B adapter (`benchmark/qwen.py`)

This is the real-model adapter for the native benchmark: a Hugging Face
`Qwen/Qwen3-8B` agent that proposes actions for each scenario, behind the same
`ModelAdapter` seam the `scripted` adapter implements. The Colab/Kaggle notebooks
import `benchmark.qwen`; the evaluation logic lives here, not in a cell.

It is a **new** document rather than a section of the evaluation card: the card
is the reproduction recipe for the committed runs, while this file is the
adapter's own contract (frozen configuration, prompt revision, enabling steps).
The adapter is **declared and enabled but not run here**: this machine has no
GPU and no torch, so every number this repository publishes remains a
`scripted` number until a real GPU run writes its own run directory.

## 1. What the adapter is

- `kind` is `qwen3-8b`; the runner records it in `manifest.json` under
  `model.kind`, so a reader cannot mistake a scripted run for a model run.
- `identity()` carries **every** `QwenConfig` field plus the resolved
  torch/transformers versions and the prompt revision. The `note` restates the
  frozen configuration.
- Importing `benchmark.qwen` never imports torch or transformers. The heavy
  toolchain is resolved inside `QwenModelAdapter.load()`.
- It is registered in `benchmark.runner.model_adapter` under the name `qwen`, so
  the CLI accepts `--model qwen` alongside `scripted` and `ollama`.

## 2. The frozen inference configuration

`QwenConfig` (defaults shown) is the record of what a run used.
**Every deviation must be recorded**; these defaults are the frozen configuration
the notebooks start from.

| Field | Default | Meaning |
| --- | --- | --- |
| `model_id` | `Qwen/Qwen3-8B` | the Hugging Face repository |
| `revision` | `"unpinned"` | the commit pin; `"unpinned"` is the honest value when no pin is known and is never replaced by an invented hash |
| `quantization` | `"none"` | `"none"`, `"4bit"` (nf4) or `"8bit"` via bitsandbytes |
| `dtype` | `"bfloat16"` | `"bfloat16"`, `"float16"` or `"float32"` |
| `seed` | `0` | torch seed set before generation |
| `temperature` | `0.0` | `0.0` is greedy/deterministic (sampling is off) |
| `top_p` | `1.0` | nucleus sampling, used only when `temperature > 0` |
| `max_new_tokens` | `768` | generation length; the context/batch knob to lower on OOM |
| `thinking` | `False` | Qwen3 thinking mode; when on it is passed to the chat template and stripped from the answer before parsing |
| `device` | `"cuda"` | torch device (e.g. `"cuda"`, `"cuda:1"`, `"cpu"`) |

The prompt revision is a module constant: **`PROMPT_REVISION = "qwen3-agent/v1"`**.
It is embedded in the prompt and recorded in `identity()`, so a run can name the
prompt that produced it. The action contract is the versioned constant
`ACTION_SCHEMA_JSON`.

## 3. What the adapter does

- `plan(scenario)` performs **one generation per step of the scenario's authored
  script**, stopping early if the model returns a `final` respond action.
- Each prompt is built from the scenario: the user goal, the observations **with
  their provenance ids**, the allowed tools, the authored history and every
  previous step's proposal. When the caller passes the optional `decide` hook
  (a gateway client), each step's verdict is fed back into the next prompt;
  without a hook the adapter invents no verdict.
- `parse_action` extracts exactly one `ActionSpec` from the model output,
  tolerating a fenced `json` code block, a Qwen3 thinking block and surrounding
  prose. It validates against `ActionSpec` before returning.
- `identity()` and `load()` fail closed (section 4).

## 4. What the adapter does not do, and how it fails closed

- It never returns a plausible-looking fake action. A malformed output raises
  `QwenParseError`, carrying the bounded raw output (`raw_output`, at most 2000
  characters), the step id and a reason. It subclasses the runner's `RunError`,
  so the CLI reports a clean `run failed: ...` line and the run writes nothing —
  a parse failure can never be a silent success.
- It does not call the gateway itself. In the runner path, `plan(scenario)` is
  called once and the runner applies the verdicts afterwards, so the runner path
  is **open-loop** (one generation per authored step, no verdict fed back).
  Notebooks that want the closed loop drive `plan(..., decide=<http client>)`
  directly.
- It does not download or install anything. Missing dependencies and missing
  models are reported with the exact command:

  - torch/transformers missing →
    `ModelUnavailable: model adapter 'qwen' needs torch and transformers, which are not importable here (...); to run it, execute: python -m pip install 'torch>=2.4' 'transformers>=4.51,<5' 'accelerate>=1.0' 'bitsandbytes>=0.43', then re-run with --model qwen`
  - the model is not available locally → `ModelUnavailable` naming the
    `huggingface-cli download` command (with the pinned revision when set);
  - CUDA out of memory (at load or generation) → `ModelUnavailable` naming
    `quantization='4bit'` and the `max_new_tokens` knob.

## 5. Enabling steps on Colab / Kaggle

There is no GPU here; run the campaign in a GPU notebook. All commands are run
from the repository root.

1. **Confirm the GPU.** Colab/Kaggle images ship a CUDA torch:
   `python -c "import torch; print(torch.__version__, torch.cuda.is_available())"`.
2. **Install the toolchain** (the exact fail-closed command):

   ```bash
   python -m pip install 'torch>=2.4' 'transformers>=4.51,<5' 'accelerate>=1.0' 'bitsandbytes>=0.43'
   ```

3. **Download the model**, pinning the revision when one is known:

   ```bash
   python -m pip install 'huggingface_hub[cli]>=0.24'
   huggingface-cli download Qwen/Qwen3-8B --revision <pinned-sha>
   ```

   Record that revision in `QwenConfig.revision`. With no pin, leave it
   `"unpinned"` and say so; never invent a hash.
4. **Start the gateway and publish the policy sets**, exactly as in the
   evaluation card, section 2 / 2a. The runner probes `GET /healthz` first.
5. **Run the campaign.** The CLI uses the frozen default configuration:

   ```bash
   python scripts/bench_run.py \
     --defense-url http://127.0.0.1:18082 \
     --model qwen \
     --splits development,validation \
     --seed 0 --config-slug qwen3-8b-colab
   ```

   For a non-default configuration (4-bit, a pinned revision, thinking on, a
   different device), import the adapter in the notebook and drive it explicitly:

   ```python
   from benchmark.qwen import QwenConfig, QwenModelAdapter

   adapter = QwenModelAdapter(QwenConfig(revision="<pinned-sha>", quantization="4bit"))
   adapter.load()
   plan = adapter.plan(scenario, decide=lambda step_id, action: gateway.decide(step_id, action))
   ```

6. **Score and record.** `python scripts/bench_score.py --run <run-dir>`. The
   manifest records `model.kind`, every configuration field, the resolved
   torch/transformers versions, the prompt revision, the seed, the temperature
   and the token limit. Preserve the run directory before the session expires.

A run with different versions or a different model revision is a **new
experiment**, not a reproduction of any earlier run.
