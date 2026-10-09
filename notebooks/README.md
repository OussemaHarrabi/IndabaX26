# Notebooks — running the Qwen3-8B campaign in the cloud

These four notebooks are **thin interfaces** over the tested benchmark modules and
CLIs. No scoring, statistics, pairing or campaign logic lives in a cell: every
evaluation step calls `benchmark/analysis.py`, `benchmark/qwen.py`,
`scripts/bench_campaign.py`, `scripts/bench_run.py`, `scripts/bench_score.py`,
`scripts/bench_validate.py`, `scripts/bench_seal.py` or `scripts/bench_policies.py`.

| Notebook | What it does | Needs a GPU? |
| --- | --- | --- |
| `00_environment_and_smoke.ipynb` | Runtime/GPU check, pinned install, Qwen3-8B load, the fixed six-scenario Stage A smoke through the allow-all control and the defence, per-scenario saves, resume, scoring and bundling. | Yes for the real run |
| `01_qwen3_8b_public_campaign.ipynb` | The full public campaign: Stage B (development, 42 scenarios, ≥ 3 seeds) and Stage C (validation, 18 scenarios, 5 preferred / 3 the floor), with the paired allow-all and full-AegisGraph conditions, resume, Drive checkpoints and a downloadable bundle. | Yes |
| `02_qwen3_8b_ablations.ipynb` | The preregistered single-mechanism ablations — `provenance_enforcement`, `trust_ceiling`, `strict_confirmation`, `rewrite_revalidation` — each through `--condition ablation:<name>`, plus the control and full-defence rows. | Yes |
| `03_qwen_results_analysis.ipynb` | Load one or more immutable run directories or `.zip` bundles, verify every hash, reproduce the committed aggregate, emit the paired statistics, tables and plots. Runs on CPU against the committed scripted run. | No |

**No real-model result exists in this repository.** The native real-model campaign
has not been run. Notebooks 00–02 produce evidence only in the cloud, in a
directory you choose; nothing is committed and no output is saved into the
notebook files. Notebook 03 is the only one whose default parameters execute
here, and it analyses the **committed scripted run**
(`benchmark/runs/20261008T203656Z-m6-campaign/`) — scripted replay, evidence
class 1, not a model result.

## Badges

Replace `<branch>` with the branch that carries these notebooks.

```markdown
[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/OussemaHarrabi/IndabaX26/blob/<branch>/notebooks/00_environment_and_smoke.ipynb)
[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/OussemaHarrabi/IndabaX26/blob/<branch>/notebooks/01_qwen3_8b_public_campaign.ipynb)
[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/OussemaHarrabi/IndabaX26/blob/<branch>/notebooks/02_qwen3_8b_ablations.ipynb)
[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/OussemaHarrabi/IndabaX26/blob/<branch>/notebooks/03_qwen_results_analysis.ipynb)
```

Kaggle has no per-file badge. Create a notebook or dataset and use its own URL:

```markdown
[![Kaggle](https://kaggle.com/static/images/open-in-kaggle.svg)](https://kaggle.com/kernels/)<your-kernel-slug>
```

## Google Colab

1. Open a notebook with its badge (above), or `File → Upload notebook`.
2. `Runtime → Change runtime type → T4 GPU` (free tier) and save. A free T4 has
   about 15 GiB of VRAM, enough for the frozen **4-bit** (`Q4_K_M`) Qwen3-8B.
3. Run the cells in order. Notebooks 00–02 clone nothing: you must already be in a
   checkout of the repository. Either clone it first —

   ```python
   !git clone https://github.com/OussemaHarrabi/IndabaX26.git
   %cd IndabaX26
   ```

   — or mount a Drive copy. The notebooks locate the repository root
   automatically (they search upward for `scripts/bench_validate.py`) and `chdir`
   into it; set `AEGISGRAPH_REPO` to override.

## Kaggle

1. Create a notebook, attach the GPU accelerator (P100 or T4×2), and enable
   **Internet** (needed for the pinned install and the model download).
2. Clone the repository into `/kaggle/working` and run the same cells.
3. Kaggle sessions are shorter and have no `google.colab` module; leave
   `ENABLE_DRIVE = False` and download the bundle from `/kaggle/working`.

## Expected GPU memory

| Configuration | Approximate VRAM for Qwen3-8B |
| --- | --- |
| 4-bit nf4 (`QUANTIZATION = "4bit"`, the frozen class) | ~6–7 GiB weights + activations; fits a 15 GiB T4 |
| 8-bit | ~10–11 GiB |
| `bfloat16` / `float16` (`quantization = "none"`) | ~16–17 GiB; needs an A100 or 2× GPUs |

The notebooks mark the environment unsuitable below 14 GiB with the frozen 4-bit
configuration and stop with an explicit reason (notebook 00, section 10). The
adapter also fails closed on CUDA out-of-memory with the exact knobs to lower
(`quantization`, `max_new_tokens`); see `benchmark/qwen.py`.

## Storing secrets

**Never paste a token, key or credential into a cell.** These notebooks need no
secret at all: they mint a **development-only** identity with
`scripts/dev_issuer.py` and write the bearer to a temporary file (UTF-8, no BOM)
outside the repository.

If you must hold a Hugging Face token for a gated model, keep it in the platform's
secret store and read it at runtime:

```python
# Colab: add the secret in the key/lock icon (left sidebar), then:
from google.colab import userdata
HF_TOKEN = userdata.get("HF_TOKEN")   # never printed, never written to a cell
```

```python
# Kaggle: Add-ons → Secrets, then:
from kaggle_secrets import UserSecretsClient
HF_TOKEN = UserSecretsClient().get_secret("HF_TOKEN")
```

The committed notebooks are scanned by `tests/test_notebooks.py` for
secret-shaped strings in every cell and every saved output; a saved output that
leaks a token fails the test.

## Mounting Google Drive (checkpoints)

Notebook 01 checkpoints to Drive when `ENABLE_DRIVE = True`:

```python
from google.colab import drive
drive.mount("/content/drive")
# then set:
ENABLE_DRIVE = True
DRIVE_DIR = "aegisgraph-qwen-campaign"
```

The notebook copies each **run directory** and each `.zip` bundle into
`/content/drive/MyDrive/<DRIVE_DIR>/`, skipping anything already present (it never
overwrites an existing checkpoint).

## Resuming an interrupted campaign

An interrupted stage resumes from verified per-scenario checkpoints; a completed
run directory is never overwritten.

* Notebook 00 exercises this explicitly: `--max-scenarios 2` stops cleanly after
  two scenarios (`RESULT: CAMPAIGN INCOMPLETE`), then a `--resume` invocation
  (`RESULT: CAMPAIGN COMPLETE`) continues from the checkpoints.
* Notebook 01/02: set `RESUME = True` (or `MAX_SCENARIOS = N` for a bounded
  session). The driver re-finds the newest **incomplete** run directory for each
  (model, stage, condition, seed), verifies each checkpoint's hash and re-runs only
  the missing or failed ones. A fresh run without `--resume` always gets a new
  timestamp.

## Downloading the bundle

The campaign CLI writes one `.zip` per run directory under `RUNS_DIR`. In Colab:

```python
from google.colab import files
files.download("/content/aegisgraph-runs/<run-name>.zip")
```

In Kaggle, download from the notebook's **Output** tab (`/kaggle/working`).

## Verifying the bundle's hashes locally

Each run directory carries `hashes.sha256` (the authoritative manifest, extended
by `--bundle` to cover `score.json` and `score.txt`). Verify the archive and the
run inside it against the repository's own analysis module:

```bash
# 1. the archive's own digest
sha256sum <run-name>.zip

# 2. extract, then re-verify every recorded hash and reproduce the score
unzip <run-name>.zip -d /tmp/<run-name>
python -c "from benchmark.analysis import load_run_directory, reproduce_score; \
print(reproduce_score(load_run_directory('/tmp/<run-name>')))"
```

`pip install -e .` (or run from the repository root) first. A hash mismatch raises
`benchmark.analysis.AnalysisError`; nothing is silently dropped.

## Contributing results back to the repository

The repository never edits a completed run. To contribute a campaign:

1. **Keep every artifact.** Copy each run directory (not just the numbers) and its
   `hashes.sha256`; the raw outcomes are the evidence.
2. **Do not edit them.** A completed bundle is immutable; a new run is a new
   directory with a new timestamp.
3. **Record the environment.** `environment.json`/`configuration.json` and the
   resolved model revision are part of the run; keep them alongside the outcomes.
4. **Open a pull request** that adds the raw run directories under `benchmark/runs/`
   (or attaches the bundles) plus a short note naming the exact commands, the
   freeze block, the commit and the OS/GPU. Do **not** edit a freeze block: a
   configuration change is a **new** block appended with a new date.
5. **Let the analysis reproduce.** A reviewer re-runs
   `python scripts/bench_analyze.py --run <dir> --out /tmp/check`; the numbers must
   reproduce from the raw outcomes byte-for-byte.

Report negative and null results exactly as they are; a missed objective is a
result, not something to re-run away.
