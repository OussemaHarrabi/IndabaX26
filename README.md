# AegisGraph

AegisGraph is a local SENTINEL v1 decision gateway for proposed agent actions. It combines
bounded request contracts, provenance-aware policy checks, and an HTTP adapter. It accepts an
inert action proposal and returns `allow`, `block`, `escalate`, or `rewrite`; it never invokes a
tool, model, or external service.

The Python 3.12 package lives in `backend/aegisgraph`. `contracts.py` defines immutable canonical
models and stable action digests. `sentinel.py` defines the wire models, `adapter.py` resolves
provenance, `policy.py` parses authorization facts, and `engine.py` makes deterministic decisions.
The local API is in `app.py`.

## Run locally

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m uvicorn aegisgraph.app:app --app-dir backend --host 127.0.0.1 --port 8080
```

The service has no API key requirement for local simulation. Keep it bound to localhost unless it
is placed behind your deployment's authentication and network controls. Interactive API docs and
OpenAPI output are disabled.

Health check:

```powershell
curl.exe http://127.0.0.1:8080/healthz
```

Example decision request:

```powershell
curl.exe -X POST http://127.0.0.1:8080/v1/decision `
  -H "Content-Type: application/json" `
  --data-binary '{"run_id":"local-demo","step_id":1,"user_goal":"Summarize the request","candidate_action":{"type":"respond","content":"The request is ready for review."},"policy_context":{"allowed_tools":[]}}'
```

Requests with unknown envelope fields are ignored for forward compatibility. Candidate action
shapes and responses are strict. Invalid requests receive a generic sanitized 4xx response; a valid
request that cannot be evaluated safely receives a generic `block`. Responses are bounded below
64 KB and marked `no-store`. These decisions are deterministic policy checks, not proof that every
possible prompt injection or cyberattack is detected. The service has no authentication by default
and must not be exposed directly to an untrusted network.

## Container

Build and run with a read-only root filesystem, a small writable `/tmp`, no Linux capabilities,
and no-new-privileges:

```powershell
docker build -t aegisgraph:local .
docker run --rm --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m `
  --cap-drop=ALL --security-opt=no-new-privileges --pids-limit=64 --memory=512m `
  -p 8080:8080 aegisgraph:local
```

The image installs exact runtime dependency versions from `requirements.lock`, runs as UID 10001,
and listens on port 8080. `sentinel-submission.yaml` contains the owner-supplied team name
`9ahwa mahrou9a`; its live organizer validation is still pending. Record the actual agent
model/backend on every evaluation result. The pinned public scenario suite is declared under the
Apache-2.0 license. A live Docker-engine run has not yet been verified.

## Evaluation reproducibility

The public evaluation source is pinned in `benchmark.lock` to
`dd2e5fe0979d0781a4bfe6d0849cd80cf69ef4a2`: 40 scenarios total (31 attack and 9 benign), across
enterprise (15), finance (12), and SOC (13). The source PDF mentions an earlier 19-scenario count;
use the pinned starter kit as the operational count and state the difference in the report.

The matched public-suite self-test has now run on a free Colab T4 with locally served
`Qwen/Qwen3-8B` via Ollama `qwen3:8b` Q4_K_M, thinking off and a 768-token decode cap. The agent's
system prompt and tools were unchanged; no external inference API was used. All four runs
(`allow_all`, `provenance`, AegisGraph v1 and v3) completed 40/40 scenarios, with raw artifacts in
[`evaluation/real-qwen/`](evaluation/real-qwen/README.md). Allow-all reached 22/31 attacks; nine
unreached attacks are excluded from defense-effectiveness claims. V3 stopped all 22 reached attacks
in this one seeded public-suite run, but benign task utility was only 4/9: the kit reports
`eligible=false` below its 0.5 utility gate. These are self-test outcomes, **not official jury
scores or universal-coverage claims**. The failure analysis, hashes, and two individually reached
demo cases are in [`REPORT.tex`](REPORT.tex) and [`DEMO_RUNBOOK.md`](DEMO_RUNBOOK.md).

Open `http://127.0.0.1:8080/` while the local service is running to import a JSONL trace
and scorecard for read-only investigation. The interface never executes a trace or launches a
simulation. The technical report is LaTeX source; report rendering, manual import of the real
artifacts at narrow width, final video, live validator, Docker check, and human-team eligibility are pending.

## Development checks

```powershell
python -m pytest
python -m ruff check backend tests
python -m mypy
```
