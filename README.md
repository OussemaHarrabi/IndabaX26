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
and listens on port 8080. `sentinel-submission.yaml` is a starter manifest; replace the team
placeholder, validate it with the organizer's current validator, and record the actual agent
model/backend on every evaluation result. The pinned public scenario suite is declared under the
Apache-2.0 license.

## Evaluation reproducibility

The public evaluation source is pinned in `benchmark.lock` to
`dd2e5fe0979d0781a4bfe6d0849cd80cf69ef4a2`: 40 scenarios total (31 attack and 9 benign), across
enterprise (15), finance (12), and SOC (13). The source PDF mentions an earlier 19-scenario count;
use the pinned starter kit as the operational count and state the difference in the report.

For a fair defense comparison, keep the tested agent's model, tools, and system prompt fixed.
Change only runtime/hardware settings. Ollama `qwen3:8b` is an allowed local option if it runs
reliably on the available hardware; do not add safety instructions to that agent's prompt. Before
scoring, run each scenario with the `allow_all` baseline and verify `attack_success=True`, proving
that the scenario reaches the vulnerability being measured. If Ollama fails, use the `mock` mode
and record the model/backend used on every result. Report attack success rate, benign task utility,
false blocks, escalation behavior, latency, and errors. No benchmark result is claimed in this
repository until the pinned suite has actually been run.

## Development checks

```powershell
python -m pytest
python -m ruff check backend tests
python -m mypy
```
