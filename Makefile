# AegisGraph developer entry points.
#
# `make` is optional: every target is a thin wrapper over the exact commands in
# docs/ops/*.md, and on Windows you can run those commands directly (or under Git
# Bash). CI does NOT use this Makefile — it calls the same commands explicitly so
# the gates stay visible in the workflow log.
#
#   make help          list targets
#   make gates         run every local gate that CI runs
#   make stack-up      bring up API + PostgreSQL + observability backends
#
# `make` is not installed in the current Windows environment; the raw
# `docker compose` commands in docs/ops/compose.md are the canonical bring-up.

SHELL := /bin/sh
IMAGE ?= aegisgraph:local
COVERAGE_FAIL_UNDER ?= 94

.PHONY: help gates lint typecheck test audit bandit image smoke sbom \
        k8s-validate compose-config stack-up stack-down stack-logs stack-ps clean

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-16s %s\n", $$1, $$2}'

gates: lint typecheck test ## ruff + mypy + pytest with the coverage gate

lint: ## ruff over backend, tests and scripts
	python -m ruff check backend tests scripts

typecheck: ## strict mypy
	python -m mypy

test: ## pytest with coverage gate (COVERAGE_FAIL_UNDER, default 94)
	python -m pytest -q --cov=aegisgraph --cov-report=term-missing \
		--cov-fail-under=$(COVERAGE_FAIL_UNDER)

audit: ## pip-audit against the shipped pins
	python -m pip_audit -r requirements.lock --strict --progress-spinner off

bandit: ## static security scan
	python -m bandit -r backend -q --severity-level medium

image: ## build the hardened image
	docker build -t $(IMAGE) .

smoke: image ## run the hardened read-only smoke test
	docker run --rm -d --name aegisgraph-smoke --read-only \
		--tmpfs /tmp:rw,noexec,nosuid,size=16m --cap-drop=ALL \
		--security-opt=no-new-privileges -p 18080:8080 $(IMAGE)
	@echo "waiting for /healthz ..."; \
	for i in $$(seq 1 30); do \
		curl -fsS http://127.0.0.1:18080/healthz >/dev/null 2>&1 && break; \
		sleep 1; \
	done; \
	curl -fsS http://127.0.0.1:18080/healthz; echo; \
	docker stop aegisgraph-smoke >/dev/null

sbom: ## emit the SBOM / dependency inventory for $(IMAGE)
	python scripts/generate_sbom.py --image $(IMAGE)

k8s-validate: ## render, schema-validate and policy-check the manifests
	python scripts/validate_k8s_manifests.py

compose-config: ## validate the Compose stack without starting it
	cp -n .env.example .env 2>/dev/null || true; \
	docker compose config --quiet && echo "compose config OK"

stack-up: ## bring the whole stack up (requires .env)
	docker compose up -d --build

stack-down: ## stop the stack, keep named volumes
	docker compose down

stack-logs: ## follow stack logs
	docker compose logs -f --tail=100

stack-ps: ## show stack health
	docker compose ps

clean: ## remove local build artifacts (keeps named volumes)
	rm -rf artifacts/
