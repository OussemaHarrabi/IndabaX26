# AegisGraph runtime image.
#
# Hardening posture (security finding F10):
#   * the application directory /app is owned by root:root and has every write
#     bit cleared, so the non-root runtime user cannot rewrite the service's own
#     code (and cannot, for example, drop a malicious `aegisgraph/` module);
#   * `--read-only` is the supported container posture: the service writes nothing
#     to disk (PYTHONDONTWRITEBYTECODE=1 stops .pyc writes), so a read-only root
#     filesystem is expected, not merely tolerated; run it with
#         docker run --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
#                    --cap-drop=ALL --security-opt=no-new-privileges ...
#   * no compiler or build toolchain and no pip/wheel/setuptools are present in
#     the final layer; dependencies are installed in a builder stage and copied in;
#   * the runtime user is non-root (uid/gid 10001) and owns nothing writable.
#
# Dependencies are exact pins from requirements.lock. requirements.lock carries
# versions but not hashes (finding F8); hash pinning is proposed in the M4
# handoff and is deliberately not applied here because requirements.lock is owned
# by the orchestrator and is outside this milestone's write scope.
#
# The base image is pinned by digest (the manifest-list digest for
# python:3.12-slim on 2026-10-08) so the build cannot silently pick up a new base.
# Build with `--provenance=false --sbom=false` for a reproducible image digest:
# BuildKit's default provenance attestation records build metadata, so the
# manifest-list digest varies between builds even when the content does not.

# --- stage 1: resolve and install the exact dependency set ---------------------
FROM python:3.12-slim@sha256:05cda9777409a9c3ffddd94a4c476b79f0769a0b4857f0c7ed9226b6800b0d6f AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build
COPY requirements.lock ./requirements.lock
# --target keeps the tree self-contained so it can be copied wholesale; no
# compiler is needed because every pin in the lock is a pure-Python wheel.
RUN python -m pip install --no-cache-dir --target=/install --requirement requirements.lock

# --- stage 2: minimal runtime ---------------------------------------------------
FROM python:3.12-slim@sha256:05cda9777409a9c3ffddd94a4c476b79f0769a0b4857f0c7ed9226b6800b0d6f AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/backend

# Dependency tree, root-owned like everything else.
COPY --from=builder --chown=root:root /install /usr/local/lib/python3.12/site-packages

# Image hygiene + the non-root runtime user. Removing pip/setuptools/wheel drops
# roughly 30 MB and the whole "install something at runtime" attack surface;
# `aegisgraph` owns nothing, so the service user cannot persist a foothold.
RUN rm -rf /usr/local/lib/python3.12/site-packages/pip \
           /usr/local/lib/python3.12/site-packages/pip-*.dist-info \
           /usr/local/lib/python3.12/site-packages/setuptools \
           /usr/local/lib/python3.12/site-packages/setuptools-*.dist-info \
           /usr/local/lib/python3.12/site-packages/wheel \
           /usr/local/lib/python3.12/site-packages/wheel-*.dist-info \
           /usr/local/lib/python3.12/site-packages/_distutils_hack \
           /usr/local/lib/python3.12/site-packages/pkg_resources \
           /usr/local/lib/python3.12/site-packages/distutils-precedence.pth \
           /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.12 \
    && addgroup --system --gid 10001 aegisgraph \
    && adduser --system --uid 10001 --ingroup aegisgraph --home /nonexistent --no-create-home aegisgraph

WORKDIR /app

# Application code and the lock (kept for provenance/introspection) are copied
# root-owned, then made read-only for everyone. The service user gets no write
# bit anywhere under /app.
COPY --chown=root:root backend ./backend
COPY --chown=root:root requirements.lock ./requirements.lock
RUN chmod -R a-w /app && chmod a-w /app

USER 10001:10001
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import sys,urllib.request;\
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).status == 200 else 1)"]

CMD ["python", "-m", "uvicorn", "aegisgraph.app:app", \
     "--host", "0.0.0.0", "--port", "8080", "--no-server-header"]
