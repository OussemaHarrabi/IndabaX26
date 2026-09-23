FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app/backend

WORKDIR /app

COPY requirements.lock ./requirements.lock
RUN python -m pip install --no-cache-dir --requirement requirements.lock

COPY backend ./backend

RUN addgroup --system --gid 10001 aegisgraph \
    && adduser --system --uid 10001 --ingroup aegisgraph --home /nonexistent aegisgraph \
    && chown -R aegisgraph:aegisgraph /app

USER 10001:10001
EXPOSE 8080

CMD ["python", "-m", "uvicorn", "aegisgraph.app:app", "--host", "0.0.0.0", "--port", "8080", "--no-server-header"]
