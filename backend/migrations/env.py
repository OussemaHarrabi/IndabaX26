"""Alembic environment: the schema lives in ``aegisgraph.models``.

The database URL is never stored in ``alembic.ini``. It is read from the
environment (``DATABASE_URL``) so a migration run and the service always agree on
the target, and so no connection string reaches Git.
"""

from __future__ import annotations

import os
from logging.config import fileConfig
from pathlib import Path

from aegisgraph.models import Base
from alembic import context
from sqlalchemy import engine_from_config, pool

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def database_url() -> str:
    """Return the migration target, refusing to guess when it is absent."""

    url = os.environ.get("DATABASE_URL", "").strip()
    if not url:
        raise SystemExit(
            "alembic: DATABASE_URL is required; export the same value the service uses"
        )
    return url


def run_migrations_offline() -> None:
    """Emit SQL to stdout without connecting (``alembic upgrade head --sql``)."""

    context.configure(
        url=database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        include_schemas=False,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run the migrations against the configured database."""

    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = database_url()
    connectable = engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            include_schemas=False,
        )
        with context.begin_transaction():
            context.run_migrations()


def script_directory() -> Path:
    """Report the migration directory, for diagnostics and tests."""

    return Path(__file__).resolve().parent


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
