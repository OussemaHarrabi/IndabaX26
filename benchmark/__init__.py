"""AegisGraph native benchmark: schema, validation, scoring, splits and runner.

The native benchmark is framework independent. It imports the gateway only
through its public HTTP contract (:mod:`benchmark.runner`) and never imports
``aegisgraph`` Python modules, so a scenario cannot depend on defence internals.

Modules
-------
``schema``      the authoritative native scenario model
``wire``        native scenario -> SENTINEL decision request (the only coupling)
``validators``  one entry point that validates a dataset and fails loudly
``scoring``     deterministic native metrics from raw outcomes
``splits``      development / validation / sealed-holdout assignment and leakage control
``seal``        passphrase-sealed holdout (open / verify)
``runner``      HTTP driver producing immutable run directories
``adapters.sentinel``  legacy SENTINEL compatibility layer (read-only inputs)
"""

from __future__ import annotations

SCHEMA_VERSION = "aegisgraph-benchmark/v1"

__all__ = ["SCHEMA_VERSION"]
