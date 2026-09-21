# AegisGraph

AegisGraph provides the policy-neutral security contracts used to describe observations,
candidate actions, guard requests, decisions, and decision receipts. The Python package lives in
`backend/aegisgraph` and targets Python 3.12.

## Contracts

`aegisgraph.contracts` contains the immutable canonical models and stable action digest.
`aegisgraph.sentinel` contains the SENTINEL v1 boundary models: request envelopes are
forward-compatible, while candidate actions and responses reject unknown fields. These modules
only validate data; they do not execute tools, apply policy, or make network calls.

For local development, create a virtual environment and install `.[dev]`, then run
`python -m pytest` and `python -m ruff check backend tests`.
