"""Loading, indexing and hashing of a native benchmark dataset.

The dataset on disk is ``<root>/scenarios/<domain>/<id>.json``. The sealed
holdout lives in ``<root>/holdout/`` and is *not* part of the plaintext dataset:
it is only readable through :mod:`benchmark.seal` with the custodian passphrase.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from benchmark.schema import Scenario, canonical_scenario_text, scenario_hash

SCENARIO_DIR = "scenarios"
HOLDOUT_DIR = "holdout"
SEAL_FILE = "holdout/seal.json"
SEALED_FILE = "holdout/sealed-holdout.json.enc"


class DatasetError(RuntimeError):
    """Raised when the dataset on disk cannot be read at all."""


@dataclass(frozen=True)
class DatasetEntry:
    relative_path: str
    sha256: str
    scenario: Scenario


@dataclass(frozen=True)
class Dataset:
    """A loaded, id-sorted dataset plus the bytes that identify it."""

    root: Path
    entries: tuple[DatasetEntry, ...]

    @property
    def scenarios(self) -> tuple[Scenario, ...]:
        return tuple(entry.scenario for entry in self.entries)

    @property
    def by_id(self) -> dict[str, Scenario]:
        return {entry.scenario.id: entry.scenario for entry in self.entries}

    def subset(self, split: str) -> tuple[Scenario, ...]:
        return tuple(
            entry.scenario for entry in self.entries if entry.scenario.split.value == split
        )

    def dataset_hash(self) -> str:
        """SHA-256 over ``(relative path, file sha256)`` pairs, path-sorted."""

        digest = hashlib.sha256()
        for entry in sorted(self.entries, key=lambda item: item.relative_path):
            digest.update(entry.relative_path.encode("utf-8"))
            digest.update(b"\0")
            digest.update(entry.sha256.encode("ascii"))
            digest.update(b"\n")
        return digest.hexdigest()


def scenario_set_hash(scenarios: tuple[Scenario, ...] | list[Scenario]) -> str:
    """SHA-256 over ``(scenario id, scenario hash)`` pairs, id-sorted.

    This is the hash of the *selection*: a run over the development split alone
    and a run over development plus validation produce different values even
    though they share scenario files.
    """

    digest = hashlib.sha256()
    for scenario in sorted(scenarios, key=lambda item: item.id):
        digest.update(scenario.id.encode("utf-8"))
        digest.update(b"\0")
        digest.update(scenario_hash(scenario).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def load_dataset(root: Path | str) -> Dataset:
    """Load every ``<root>/scenarios/**/*.json`` file. Never reads the holdout."""

    base = Path(root)
    scenario_root = base / SCENARIO_DIR
    if not scenario_root.is_dir():
        raise DatasetError(f"no scenario directory at {scenario_root}")
    entries: list[DatasetEntry] = []
    ids: set[str] = set()
    for path in sorted(scenario_root.rglob("*.json")):
        raw = path.read_bytes()
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise DatasetError(f"{path}: not valid UTF-8 JSON: {error}") from error
        scenario = Scenario.model_validate(decoded)
        if scenario.id in ids:
            raise DatasetError(f"{path}: duplicate scenario id {scenario.id!r}")
        ids.add(scenario.id)
        relative = path.relative_to(base).as_posix()
        entries.append(
            DatasetEntry(
                relative_path=relative,
                sha256=hashlib.sha256(raw).hexdigest(),
                scenario=scenario,
            )
        )
    if not entries:
        raise DatasetError(f"no scenarios found under {scenario_root}")
    entries.sort(key=lambda entry: entry.scenario.id)
    return Dataset(root=base, entries=tuple(entries))


def scenario_text(scenario: Scenario) -> str:
    return canonical_scenario_text(scenario)


def write_scenario(path: Path, scenario: Scenario) -> None:
    """Write a scenario in canonical form (used by authoring tools and tests)."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical_scenario_text(scenario), encoding="utf-8", newline="\n")
