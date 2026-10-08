"""Split assignment and leakage control for the native benchmark.

Three splits exist: ``development`` (policy authoring may read it),
``validation`` (policy authoring may read it but must not tune on it per episode)
and ``holdout`` (sealed; policy authoring must never see it before the freeze).

The scenario file declares its own split, so there is exactly one source of
truth. This module does four things:

1. builds the split index from the declared splits;
2. refuses any split whose *leakage unit* (scenario, pair, paraphrase family or
   payload template) appears in more than one split;
3. reports near-duplicate payload shingles, which are the leakage a template
   copy-paste produces even when the identifiers differ;
4. reports the sealed holdout as a **hash only** — never as content.

Holdout membership is a hash until the orchestrator opens the seal: the plaintext
is not in the working tree, and the seal manifest carries the SHA-256 of the
plaintext and of the sealed bytes so tampering is detectable without the
passphrase.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from benchmark.dataset import SEAL_FILE, SEALED_FILE, Dataset
from benchmark.schema import Scenario, Split

#: Cross-split payload shingles at or above this Jaccard similarity are a leak.
LEAK_SIMILARITY_THRESHOLD = 0.9

#: Token-shingle width used for the near-duplicate check.
SHINGLE_WIDTH = 5

#: A text must yield at least this many shingles to take part in the comparison.
#: Short strings are identifiers and argument values ("isolate", "AL-3001"), not
#: payload templates: treating them as templates produces false leaks. With
#: ``SHINGLE_WIDTH = 5`` this means a text needs at least seven tokens.
MIN_SHINGLES = 3

_NORMALIZE = re.compile(r"[^a-z0-9 ]+")
_WHITESPACE = re.compile(r"\s+")

SPLIT_ORDER: tuple[Split, ...] = (Split.DEVELOPMENT, Split.VALIDATION, Split.HOLDOUT)


@dataclass(frozen=True)
class Finding:
    code: str
    message: str
    severity: str = "error"
    where: tuple[str, ...] = ()

    def render(self) -> str:
        location = f" [{', '.join(self.where)}]" if self.where else ""
        return f"{self.severity.upper():7} {self.code}: {self.message}{location}"


@dataclass(frozen=True)
class SplitIndex:
    assignment: dict[str, str]
    families: dict[str, str]
    pairs: dict[str, str]
    counts: dict[str, int]
    pairs_by_split: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def to_json(self) -> dict[str, object]:
        return {
            "assignment": dict(sorted(self.assignment.items())),
            "families": dict(sorted(self.families.items())),
            "pairs": dict(sorted(self.pairs.items())),
            "counts": dict(sorted(self.counts.items())),
        }


@dataclass(frozen=True)
class HoldoutManifest:
    """Everything that may be said about the holdout without opening it."""

    sealed: bool
    sealed_file: str
    ciphertext_sha256: str
    plaintext_sha256: str
    scenario_count: int
    created: str
    cipher: str
    kdf: str
    present: bool

    def to_json(self) -> dict[str, object]:
        return {
            "sealed": self.sealed,
            "sealed_file": self.sealed_file,
            "ciphertext_sha256": self.ciphertext_sha256,
            "plaintext_sha256": self.plaintext_sha256,
            "scenario_count": self.scenario_count,
            "created": self.created,
            "cipher": self.cipher,
            "kdf": self.kdf,
            "present": self.present,
        }


def build_index(dataset: Dataset) -> tuple[SplitIndex, list[Finding]]:
    """Build the split index and report unit-level split conflicts."""

    findings: list[Finding] = []
    assignment: dict[str, str] = {}
    families: dict[str, str] = {}
    pairs: dict[str, str] = {}
    counts: dict[str, int] = {split.value: 0 for split in SPLIT_ORDER}
    pairs_by_split: dict[str, list[str]] = defaultdict(list)

    family_splits: dict[str, set[str]] = defaultdict(set)
    pair_splits: dict[str, set[str]] = defaultdict(set)

    for entry in dataset.entries:
        scenario = entry.scenario
        split = scenario.split.value
        assignment[scenario.id] = split
        counts[split] = counts.get(split, 0) + 1
        family_splits[scenario.paraphrase_family].add(split)
        pair_splits[scenario.pair_id].add(split)
        pairs_by_split[split].append(scenario.pair_id)
        families.setdefault(scenario.paraphrase_family, split)
        pairs.setdefault(scenario.pair_id, split)

    for family, splits in sorted(family_splits.items()):
        if len(splits) > 1:
            findings.append(
                Finding(
                    code="SPLIT_LEAK_FAMILY",
                    message=(
                        f"paraphrase family {family!r} appears in splits "
                        f"{sorted(splits)}; a family must live in exactly one split"
                    ),
                    where=tuple(
                        entry.scenario.id
                        for entry in dataset.entries
                        if entry.scenario.paraphrase_family == family
                    ),
                )
            )
    for pair, splits in sorted(pair_splits.items()):
        if len(splits) > 1:
            findings.append(
                Finding(
                    code="SPLIT_LEAK_PAIR",
                    message=(
                        f"matched pair {pair!r} is split across {sorted(splits)}; "
                        "an attack and its control must share a split"
                    ),
                    where=tuple(
                        entry.scenario.id
                        for entry in dataset.entries
                        if entry.scenario.pair_id == pair
                    ),
                )
            )

    index = SplitIndex(
        assignment=assignment,
        families=families,
        pairs=pairs,
        counts=counts,
        pairs_by_split={key: tuple(sorted(value)) for key, value in pairs_by_split.items()},
    )
    return index, findings


# --------------------------------------------------------------------------- #
# Template leakage
# --------------------------------------------------------------------------- #


def normalize_text(value: str) -> str:
    lowered = value.lower()
    replaced = _NORMALIZE.sub(" ", lowered)
    return _WHITESPACE.sub(" ", replaced).strip()


def payload_texts(scenario: Scenario) -> tuple[str, ...]:
    """The security-relevant text a scenario carries: evidence and action bodies."""

    texts = [observation.content for observation in scenario.observations]
    for proposed in scenario.proposed_actions:
        action = proposed.action
        if action.content:
            texts.append(action.content)
        texts.extend(value for value in action.arguments.values() if isinstance(value, str))
    return tuple(texts)


def template_fingerprint(scenario: Scenario) -> str:
    """A stable fingerprint of a scenario's normalized payload corpus."""

    blob = "\n".join(normalize_text(text) for text in payload_texts(scenario))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _shingles(text: str) -> frozenset[tuple[str, ...]]:
    tokens = normalize_text(text).split()
    if len(tokens) < SHINGLE_WIDTH + MIN_SHINGLES - 1:
        return frozenset()
    span = len(tokens) - SHINGLE_WIDTH + 1
    return frozenset(tuple(tokens[index : index + SHINGLE_WIDTH]) for index in range(span))


def _jaccard(left: frozenset[tuple[str, ...]], right: frozenset[tuple[str, ...]]) -> float:
    if len(left) < MIN_SHINGLES or len(right) < MIN_SHINGLES:
        return 0.0
    union = left | right
    if not union:
        return 0.0
    return len(left & right) / len(union)


def leakage_findings(dataset: Dataset) -> list[Finding]:
    """Cross-split payload-template and near-duplicate leakage."""

    findings: list[Finding] = []

    fingerprint_splits: dict[str, set[str]] = defaultdict(set)
    fingerprint_ids: dict[str, list[str]] = defaultdict(list)
    shingle_cache: dict[str, tuple[frozenset[tuple[str, ...]], ...]] = {}

    scenarios = list(dataset.scenarios)
    for scenario in scenarios:
        fingerprint = template_fingerprint(scenario)
        fingerprint_splits[fingerprint].add(scenario.split.value)
        fingerprint_ids[fingerprint].append(scenario.id)
        shingle_cache[scenario.id] = tuple(_shingles(text) for text in payload_texts(scenario))

    for fingerprint, splits in sorted(fingerprint_splits.items()):
        if len(splits) > 1:
            findings.append(
                Finding(
                    code="SPLIT_LEAK_TEMPLATE",
                    message=(
                        f"identical payload template (fingerprint {fingerprint[:12]}) appears "
                        f"in splits {sorted(splits)}"
                    ),
                    where=tuple(sorted(fingerprint_ids[fingerprint])),
                )
            )

    for index, left in enumerate(scenarios):
        for right in scenarios[index + 1 :]:
            if left.split is right.split:
                continue
            best = 0.0
            for left_shingles in shingle_cache[left.id]:
                for right_shingles in shingle_cache[right.id]:
                    best = max(best, _jaccard(left_shingles, right_shingles))
            if best >= LEAK_SIMILARITY_THRESHOLD:
                findings.append(
                    Finding(
                        code="SPLIT_LEAK_NEAR_DUPLICATE",
                        message=(
                            f"payloads are {best:.3f} similar across splits "
                            f"({left.split.value} vs {right.split.value})"
                        ),
                        where=(left.id, right.id),
                    )
                )
    return findings


# --------------------------------------------------------------------------- #
# Matched-pair completeness
# --------------------------------------------------------------------------- #


def pair_findings(dataset: Dataset) -> list[Finding]:
    """Every attack must have exactly one matched benign control using the same tools."""

    findings: list[Finding] = []
    by_pair: dict[str, list[Scenario]] = defaultdict(list)
    for scenario in dataset.scenarios:
        by_pair[scenario.pair_id].append(scenario)

    for pair, members in sorted(by_pair.items()):
        attacks = [scenario for scenario in members if scenario.attack_present]
        controls = [scenario for scenario in members if not scenario.attack_present]
        ids = tuple(sorted(scenario.id for scenario in members))
        if len(attacks) != 1:
            findings.append(
                Finding(
                    code="PAIR_ATTACK_COUNT",
                    message=(
                        f"pair {pair!r} has {len(attacks)} attack scenarios, expected exactly 1"
                    ),
                    where=ids,
                )
            )
        if len(controls) != 1:
            findings.append(
                Finding(
                    code="PAIR_CONTROL_COUNT",
                    message=(
                        f"pair {pair!r} has {len(controls)} benign controls, expected exactly 1"
                    ),
                    where=ids,
                )
            )
        if attacks and controls:
            attack, control = attacks[0], controls[0]
            if attack.domain is not control.domain:
                findings.append(
                    Finding(
                        code="PAIR_DOMAIN_MISMATCH",
                        message=(
                            f"pair {pair!r} spans domains "
                            f"{attack.domain.value}/{control.domain.value}"
                        ),
                        where=ids,
                    )
                )
            if (
                attack.attack_family is not None
                and control.attack_family is not None
                and attack.attack_family is not control.attack_family
            ):
                findings.append(
                    Finding(
                        code="PAIR_FAMILY_MISMATCH",
                        message=(
                            f"pair {pair!r} spans families "
                            f"{attack.family_label}/{control.family_label}"
                        ),
                        where=ids,
                    )
                )
            attack_tools = set(attack.policy_context.allowed_tools)
            control_tools = set(control.policy_context.allowed_tools)
            if attack_tools != control_tools:
                findings.append(
                    Finding(
                        code="PAIR_TOOL_MISMATCH",
                        message=(
                            f"pair {pair!r}: attack tools {sorted(attack_tools)} differ from "
                            f"control tools {sorted(control_tools)}"
                        ),
                        where=ids,
                    )
                )
            if not attack.proposed_actions or not control.proposed_actions:
                continue
            attack_tools_used = {
                proposed.action.tool
                for proposed in attack.proposed_actions
                if proposed.action.tool is not None
            }
            control_tools_used = {
                proposed.action.tool
                for proposed in control.proposed_actions
                if proposed.action.tool is not None
            }
            if not attack_tools_used & control_tools_used:
                findings.append(
                    Finding(
                        code="PAIR_NO_SHARED_TOOL",
                        message=(
                            f"pair {pair!r}: attack uses {sorted(attack_tools_used)} and control "
                            f"uses {sorted(control_tools_used)}; no tool is shared"
                        ),
                        where=ids,
                    )
                )
    return findings


# --------------------------------------------------------------------------- #
# Sealed holdout
# --------------------------------------------------------------------------- #


def holdout_manifest(root: Path | str) -> HoldoutManifest:
    """Read ``holdout/seal.json``. Returns a hash-only view; never content."""

    base = Path(root)
    seal_path = base / SEAL_FILE
    sealed_path = base / SEALED_FILE
    if not seal_path.is_file():
        return HoldoutManifest(
            sealed=False,
            sealed_file=SEALED_FILE,
            ciphertext_sha256="",
            plaintext_sha256="",
            scenario_count=0,
            created="",
            cipher="",
            kdf="",
            present=False,
        )
    seal = json.loads(seal_path.read_text(encoding="utf-8"))
    ciphertext_sha256 = ""
    if sealed_path.is_file():
        ciphertext_sha256 = hashlib.sha256(sealed_path.read_bytes()).hexdigest()
    return HoldoutManifest(
        sealed=True,
        sealed_file=str(seal.get("sealed_file", SEALED_FILE)),
        ciphertext_sha256=ciphertext_sha256,
        plaintext_sha256=str(seal.get("plaintext_sha256", "")),
        scenario_count=int(seal.get("scenario_count", 0)),
        created=str(seal.get("created", "")),
        cipher=str(seal.get("cipher", "")),
        kdf=str(seal.get("kdf", "")),
        present=sealed_path.is_file(),
    )


def assert_seal_closed(root: Path | str) -> list[Finding]:
    """The holdout must be sealed on disk and must not appear as plaintext."""

    base = Path(root)
    findings: list[Finding] = []
    manifest = holdout_manifest(base)
    plaintext = sorted((base / "holdout").glob("*.json")) if (base / "holdout").is_dir() else []
    plaintext = [path for path in plaintext if path.name != "seal.json"]
    if plaintext:
        findings.append(
            Finding(
                code="HOLDOUT_UNSEALED",
                message=(
                    "plaintext holdout scenarios are present in the tree: "
                    f"{[path.name for path in plaintext]}"
                ),
            )
        )
    if not manifest.present:
        findings.append(
            Finding(
                code="HOLDOUT_MISSING",
                message=f"no sealed holdout at {SEALED_FILE}; the unsealed set cannot be released",
            )
        )
        return findings
    return findings


def holdout_leakage_findings(holdout: list[Scenario], dataset: Dataset) -> list[Finding]:
    """Check a candidate holdout against the plaintext dataset before sealing it.

    This is the gate the seal command runs. A holdout that shares an id, a pair,
    a paraphrase family, a payload template or a near-duplicate payload with the
    plaintext dataset is not a holdout: it measures memorisation, so sealing it
    would be worse than not having one.
    """

    findings: list[Finding] = []
    plaintext = list(dataset.scenarios)

    known_ids = {scenario.id for scenario in plaintext}
    known_pairs = {scenario.pair_id for scenario in plaintext}
    known_families = {scenario.paraphrase_family for scenario in plaintext}

    for scenario in holdout:
        if scenario.id in known_ids:
            findings.append(
                Finding(
                    code="HOLDOUT_ID_COLLISION",
                    message=f"holdout id {scenario.id!r} already exists in the plaintext dataset",
                    where=(scenario.id,),
                )
            )
        if scenario.pair_id in known_pairs:
            findings.append(
                Finding(
                    code="HOLDOUT_PAIR_COLLISION",
                    message=(
                        f"holdout pair {scenario.pair_id!r} already exists in the plaintext dataset"
                    ),
                    where=(scenario.id,),
                )
            )
        if scenario.paraphrase_family in known_families:
            findings.append(
                Finding(
                    code="HOLDOUT_FAMILY_COLLISION",
                    message=(
                        f"holdout paraphrase family {scenario.paraphrase_family!r} already "
                        "exists in the plaintext dataset"
                    ),
                    where=(scenario.id,),
                )
            )
        if scenario.split is not Split.HOLDOUT:
            findings.append(
                Finding(
                    code="HOLDOUT_SPLIT_MISMATCH",
                    message=f"sealed scenario {scenario.id!r} does not declare split 'holdout'",
                    where=(scenario.id,),
                )
            )

    plaintext_fingerprints = {template_fingerprint(scenario): scenario.id for scenario in plaintext}
    for scenario in holdout:
        collision = plaintext_fingerprints.get(template_fingerprint(scenario))
        if collision is not None:
            findings.append(
                Finding(
                    code="HOLDOUT_TEMPLATE_COLLISION",
                    message=(
                        f"holdout payload template is identical to plaintext scenario {collision!r}"
                    ),
                    where=(scenario.id, collision),
                )
            )

    plaintext_shingles = [
        (scenario.id, _shingles(text)) for scenario in plaintext for text in payload_texts(scenario)
    ]
    for scenario in holdout:
        for text in payload_texts(scenario):
            candidate = _shingles(text)
            for plaintext_id, known in plaintext_shingles:
                similarity = _jaccard(candidate, known)
                if similarity >= LEAK_SIMILARITY_THRESHOLD:
                    findings.append(
                        Finding(
                            code="HOLDOUT_NEAR_DUPLICATE",
                            message=(
                                f"holdout payload is {similarity:.3f} similar to plaintext "
                                f"scenario {plaintext_id!r}"
                            ),
                            where=(scenario.id, plaintext_id),
                        )
                    )
    return findings


def split_disjointness(index: SplitIndex, dataset: Dataset) -> list[Finding]:
    """Every scenario belongs to exactly one split, and the split pools are disjoint.

    The assignment comes from the scenario files themselves, so a mismatch or an
    overlap means two sources disagreed — the failure mode this check exists for.
    """

    findings: list[Finding] = []
    pools: dict[str, set[str]] = {split.value: set() for split in SPLIT_ORDER}
    for scenario in dataset.scenarios:
        assigned = index.assignment.get(scenario.id)
        if assigned is None:
            findings.append(
                Finding(
                    code="SPLIT_UNASSIGNED",
                    message=f"scenario {scenario.id!r} has no split assignment",
                    where=(scenario.id,),
                )
            )
            continue
        if assigned != scenario.split.value:
            findings.append(
                Finding(
                    code="SPLIT_MISMATCH",
                    message=(
                        f"scenario {scenario.id!r} declares {scenario.split.value!r} "
                        f"but the index assigns {assigned!r}"
                    ),
                    where=(scenario.id,),
                )
            )
            continue
        pools.setdefault(assigned, set()).add(scenario.id)

    names = sorted(pools)
    for index_left, left in enumerate(names):
        for right in names[index_left + 1 :]:
            overlap = pools[left] & pools[right]
            if overlap:
                findings.append(
                    Finding(
                        code="SPLIT_OVERLAP",
                        message=(f"splits {left!r} and {right!r} share {len(overlap)} scenarios"),
                        where=tuple(sorted(overlap)),
                    )
                )

    assigned_ids = set().union(*pools.values()) if pools else set()
    unassigned = {scenario.id for scenario in dataset.scenarios} - assigned_ids
    if unassigned:
        findings.append(
            Finding(
                code="SPLIT_UNCOVERED",
                message=f"{len(unassigned)} scenarios are in no split pool",
                where=tuple(sorted(unassigned)),
            )
        )
    return findings


__all__ = [
    "LEAK_SIMILARITY_THRESHOLD",
    "MIN_SHINGLES",
    "SHINGLE_WIDTH",
    "SPLIT_ORDER",
    "Finding",
    "HoldoutManifest",
    "SplitIndex",
    "assert_seal_closed",
    "build_index",
    "holdout_leakage_findings",
    "holdout_manifest",
    "leakage_findings",
    "normalize_text",
    "pair_findings",
    "payload_texts",
    "split_disjointness",
    "template_fingerprint",
]
