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
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from benchmark.dataset import SEAL_FILE, SEALED_FILE, Dataset
from benchmark.schema import AttackFamily, Scenario, Split

#: Cross-split payload shingles at or above this Jaccard similarity are a leak.
LEAK_SIMILARITY_THRESHOLD = 0.9

#: Token-shingle width used for the near-duplicate check.
SHINGLE_WIDTH = 5

#: A text must yield at least this many shingles to take part in the comparison.
#: Short strings are identifiers and argument values ("isolate", "AL-3001"), not
#: payload templates: treating them as templates produces false leaks. With
#: ``SHINGLE_WIDTH = 5`` this means a text needs at least seven tokens.
MIN_SHINGLES = 3

#: Order-insensitive token-multiset threshold. Two payloads with the same tokens
#: in a different order — the slot-swap case — score 1.0 here, and a one-token
#: edit scores ``(T-1)/(T+1)``, so at ``T >= 19`` tokens a single changed token is
#: detected. Only texts with at least :data:`MIN_TEMPLATE_TOKENS` tokens are
#: compared, because below that an identifier pair looks like a paraphrase.
LEAK_MULTISET_THRESHOLD = 0.9
MIN_TEMPLATE_TOKENS = 20

#: Legacy-shaped scenario ids as they appear in the published tree.
LEGACY_ID_PATTERN = re.compile(r"\b(?:ent|fin|soc)_[a-z0-9_]{4,}\b")

_NORMALIZE = re.compile(r"[^a-z0-9 ]+")
_WHITESPACE = re.compile(r"\s+")

SPLIT_ORDER: tuple[Split, ...] = (Split.DEVELOPMENT, Split.VALIDATION, Split.HOLDOUT)

#: The machine-checkable family -> split policy the data card states: families 1-7
#: are development, 8-10 are validation. Without this the development/validation
#: separation would rest on an unverifiable label, and a whole matched pair could
#: be moved between splits with nothing to notice it. A sealed ``holdout``
#: scenario is exempt: the seal, not this table, governs its membership.
DEVELOPMENT_FAMILIES: tuple[AttackFamily, ...] = (
    AttackFamily.DIRECT_PROMPT_INJECTION,
    AttackFamily.INDIRECT_PROMPT_INJECTION,
    AttackFamily.PROVENANCE_LAUNDERING,
    AttackFamily.MEMORY_POISONING,
    AttackFamily.UNAUTHORIZED_TOOL_USE,
    AttackFamily.SENSITIVE_DATA_EXFILTRATION,
    AttackFamily.CONFIRMATION_BYPASS,
)
VALIDATION_FAMILIES: tuple[AttackFamily, ...] = (
    AttackFamily.REPLAY_TAMPERING,
    AttackFamily.UNSAFE_REWRITE,
    AttackFamily.OUTPUT_INTEGRITY,
)
FAMILY_SPLIT_POLICY: Mapping[AttackFamily, Split] = {
    **{family: Split.DEVELOPMENT for family in DEVELOPMENT_FAMILIES},
    **{family: Split.VALIDATION for family in VALIDATION_FAMILIES},
}


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


def build_index(
    dataset: Dataset,
    *,
    assignments: Mapping[str, str] | None = None,
) -> tuple[SplitIndex, list[Finding]]:
    """Build the split index from the declared splits, or from an independent source.

    ``assignments`` lets a caller supply a second source of truth for membership —
    a plan, a manifest, a previous freeze. :func:`split_disjointness` then compares
    the two, which is what makes its mismatch and overlap branches reachable.
    ``build_index`` itself reports nothing: the checks live in one place.
    """

    findings: list[Finding] = []
    assignment: dict[str, str] = {}
    families: dict[str, str] = {}
    pairs: dict[str, str] = {}
    counts: dict[str, int] = {split.value: 0 for split in SPLIT_ORDER}
    pairs_by_split: dict[str, list[str]] = defaultdict(list)

    for entry in dataset.entries:
        scenario = entry.scenario
        split = (
            assignments[scenario.id]
            if assignments is not None and scenario.id in assignments
            else scenario.split.value
        )
        assignment[scenario.id] = split
        counts[split] = counts.get(split, 0) + 1
        pairs_by_split[split].append(scenario.pair_id)
        families.setdefault(scenario.paraphrase_family, split)
        pairs.setdefault(scenario.pair_id, split)

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


def _token_multiset(text: str) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for token in normalize_text(text).split():
        counts[token] += 1
    return dict(counts)


def _multiset_jaccard(left: dict[str, int], right: dict[str, int]) -> float:
    """Order-insensitive similarity: shared tokens over the token union."""

    if not left or not right:
        return 0.0
    shared = sum(min(count, right.get(token, 0)) for token, count in left.items())
    union = sum(max(count, right.get(token, 0)) for token, count in left.items())
    union += sum(count for token, count in right.items() if token not in left)
    if not union:
        return 0.0
    return shared / union


def template_similarity(left: Scenario, right: Scenario) -> tuple[float, str]:
    """The strongest similarity between any two payload texts of two scenarios.

    Two metrics are used, because one is not enough:

    ``shingle``
        order-sensitive 5-gram Jaccard, which catches a copied paragraph;
    ``multiset``
        order-insensitive token Jaccard over texts of at least
        :data:`MIN_TEMPLATE_TOKENS` tokens, which catches a reused skeleton with
        its named slots swapped, and a one-token edit in a text of 19+ tokens.

    Residual limit: a paraphrase that changes the *vocabulary* (a synonym
    rewrite) is not detected by either metric, and a text shorter than
    :data:`MIN_TEMPLATE_TOKENS` tokens is not compared at all. Both limits are
    stated in ``docs/benchmark/data-card.md``.
    """

    best = (0.0, "shingle")
    for left_text in payload_texts(left):
        for right_text in payload_texts(right):
            shingle = _jaccard(_shingles(left_text), _shingles(right_text))
            if shingle > best[0]:
                best = (shingle, "shingle")
            left_tokens = normalize_text(left_text).split()
            right_tokens = normalize_text(right_text).split()
            if len(left_tokens) < MIN_TEMPLATE_TOKENS or len(right_tokens) < MIN_TEMPLATE_TOKENS:
                continue
            multiset = _multiset_jaccard(_token_multiset(left_text), _token_multiset(right_text))
            if multiset > best[0]:
                best = (multiset, "multiset")
    return best


def is_leak(similarity: float, metric: str) -> bool:
    """Whether a similarity value crosses the threshold for its metric."""

    return similarity >= (
        LEAK_MULTISET_THRESHOLD if metric == "multiset" else LEAK_SIMILARITY_THRESHOLD
    )


def leakage_findings(dataset: Dataset) -> list[Finding]:
    """Cross-split payload-template and near-duplicate leakage."""

    findings: list[Finding] = []

    fingerprint_splits: dict[str, set[str]] = defaultdict(set)
    fingerprint_ids: dict[str, list[str]] = defaultdict(list)

    scenarios = list(dataset.scenarios)
    for scenario in scenarios:
        fingerprint = template_fingerprint(scenario)
        fingerprint_splits[fingerprint].add(scenario.split.value)
        fingerprint_ids[fingerprint].append(scenario.id)

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
            similarity, metric = template_similarity(left, right)
            if is_leak(similarity, metric):
                findings.append(
                    Finding(
                        code="SPLIT_LEAK_NEAR_DUPLICATE",
                        message=(
                            f"payloads are {similarity:.3f} similar across splits by the "
                            f"{metric} metric ({left.split.value} vs {right.split.value})"
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


def published_id_namespace(
    repo_root: Path | str,
    *,
    max_files: int = 8_000,
    max_bytes: int = 32_000_000,
) -> set[str]:
    """Every legacy-shaped scenario id published in the *tracked* tree.

    The holdout must be disjoint not only from the native plaintext dataset but
    from every id the repository already publishes — the legacy SENTINEL suite in
    ``COURSE/**`` and ``evaluation/**`` uses the same ``ent_``/``fin_``/``soc_``
    namespace. Only tracked files are read: an untracked working copy is not a
    published namespace, and reading it would make the check non-reproducible.
    """

    import subprocess

    root = Path(repo_root)
    try:
        listing = subprocess.run(
            ["git", "ls-files", "-z"],
            capture_output=True,
            cwd=root,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):  # pragma: no cover - environment dependent
        return set()
    if listing.returncode != 0:
        return set()

    ids: set[str] = set()
    budget = max_bytes
    for index, raw_name in enumerate(listing.stdout.split(b"\0")):
        if index >= max_files or budget <= 0:
            break
        if not raw_name:
            continue
        path = root / raw_name.decode("utf-8", "replace")
        try:
            if not path.is_file() or path.stat().st_size > 2_000_000:
                continue
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        budget -= len(text)
        ids.update(LEGACY_ID_PATTERN.findall(text))
    return ids


def holdout_leakage_findings(
    holdout: list[Scenario],
    dataset: Dataset,
    *,
    published_ids: set[str] | None = None,
) -> list[Finding]:
    """Check a candidate holdout against the plaintext dataset before sealing it.

    This is the gate the seal command runs. A holdout that shares an id, a pair,
    a paraphrase family, a payload template or a near-duplicate payload with the
    plaintext dataset is not a holdout: it measures memorisation, so sealing it
    would be worse than not having one.
    """

    findings: list[Finding] = []
    plaintext = list(dataset.scenarios)

    known_ids = {scenario.id for scenario in plaintext}
    if published_ids:
        for scenario in holdout:
            if scenario.id in published_ids:
                findings.append(
                    Finding(
                        code="HOLDOUT_LEGACY_ID_COLLISION",
                        message=(
                            f"holdout id {scenario.id!r} is already published in the tracked "
                            "tree (legacy SENTINEL namespace)"
                        ),
                        where=(scenario.id,),
                    )
                )
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

    for candidate in holdout:
        for known in plaintext:
            similarity, metric = template_similarity(candidate, known)
            if is_leak(similarity, metric):
                findings.append(
                    Finding(
                        code="HOLDOUT_NEAR_DUPLICATE",
                        message=(
                            f"holdout payload is {similarity:.3f} similar to plaintext "
                            f"scenario {known.id!r} by the {metric} metric"
                        ),
                        where=(candidate.id, known.id),
                    )
                )
    return findings


def split_disjointness(
    index: SplitIndex,
    dataset: Dataset,
    *,
    policy: Mapping[AttackFamily, Split] | None = None,
) -> list[Finding]:
    """Every scenario sits in exactly one split, and two independent sources agree.

    Three sources of split membership exist, and this function compares them:

    1. **the scenario file** — ``scenario.split``, the declared label;
    2. **the index** — ``index.assignment``, which may be built from an
       independent mapping (``build_index(..., assignments=...)``);
    3. **the family policy** — :data:`FAMILY_SPLIT_POLICY`, the machine-checkable
       statement that families 1-7 belong to development and 8-10 to validation.

    Comparing (1) with (2) makes ``SPLIT_MISMATCH`` reachable; comparing (1) with
    (3) makes ``SPLIT_OVERLAP`` and ``SPLIT_POLICY_VIOLATION`` reachable, which is
    what catches a whole matched pair moved between splits. A sealed ``holdout``
    scenario is exempt from the family policy: its membership is governed by the
    seal, not by this rule.
    """

    findings: list[Finding] = []
    effective_policy: Mapping[AttackFamily, Split] = (
        FAMILY_SPLIT_POLICY if policy is None else policy
    )

    declared: dict[str, set[str]] = {split.value: set() for split in SPLIT_ORDER}
    policy_pools: dict[str, set[str]] = {split.value: set() for split in SPLIT_ORDER}
    family_members: dict[str, set[str]] = defaultdict(set)
    pair_members: dict[str, set[str]] = defaultdict(set)

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
        declared.setdefault(scenario.split.value, set()).add(scenario.id)
        family_members[scenario.paraphrase_family].add(scenario.id)
        pair_members[scenario.pair_id].add(scenario.id)

        if scenario.split is Split.HOLDOUT:
            continue
        required = effective_policy.get(scenario.attack_family) if scenario.attack_family else None
        if required is None:
            continue
        policy_pools[required.value].add(scenario.id)
        if scenario.split is not required:
            findings.append(
                Finding(
                    code="SPLIT_POLICY_VIOLATION",
                    message=(
                        f"scenario {scenario.id!r} is declared {scenario.split.value!r} but "
                        f"its family {scenario.attack_family.value!r} belongs to {required.value!r}"
                    ),
                    where=(scenario.id,),
                )
            )

    # Two independent memberships disagreeing is the overlap this check exists for.
    for split_name, members in sorted(policy_pools.items()):
        for other_name, other in sorted(declared.items()):
            if other_name == split_name:
                continue
            disagreement = members & other
            if disagreement:
                findings.append(
                    Finding(
                        code="SPLIT_OVERLAP",
                        message=(
                            f"the family policy places {len(disagreement)} scenarios in "
                            f"{split_name!r} while their files declare {other_name!r}"
                        ),
                        where=tuple(sorted(disagreement)),
                    )
                )

    for family, members in sorted(family_members.items()):
        splits = {
            scenario.split.value
            for scenario in dataset.scenarios
            if scenario.paraphrase_family == family
        }
        if len(splits) > 1:
            findings.append(
                Finding(
                    code="SPLIT_LEAK_FAMILY",
                    message=(
                        f"paraphrase family {family!r} appears in splits {sorted(splits)}; "
                        "a family must live in exactly one split"
                    ),
                    where=tuple(sorted(members)),
                )
            )
    for pair, members in sorted(pair_members.items()):
        splits = {
            scenario.split.value for scenario in dataset.scenarios if scenario.pair_id == pair
        }
        if len(splits) > 1:
            findings.append(
                Finding(
                    code="SPLIT_LEAK_PAIR",
                    message=(
                        f"matched pair {pair!r} is split across {sorted(splits)}; "
                        "an attack and its control must share a split"
                    ),
                    where=tuple(sorted(members)),
                )
            )

    covered = set().union(*declared.values()) if declared else set()
    uncovered = {scenario.id for scenario in dataset.scenarios} - covered
    if uncovered:
        findings.append(
            Finding(
                code="SPLIT_UNCOVERED",
                message=f"{len(uncovered)} scenarios are in no split pool",
                where=tuple(sorted(uncovered)),
            )
        )
    return findings


__all__ = [
    "DEVELOPMENT_FAMILIES",
    "FAMILY_SPLIT_POLICY",
    "LEAK_MULTISET_THRESHOLD",
    "LEAK_SIMILARITY_THRESHOLD",
    "LEGACY_ID_PATTERN",
    "MIN_SHINGLES",
    "MIN_TEMPLATE_TOKENS",
    "SHINGLE_WIDTH",
    "SPLIT_ORDER",
    "VALIDATION_FAMILIES",
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
    "published_id_namespace",
    "split_disjointness",
    "template_fingerprint",
    "template_similarity",
]
