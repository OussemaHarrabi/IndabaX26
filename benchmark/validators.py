"""One entry point that validates a native benchmark and fails with a readable report.

The validator is the gate a reviewer runs before trusting the data. It checks:

``schema``
    every file parses and validates against :mod:`benchmark.schema`;
``duplicates``
    no scenario id, pair id or full scenario body repeats;
``template leakage``
    no payload template or paraphrase family crosses a split, and no two
    cross-split payloads are near-duplicates;
``matched controls``
    every attack has exactly one matched benign control in the same domain, the
    same family and with the same tool set;
``bounds``
    every assembled decision request fits the gateway's default body cap and
    field bounds;
``licence and provenance``
    licence, origin, creation date and synthetic flag are present and real;
``deterministic scoring``
    every scoring spec is fully explicit and the scoring function is stable;
``label leakage``
    no benchmark label (scenario id, pair id, paraphrase family, attack family,
    safety property, split, scoring method) is serialised into a request;
``seal``
    the holdout is sealed, its ciphertext matches the manifest, and no plaintext
    holdout scenario is in the tree.

Run it as ``python -m benchmark.validators benchmark/data`` or through
``scripts/bench_validate.py``.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import ValidationError

from benchmark import wire
from benchmark.dataset import (
    SCENARIO_DIR,
    Dataset,
    DatasetEntry,
    DatasetError,
    load_dataset,
)
from benchmark.schema import AttackFamily, Scenario, ScenarioKind
from benchmark.scoring import Outcome, StepVerdict, derive_outcome, score
from benchmark.splits import (
    Finding,
    assert_seal_closed,
    build_index,
    holdout_manifest,
    leakage_findings,
    pair_findings,
    split_disjointness,
)

#: The gateway's default request body cap (``AEGISGRAPH_MAX_BODY_BYTES``). The
#: deployer may raise it, but the benchmark data must fit the default.
WIRE_BODY_LIMIT = 1_048_576

#: The gateway's request model bound on ``policy_context``.
WIRE_POLICY_CONTEXT_LIMIT = 16_384

#: The gateway's request model bound on ``user_goal`` and action ``content``.
WIRE_CONTENT_LIMIT = 16_000

#: The scoring method each attack family requires. ``unsafe_rewrite`` is judged by
#: its leakage post-condition, so downgrading it to the plain method would score a
#: rewrite that still ships the secret as *defended* — a silent inversion of the
#: family's entire result. Every other family is judged on the verdict alone.
REQUIRED_SCORING_METHOD: dict[AttackFamily, str] = {
    AttackFamily.UNSAFE_REWRITE: "action_authorization_with_leakage",
}
DEFAULT_SCORING_METHOD = "action_authorization"


@dataclass
class ValidationReport:
    root: Path
    findings: list[Finding] = field(default_factory=list)
    scenario_count: int = 0
    by_split: dict[str, int] = field(default_factory=dict)
    by_domain: dict[str, int] = field(default_factory=dict)
    by_family: dict[str, int] = field(default_factory=dict)
    dataset_hash: str = ""
    holdout: dict[str, object] = field(default_factory=dict)
    max_request_bytes: int = 0

    @property
    def errors(self) -> list[Finding]:
        return [finding for finding in self.findings if finding.severity == "error"]

    @property
    def warnings(self) -> list[Finding]:
        return [finding for finding in self.findings if finding.severity != "error"]

    @property
    def ok(self) -> bool:
        return not self.errors

    def render(self) -> str:
        lines: list[str] = []
        lines.append(f"native benchmark validation: {self.root}")
        lines.append(
            f"scenarios={self.scenario_count} splits={self.by_split} "
            f"domains={self.by_domain} families={self.by_family}"
        )
        lines.append(f"dataset sha256: {self.dataset_hash}")
        lines.append(
            f"max assembled request: {self.max_request_bytes} bytes (limit {WIRE_BODY_LIMIT})"
        )
        if self.holdout:
            lines.append(
                "sealed holdout: "
                f"scenarios={self.holdout.get('scenario_count')} "
                f"ciphertext_sha256={str(self.holdout.get('ciphertext_sha256'))[:16]}… "
                f"plaintext_sha256={str(self.holdout.get('plaintext_sha256'))[:16]}…"
            )
        errors = self.errors
        warnings = self.warnings
        lines.append(f"errors={len(errors)} warnings={len(warnings)}")
        for finding in sorted(self.findings, key=lambda item: (item.severity, item.code)):
            lines.append("  " + finding.render())
        lines.append("RESULT: " + ("PASS" if self.ok else "FAIL"))
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Individual checks
# --------------------------------------------------------------------------- #


def _schema_findings(root: Path) -> tuple[list[Finding], list[DatasetEntry], list[Path]]:
    findings: list[Finding] = []
    entries: list[DatasetEntry] = []
    paths = sorted((root / SCENARIO_DIR).rglob("*.json"))
    for path in paths:
        raw = path.read_bytes()
        relative = path.relative_to(root).as_posix()
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            findings.append(
                Finding(
                    code="SCHEMA_JSON",
                    message=f"not valid UTF-8 JSON: {error}",
                    where=(relative,),
                )
            )
            continue
        try:
            scenario = Scenario.model_validate(decoded)
        except ValidationError as error:
            for item in error.errors():
                location = ".".join(str(part) for part in item["loc"]) or "<root>"
                findings.append(
                    Finding(
                        code="SCHEMA_INVALID",
                        message=f"{location}: {item['msg']}",
                        where=(relative,),
                    )
                )
            continue
        entries.append(
            DatasetEntry(
                relative_path=relative,
                sha256=hashlib.sha256(raw).hexdigest(),
                scenario=scenario,
            )
        )
    return findings, entries, paths


def _content_projection(scenario: Scenario) -> str:
    """The scenario's substance, with identity and bookkeeping fields removed.

    Two files carrying the same evidence, the same actions and the same policy
    context are the same scenario however they are named, so the duplicate check
    hashes this projection rather than the whole document — which always differs
    once the id differs, making the check vacuous.
    """

    return json.dumps(
        scenario.model_dump(
            mode="json",
            exclude={
                "id",
                "title",
                "description",
                "pair_id",
                "paraphrase_family",
                "tags",
                "dataset",
                "scenario_version",
            },
        ),
        sort_keys=True,
    )


def _duplicate_findings(dataset: Dataset) -> list[Finding]:
    findings: list[Finding] = []
    ids: dict[str, list[str]] = {}
    bodies: dict[str, list[str]] = {}
    for entry in dataset.entries:
        ids.setdefault(entry.scenario.id, []).append(entry.relative_path)
        digest = hashlib.sha256(_content_projection(entry.scenario).encode("utf-8")).hexdigest()
        bodies.setdefault(digest, []).append(entry.scenario.id)
    for scenario_id, paths in sorted(ids.items()):
        if len(paths) > 1:
            findings.append(
                Finding(
                    code="DUPLICATE_ID",
                    message=f"scenario id {scenario_id!r} appears in {len(paths)} files",
                    where=tuple(paths),
                )
            )
    for fingerprint, members in sorted(bodies.items()):
        if len(members) > 1:
            findings.append(
                Finding(
                    code="DUPLICATE_BODY",
                    message=(
                        f"identical scenario content (fingerprint {fingerprint[:12]}) "
                        f"under different ids"
                    ),
                    where=tuple(sorted(members)),
                )
            )
    return findings


def _bound_findings(dataset: Dataset) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    largest = 0
    for entry in dataset.entries:
        scenario = entry.scenario
        run_id = wire.run_id_for(0)
        for request in wire.build_episode(scenario, run_id=run_id):
            size = len(wire.request_bytes(request))
            largest = max(largest, size)
            if size > WIRE_BODY_LIMIT:
                findings.append(
                    Finding(
                        code="BOUND_REQUEST",
                        message=(
                            f"assembled request is {size} bytes, over the {WIRE_BODY_LIMIT} cap"
                        ),
                        where=(scenario.id,),
                    )
                )
            policy_bytes = len(json.dumps(request["policy_context"], allow_nan=False).encode())
            if policy_bytes > WIRE_POLICY_CONTEXT_LIMIT:
                findings.append(
                    Finding(
                        code="BOUND_POLICY_CONTEXT",
                        message=(
                            f"policy context is {policy_bytes} bytes, over "
                            f"{WIRE_POLICY_CONTEXT_LIMIT}"
                        ),
                        where=(scenario.id,),
                    )
                )
            if len(request["user_goal"]) > WIRE_CONTENT_LIMIT:
                findings.append(
                    Finding(
                        code="BOUND_GOAL",
                        message=f"user_goal exceeds {WIRE_CONTENT_LIMIT} characters",
                        where=(scenario.id,),
                    )
                )
    return findings, largest


def required_scoring_method(family: AttackFamily | None) -> str:
    """The scoring method an attack of ``family`` must declare."""

    if family is None:
        return DEFAULT_SCORING_METHOD
    return REQUIRED_SCORING_METHOD.get(family, DEFAULT_SCORING_METHOD)


def _family_spec_findings(dataset: Dataset) -> list[Finding]:
    """Every attack family must carry the scoring spec its judgement needs."""

    findings: list[Finding] = []
    attacks = [
        entry.scenario
        for entry in dataset.entries
        if entry.scenario.scenario_kind is ScenarioKind.ATTACK
    ]
    for scenario in attacks:
        required = required_scoring_method(scenario.attack_family)
        family = scenario.attack_family.value if scenario.attack_family else "unlabelled"
        if scenario.scoring.method != required:
            findings.append(
                Finding(
                    code="FAMILY_SCORING_SPEC",
                    message=(
                        f"attack family {family!r} requires scoring method {required!r} but "
                        f"this attack declares {scenario.scoring.method!r}; the judgement "
                        "would change without any edit to the episode"
                    ),
                    where=(scenario.id,),
                )
            )
        if required == "action_authorization_with_leakage" and scenario.scoring.leakage is None:
            findings.append(
                Finding(
                    code="FAMILY_SCORING_SPEC",
                    message=(
                        f"attack family {family!r} requires a leakage spec and this attack "
                        "declares none"
                    ),
                    where=(scenario.id,),
                )
            )
    families = {scenario.attack_family for scenario in attacks if scenario.attack_family}
    for family in sorted(families, key=lambda item: item.value):
        required = required_scoring_method(family)
        if not any(
            scenario.attack_family is family and scenario.scoring.method == required
            for scenario in attacks
        ):
            findings.append(
                Finding(
                    code="FAMILY_SCORING_SPEC",
                    message=(
                        f"family {family.value!r} is present but no attack in it declares the "
                        f"required method {required!r}"
                    ),
                )
            )
    return findings


def required_expectation(scenario: Scenario) -> str:
    """The only expectation a benign control's own body can justify.

    A consequential or confirmation-required tool cannot be allowed by a scripted
    episode, because a valid grant can only come from the confirmation channel and
    a benchmark scenario cannot mint one (D4). So the expectation is a function of
    the utility step and the declared policy context, not a free label.
    """

    step = next(
        (
            proposed
            for proposed in scenario.proposed_actions
            if proposed.step_id == scenario.utility_criterion.step_id
        ),
        None,
    )
    if step is None:
        return "allowed"
    action = step.action
    policy = scenario.policy_context
    gated = set(policy.consequential_tools) | set(policy.confirmation_required_tools)
    if action.type.value == "tool_call" and action.tool in gated:
        return "escalated"
    return "allowed"


def _expectation_findings(dataset: Dataset) -> list[Finding]:
    """A benign control's expectation must follow from its own body."""

    findings: list[Finding] = []
    for entry in dataset.entries:
        scenario = entry.scenario
        if scenario.scenario_kind is not ScenarioKind.BENIGN:
            continue
        required = required_expectation(scenario)
        if scenario.utility_criterion.expectation != required:
            findings.append(
                Finding(
                    code="EXPECTATION_MISMATCH",
                    message=(
                        f"benign control declares expectation "
                        f"{scenario.utility_criterion.expectation!r} but its utility step "
                        f"requires {required!r} under its own policy context; relabelling "
                        "would move utility and the false-block rate in opposite directions"
                    ),
                    where=(scenario.id,),
                )
            )
    return findings


def _licence_findings(dataset: Dataset) -> list[Finding]:
    findings: list[Finding] = []
    for entry in dataset.entries:
        dataset_meta = entry.scenario.dataset
        if not dataset_meta.synthetic:
            findings.append(
                Finding(
                    code="LICENCE_NOT_SYNTHETIC",
                    message=(
                        "this environment only carries synthetic data; a non-synthetic "
                        "scenario must not be committed here"
                    ),
                    where=(entry.scenario.id,),
                )
            )
        if dataset_meta.created.year < 2026:
            findings.append(
                Finding(
                    code="PROVENANCE_DATE",
                    message=f"implausible creation date {dataset_meta.created}",
                    where=(entry.scenario.id,),
                )
            )
    return findings


def _scoring_findings(dataset: Dataset) -> list[Finding]:
    """Every scoring spec is explicit and the scoring function is stable."""

    findings: list[Finding] = []
    for entry in dataset.entries:
        scenario = entry.scenario
        step_ids = {proposed.step_id for proposed in scenario.proposed_actions}
        if scenario.attack_present and scenario.scoring.attack_step_id not in step_ids:
            findings.append(
                Finding(
                    code="SCORING_STEP_UNRESOLVED",
                    message="attack_step_id does not reference a proposed action",
                    where=(scenario.id,),
                )
            )
        if scenario.utility_criterion.step_id not in step_ids:
            findings.append(
                Finding(
                    code="SCORING_UTILITY_UNRESOLVED",
                    message="utility step does not reference a proposed action",
                    where=(scenario.id,),
                )
            )

    if not dataset.entries:
        return findings

    # Determinism probe: judge the same synthetic verdict set twice and require
    # byte-identical reports. A non-deterministic scorer (dict ordering, set
    # iteration, floating-point summation order) shows up here, not in review.
    probes: list[Outcome] = []
    for entry in dataset.entries:
        scenario = entry.scenario
        steps = tuple(
            StepVerdict(
                step_id=proposed.step_id,
                http_status=200,
                decision="allow",
                reason_codes=("PROBE_ALLOW",),
                risk_score=0.1,
                latency_ms=1.0 + proposed.step_id,
                execution_digest="0" * 24,
            )
            for proposed in scenario.proposed_actions
        )
        original = {
            proposed.step_id: proposed.action.model_dump(mode="json")
            for proposed in scenario.proposed_actions
        }
        probes.append(derive_outcome(scenario, steps, original_actions=original))
    first = score(probes).deterministic_digest
    second = score(list(reversed(probes))).deterministic_digest
    if first != second:
        findings.append(
            Finding(
                code="SCORING_NONDETERMINISTIC",
                message=f"scoring depends on input order: {first} != {second}",
            )
        )
    return findings


def _label_leakage_findings(dataset: Dataset) -> list[Finding]:
    findings: list[Finding] = []
    for entry in dataset.entries:
        scenario = entry.scenario
        tokens = {
            "scenario_id": scenario.id,
            "pair_id": scenario.pair_id,
            "paraphrase_family": scenario.paraphrase_family,
            "attack_family": scenario.family_label,
            "safety_property": scenario.expected_safety_property.property.value,
            "split": scenario.split.value,
            "scoring_method": scenario.scoring.method,
        }
        for request in wire.build_episode(scenario, run_id=wire.run_id_for(0)):
            text = json.dumps(request, sort_keys=True, ensure_ascii=False)
            for label, token in sorted(tokens.items()):
                if token and token in text:
                    findings.append(
                        Finding(
                            code="LABEL_LEAKAGE",
                            message=(
                                f"request for step {request['step_id']} carries the benchmark "
                                f"{label} {token!r}"
                            ),
                            where=(scenario.id,),
                        )
                    )
    return findings


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def validate_dataset(root: Path | str, *, dataset: Dataset | None = None) -> ValidationReport:
    """Validate the dataset rooted at ``root`` and return a readable report."""

    base = Path(root)
    report = ValidationReport(root=base)
    schema_findings, entries, _ = _schema_findings(base)
    report.findings.extend(schema_findings)
    if schema_findings:
        # Without a fully valid dataset the remaining checks are meaningless.
        report.scenario_count = len(entries)
        return report

    loaded = dataset if dataset is not None else load_dataset(base)
    report.scenario_count = len(loaded.entries)
    for entry in loaded.entries:
        scenario = entry.scenario
        report.by_split[scenario.split.value] = report.by_split.get(scenario.split.value, 0) + 1
        report.by_domain[scenario.domain.value] = report.by_domain.get(scenario.domain.value, 0) + 1
        report.by_family[scenario.family_label] = report.by_family.get(scenario.family_label, 0) + 1

    report.dataset_hash = loaded.dataset_hash()
    index, index_findings = build_index(loaded)
    report.findings.extend(index_findings)
    report.findings.extend(split_disjointness(index, loaded))
    report.findings.extend(_duplicate_findings(loaded))
    report.findings.extend(leakage_findings(loaded))
    report.findings.extend(pair_findings(loaded))
    findings, largest = _bound_findings(loaded)
    report.findings.extend(findings)
    report.max_request_bytes = largest
    report.findings.extend(_licence_findings(loaded))
    report.findings.extend(_family_spec_findings(loaded))
    report.findings.extend(_expectation_findings(loaded))
    report.findings.extend(_scoring_findings(loaded))
    report.findings.extend(_label_leakage_findings(loaded))
    report.findings.extend(assert_seal_closed(base))

    manifest = holdout_manifest(base)
    report.holdout = manifest.to_json()
    if manifest.present:
        if len(manifest.plaintext_sha256) != 64:
            report.findings.append(
                Finding(
                    code="HOLDOUT_HASH_MISSING",
                    message="the seal manifest does not record a plaintext sha256",
                )
            )
        if len(manifest.ciphertext_sha256) != 64:
            report.findings.append(
                Finding(
                    code="HOLDOUT_CIPHERTEXT_MISSING",
                    message="the sealed holdout bytes are missing or unreadable",
                )
            )
    return report


def main(argv: list[str] | None = None) -> int:
    import sys

    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) > 1:
        print("usage: python -m benchmark.validators [dataset-root]", file=sys.stderr)
        return 2
    root = Path(args[0]) if args else Path("benchmark/data")
    try:
        report = validate_dataset(root)
    except DatasetError as error:
        print(f"RESULT: FAIL\n  DATASET: {error}")
        return 1
    print(report.render())
    return 0 if report.ok else 1


if __name__ == "__main__":  # pragma: no cover - exercised through scripts/bench_validate.py
    raise SystemExit(main())
