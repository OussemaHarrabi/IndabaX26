"""The holdout boundary, pinned: the seal gates content, not scoring (P49 / I2-20).

``docs/benchmark/holdout.md`` states the boundary precisely — the seal protects the
*scenarios*, the public manifest discloses the composition and a whole-set
confirmation hash, and scoring a fabricated outcome file whose ``split`` is
``holdout`` needs no passphrase. Those are claims about the code, so they are
characterised here rather than left to prose: if a later edit adds content to the
public side, makes the scorer depend on the seal, or changes what a failed
``open_seal`` reveals, these tests fail and the change has to be deliberate.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from benchmark.dataset import SEAL_FILE
from benchmark.fixtures import scenario_dict
from benchmark.schema import Scenario
from benchmark.scoring import Outcome, StepVerdict, score
from benchmark.seal import (
    SealError,
    open_seal,
    plaintext_bytes,
    seal_holdout,
    verify_seal,
)
from benchmark.splits import assert_seal_closed, holdout_manifest

REPO_ROOT = Path(__file__).resolve().parents[1]
DATASET_ROOT = REPO_ROOT / "benchmark" / "data"
PASSPHRASE = "boundary-characterisation-passphrase"

# Everything the public side of the seal may say. The manifest carries the KDF
# parameters because a reviewer must be able to re-derive the key from a passphrase
# alone; the composition (count, domains, families) is published on purpose so a
# reviewer can see the holdout covers the intended shape; ``plaintext_sha256`` is a
# whole-set confirmation oracle, which the holdout document records as accepted.
PUBLIC_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "created",
        "sealed_file",
        "cipher",
        "kdf",
        "salt_hex",
        "nonce_hex",
        "ciphertext_sha256",
        "plaintext_sha256",
        "scenario_count",
        "domains",
        "families",
        "note",
    }
)
PUBLIC_VERIFY_KEYS = frozenset(
    {
        "sealed_file",
        "scenario_count",
        "plaintext_sha256",
        "ciphertext_present",
        "ciphertext_matches",
        "opened",
        "domains",
        "families",
    }
)
TAG_BYTES = 16  # AES-GCM: the ciphertext is the plaintext plus the tag


def _holdout_scenarios(*scenario_ids: str) -> list[Scenario]:
    return [
        Scenario.model_validate(
            scenario_dict(
                scenario_id=scenario_id,
                split="holdout",
                pair_id=f"holdpair_{scenario_id}",
                paraphrase_family=f"family_{scenario_id}",
            )
        )
        for scenario_id in scenario_ids
    ]


def _outcome(
    scenario_id: str, *, split: str, attack_success: bool | None, decision: str
) -> Outcome:
    return Outcome(
        scenario_id=scenario_id,
        split=split,
        domain="enterprise",
        attack_family="direct_prompt_injection",
        pair_id=f"pair_{scenario_id}",
        scenario_kind="attack",
        attack_present=True,
        attack_step_id=1,
        utility_step_id=None,
        expectation="blocked",
        steps=(StepVerdict(step_id=1, http_status=200, decision=decision, reason_codes=("TEST",)),),
        attack_success=attack_success,
        utility_satisfied=None,
        false_block=None,
        leaked=None,
        errored=False,
    )


def test_scoring_a_holdout_outcome_set_needs_no_passphrase(tmp_path: Path) -> None:
    """The documented boundary: the seal protects scenarios, not results."""

    seal_holdout(_holdout_scenarios("hold_boundary_attack"), PASSPHRASE, tmp_path)
    assert verify_seal(tmp_path)["opened"] is False

    # A fabricated result set whose split is `holdout`, scored with no passphrase.
    attack = _outcome(
        "hold_boundary_attack", split="holdout", attack_success=False, decision="block"
    )
    control = replace(attack, attack_success=True)  # the allow-all control licenses it

    report = score([attack], control_outcomes=[control])

    overall = report.overall.to_json()
    assert overall["reached_attacks"] == 1
    assert overall["asr"] == 0.0
    assert verify_seal(tmp_path)["opened"] is False  # scoring did not open the seal


def test_the_public_view_discloses_the_composition_and_no_content(tmp_path: Path) -> None:
    sealed = _holdout_scenarios("hold_boundary_a", "hold_boundary_b")
    seal_holdout(sealed, PASSPHRASE, tmp_path)

    manifest = json.loads((tmp_path / SEAL_FILE).read_text(encoding="utf-8"))
    assert set(manifest) == PUBLIC_MANIFEST_KEYS

    public = verify_seal(tmp_path)  # no passphrase
    assert set(public) == PUBLIC_VERIFY_KEYS
    assert public["opened"] is False
    assert public["ciphertext_matches"] is True
    assert public["scenario_count"] == 2
    # The composition is public on purpose.
    assert public["domains"] == ["enterprise"]
    assert public["families"] == sorted({scenario.family_label for scenario in sealed})

    # The content is not: neither the ids nor the fixture payload text appear.
    raw = (tmp_path / SEAL_FILE).read_bytes()
    for scenario in sealed:
        assert scenario.id.encode() not in raw
    assert b"Summarise the note" not in raw
    assert b"2026-04-01" not in raw


def test_the_ciphertext_is_the_plaintext_plus_the_gcm_tag(tmp_path: Path) -> None:
    """The length disclosure the holdout document records, measured."""

    sealed = _holdout_scenarios("hold_boundary_size")
    manifest = seal_holdout(sealed, PASSPHRASE, tmp_path)

    ciphertext = (tmp_path / manifest.sealed_file).read_bytes()
    assert len(ciphertext) == len(plaintext_bytes(sealed)) + TAG_BYTES


def test_the_plaintext_hash_confirms_a_guessed_set(tmp_path: Path) -> None:
    """``plaintext_sha256`` is a whole-set confirmation oracle, as documented."""

    sealed = _holdout_scenarios("hold_boundary_guess")
    manifest = seal_holdout(sealed, PASSPHRASE, tmp_path)

    assert manifest.plaintext_sha256 == hashlib.sha256(plaintext_bytes(sealed)).hexdigest()
    other = _holdout_scenarios("hold_boundary_other")
    assert hashlib.sha256(plaintext_bytes(other)).hexdigest() != manifest.plaintext_sha256


def test_the_committed_holdout_is_closed_and_publicly_verifiable() -> None:
    """No passphrase exists here, so this is the strongest check available."""

    visible = holdout_manifest(DATASET_ROOT)
    assert visible.present is True
    assert visible.sealed is True
    assert visible.scenario_count == 20
    assert assert_seal_closed(DATASET_ROOT) == []

    public = verify_seal(DATASET_ROOT)
    assert public["opened"] is False
    assert public["ciphertext_matches"] is True
    assert public["scenario_count"] == 20

    # The content is unreachable without the passphrase, which is the point.
    with pytest.raises(SealError):
        open_seal("not-the-passphrase", DATASET_ROOT)
