# Data card — the native AegisGraph benchmark

Everything here is **synthetic**. No real person, organisation, host, credential
or mailbox is represented. Addresses use reserved example domains
(`corp.example`, `vendor.example`, `evil.example`, …); credential-like strings are
obvious canaries (`ABCD1234EFGH5678`, `KLMN9876PQRS4321`).

## 1. Composition

| Property | Value |
| --- | --- |
| Scenarios | 60 in the open splits, 20 sealed in the holdout |
| Domains | `enterprise`, `finance`, `soc` (20 scenarios each) |
| Families | all ten required families, one matched pair per family per domain |
| Splits | `development` 42, `validation` 18, `holdout` 20 (sealed) |
| Matched pairs | 30 open pairs + 10 sealed pairs; every attack has exactly one benign control |
| Licence | `CC-BY-4.0` for every scenario file |
| Origin | project-authored for AegisGraph; `dataset.synthetic = true` |
| Largest assembled request | 2118 bytes (the gateway's default cap is 1 048 576) |

The ten families:

`direct_prompt_injection`, `indirect_prompt_injection`, `provenance_laundering`,
`memory_poisoning`, `unauthorized_tool_use`, `sensitive_data_exfiltration`,
`confirmation_bypass`, `replay_tampering`, `unsafe_rewrite`, `output_integrity`.

Split policy: families 1–7 are `development`, families 8–10 are `validation`, so
the two open splits are separated by family rather than by random assignment. A
paraphrase family, a matched pair and a payload template each live in exactly one
split; `benchmark/splits.py` fails the dataset if that is not true.

## 2. Identifiers

| Dataset | Scenario SHA-256 (aggregate over path + file hash) |
| --- | --- |
| Open splits (60 files under `benchmark/data/scenarios/**`) | `7e916a11981fa6444724dc78558e51561d32a3005b182862efb52b7c5f2cf735` |

| Sealed artifact | SHA-256 |
| --- | --- |
| `benchmark/data/holdout/sealed-holdout.json.enc` (20 scenarios) | `52f67318c248b7a7be90b4d47988b676fe492e29a5b8a926d89df5b665c00c05` |
| `benchmark/data/holdout/seal.json` (manifest) | `ff6e9c322b28ce58b515cea4febebe84596d03a247432c2aeaedaf475eb7ee0e` |
| Plaintext holdout, as recorded in the manifest | `7c0990b4b854141b9f645dce64e9d8f6f94a09010ac6e68a8b5baba35547eaf6` |

The plaintext holdout hash identifies the sealed set without revealing it; the
ciphertext hash lets a reviewer detect tampering with the committed blob. See
`docs/benchmark/holdout.md`.

### Per-scenario hashes

<details>
<summary>60 open scenario files</summary>

| File | SHA-256 |
| --- | --- |
| `scenarios/enterprise/ent_confirmation_bypass_invoice_transfer_attack.json` | `3128c32129afac577ab99416014aac23b356ee891b6f81c0a5e12e4b882db965` |
| `scenarios/enterprise/ent_confirmation_bypass_invoice_transfer_control.json` | `0ded556cefc07387a8c502b29a313197f81266977aea4233f1f8b9858f19a21d` |
| `scenarios/enterprise/ent_direct_injection_vendor_note_attack.json` | `6ef7168688c42706cbe5c4d52925159587b662b99adde295f44a4cf92bcda518` |
| `scenarios/enterprise/ent_direct_injection_vendor_note_control.json` | `7303790ae5722dbbbd6b1a6625800bce42654141d377a41b4e72c4bc90342d1a` |
| `scenarios/enterprise/ent_indirect_injection_partner_brief_attack.json` | `56c4a2ded3c642316b00daf3f6eda0e5d11a4b40d12ce824f4746193215c7ecc` |
| `scenarios/enterprise/ent_indirect_injection_partner_brief_control.json` | `88c41d58a1f1c612195aa3dcefd09e6803aaf56f3d24a29e87fba7f70c362fad` |
| `scenarios/enterprise/ent_memory_poisoning_handover_shift_attack.json` | `3e68d0333c406fb1375672b5134be1b45a32b38d4039ac47b0d17172d32be193` |
| `scenarios/enterprise/ent_memory_poisoning_handover_shift_control.json` | `7301c86094e1f11ac849a6a69f846eab3a53c5978ef3d74984809f7e0898b3a9` |
| `scenarios/enterprise/ent_output_integrity_change_closure_attack.json` | `7943066eaf6c0d8155dc458cc8508bed19c2b29a8af05767964544673d4e8f28` |
| `scenarios/enterprise/ent_output_integrity_change_closure_control.json` | `08ad2f9b412119cf56caf523aee35c0be898475582fac4a174409a40d1f3a57d` |
| `scenarios/enterprise/ent_provenance_laundering_records_wiki_attack.json` | `287807f27a9aab1a2568ca1732cb8612f18369d01078d75a4508336405517db1` |
| `scenarios/enterprise/ent_provenance_laundering_records_wiki_control.json` | `889935c006947ffcd480ffe621ad4f99a7cd9d7dc92e7a190fc5226118c955be` |
| `scenarios/enterprise/ent_replay_tampering_batch_release_attack.json` | `8f6c6a84a6c32c8e360da2834784641f202f08aa8d7688a5e77a955dd9720f0b` |
| `scenarios/enterprise/ent_replay_tampering_batch_release_control.json` | `8b4e1e3af57188f208390ee1cad83fedd43d115503a15099b68acffa186ec0c6` |
| `scenarios/enterprise/ent_sensitive_data_exfiltration_settlement_bundle_attack.json` | `4bf904b5273f5105557f1c3008b739a8d81b3f6d58be5ab3bd6d0d88f7eac5a3` |
| `scenarios/enterprise/ent_sensitive_data_exfiltration_settlement_bundle_control.json` | `81eb06e351cf30a8fa627dd253c86245753cb7872c2853396d0556c6daefe748` |
| `scenarios/enterprise/ent_unauthorized_tool_use_payroll_roster_attack.json` | `96669173d16122b3b0c81a84692ae509599c3ac81ee9ea1d21e604ca9fc1e3bd` |
| `scenarios/enterprise/ent_unauthorized_tool_use_payroll_roster_control.json` | `62884583988f24666e506acde14d7a2b5040cb195f9213d3e82764d6f7613aa6` |
| `scenarios/enterprise/ent_unsafe_rewrite_handover_key_attack.json` | `6df6da6aa84f4642eceba2a83f5b5eb40d33935c9813ca124b7d7eaf5932aa42` |
| `scenarios/enterprise/ent_unsafe_rewrite_handover_key_control.json` | `b183b52fba7314bc9e1ee631b5b570be854ff8a329d1ae92cbc0d3818c1455a6` |
| `scenarios/finance/fin_confirmation_bypass_urgent_release_attack.json` | `5404009434caaeb94d2cdc6e1c7cad221ec4d969ef25818a99fd3825f7638b1a` |
| `scenarios/finance/fin_confirmation_bypass_urgent_release_control.json` | `81ed24f5f958ce4be4496dca0540e0f6717d37b1ae8d3763c2eafb128bff0737` |
| `scenarios/finance/fin_direct_injection_remittance_advice_attack.json` | `ea1149c58b1cbf7af286269b92417e4d9aeeb4ec1da9b0279f9a49eb62335a57` |
| `scenarios/finance/fin_direct_injection_remittance_advice_control.json` | `02089d26cadf8e30d819939d6bac76d2bd371c274dc4944e7a1904c607346014` |
| `scenarios/finance/fin_indirect_injection_onboarding_page_attack.json` | `c6f62ea1fd0e0070a365c40dc02a3e4548315a168c98131e1e38e77457d19c54` |
| `scenarios/finance/fin_indirect_injection_onboarding_page_control.json` | `7eef4e1ceb9ee31ed8c11ce86dc574266d67307a82518be81175ba85e73b9bd0` |
| `scenarios/finance/fin_memory_poisoning_standing_release_attack.json` | `4d105d309ed2a7a39540afae39028c0dd74ec8e9547d95ae8d887537f317964d` |
| `scenarios/finance/fin_memory_poisoning_standing_release_control.json` | `555405b91003a95799a8ca6eabe1a2168adc16d5edc24bbae1c6a80be57f67f7` |
| `scenarios/finance/fin_output_integrity_refund_claim_attack.json` | `f1f3f64f11df4351ec61bd28dc428d0c418ca214ca709b08f484b0d6fb655b8e` |
| `scenarios/finance/fin_output_integrity_refund_claim_control.json` | `370a5b8c34269bb8d8db1b9d0880399bbe58b1ccd5751b8aaa9ce9eee074ec98` |
| `scenarios/finance/fin_provenance_laundering_bank_change_memo_attack.json` | `088f41fed84afa4600b55e48964e5effaf34996b6eb54a8694394ba6a967dd61` |
| `scenarios/finance/fin_provenance_laundering_bank_change_memo_control.json` | `959aee34a4dfa08de5bd4548eba90a9c333210647f328caf847776d27883e97b` |
| `scenarios/finance/fin_replay_tampering_reused_grant_attack.json` | `e6b3ef3e72facc121ef7b6372fed6d9c4160c934a8ee82375d9c07e572596bbe` |
| `scenarios/finance/fin_replay_tampering_reused_grant_control.json` | `6d52839a2fd3e860a4b375932e2fef2344784d07902b7b2f72b5b00151521c4c` |
| `scenarios/finance/fin_sensitive_data_exfiltration_settlement_key_attack.json` | `540a422e5ff322d3e03d41ed7dac06f86fc3b09510aaa753179d41940422d817` |
| `scenarios/finance/fin_sensitive_data_exfiltration_settlement_key_control.json` | `c7846018090ddfd0e5100cb97741f16feafb26fb2a0b724823442f5ecc48e322` |
| `scenarios/finance/fin_unauthorized_tool_use_instant_settlement_attack.json` | `5ba135f26aa48678a4e2d4e17bfe7a88b519bd9f25d7c254ea60efea87ecd3fd` |
| `scenarios/finance/fin_unauthorized_tool_use_instant_settlement_control.json` | `c498435d98489b8c51be716e8f255d548593fbf9eb8bd46f56582e73074b2073` |
| `scenarios/finance/fin_unsafe_rewrite_reformatted_key_attack.json` | `aad22a3a41bfdfa48a1c16df0ae80bd40076879fff7baf34198e36fcd571850c` |
| `scenarios/finance/fin_unsafe_rewrite_reformatted_key_control.json` | `969c85890db4c7cb30768ce8c3e47d8d4046f7734b6e8e4050aa0c1e9ae30c10` |
| `scenarios/soc/soc_confirmation_bypass_isolate_attack.json` | `d87dad3a07549642010449dc0b079e7e5df2b84b4837d471710e2aaf6940bd5a` |
| `scenarios/soc/soc_confirmation_bypass_isolate_control.json` | `915d78f1a06a9491bb078791ee715b256ea90f3b0796c7126784f25ff51cd870` |
| `scenarios/soc/soc_direct_injection_alert_attack.json` | `c587979a5e43b910f29221eaa434cf32653485340e770204663ad24670bd0a4a` |
| `scenarios/soc/soc_direct_injection_alert_control.json` | `798188ad3521ed9cf89b032236e4b3057486d83d40125c7db28258f70c2a0904` |
| `scenarios/soc/soc_indirect_injection_bulletin_attack.json` | `f22396c0fdce58e59d286269701543f722feada6b076969b4ec190b3fa41e011` |
| `scenarios/soc/soc_indirect_injection_bulletin_control.json` | `3ff182684f278284659409e4047453d01ede51f1e1be6a9d770ffaac9d6dd71b` |
| `scenarios/soc/soc_memory_poisoning_shiftnote_attack.json` | `95fb353dd27a88640d70dd0d859efc1f067381e8201827ab0990f52728c2eaf0` |
| `scenarios/soc/soc_memory_poisoning_shiftnote_control.json` | `905c4aac952e3dd8c0665c204e847deead7bd750f79a4a07f561ac772d25cc9f` |
| `scenarios/soc/soc_output_integrity_cleanclaim_attack.json` | `b8aaf83e05268e060e89fbb1bb1a717c4e04148d1092b820e4e010cd8d6d556e` |
| `scenarios/soc/soc_output_integrity_cleanclaim_control.json` | `d54884ef14511f16752b38db6f4c07c98b860bf8b8c1efe3df039a81553a616c` |
| `scenarios/soc/soc_provenance_laundering_digest_attack.json` | `2444e14ab48af641153dac2178cabaefc973ea17d8e724a475d40f91439f58f0` |
| `scenarios/soc/soc_provenance_laundering_digest_control.json` | `52bf30d2d26f64711e171331916967f62329589ab387eb24cb763218a63b8f69` |
| `scenarios/soc/soc_replay_tampering_grant_attack.json` | `7f57e739ff945d9d82a1ba9cfdf0583ef09782297af406674f6658b4ebb2787d` |
| `scenarios/soc/soc_replay_tampering_grant_control.json` | `f5735f192d507638208005a4629d152a344272e4a2cdde7aa0b84b2aef817fd3` |
| `scenarios/soc/soc_sensitive_data_exfiltration_runbook_attack.json` | `19f737aa65e1f6fddde42e89732766258accad24e5aae4dc4a7dd1948258aef6` |
| `scenarios/soc/soc_sensitive_data_exfiltration_runbook_control.json` | `8c881cae7bbfa0eeaf2941b2cce0277bd1cf553eedf1b11ae74531a8763664c3` |
| `scenarios/soc/soc_unauthorized_tool_use_isolate_attack.json` | `3d9026f704a6c2968109bd183c7300f2031d71730714eb5723f2e722910aa2b1` |
| `scenarios/soc/soc_unauthorized_tool_use_isolate_control.json` | `c3a47873cbdd332042b17076280684e92a2a01424f3a1d8bad3cdb8011587dcd` |
| `scenarios/soc/soc_unsafe_rewrite_credential_attack.json` | `b245536aa3303349a26f91f6ff8f804c38d987ec693aee70a398f722d4ed94e1` |
| `scenarios/soc/soc_unsafe_rewrite_credential_control.json` | `242e8d606c99c01701823cc8733c0dece44df639cfd6938b927d85893d314f6b` |

</details>

## 3. Provenance of the data itself

| Field | Value |
| --- | --- |
| Author | project-authored for AegisGraph (this repository) |
| Method | hand-authored JSON, validated by `benchmark/schema.py` |
| Licence | `CC-BY-4.0` |
| Synthetic | yes, every file |
| Derived from legacy artifacts | no. The native dataset shares no payload text with the SENTINEL starter kit; the legacy suite is read only through the adapter |
| Holdout | authored at the same time, sealed immediately, plaintext never committed |

## 4. How to validate

```bash
python scripts/bench_validate.py            # must end in RESULT: PASS
python -m pytest -q -k benchmark            # schema, leakage, scoring, splits, runner, adapter
python scripts/bench_seal.py verify         # the sealed blob matches its manifest
```

The validator reports the dataset hash, the split/domain/family counts, the
largest assembled request, the holdout hashes, and every finding with a code, a
message and the files it concerns. Findings are errors; a dataset with any error
is not publishable.

## 5. What the data does **not** cover yet

Stated plainly, because a benchmark's gaps matter as much as its coverage:

1. **No model-driven episodes.** Every scenario declares a scripted action plan.
   There is no scenario in which a model's own choice is measured, because no
   model runs in this environment (`docs/benchmark/evaluation-card.md`, §5).
2. **One episode per (family, domain).** Each family has three attacks in the open
   splits, one per domain. That supports a per-domain slice and a per-family
   direction, not a per-family confidence interval; per-family numbers rest on
   n = 3.
3. **Two-party matching only.** A pair is one attack and one control. There are no
   matched *near-miss* negatives (a benign action that superficially resembles the
   attack) beyond the one control per pair.
4. **No multi-turn state.** Turn-to-turn evolution is summarised in `history`; a
   scenario cannot assert that a poisoned memory changed a later decision, only
   that the poisoning write was authorised or refused.
5. **No tool execution.** The gateway evaluates inert proposals, so no scenario
   asserts a real-world effect. "Effect" means "the proposal was authorised".
6. **No infrastructure attacks.** No denial of service, no oversized-body probing,
   no concurrency or timeout behaviour: the families are semantic.
7. **Three domains.** Healthcare, government, retail and industrial control are
   not covered, and the domains that exist are stylised rather than sampled.
8. **English only.**
9. **Small holdout.** Twenty sealed scenarios. It detects gross regressions; it
   does not support a precise claim.
10. **No adaptive attacker.** The payloads are static; nothing re-plans against
    the defence between attempts.
