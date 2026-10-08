# The sealed holdout

The native benchmark has three splits. Two of them — `development` and
`validation` — are plain JSON in `benchmark/data/scenarios/`. The third, the
`holdout`, is **sealed**: the scenarios exist, are validated, and are hashed, but
their plaintext is not in the repository and must not be read by any agent that
writes policy until the orchestrator opens the seal after the policy freeze.

This document is the whole procedure. A reviewer who reads only this file should
be able to state what is sealed, who may open it, when, and with which command.

## 1. What is sealed, and what is public

| Artifact | Path | Visibility |
| --- | --- | --- |
| Development and validation scenarios | `benchmark/data/scenarios/**` | public, reviewable |
| The seal manifest | `benchmark/data/holdout/seal.json` | public: hashes, KDF parameters, counts |
| The sealed holdout | `benchmark/data/holdout/sealed-holdout.json.enc` | public bytes, unreadable content |
| The custodian passphrase | not in the repository | orchestrator only |

The manifest publishes exactly this and nothing more:

```json
{
  "schema_version": "aegisgraph-benchmark-holdout/v1",
  "created": "<UTC timestamp>",
  "sealed_file": "holdout/sealed-holdout.json.enc",
  "cipher": "AES-256-GCM",
  "kdf": "scrypt-n32768-r8-p1",
  "salt_hex": "...",
  "nonce_hex": "...",
  "ciphertext_sha256": "<sha256 of the sealed bytes>",
  "plaintext_sha256": "<sha256 of the decrypted payload>",
  "scenario_count": 20,
  "domains": [...],
  "families": [...],
  "note": "..."
}
```

The scenario **ids** are not in the manifest. Holdout membership is recorded as a
hash: `plaintext_sha256` identifies the set, and the ciphertext hash lets anyone
detect tampering with the committed blob without holding the passphrase.

## 2. Why it is sealed rather than merely ignored

A plaintext file in Git is readable by every agent that clones the repository, so
a rule that says "do not read the holdout" would be unenforceable and, worse,
would make an honest measurement impossible: a policy author who has seen the
holdout can tune to it, and the holdout then measures memorisation instead of
generalisation. Encryption makes the rule mechanical.

The seal is not a security boundary against the repository owner; it is a
**procedural** boundary against accidental and untracked exposure. The custodian
rule below is what gives it force.

## 3. Custodian rule

- The passphrase is generated when the seal is created and is printed **once**,
  outside the repository. It is never committed, never written to a log, never
  placed in an artifact and never passed on the command line.
- The orchestrator is the custodian. The passphrase is handed over out of band
  (a password manager entry, or an environment variable in the orchestrator's
  own session).
- Agents that write policy, author scenarios or edit the gateway must not
  possess the passphrase, must not request it, and must not attempt to decrypt
  the blob.
- The custodian may verify the seal **without opening it** at any time (section 6).
- Rotation is not supported in place: re-sealing writes a new salt, a new nonce
  and a new ciphertext, and the old manifest hash becomes history.

## 4. Freeze checklist

The seal may be opened only when every item below is true. Each item is a
statement someone can check, not an intention.

1. **Policy freeze declared.** The orchestrator has declared the policy set
   frozen: `GET /api/v1/version` returns a policy set that will not change for
   the duration of the evaluation.
2. **Gateway commit recorded.** The exact commit of the gateway under test is
   recorded (the run manifest records it; a run made before the freeze cannot be
   used for the holdout result).
3. **Data frozen.** `python scripts/bench_validate.py` reports `RESULT: PASS` on
   `benchmark/data`, and the dataset hash in that report matches the hash quoted
   in `docs/benchmark/data-card.md`.
4. **Seal verified closed.** `python scripts/bench_seal.py status` prints a
   manifest whose `ciphertext_sha256` equals the hash quoted in the data card,
   and `python scripts/bench_seal.py verify` reports `ciphertext_matches: true`.
5. **Evaluation command frozen.** The exact run command (model adapter, splits,
   seed, defense URL) is written down before the seal is opened, so the holdout
   result cannot be produced by a command chosen after seeing the data.
6. **Single opening.** The seal is opened once, into a temporary directory
   outside the repository, and the plaintext is deleted after the run.
7. **No tuning after opening.** Once the seal is open, no change to the gateway,
   the policy set or the scoring code is permitted before the holdout numbers are
   recorded.

## 5. Opening the seal (the exact command)

The only command that opens the seal is:

```bash
# from the repository root, with the custodian passphrase in the environment
AEGISGRAPH_HOLDOUT_PASSPHRASE='<custodian passphrase>' \
  python scripts/bench_seal.py open --out /tmp/aegisgraph-holdout-plaintext
```

On Windows PowerShell:

```powershell
$env:AEGISGRAPH_HOLDOUT_PASSPHRASE = '<custodian passphrase>'
python scripts/bench_seal.py open --out C:\Temp\aegisgraph-holdout-plaintext
```

`open` refuses to write anything without `--out`, validates the ciphertext hash
against the manifest before decrypting, verifies the decrypted payload hash, and
validates every scenario against the native schema. The equivalent library call is
`benchmark.seal.open_seal(passphrase, "benchmark/data")`.

Running the holdout afterwards uses the same runner as any other split, with the
plaintext directory as the dataset root:

```bash
python scripts/bench_run.py --defense-url http://127.0.0.1:8080 \
  --dataset /tmp/aegisgraph-holdout-plaintext-parent --splits holdout \
  --config-slug holdout-post-freeze --timestamp <UTC timestamp>
```

The runner refuses `--splits holdout` against the repository dataset on purpose:
the sealed holdout is never part of a routine run.

## 6. Verifying without opening

```bash
python scripts/bench_seal.py status              # hash-only manifest
python scripts/bench_seal.py verify              # ciphertext vs manifest
python scripts/bench_seal.py verify --with-passphrase --passphrase-file <path>
```

`verify` reports `ciphertext_matches`, and, when a passphrase is supplied,
`opened` plus the scenario count and the splits found. A wrong passphrase or a
tampered blob is reported as a failed verification, not as a traceback.

The automated checks that enforce the seal state live in
`tests/test_benchmark_splits.py` and `tests/test_benchmark_validators.py`:

- the blob is not valid UTF-8 JSON and does not contain a holdout scenario id;
- the plaintext and ciphertext hashes are both recorded;
- `assert_seal_closed` reports `HOLDOUT_UNSEALED` if any plaintext holdout file
  appears in the tree, and `HOLDOUT_MISSING` if the seal is absent;
- sealing refuses to overwrite an existing seal and refuses to seal a scenario
  that does not declare `split: holdout`.

## 7. What the seal does not do

- It does not stop the repository owner from decrypting the blob. It stops an
  accidental or untracked read, and it makes the read an explicit, logged act.
- It does not make the holdout a statistically large sample. Twenty scenarios
  support a direction, not a confidence interval.
- It does not replace the reachability control. Every holdout attack is still
  licensed by the control configuration before its result is used
  (`docs/benchmark/evaluation-card.md`, section 6).
