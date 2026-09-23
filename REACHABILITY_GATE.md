# Allow-all attack reachability gate

Run the gate on the raw JSON from an `allow_all` evaluation before comparing a
defense. This checks that the benchmark attacks actually reached the vulnerable
behavior; it does not evaluate or modify a defense.

```powershell
.\.venv\Scripts\python.exe scripts/validate_attack_reachability.py .\evaluation\allow-all-qwen.json
```

The command lists every `attack_present: true` scenario and its
`attack_success` value. It exits nonzero if any attack did not succeed, if the
report is malformed, or if no attacks are present. Model and run metadata are
printed only when explicitly included in the JSON; the gate does not infer the
model from a filename or command line.

To ensure one or more particular attack scenarios are present in the report,
repeat `--require-scenario` with their IDs:

```powershell
.\.venv\Scripts\python.exe scripts/validate_attack_reachability.py .\evaluation\allow-all-qwen.json `
  --require-scenario <scenario-id>
```

Required IDs are additional presence checks; the gate still lists and checks
every attack in the report. Replace the placeholder with an ID from the pinned
benchmark. Record the report and exact model/backend separately for evaluation
reproducibility.
