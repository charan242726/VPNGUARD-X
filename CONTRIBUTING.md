# Contributing

Changes must preserve the evidence contract: no field becomes observed or deterministic without a parser/telemetry premise and traceable rationale. New standards rules require source ID, exact section, normative scope, rule tests, review date, and rulebook versioning.

Run:

```bash
python -m unittest discover -s tests -v
python -m compileall -q .
```

For experiment contributions, commit only manifests, code, and authorized/redacted data. Report unrun metrics as `TBD — requires experiment`; never insert illustrative accuracy values into result tables. Dataset splits must be group-disjoint by scenario/configuration lineage.
