# `rules/` — a sample Sigma library for the detection CLI

A small, deliberately imperfect Sigma library so the detection commands in the project
README run **as written**, on a fresh clone, with zero AWS and zero network:

```bash
sentinel detection audit rules/ --techniques T1059,T1190
sentinel detection baseline rules/ --snapshot baseline.json
sentinel detection ci rules/ --min-score 60
```

Imperfect on purpose. A library that scored 100 would make the health score, the
findings list and the `--min-score` gate all look like decoration. This one contains a
near-duplicate pair and an untagged rule, so `detection audit` has something real to
report and a reader can see the tool disagree with the library.

Generic detection content only — no org-specific data, no customer names, no real
hostnames or account ids.
