# sec-dependency-risk-gate

![ci](https://github.com/Supp3r-Man/sec-dependency-risk-gate/actions/workflows/ci.yml/badge.svg)

An **offline dependency-risk gate for CI**: it reads a pinned requirements file, a lockfile with the dependency graph (direct and transitive, with depth), a synthetic advisory database, a license policy, a popular-package list and an exceptions file, and answers with **exit 0 (pass), 1 (policy violation) or 2 (could not judge)**. Output is JSON or SARIF 2.1.0, with the dependency path from the direct dependency and a fix suggestion (the lowest fixed version that is not itself affected). Python standard library only.

> **What is verified, and what is not.** 45 tests pass locally on Python 3.13 (stdlib only; pytest for the tests). The GitHub Actions workflow (Linux, Python 3.11 and 3.13) ran green after the first push. The version and range matcher is cross-checked against a trivial reference over tens of thousands of seeded random cases, the exit codes are tested through a real subprocess, and I broke 10 behaviours on purpose (comparison operators, `~=`, trailing zeros, severity threshold, exception expiry, fix suggestion, depth check, exit code 2, unknown-license policy, typosquat length rule): **all 10 made the tests fail** (first-failing test only, `-x`). **All data is synthetic**: fictional package names, made-up `SYNADV-` ids, planted ground truth. The numbers below measure this gate against a corpus I generated and against a deliberately naive baseline; they say nothing about how many real vulnerabilities it would catch. The reference and the gate share my reading of the version rules, so agreement shows internal consistency, not conformance with pip.

## Measured results (`python -m sec_dependency_risk_gate demo`, seed 21)

150 synthetic projects, 48 advisories, 128 planted true findings (the planted truth comes from `reference.py`, plain integer tuples).

| Advisory detection | gate | naive string baseline |
|---|---|---|
| all findings found / planted | 128/128 | 49/128 (38.3%) |
| direct dependencies | 68/68 | 49/68 (72.1%) |
| transitive dependencies | 60/60 | 0/60 (direct only) |
| false positives, all | 0 | 24 |
| false positives at safe boundary versions | 0/262 | 20/262 |

The baseline is: exact name, direct dependencies only, versions compared as plain strings (so `1.10 < 1.9`). It is a strawman on purpose, to show what the real matcher buys; a tool like pip-audit is not this baseline. The "boundary" pool is the neighbours of every range endpoint plus the `x.10`/`x.11` minors that break string order, so it is built to hurt the baseline.

| Typosquat heuristic (320 squats, 324 random benign, 60 hard benign) | result |
|---|---|
| recall overall | 85.9% |
| transposition, deletion, insertion, substitution, separator, homoglyph | 40/40 each |
| double edit | 35/40 |
| combosquat (`name-utils`, `py-name`) | 0/40 |
| false positives, random benign names | 18/324 (5.6%) |
| false positives, hard benign (`name2`, `names`, `name-lite`) | 40/60 (66.7%) |
| precision (random benign only / incl. hard benign) | 93.9% / 82.6% |

The random-benign false positives are mostly legitimate siblings (`ember-x` vs `amber-x`): a name rule cannot tell them from squats, which is why typosquat findings can be suppressed with an expiring exception.

| Planted cases the gate cannot see | seen |
|---|---|
| vulnerability with no advisory listed | 0/10 |
| yanked version | 0/10 |
| vendored copy absent from the lockfile | 0/10 |

These 0/10 are true by construction (the gate has no data for them); the table shows the blind spot is real, not how common it is.

## Run

```
python -m sec_dependency_risk_gate demo                 # the tables above
python -m sec_dependency_risk_gate sample examples      # write the sample inputs (already in examples/)
python -m sec_dependency_risk_gate check --requirements examples/requirements.txt --lock examples/lock.json \
  --advisories examples/advisories.json --licenses examples/licenses.json --popular examples/popular.txt \
  --exceptions examples/exceptions.json --today 2026-10-18 [--fail-on high] [--format sarif] [--output out.sarif]
python -m pytest
```
`--fail-on` sets the severity threshold for advisories (default high). License denials and typosquat findings always fail unless excepted; an unknown license is a warning. `--max-db-age-days N` makes a stale database exit 2. On exit 2 nothing is printed to stdout, and `--output` is overwritten with an error document so a stale clean report cannot be uploaded.

## Rules in one place

- Versions: documented PEP 440 subset (release, a/b/rc, .post, .dev); epochs, local versions, wildcards and other spellings are rejected, never guessed. `1.0 == 1.0.0`. Specifiers `>= <= > < == != ~=`, comma = AND. Simplification: plain total order, so `<1.0` matches `1.0rc1`.
- Exceptions need `id`, a `reason` of at least 10 characters and an `expires` date (YYYY-MM-DD); valid through the expiry day; an expired entry fails the gate even if the finding is gone.
- Fix suggestion: smallest listed fixed version above the current one that no advisory for that package still affects; none is reported honestly.
- Lockfile checks: declared depth must equal the shortest path from a direct dependency; orphans, unknown `requires`, and requirements/lock disagreement exit 2.

## Layout

`sec_dependency_risk_gate/` versions.py (parser, ordering, specifiers), gate.py (loading, validation, evaluation), typosquat.py, report.py (JSON, SARIF), reference.py (trivial reference), corpus.py (seeded corpus, measurement, sample data), `__main__.py` (CLI). `tests/` 45 tests in five files. `examples/` sample inputs. `STEPS.md` how it was built and how to run it.

## Known gaps

- Only what is listed in the advisory database can be found; no live feeds (offline by design), no yanked-version data, no vendored or copied code, no malicious-package analysis beyond a name heuristic.
- Fix suggestion ignores whether the new version satisfies other dependents' constraints; no resolver.
- Typosquat: names only; combosquats and larger edits are missed, and legitimate siblings are flagged.
- Licenses: simple `OR`/`AND` expressions only (no `WITH` exceptions, no SPDX validation).
- Not implemented: wildcard `==1.*`, epochs, `===`; SARIF output is checked structurally, not against the official JSON schema (no network/jsonschema); CI untested until pushed.
