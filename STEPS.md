# STEPS

**Part A** is what I did, in order. **Part B** is how you run it.

---

## Part A: steps taken

1. **Fixed the scope:** stdlib only, fully offline, every input synthetic. Decision: judge in three states, not two. Exit 2 ("could not judge") is separate from exit 1 so a broken input can never look like a pass.
2. **Wrote `versions.py`:** a documented PEP 440 subset. Epochs, local versions and wildcards are rejected instead of guessed. Sort key = trimmed release, pre-release phase, post, dev. Specifiers `>= <= > < == != ~=`, comma-joined as AND.
3. **Wrote `reference.py`:** a deliberately different, trivial comparison (zero-padded tuples, explicit phases, works on components rather than strings) to cross-check the real parser with seeded random cases.
4. **Wrote `gate.py`:** strict loaders (requirements, lockfile, advisory DB, exceptions, license policy, popular list), shortest-path computation from direct dependencies, depth validation, evaluation, and fix suggestion (smallest fixed version no advisory still affects).
5. **Wrote the exception rules:** `id`, `reason` (10+ characters) and `expires` are all required; valid through the expiry day; an expired entry fails the gate even when nothing needs suppressing.
6. **Wrote `typosquat.py`:** separator, homoglyph, transposition and edit-distance rules (distance 1 for 5+ characters, 2 for 12+), names under 5 characters never compared.
7. **Wrote `report.py` and the CLI:** JSON and SARIF 2.1.0, exit codes 0/1/2, and a catch-all so an unexpected exception exits 2 (Python's default would be 1, which looks like a violation). On exit 2 the `--output` file is overwritten with an error document.
8. **Wrote `corpus.py`:** seeded generator (150 projects, direct and transitive, boundary versions, `1.4` written as `1.4.0`), planted truth from the reference, a naive string baseline, typosquat generator by mutation kind, and the blind-spot cases. First demo run gave a naive baseline that was almost as good as the gate on boundaries, so I added the multi-digit minors (`x.10`, `x.11`) to the boundary pool and said so in the README.
9. **Wrote 45 tests** in five files (versions 7, specifiers 6, gate 13, typosquat 5, CLI/report/corpus 14), including real-subprocess exit-code tests.
10. **Mutation-checked:** 10 deliberate breaks applied to a fresh copy, one at a time; all 10 killed on the first run. I also read which test caught each.
11. **Wrote README and this file, then committed locally** (no push yet).

Problems and choices along the way:
- The first full test run failed 3 tests. The cause was a bug in my **reference**, not the gate: it ignored `.postN` on a pre-release (`1.0rc1.post0`). The brute-force cross-check found it; the reference is fixed.
- A test comment claimed `tinyq` (5 characters) was never compared; it is, and the test now says so.
- Wrote the mutation runner so a missing pattern prints `PATTERN MISSED` instead of silently counting as killed.
- `-x` in the mutation run shows only the first failing test per break, not how many catch it.

---

## Part B: steps for you

### Run it
1. Needs Python 3.11 or newer. No packages to install (pytest only for the tests).
2. From the repo folder: `python -m sec_dependency_risk_gate demo` prints the measured tables.
3. Try the sample project (exit code 1: a high advisory on a transitive dependency, a denied license and a typosquat; the critical advisory is suppressed by the example exception):
   ```
   python -m sec_dependency_risk_gate check --requirements examples/requirements.txt --lock examples/lock.json --advisories examples/advisories.json --licenses examples/licenses.json --popular examples/popular.txt --exceptions examples/exceptions.json --today 2026-10-18 --format sarif --output out.sarif
   ```
4. Check the exit code (`echo %ERRORLEVEL%` in cmd, `$LASTEXITCODE` in PowerShell, `echo $?` in bash). Then break an input (delete a `}` in `examples/lock.json`) and see exit 2 with empty stdout.
5. Change `--today` to `2027-01-01`: the exception in `examples/exceptions.json` is now expired and the gate says so.

### Run the tests
1. `python -m pip install pytest`, then `python -m pytest` (about 20 seconds; expect 45 passed).

### Push and CI (not done yet)
1. Create an empty GitHub repo named `sec-dependency-risk-gate`, add it as `origin`, and `git push -u origin main`.
2. Open the Actions tab and confirm the `ci` workflow passes on Python 3.11 and 3.13. Only then add a CI line to the README banner.
