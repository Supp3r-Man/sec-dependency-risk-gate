"""CLI. Exit codes: 0 pass, 1 policy violation, 2 could not judge (never looks like a pass)."""
import argparse
import datetime as dt
import json
import os
import sys

from . import corpus, gate, report


def _read(path, what):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except (OSError, ValueError) as e:
        raise gate.GateError(f"{what} unreadable: {e}")


def run_check(a):
    today = dt.date.fromisoformat(a.today) if a.today else dt.date.today()
    lock = gate.load_lock(gate.load_json(a.lock, "lockfile"))
    gate.cross_check(gate.parse_requirements(_read(a.requirements, "requirements file")), lock)
    db = gate.load_db(gate.load_json(a.advisories, "advisory database"))
    gate.check_db_age(db, today, a.max_db_age_days)
    lic = gate.load_license_policy(gate.load_json(a.licenses, "license policy")) if a.licenses else None
    pop = gate.load_popular(_read(a.popular, "popular list")) if a.popular else None
    exc = gate.load_exceptions(gate.load_json(a.exceptions, "exceptions file")) if a.exceptions else []
    res = gate.evaluate(lock, db, fail_on=a.fail_on, licenses=lic, popular=pop, exceptions=exc, today=today)
    uri = a.lock.replace("\\", "/")
    doc = report.to_sarif(res, uri) if a.format == "sarif" else report.to_json(res, uri)
    return res, doc


def _emit(doc, out):
    text = json.dumps(doc, indent=2)
    if out:
        with open(out, "w", encoding="utf-8", newline="\n") as f:
            f.write(text + "\n")
    else:
        print(text)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="sec_dependency_risk_gate")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="gate one project")
    for opt in ("requirements", "lock", "advisories"):
        c.add_argument("--" + opt, required=True)
    for opt in ("licenses", "popular", "exceptions", "output", "today"):
        c.add_argument("--" + opt)
    c.add_argument("--fail-on", default="high", choices=sorted(gate.SEV))
    c.add_argument("--format", default="json", choices=["json", "sarif"])
    c.add_argument("--max-db-age-days", type=int)
    sub.add_parser("demo", help="print the measured table")
    s = sub.add_parser("sample", help="write the sample input files")
    s.add_argument("dir")
    a = ap.parse_args(argv)
    if a.cmd == "demo":
        print(corpus.demo_text())
        return 0
    if a.cmd == "sample":
        os.makedirs(a.dir, exist_ok=True)
        for name, body in corpus.SAMPLE.items():
            with open(os.path.join(a.dir, name), "w", encoding="utf-8", newline="\n") as f:
                f.write(body if isinstance(body, str) else json.dumps(body, indent=2) + "\n")
        print(f"wrote {len(corpus.SAMPLE)} files to {a.dir}")
        return 0
    try:
        res, doc = run_check(a)
    except Exception as e:  # any failure to judge must be exit 2, never Python's default 1
        msg = str(e) if isinstance(e, gate.GateError) else f"internal error: {type(e).__name__}: {e}"
        print(f"error: {msg}", file=sys.stderr)
        if a.output:
            try:
                _emit(report.error_doc(a.format, msg), a.output)
            except OSError:
                pass
        return 2
    _emit(doc, a.output)
    n = sum(f["violation"] for f in res.findings)
    print(f"{'PASS' if res.exit_code == 0 else 'FAIL'}: {n} violation(s), {len(res.expired)} expired exception(s)", file=sys.stderr)
    return res.exit_code


if __name__ == "__main__":
    sys.exit(main())
