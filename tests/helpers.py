import datetime as dt
import json
import subprocess
import sys
from pathlib import Path

from sec_dependency_risk_gate import gate as G

ROOT = Path(__file__).resolve().parent.parent
TODAY = dt.date(2026, 10, 18)


def pkg(version, depth=1, requires=(), license="MIT"):
    d = {"version": version, "depth": depth, "requires": list(requires)}
    if license is not None:
        d["license"] = license
    return d


def lock(pk, direct):
    return {"lockfile_version": 1, "packages": pk, "direct": direct}


def adv(id, package, affected, severity="high", fixed=()):
    return {"id": id, "package": package, "affected": list(affected), "severity": severity, "fixed": list(fixed)}


def db(*advs, generated="2026-10-01"):
    return {"schema": 1, "generated": generated, "advisories": list(advs)}


BASE_LOCK = lock({"alpha-http": pkg("1.9.0", 1, ["beta-codec"]), "beta-codec": pkg("1.10", 2, ["gamma-schema"]),
                  "gamma-schema": pkg("2.0", 3)}, ["alpha-http"])
BASE_ADV = adv("SYNADV-1", "beta-codec", [">=1.2,<1.10.1"], "high", ["1.10.1"])
BASE_REQ = "alpha-http==1.9.0\n"
CLEAN_LOCK = lock({"alpha-http": pkg("1.9.0")}, ["alpha-http"])


def run(lockd, dbd, today=TODAY, **kw):
    return G.evaluate(G.load_lock(lockd), G.load_db(dbd), today=today, **kw)


def cli(tmp, lockd=BASE_LOCK, dbd=None, req=BASE_REQ, extra=(), raw_lock=None, with_db=True, fmt="json"):
    files = {}
    (tmp / "lock.json").write_text(raw_lock if raw_lock is not None else json.dumps(lockd), encoding="utf-8")
    (tmp / "req.txt").write_text(req, encoding="utf-8")
    if with_db:
        (tmp / "db.json").write_text(json.dumps(dbd if dbd is not None else db(BASE_ADV)), encoding="utf-8")
    cmd = [sys.executable, "-m", "sec_dependency_risk_gate", "check", "--requirements", str(tmp / "req.txt"),
           "--lock", str(tmp / "lock.json"), "--advisories", str(tmp / "db.json"), "--today", "2026-10-18",
           "--format", fmt, *extra]
    p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=60)
    return p.returncode, p.stdout, p.stderr
