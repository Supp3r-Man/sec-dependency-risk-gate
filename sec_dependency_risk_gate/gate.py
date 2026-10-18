"""Load, validate and evaluate. Anything unreadable or inconsistent raises GateError,
which the CLI maps to exit 2 ("could not judge") so it can never look like a pass."""
import datetime as dt
import json
import re
from collections import deque

from .typosquat import check_name, norm
from .versions import SpecError, SpecifierSet, Version, VersionError

SEV = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_REQ = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==(\S+)$")


class GateError(Exception):
    """The inputs could not be judged (malformed, inconsistent or missing)."""


def load_json(path, what):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        raise GateError(f"{what} not found: {path}")
    except (OSError, ValueError) as e:
        raise GateError(f"{what} unreadable: {e}")


def _date(s, what):
    if not isinstance(s, str) or not _DATE.match(s):
        raise GateError(f"{what}: expected YYYY-MM-DD, got {s!r}")
    try:
        return dt.date.fromisoformat(s)
    except ValueError:
        raise GateError(f"{what}: invalid date {s!r}")


def parse_requirements(text):
    out = {}
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = _REQ.match(line)
        if not m:
            raise GateError(f"requirements line {n}: not an exact pin (name==version): {line!r}")
        try:
            v = Version(m.group(2))
        except VersionError as e:
            raise GateError(f"requirements line {n}: {e}")
        name = norm(m.group(1))
        if name in out and out[name] != v:
            raise GateError(f"requirements line {n}: {name} pinned twice with different versions")
        out[name] = v
    return out


class Lock:
    def __init__(self, pkgs, direct, parent):
        self.pkgs, self.direct, self.parent = pkgs, direct, parent

    def path(self, name):
        p = []
        while name is not None:
            p.append(name)
            name = self.parent[name]
        return p[::-1]


def load_lock(data):
    if not isinstance(data, dict) or data.get("lockfile_version") != 1:
        raise GateError("lockfile: lockfile_version must be 1")
    raw, direct = data.get("packages"), data.get("direct")
    if not isinstance(raw, dict) or not raw:
        raise GateError("lockfile: 'packages' must be a non-empty object")
    if not isinstance(direct, list) or not direct or not all(isinstance(d, str) for d in direct):
        raise GateError("lockfile: 'direct' must be a non-empty list of names")
    pkgs = {}
    for name, e in raw.items():
        n = norm(name)
        if n in pkgs:
            raise GateError(f"lockfile: duplicate package {n}")
        if not isinstance(e, dict):
            raise GateError(f"lockfile: {name}: entry must be an object")
        try:
            v = Version(e.get("version"))
        except VersionError as ex:
            raise GateError(f"lockfile: {name}: {ex}")
        depth, req, lic = e.get("depth"), e.get("requires", []), e.get("license")
        if type(depth) is not int or depth < 1:
            raise GateError(f"lockfile: {name}: depth must be an integer >= 1")
        if not isinstance(req, list) or not all(isinstance(r, str) for r in req):
            raise GateError(f"lockfile: {name}: requires must be a list of names")
        if lic is not None and not isinstance(lic, str):
            raise GateError(f"lockfile: {name}: license must be a string")
        pkgs[n] = {"version": v, "depth": depth, "requires": [norm(r) for r in req], "license": lic}
    direct = sorted({norm(d) for d in direct})
    for d in direct:
        if d not in pkgs:
            raise GateError(f"lockfile: direct dependency {d} is not in packages")
    for n, p in pkgs.items():
        for r in p["requires"]:
            if r not in pkgs:
                raise GateError(f"lockfile: {n} requires unknown package {r}")
    dist, parent, q = {d: 1 for d in direct}, {d: None for d in direct}, deque(direct)
    while q:
        cur = q.popleft()
        for r in sorted(pkgs[cur]["requires"]):
            if r not in dist:
                dist[r], parent[r] = dist[cur] + 1, cur
                q.append(r)
    for n, p in pkgs.items():
        if n not in dist:
            raise GateError(f"lockfile: {n} is not reachable from any direct dependency")
        if p["depth"] != dist[n]:
            raise GateError(f"lockfile: {n} declares depth {p['depth']} but its shortest depth is {dist[n]}")
    return Lock(pkgs, direct, parent)


def cross_check(reqs, lock):
    if set(reqs) != set(lock.direct):
        raise GateError("requirements and lockfile disagree on the set of direct dependencies")
    for n, v in reqs.items():
        if lock.pkgs[n]["version"] != v:
            raise GateError(f"requirements pin {n}=={v.text} but lockfile has {lock.pkgs[n]['version'].text}")


class Advisory:
    def __init__(self, id, package, ranges, fixed, severity, summary):
        self.id, self.package, self.ranges, self.fixed = id, package, ranges, fixed
        self.severity, self.summary = severity, summary

    def affects(self, v):
        return any(r.contains(v) for r in self.ranges)


class AdvisoryDB:
    def __init__(self, advisories, generated):
        self.advisories, self.generated = advisories, generated
        self.by_pkg = {}
        for a in advisories:
            self.by_pkg.setdefault(a.package, []).append(a)


def load_db(data):
    if not isinstance(data, dict) or data.get("schema") != 1 or not isinstance(data.get("advisories"), list):
        raise GateError("advisory db: expected {'schema': 1, 'generated': date, 'advisories': [...]}")
    generated = _date(data.get("generated"), "advisory db 'generated'")
    out, seen = [], set()
    for i, a in enumerate(data["advisories"]):
        if not isinstance(a, dict):
            raise GateError(f"advisory #{i}: must be an object")
        aid, pkg, sev = a.get("id"), a.get("package"), a.get("severity")
        if not isinstance(aid, str) or not aid.strip() or not isinstance(pkg, str) or not pkg.strip():
            raise GateError(f"advisory #{i}: id and package are required strings")
        if aid in seen:
            raise GateError(f"advisory {aid}: duplicate id")
        seen.add(aid)
        if sev not in SEV:
            raise GateError(f"advisory {aid}: severity must be one of {sorted(SEV)}")
        aff = a.get("affected")
        aff = [aff] if isinstance(aff, str) else aff
        if not isinstance(aff, list) or not aff:
            raise GateError(f"advisory {aid}: 'affected' must be a non-empty list of ranges")
        fixed = a.get("fixed", [])
        if not isinstance(fixed, list):
            raise GateError(f"advisory {aid}: 'fixed' must be a list")
        try:
            ranges = [SpecifierSet(r) for r in aff]
            fx = [Version(f) for f in fixed]
        except (SpecError, VersionError) as e:
            raise GateError(f"advisory {aid}: {e}")
        out.append(Advisory(aid, norm(pkg), ranges, fx, sev, str(a.get("summary", ""))))
    return AdvisoryDB(out, generated)


def check_db_age(db, today, max_days):
    if max_days is not None and (today - db.generated).days > max_days:
        raise GateError(f"advisory db is stale: generated {db.generated}, older than {max_days} days")


def load_exceptions(data):
    if not isinstance(data, dict) or not isinstance(data.get("exceptions"), list):
        raise GateError("exceptions: expected {'exceptions': [...]}")
    out = []
    for i, e in enumerate(data["exceptions"]):
        if not isinstance(e, dict):
            raise GateError(f"exception #{i}: must be an object")
        eid, reason = e.get("id"), e.get("reason")
        if not isinstance(eid, str) or not eid.strip():
            raise GateError(f"exception #{i}: 'id' is required")
        if not isinstance(reason, str) or len(reason.strip()) < 10:
            raise GateError(f"exception {eid}: 'reason' is required (at least 10 characters)")
        if "expires" not in e:
            raise GateError(f"exception {eid}: 'expires' (YYYY-MM-DD) is required")
        pkg = e.get("package")
        if pkg is not None and not isinstance(pkg, str):
            raise GateError(f"exception {eid}: 'package' must be a string")
        out.append({"id": eid, "package": norm(pkg) if pkg else None, "reason": reason.strip(),
                    "expires": _date(e["expires"], f"exception {eid} 'expires'")})
    return out


def load_license_policy(data):
    if not isinstance(data, dict):
        raise GateError("license policy: must be an object")
    for k in ("deny", "allow"):
        v = data.get(k, [])
        if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
            raise GateError(f"license policy: '{k}' must be a list of strings")
    return {"deny": {x.upper() for x in data.get("deny", [])}, "allow": {x.upper() for x in data.get("allow", [])}}


def load_popular(text):
    names = {norm(l.split("#", 1)[0]) for l in text.splitlines() if l.split("#", 1)[0].strip()}
    if not names:
        raise GateError("popular-package list is empty")
    return names


def license_status(expr, pol):
    """'ok' | 'deny' | 'notallowed' | 'unknown'. Understands simple 'A OR B' / 'A AND B'."""
    if not expr or not expr.strip() or expr.strip().upper() in ("UNKNOWN", "NOASSERTION"):
        return "unknown"

    def one(x):
        x = x.strip().strip("()").strip().upper()
        if x in pol["deny"]:
            return "deny"
        return "notallowed" if pol["allow"] and x not in pol["allow"] else "ok"

    alts = [[one(x) for x in re.split(r"\s+AND\s+", alt, flags=re.I)] for alt in re.split(r"\s+OR\s+", expr, flags=re.I)]
    if any(all(s == "ok" for s in alt) for alt in alts):
        return "ok"
    flat = [s for alt in alts for s in alt]
    return "deny" if "deny" in flat else "notallowed"


def suggest_fix(db, pkg, current):
    """Smallest fixed version above `current` that no advisory for the package still affects."""
    advs = db.by_pkg.get(pkg, [])
    for c in sorted({f for a in advs for f in a.fixed if f > current}):
        if not any(a.affects(c) for a in advs):
            return c
    return None


class Result:
    def __init__(self, findings, warnings, expired, fail_on):
        self.findings, self.warnings, self.expired, self.fail_on = findings, warnings, expired, fail_on
        bad = any(f["violation"] for f in findings) or bool(expired)
        self.exit_code = 1 if bad else 0


def evaluate(lock, db, *, fail_on="high", licenses=None, popular=None, exceptions=(), today=None):
    if fail_on not in SEV:
        raise GateError(f"fail_on must be one of {sorted(SEV)}")
    today = today or dt.date.today()
    thr, findings, warnings = SEV[fail_on], [], []

    def add(kind, key, name, sev, violation, message, fix=None, fixed_in=None, summary=""):
        p = lock.pkgs[name]
        findings.append({"kind": kind, "key": key, "package": name, "version": p["version"].text, "severity": sev,
                         "depth": p["depth"], "path": lock.path(name), "summary": summary, "message": message,
                         "fixed_in": fixed_in, "fix": fix, "violation": violation, "suppressed": None})

    for name in sorted(lock.pkgs):
        p = lock.pkgs[name]
        for a in db.by_pkg.get(name, []):
            if a.affects(p["version"]):
                fx = suggest_fix(db, name, p["version"])
                fix = (f"upgrade {name} to >= {fx.text}" if fx else
                       f"no listed fixed version of {name} is itself unaffected; replace or pin around it")
                if p["depth"] > 1:
                    fix += f" (transitive: bump or override via {lock.path(name)[0]})"
                add("advisory", a.id, name, a.severity, SEV[a.severity] >= thr,
                    f"{name} {p['version'].text} is affected by {a.id}", fix, fx.text if fx else None, a.summary)
        if licenses is not None:
            st = license_status(p["license"], licenses)
            if st == "unknown":
                add("license-unknown", f"license:{name}", name, "low", False, f"{name}: license unknown, review manually")
            elif st != "ok":
                add("license", f"license:{name}", name, "high", True,
                    f"{name}: license {p['license']!r} is {'denied' if st == 'deny' else 'not on the allowlist'}")
        if popular:
            hit = check_name(name, popular)
            if hit:
                add("typosquat", f"typosquat:{name}", name, "high", True,
                    f"{name} looks like {hit[1]} ({hit[0]}); verify it is the intended package",
                    f"if intended, add an exception for typosquat:{name}; otherwise depend on {hit[1]}")
    expired, used = [], set()
    for e in exceptions:
        if e["expires"] < today:
            expired.append({"id": e["id"], "package": e["package"], "expires": e["expires"].isoformat(),
                            "reason": e["reason"]})
            continue
        for f in findings:
            if f["violation"] and f["key"] == e["id"] and e["package"] in (None, f["package"]):
                f["violation"], f["suppressed"] = False, e["reason"]
                used.add(e["id"])
        if e["id"] not in used:
            warnings.append(f"exception {e['id']} matched no active violation (remove it?)")
    if not db.advisories:
        warnings.append("advisory database contains 0 advisories")
    return Result(findings, warnings, expired, fail_on)
