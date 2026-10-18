import copy
import datetime as dt

import pytest

from helpers import BASE_ADV, BASE_LOCK, CLEAN_LOCK, TODAY, adv, db, lock, pkg, run
from sec_dependency_risk_gate import gate as G
from sec_dependency_risk_gate.versions import Version


def test_requirements_parsing_and_cross_check():
    r = G.parse_requirements("# c\nAlpha_HTTP==1.9.0  # inline\n\nbeta-codec==1.10\r\n")
    assert set(r) == {"alpha-http", "beta-codec"} and r["beta-codec"] == Version("1.10")
    for bad in ["alpha>=1.0", "alpha", "alpha==1.x", "alpha==1.0\nalpha==1.1", "-r other.txt", "alpha===1.0"]:
        with pytest.raises(G.GateError):
            G.parse_requirements(bad)
    lk = G.load_lock(BASE_LOCK)
    G.cross_check({"alpha-http": Version("1.9.0")}, lk)
    for bad in [{"alpha-http": Version("1.9.1")}, {"other": Version("1.0")}, {}]:
        with pytest.raises(G.GateError):
            G.cross_check(bad, lk)


def test_lock_rejections():
    def mutate(f):
        d = copy.deepcopy(BASE_LOCK)
        f(d)
        return d
    bad = [
        mutate(lambda d: d["packages"]["beta-codec"].update(version="1.x")),
        mutate(lambda d: d["packages"]["beta-codec"].update(version=None)),
        mutate(lambda d: d["packages"]["beta-codec"].update(depth=3)),  # shortest depth is 2
        mutate(lambda d: d["packages"]["alpha-http"].update(depth=True)),
        mutate(lambda d: d["packages"]["alpha-http"].update(requires=["ghost"])),
        mutate(lambda d: d["packages"].update({"orphan": pkg("1.0", 1)})),
        mutate(lambda d: d.update(direct=["ghost"])),
        mutate(lambda d: d.update(direct=[])),
        mutate(lambda d: d.update(lockfile_version=2)),
        mutate(lambda d: d["packages"].update({"Alpha_HTTP": pkg("1.0")})),  # duplicate after normalisation
        [], "x", None,
    ]
    for d in bad:
        with pytest.raises(G.GateError):
            G.load_lock(d)


def test_shortest_path_cycle_and_diamond():
    lk = G.load_lock(lock({"a": pkg("1.0", 1, ["c"]), "b": pkg("1.0", 1, ["x"]), "x": pkg("1.0", 2, ["c"]),
                           "c": pkg("1.0", 2, ["a", "x"])}, ["a", "b"]))  # cycles a->c->a and x->c->x
    assert lk.path("c") == ["a", "c"] and lk.path("x") == ["b", "x"] and lk.path("a") == ["a"]


def test_transitive_advisory_reports_path_from_direct():
    res = run(BASE_LOCK, db(BASE_ADV))
    (f,) = res.findings
    assert f["package"] == "beta-codec" and f["path"] == ["alpha-http", "beta-codec"] and f["depth"] == 2
    assert f["violation"] and res.exit_code == 1 and "transitive" in f["fix"] and f["fixed_in"] == "1.10.1"
    # boundary: the fixed version itself, and the string-order trap 1.9 < 1.10, are outside >=1.2,<1.10.1
    for v, hit in (("1.10.1", False), ("1.10.0", True), ("1.1.9", False), ("1.2", True), ("1.9", True)):
        d = copy.deepcopy(BASE_LOCK)
        d["packages"]["beta-codec"]["version"] = v
        assert bool(run(d, db(BASE_ADV)).findings) is hit, v


def test_severity_threshold_exact():
    pk = {"alpha-http": pkg("1.0", 1, ["p1", "p2", "p3", "p4"])}
    pk.update({f"p{i}": pkg("1.0", 2) for i in range(1, 5)})
    advs = [adv(f"A{i}", f"p{i}", ["<2"], s) for i, s in enumerate(["low", "medium", "high", "critical"], 1)]
    for thr, want in (("low", 4), ("medium", 3), ("high", 2), ("critical", 1)):
        res = run(lock(pk, ["alpha-http"]), db(*advs), fail_on=thr)
        assert sum(f["violation"] for f in res.findings) == want and len(res.findings) == 4, thr
        assert res.exit_code == 1
    res = run(lock(pk, ["alpha-http"]), db(*advs[:2]), fail_on="high")
    assert res.exit_code == 0 and len(res.findings) == 2  # below threshold: reported, not failing


def test_fix_skips_fixed_versions_that_are_still_affected():
    d = db(adv("A1", "alpha-http", [">=1.0,<1.5"], fixed=["1.5"]), adv("A2", "alpha-http", [">=1.5,<1.7"], fixed=["1.7"]))
    lk = lock({"alpha-http": pkg("1.2")}, ["alpha-http"])
    fs = {f["key"]: f["fixed_in"] for f in run(lk, d).findings}
    assert fs == {"A1": "1.7"}  # 1.5 is itself affected by A2, so the minimum safe fix is 1.7
    d2 = db(adv("A1", "alpha-http", ["<2.0"], fixed=["2.0"]), adv("A2", "alpha-http", [">=2.0"]))
    (f,) = run(lock({"alpha-http": pkg("1.2")}, ["alpha-http"]), d2).findings[:1]
    assert f["fixed_in"] is None and "no listed fixed version" in f["fix"]


def test_exception_requires_reason_and_expiry():
    ok = {"id": "A1", "reason": "waiting on vendor patch", "expires": "2026-12-31"}
    assert G.load_exceptions({"exceptions": [ok]})[0]["expires"] == dt.date(2026, 12, 31)
    for drop in ("reason", "expires", "id"):
        e = {k: v for k, v in ok.items() if k != drop}
        with pytest.raises(G.GateError):
            G.load_exceptions({"exceptions": [e]})
    for patch in ({"reason": "n/a"}, {"reason": "   "}, {"expires": "2026-13-01"}, {"expires": "20261231"},
                  {"expires": 20261231}, {"expires": ""}, {"expires": None}):
        with pytest.raises(G.GateError):
            G.load_exceptions({"exceptions": [{**ok, **patch}]})
    with pytest.raises(G.GateError):
        G.load_exceptions({"exceptions": "nope"})


def test_exception_expiry_boundary_and_expired_fails():
    exc = G.load_exceptions({"exceptions": [{"id": "SYNADV-1", "reason": "waiting on vendor patch", "expires": "2026-10-18"}]})
    on = run(BASE_LOCK, db(BASE_ADV), exceptions=exc, today=dt.date(2026, 10, 18))
    assert on.exit_code == 0 and on.findings[0]["suppressed"] == "waiting on vendor patch" and not on.expired
    late = run(BASE_LOCK, db(BASE_ADV), exceptions=exc, today=dt.date(2026, 10, 19))
    assert late.exit_code == 1 and late.findings[0]["violation"] and late.expired[0]["id"] == "SYNADV-1"
    # an expired exception fails the gate even when the finding it covered is gone
    gone = run(CLEAN_LOCK, db(BASE_ADV), exceptions=exc, today=dt.date(2026, 10, 19))
    assert gone.exit_code == 1 and not gone.findings


def test_exception_scope_and_unused_warning():
    exc = G.load_exceptions({"exceptions": [
        {"id": "SYNADV-1", "package": "other-pkg", "reason": "wrong package on purpose", "expires": "2027-01-01"},
        {"id": "NOPE-9", "reason": "matches nothing at all", "expires": "2027-01-01"}]})
    res = run(BASE_LOCK, db(BASE_ADV), exceptions=exc)
    assert res.exit_code == 1 and res.findings[0]["suppressed"] is None and len(res.warnings) == 2


def test_license_policy_deny_allow_unknown():
    pol = G.load_license_policy({"deny": ["AGPL-3.0-only"], "allow": ["MIT", "Apache-2.0"]})
    st = lambda e: G.license_status(e, pol)
    assert [st(x) for x in ("MIT", "mit", "AGPL-3.0-only", "GPL-2.0-only", None, "", "UNKNOWN", "NOASSERTION")] == \
        ["ok", "ok", "deny", "notallowed", "unknown", "unknown", "unknown", "unknown"]
    assert st("MIT OR AGPL-3.0-only") == "ok" and st("MIT AND AGPL-3.0-only") == "deny"
    assert st("(MIT AND Apache-2.0) OR GPL-2.0-only") == "ok" and st("GPL-2.0-only OR BSD-1-Clause") == "notallowed"
    deny_only = G.load_license_policy({"deny": ["GPL-3.0-only"]})
    assert G.license_status("WTFPL", deny_only) == "ok"
    with pytest.raises(G.GateError):
        G.load_license_policy({"deny": "GPL"})


def test_unknown_license_warns_but_denied_license_fails():
    pol = G.load_license_policy({"deny": ["AGPL-3.0-only"], "allow": ["MIT"]})
    lk = lock({"a": pkg("1.0", 1, ["b"], license=None), "b": pkg("1.0", 2, license="MIT")}, ["a"])
    res = run(lk, db(), licenses=pol)
    assert res.exit_code == 0 and [f["kind"] for f in res.findings] == ["license-unknown"]
    lk2 = lock({"a": pkg("1.0", 1, license="AGPL-3.0-only")}, ["a"])
    res2 = run(lk2, db(), licenses=pol)
    assert res2.exit_code == 1 and res2.findings[0]["kind"] == "license"


def test_advisory_db_validation_and_staleness():
    bads = [{"schema": 2, "generated": "2026-10-01", "advisories": []}, {"schema": 1, "advisories": []},
            db(adv("A", "p", ["1.0"])),  # range without operator
            db(adv("A", "p", [">=1.0,"])), db(adv("A", "p", [])), db(adv("A", "p", ["<2"], "urgent")),
            db(adv("A", "p", ["<2"], fixed=["2.x"])), db(adv("A", "p", ["<2"]), adv("A", "q", ["<2"])),
            db(generated="yesterday"), db({"id": "", "package": "p", "affected": ["<2"], "severity": "low"}), []]
    for d in bads:
        with pytest.raises(G.GateError):
            G.load_db(d)
    d = G.load_db(db())
    assert G.evaluate(G.load_lock(CLEAN_LOCK), d, today=TODAY).warnings == ["advisory database contains 0 advisories"]
    G.check_db_age(d, dt.date(2026, 10, 18), 17)  # exactly 17 days old: not stale
    with pytest.raises(G.GateError):
        G.check_db_age(d, dt.date(2026, 10, 19), 17)
    G.check_db_age(d, dt.date(2030, 1, 1), None)


def test_name_normalisation_matches_advisory_to_lock():
    lk = lock({"Alpha_HTTP": pkg("1.0")}, ["alpha.http"])
    assert len(run(lk, db(adv("A", "ALPHA-http", ["<2"]))).findings) == 1
