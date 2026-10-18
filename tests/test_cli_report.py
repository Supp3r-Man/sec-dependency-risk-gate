import json
import re
import subprocess
import sys

from helpers import BASE_ADV, BASE_LOCK, CLEAN_LOCK, ROOT, TODAY, adv, cli, db, lock, pkg, run
from sec_dependency_risk_gate import corpus, report


def test_json_report_shape_and_fix_suggestion(tmp_path):
    code, out, err = cli(tmp_path)
    doc = json.loads(out)
    assert code == 1 and doc["verdict"] == "fail" and doc["exit_code"] == 1 and "FAIL" in err
    (f,) = doc["findings"]
    assert f["package"] == "beta-codec" and f["path"] == ["alpha-http", "beta-codec"] and f["fixed_in"] == "1.10.1"
    assert doc["summary"] == {"findings": 1, "violations": 1, "suppressed": 0, "expired_exceptions": 0}


def test_sarif_2_1_0_structure(tmp_path):
    code, out, _ = cli(tmp_path, fmt="sarif")
    s = json.loads(out)
    assert code == 1 and s["version"] == "2.1.0" and s["$schema"].endswith("sarif-2.1.0.json")
    (run_,) = s["runs"]
    rules = run_["tool"]["driver"]["rules"]
    assert run_["tool"]["driver"]["name"] and run_["invocations"][0]["executionSuccessful"] is True
    for r in run_["results"]:
        assert rules[r["ruleIndex"]]["id"] == r["ruleId"] and r["level"] in ("error", "warning", "note")
        assert r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].endswith("lock.json")
        assert "alpha-http -> beta-codec" in r["message"]["text"] and "fix: upgrade beta-codec to >= 1.10.1" in r["message"]["text"]
        assert r["partialFingerprints"] and r["properties"]["fixedIn"] == "1.10.1"
    assert float(rules[0]["properties"]["security-severity"]) == 8.0


def test_sarif_levels_and_suppressions_and_expired_rule():
    pk = {"alpha-http": pkg("1.0", 1, ["a", "b"]), "a": pkg("1.0", 2), "b": pkg("1.0", 2)}
    from sec_dependency_risk_gate import gate as G
    exc = G.load_exceptions({"exceptions": [
        {"id": "A2", "reason": "accepted until vendor ships", "expires": "2026-10-18"},
        {"id": "OLD", "reason": "this one already expired", "expires": "2026-01-01"}]})
    res = run(lock(pk, ["alpha-http"]), db(adv("A1", "a", ["<2"], "medium"), adv("A2", "b", ["<2"], "critical")), exceptions=exc)
    s = report.to_sarif(res, "lock.json")
    by = {r["ruleId"]: r for r in s["runs"][0]["results"]}
    assert by["A1"]["level"] == "warning" and by["A2"]["level"] == "error"
    assert by["A2"]["suppressions"][0]["justification"] == "accepted until vendor ships" and "suppressions" not in by["A1"]
    assert by["expired-exception"]["level"] == "error" and res.exit_code == 1


def test_exit0_pass_through_real_subprocess(tmp_path):
    code, out, err = cli(tmp_path, lockd=CLEAN_LOCK, dbd=db(BASE_ADV))
    assert code == 0 and json.loads(out)["verdict"] == "pass" and "PASS" in err


def test_exit1_on_violation_and_threshold_flag(tmp_path):
    assert cli(tmp_path)[0] == 1
    assert cli(tmp_path, extra=["--fail-on", "critical"])[0] == 0  # high finding is below a critical threshold


def test_exit2_malformed_lockfile_never_a_pass(tmp_path):
    for raw in ["{not json", "", "[]", json.dumps({"lockfile_version": 1}), "\xff\xfe"]:
        code, out, err = cli(tmp_path, raw_lock=raw)
        assert code == 2 and out == "" and err.startswith("error:"), raw


def test_exit2_missing_or_bad_advisory_db(tmp_path):
    code, out, err = cli(tmp_path, with_db=False)
    assert code == 2 and out == "" and "not found" in err
    assert cli(tmp_path, dbd={"schema": 1, "generated": "2026-10-01", "advisories": [adv("A", "p", ["~=1"])]})[0] == 2
    assert cli(tmp_path, extra=["--max-db-age-days", "5"])[0] == 2  # db is 17 days old: stale means unjudged


def test_exit2_unparsable_version_in_lock_or_requirements(tmp_path):
    bad = lock({"alpha-http": pkg("1.0.final")}, ["alpha-http"])
    assert cli(tmp_path, lockd=bad, req="alpha-http==1.0.final\n")[0] == 2
    assert cli(tmp_path, lockd=CLEAN_LOCK, req="alpha-http>=1.0\n")[0] == 2
    assert cli(tmp_path, lockd=CLEAN_LOCK, req="alpha-http==1.9.1\n")[0] == 2  # req/lock disagree


def test_exception_files_through_cli(tmp_path):
    e = tmp_path / "exc.json"
    good = {"exceptions": [{"id": "SYNADV-1", "reason": "waiting on vendor patch", "expires": "2026-10-18"}]}
    e.write_text(json.dumps(good), encoding="utf-8")
    assert cli(tmp_path, extra=["--exceptions", str(e)])[0] == 0
    good["exceptions"][0]["expires"] = "2026-10-17"
    e.write_text(json.dumps(good), encoding="utf-8")
    assert cli(tmp_path, lockd=CLEAN_LOCK, extra=["--exceptions", str(e)])[0] == 1  # expired, even with nothing to suppress
    del good["exceptions"][0]["expires"]
    e.write_text(json.dumps(good), encoding="utf-8")
    assert cli(tmp_path, extra=["--exceptions", str(e)])[0] == 2
    assert cli(tmp_path, extra=["--exceptions", str(tmp_path / "missing.json")])[0] == 2


def test_error_overwrites_stale_output_file_with_error_doc(tmp_path):
    out = tmp_path / "report.sarif"
    out.write_text('{"stale":"clean pass"}', encoding="utf-8")
    code, stdout, _ = cli(tmp_path, raw_lock="{broken", extra=["--output", str(out)], fmt="sarif")
    s = json.loads(out.read_text(encoding="utf-8"))
    assert code == 2 and stdout == "" and "stale" not in s
    inv = s["runs"][0]["invocations"][0]
    assert inv["executionSuccessful"] is False and s["runs"][0]["results"] == [] and inv["exitCode"] == 2


def test_demo_and_sample_commands(tmp_path):
    p = subprocess.run([sys.executable, "-m", "sec_dependency_risk_gate", "demo"], cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert p.returncode == 0 and "naive string baseline" in p.stdout and "Typosquat heuristic" in p.stdout
    assert "cannot see" in p.stdout
    q = subprocess.run([sys.executable, "-m", "sec_dependency_risk_gate", "sample", str(tmp_path)], cwd=ROOT, capture_output=True, text=True)
    assert q.returncode == 0 and (tmp_path / "lock.json").exists()


def test_corpus_gate_matches_planted_truth_and_beats_naive():
    c = corpus.build(21)
    m = corpus.measure_advisories(c)
    assert m["gate"]["all"][1:] == [0, 0] and m["gate"]["all"][0] == m["n_truth"] > 100  # zero FP, zero FN
    assert m["naive"]["transitive"][0] == 0 and m["naive"]["all"][0] < 0.5 * m["n_truth"]
    assert m["boundary_fp_gate"] == 0 < m["boundary_fp_naive"]
    assert corpus.demo_text(21) == corpus.demo_text(21)  # deterministic


def test_blind_spots_stay_silent_by_construction():
    bl = corpus.measure_blind(corpus.build(21))
    assert all(v == 0 and n == 10 for v, n in bl.values()) and len(bl) == 3


def test_synthetic_data_has_no_card_ssn_or_email_shapes():
    c = corpus.build(21)
    blob = json.dumps([c["db"], [p["lock"] for p in c["projects"]], corpus.SAMPLE, c["popular"], c["benign"]])
    assert not re.search(r"\b(?:\d[ -]?){13,16}\b", blob) and not re.search(r"\b\d{3}-\d{2}-\d{4}\b", blob)
    assert "@" not in blob and all(a["id"].startswith("SYNADV-") for a in c["db"]["advisories"])
