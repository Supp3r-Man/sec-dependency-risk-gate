"""JSON and SARIF 2.1.0 output."""
VERSION = "0.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0"}


def to_json(res, lock_uri):
    f = res.findings
    return {"tool": "sec-dependency-risk-gate", "version": VERSION, "lockfile": lock_uri,
            "verdict": "pass" if res.exit_code == 0 else "fail", "exit_code": res.exit_code, "fail_on": res.fail_on,
            "summary": {"findings": len(f), "violations": sum(x["violation"] for x in f),
                        "suppressed": sum(x["suppressed"] is not None for x in f), "expired_exceptions": len(res.expired)},
            "findings": f, "warnings": res.warnings, "expired_exceptions": res.expired}


def to_sarif(res, lock_uri):
    rules, index, results = [], {}, []

    def rule(rid, text, sev):
        if rid not in index:
            index[rid] = len(rules)
            rules.append({"id": rid, "name": rid, "shortDescription": {"text": text},
                          "properties": {"security-severity": SCORE[sev]}})
        return index[rid]

    loc = [{"physicalLocation": {"artifactLocation": {"uri": lock_uri}, "region": {"startLine": 1}}}]
    for f in res.findings:
        txt = f["message"] + (f"; path: {' -> '.join(f['path'])}" if f["kind"] == "advisory" else "")
        if f["fix"]:
            txt += f"; fix: {f['fix']}"
        r = {"ruleId": f["key"], "ruleIndex": rule(f["key"], f["summary"] or f["message"], f["severity"]),
             "level": LEVEL[f["severity"]], "message": {"text": txt}, "locations": loc,
             "partialFingerprints": {"dependencyRisk/v1": f"{f['key']}:{f['package']}@{f['version']}"},
             "properties": {"kind": f["kind"], "package": f["package"], "version": f["version"], "depth": f["depth"],
                            "path": f["path"], "fixedIn": f["fixed_in"], "severity": f["severity"]}}
        if f["suppressed"] is not None:
            r["suppressions"] = [{"kind": "external", "justification": f["suppressed"]}]
        results.append(r)
    for e in res.expired:
        results.append({"ruleId": "expired-exception", "ruleIndex": rule("expired-exception", "Exception has expired", "high"),
                        "level": "error", "locations": loc,
                        "message": {"text": f"exception for {e['id']} expired on {e['expires']}; renew it or fix the finding"}})
    run = {"tool": {"driver": {"name": "sec-dependency-risk-gate", "version": VERSION, "rules": rules}},
           "invocations": [{"executionSuccessful": True, "exitCode": res.exit_code}], "results": results}
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}


def error_doc(fmt, msg):
    """What we write to --output when the gate could not judge: never an empty 'clean' report."""
    if fmt == "sarif":
        run = {"tool": {"driver": {"name": "sec-dependency-risk-gate", "version": VERSION, "rules": []}}, "results": [],
               "invocations": [{"executionSuccessful": False, "exitCode": 2,
                                "toolExecutionNotifications": [{"level": "error", "message": {"text": msg}}]}]}
        return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}
    return {"tool": "sec-dependency-risk-gate", "version": VERSION, "verdict": "error", "exit_code": 2, "error": msg}
