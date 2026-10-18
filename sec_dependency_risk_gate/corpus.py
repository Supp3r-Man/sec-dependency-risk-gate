"""Seeded synthetic corpus + measurement. Everything here is invented: fictional package names
(word pairs), made-up advisory ids (SYNADV-...), planted ground truth computed by reference.py."""
import datetime as dt
import random

from . import gate
from .reference import comp_str, ref_match
from .typosquat import check_name, norm

A = "quartz lumen amber nimbus cobalt ember falcon gravel harbor indigo juniper kestrel lantern meadow nectar onyx pebble quill raven summit tundra umber velvet willow".split()
B = "router cache parser queue codec logger client schema stream vault bridge signal filter render scheduler mapper".split()
TODAY = dt.date(2026, 10, 18)


def _c(rel):
    return (rel, None, None, None)


def _s(rel):
    return ".".join(map(str, rel))


def _canon():
    return sorted([(M, m) for M in (1, 2) for m in range(12)] + [(M, m, p) for M in (1, 2) for m in range(12) for p in (1, 2)],
                  key=lambda r: tuple(r) + (0,) * (3 - len(r)))


CANON = _canon()


def _advisory(rng, i, pkg):
    M, a = rng.choice([1, 2]), rng.randint(0, 8)
    b = rng.randint(a + 1, 11)
    lo, fx = (M, a), ((M, b, 1) if rng.random() < 0.3 else (M, b))
    kind = rng.choice(["range", "lt", "eq", "excl", "compat", "two"])
    if kind == "range":
        ors, fixed = [[(">=", lo), ("<", fx)]], [fx]
    elif kind == "lt":
        ors, fixed = [[("<", fx)]], [fx]
    elif kind == "eq":
        p = rng.randint(0, 1)
        ors, fixed = [[("==", (M, a, p))]], [(M, a, p + 1)]
    elif kind == "excl":
        ors, fixed = [[(">=", lo), ("<", fx), ("!=", (M, a, 1))]], [fx]
    elif kind == "compat":
        v = (M, a, rng.randint(0, 2))
        ors, fixed = [[("~=", v)]], [(M, a + 1)]
    else:
        ors, fixed = [[(">=", (M, 0)), ("<", (M, 2))], [(">=", (M, 5)), ("<", (M, 7))]], [(M, 2), (M, 7)]
    return {"id": f"SYNADV-2026-{i:04d}", "package": pkg, "affected": [",".join(op + _s(r) for op, r in o) for o in ors],
            "severity": rng.choices(["low", "medium", "high", "critical"], [2, 3, 3, 2])[0],
            "fixed": [_s(f) for f in fixed], "summary": f"synthetic advisory ({kind})"}, [[(op, _c(r)) for op, r in o] for o in ors]


def _pad3(r):
    return tuple(r) + (0,) * (3 - len(r))


def _boundary_pool(adv_raw):
    rels = set()
    for s in adv_raw["affected"] + adv_raw["fixed"]:
        for part in s.split(","):
            txt = part.lstrip("~=!<>")
            t = tuple(int(x) for x in txt.split("."))
            while len(t) > 2 and t[-1] == 0:
                t = t[:-1]
            rels.add(t)
    pool = {c for c in CANON if len(c) >= 2 and c[1] in (10, 11) and c[0] in {r[0] for r in rels}}  # multi-digit minors break string order
    for r in rels:
        k = _pad3(r)
        idx = [i for i, c in enumerate(CANON) if _pad3(c) == k]
        if idx:
            pool.update(CANON[j] for j in (idx[0] - 1, idx[0], idx[0] + 1) if 0 <= j < len(CANON))
    return sorted(pool, key=_pad3)


def build(seed=21, n_projects=150):
    rng = random.Random(seed)
    names = [f"{a}-{b}" for a in A for b in B]
    rng.shuffle(names)
    popular = names[:60] + ["tinyq", "oakmark", "zorb", "pixl"]
    benign = names[60:460]
    eco = popular[:60] + names[60:104]
    adv_pkgs = rng.sample(eco, 40)
    advisories, truth, k = [], {}, 0
    for pkg in adv_pkgs:
        for _ in range(2 if rng.random() < 0.25 else 1):
            k += 1
            raw, ors = _advisory(rng, k, pkg)
            advisories.append(raw)
            truth[raw["id"]] = ors
    db_data = {"schema": 1, "generated": "2026-10-01", "advisories": advisories}
    by_pkg = {}
    for a in advisories:
        by_pkg.setdefault(a["package"], []).append(a)

    def pick(pkg):
        advs = by_pkg.get(pkg)
        if advs and rng.random() < 0.5:
            rel, tag = rng.choice(_boundary_pool(rng.choice(advs))), "boundary"
        else:
            rel, tag = rng.choice(CANON), "random"
        if len(rel) == 2 and rng.random() < 0.3:
            rel = rel + (0,)  # 1.4 written as 1.4.0: equal under PEP 440
        return rel, tag

    projects = []
    for i in range(n_projects):
        direct = rng.sample(eco, rng.randint(3, 6))
        used, edges, layer, l2 = set(direct), {}, {d: 1 for d in direct}, []
        for d in direct:
            edges[d] = []
            for _ in range(rng.randint(0, 2)):
                if l2 and rng.random() < 0.2:
                    t = rng.choice(l2)
                else:
                    t = rng.choice([x for x in eco if x not in used])
                    used.add(t)
                    l2.append(t)
                    layer[t] = 2
                if t not in edges[d]:
                    edges[d].append(t)
        for t in list(l2):
            if rng.random() < 0.35:
                u = rng.choice([x for x in eco if x not in used])
                used.add(u)
                layer[u] = 3
                edges[t] = [u]
        pk, tags, rels = {}, {}, {}
        for n in sorted(layer):
            rel, tags[n] = pick(n)
            rels[n] = rel
            pk[n] = {"version": _s(rel), "depth": layer[n], "requires": edges.get(n, []), "license": "MIT"}
        lock = {"lockfile_version": 1, "project": f"proj-{i:03d}", "packages": pk, "direct": sorted(direct)}
        tr = {(a["id"], n) for n in pk for a in by_pkg.get(n, [])
              if any(ref_match(_c(rels[n]), o) for o in truth[a["id"]])}
        checks = {(a["id"], n) for n in pk for a in by_pkg.get(n, [])}
        projects.append({"lock": lock, "truth": tr, "checks": checks, "tags": tags, "direct": set(direct), "rels": rels})
    return {"db": db_data, "projects": projects, "popular": popular, "benign": benign, "eco": eco, "adv_pkgs": adv_pkgs,
            "by_pkg": by_pkg, "rng": rng}


def _nclause(c, v):
    op = next(o for o in ("~=", "==", "!=", ">=", "<=", ">", "<") if c.startswith(o))
    s = c[len(op):]
    return {"==": v == s, "!=": v != s, ">=": v >= s, "<=": v <= s, ">": v > s, "<": v < s,
            "~=": v >= s and v.startswith(s.rsplit(".", 1)[0])}[op]


def naive_hits(proj, by_pkg):
    """Baseline: exact name, DIRECT deps only, versions compared as plain strings."""
    out = set()
    for d in proj["direct"]:
        v = proj["lock"]["packages"][d]["version"]
        for a in by_pkg.get(d, []):
            if any(all(_nclause(c, v) for c in r.split(",")) for r in a["affected"]):
                out.add((a["id"], d))
    return out


def _prf(found, truth):
    tp, fp, fn = len(found & truth), len(found - truth), len(truth - found)
    return tp, fp, fn


def measure_advisories(corpus):
    db = gate.load_db(corpus["db"])
    T = {"all": [0, 0, 0], "direct": [0, 0, 0], "transitive": [0, 0, 0]}
    N = {"all": [0, 0, 0], "direct": [0, 0, 0], "transitive": [0, 0, 0]}
    bchk = bfp_g = bfp_n = 0
    for p in corpus["projects"]:
        lock = gate.load_lock(p["lock"])
        res = gate.evaluate(lock, db, fail_on="low", today=TODAY)
        g = {(f["key"], f["package"]) for f in res.findings if f["kind"] == "advisory"}
        nv = naive_hits(p, corpus["by_pkg"])
        for sc, keep in (("all", lambda x: True), ("direct", lambda x: x[1] in p["direct"]),
                         ("transitive", lambda x: x[1] not in p["direct"])):
            for acc, found in ((T, g), (N, nv)):
                r = _prf({x for x in found if keep(x)}, {x for x in p["truth"] if keep(x)})
                acc[sc] = [a + b for a, b in zip(acc[sc], r)]
        safe_b = {x for x in p["checks"] - p["truth"] if p["tags"][x[1]] == "boundary"}
        bchk += len(safe_b)
        bfp_g += len(safe_b & g)
        bfp_n += len(safe_b & nv)
    return {"gate": T, "naive": N, "boundary_checks": bchk, "boundary_fp_gate": bfp_g, "boundary_fp_naive": bfp_n,
            "n_truth": sum(len(p["truth"]) for p in corpus["projects"]),
            "n_projects": len(corpus["projects"]), "n_advisories": len(corpus["db"]["advisories"])}


def _edit(rng, s, kind):
    letters = "abcdefghijklmnopqrstuvwxyz"
    idx = [i for i, ch in enumerate(s) if ch != "-"]
    if kind == "transposition":
        c = [i for i in range(len(s) - 1) if s[i] != s[i + 1] and "-" not in s[i:i + 2]]
        if not c:
            return s
        i = rng.choice(c)
        return s[:i] + s[i + 1] + s[i] + s[i + 2:]
    if kind == "deletion":
        i = rng.choice(idx)
        return s[:i] + s[i + 1:]
    if kind == "insertion":
        i = rng.choice(idx)
        return s[:i] + rng.choice(letters) + s[i:]
    if kind == "substitution":
        i = rng.choice(idx)
        return s[:i] + rng.choice([x for x in letters if x != s[i]]) + s[i + 1:]
    if kind == "separator":
        if "-" in s and rng.random() < 0.5:
            return s.replace("-", "")
        i = rng.choice([j for j in idx if 0 < j < len(s) - 1])
        return s[:i] + "-" + s[i:]
    if kind == "homoglyph":
        c = [i for i, ch in enumerate(s) if ch in "oleas"[:3]]
        if not c:
            return s
        i = rng.choice(c)
        return s[:i] + {"o": "0", "l": "1", "e": "3"}[s[i]] + s[i + 1:]
    if kind == "double":
        return _edit(rng, _edit(rng, s, rng.choice(["deletion", "insertion", "substitution"])),
                     rng.choice(["deletion", "insertion", "substitution"]))
    return rng.choice([s + "-utils", s + "-py", "py-" + s, s + "-lib"])  # combosquat


KINDS = ["transposition", "deletion", "insertion", "substitution", "separator", "homoglyph", "double", "combo"]


def measure_typosquat(corpus, per_kind=40):
    rng = random.Random(7)
    pop = set(corpus["popular"])
    long_pop = sorted(p for p in pop if len(p) >= 5)
    known = set(corpus["benign"]) | pop
    per, tp_target = {}, 0
    for kind in KINDS:
        flagged = right = made = 0
        while made < per_kind:
            src = rng.choice(long_pop)
            name = _edit(rng, src, kind)
            if norm(name) in known or name == src:
                continue
            made += 1
            hit = check_name(name, pop)
            flagged += hit is not None
            right += hit is not None and hit[1] == src
        per[kind] = (flagged, made, right)
        tp_target += flagged
    rb = [check_name(n, pop) for n in corpus["benign"]]
    hard = [p + sfx for p in long_pop[:20] for sfx in ("2", "s", "-lite")]
    hb = [check_name(n, pop) for n in hard]
    fp_r, fp_h = sum(x is not None for x in rb), sum(x is not None for x in hb)
    n_sq = per_kind * len(KINDS)
    return {"per_kind": per, "recall": tp_target / n_sq, "n_squat": n_sq, "benign_n": len(rb), "benign_fp": fp_r,
            "hard_n": len(hb), "hard_fp": fp_h,
            "precision_random": tp_target / max(1, tp_target + fp_r),
            "precision_with_hard": tp_target / max(1, tp_target + fp_r + fp_h)}


def measure_blind(corpus, per=10):
    """Planted cases the gate has no data to see; verifies it stays silent (by construction)."""
    db = gate.load_db(corpus["db"])
    rng = random.Random(3)
    clean = [e for e in corpus["eco"] if e not in corpus["by_pkg"]]
    seen = {"unlisted vulnerability": 0, "yanked version": 0, "vendored copy": 0}
    for kind in seen:
        for _ in range(per):
            pkg = rng.choice(clean)  # vendored: the real lib lives under vendor/, not in the lockfile; others: no advisory exists
            lock = gate.load_lock({"lockfile_version": 1, "packages": {pkg: {"version": "1.4.0", "depth": 1}}, "direct": [pkg]})
            res = gate.evaluate(lock, db, fail_on="low", today=TODAY)
            seen[kind] += any(f["kind"] == "advisory" for f in res.findings)
    return {k: (v, per) for k, v in seen.items()}


def render(adv, ty, bl):
    g, n = adv["gate"], adv["naive"]

    def rec(a):
        tp, _, fn = a
        return f"{tp}/{tp + fn} ({100.0 * tp / max(1, tp + fn):.1f}%)"

    L = [f"Synthetic corpus: {adv['n_projects']} projects, {adv['n_advisories']} advisories, {adv['n_truth']} planted true findings (seed 21)",
         "", "Advisory detection (found / planted)         gate               naive string baseline",
         f"  all findings                               {rec(g['all']):<19}{rec(n['all'])}",
         f"  direct dependencies only                   {rec(g['direct']):<19}{rec(n['direct'])}",
         f"  transitive dependencies only               {rec(g['transitive']):<19}{rec(n['transitive'])}",
         f"  false positives (all)                      {g['all'][1]:<19}{n['all'][1]}",
         f"  false positives at safe boundary versions  {adv['boundary_fp_gate']}/{adv['boundary_checks']:<16}{adv['boundary_fp_naive']}/{adv['boundary_checks']}",
         "", f"Typosquat heuristic ({ty['n_squat']} generated squats vs {ty['benign_n']} random benign + {ty['hard_n']} hard benign names)",
         f"  recall overall                             {100 * ty['recall']:.1f}%"]
    for k, (f, m, r) in ty["per_kind"].items():
        L.append(f"    {k:<14} flagged {f}/{m}, right target {r}")
    L += [f"  false positives, random benign             {ty['benign_fp']}/{ty['benign_n']} ({100.0 * ty['benign_fp'] / ty['benign_n']:.1f}%)",
          f"  false positives, hard benign (x2, xs)      {ty['hard_fp']}/{ty['hard_n']} ({100.0 * ty['hard_fp'] / ty['hard_n']:.1f}%)",
          f"  precision (random benign only)             {100 * ty['precision_random']:.1f}%",
          f"  precision (incl. hard benign)              {100 * ty['precision_with_hard']:.1f}%",
          "", "Planted cases the gate cannot see (found / planted):"]
    L += [f"  {k:<24} {v}/{m}" for k, (v, m) in bl.items()]
    return "\n".join(L)


def demo_text(seed=21):
    c = build(seed)
    return render(measure_advisories(c), measure_typosquat(c), measure_blind(c))


SAMPLE = {
    "requirements.txt": "# direct pins\nquartz-router==1.9.0\nlumen-cache==2.1\namber-parser==1.0.3\nquartz-routr==0.1\n",
    "lock.json": {"lockfile_version": 1, "project": "sample-app", "direct": ["quartz-router", "lumen-cache", "amber-parser", "quartz-routr"],
                  "packages": {
                      "quartz-router": {"version": "1.9.0", "depth": 1, "requires": ["nectar-codec"], "license": "MIT"},
                      "nectar-codec": {"version": "1.10", "depth": 2, "requires": ["pebble-schema"], "license": "Apache-2.0"},
                      "pebble-schema": {"version": "2.0.0", "depth": 3, "license": "AGPL-3.0-only"},
                      "lumen-cache": {"version": "2.1", "depth": 1, "license": "MIT"},
                      "amber-parser": {"version": "1.0.3", "depth": 1},
                      "quartz-routr": {"version": "0.1", "depth": 1, "license": "MIT"}}},
    "advisories.json": {"schema": 1, "generated": "2026-10-01", "advisories": [
        {"id": "SYNADV-2026-0001", "package": "nectar-codec", "affected": [">=1.2,<1.10.1"], "severity": "high", "fixed": ["1.10.1"], "summary": "synthetic: decode overflow"},
        {"id": "SYNADV-2026-0002", "package": "quartz-router", "affected": ["<1.9.0"], "severity": "medium", "fixed": ["1.9.0"], "summary": "synthetic: path confusion"},
        {"id": "SYNADV-2026-0003", "package": "lumen-cache", "affected": ["~=2.0"], "severity": "critical", "fixed": ["3.0"], "summary": "synthetic: key collision"},
        {"id": "SYNADV-2026-0004", "package": "lumen-cache", "affected": [">=2.2,<2.3"], "severity": "high", "fixed": ["2.3"], "summary": "synthetic: stale entry"}]},
    "licenses.json": {"deny": ["AGPL-3.0-only"], "allow": ["MIT", "Apache-2.0", "BSD-3-Clause"]},
    "popular.txt": "# fictional popular names\nquartz-router\nlumen-cache\namber-parser\nnectar-codec\npebble-schema\n",
    "exceptions.json": {"exceptions": [{"id": "SYNADV-2026-0003", "package": "lumen-cache",
                                        "reason": "synthetic example: waiting on vendor release", "expires": "2026-12-31"}]},
}
