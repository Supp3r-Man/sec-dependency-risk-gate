import random

from sec_dependency_risk_gate.reference import comp_str, ref_match
from sec_dependency_risk_gate.versions import SpecError, SpecifierSet, Version
from test_versions import rand_comp

import pytest

TABLE = [
    (">=1.0", "1.0", True), (">=1.0", "0.9.9", False), (">=1.0", "1.0.0", True), (">=1.0", "1.0.dev1", False),
    ("<1.4.2", "1.4.1", True), ("<1.4.2", "1.4.2", False), ("<1.4.2", "1.4.2.0", False),
    ("<1.4.2", "1.4.2.dev0", True), ("<1.4.2", "1.4.2.post1", False),
    ("<=1.4.2", "1.4.2", True), ("<=1.4.2", "1.4.2.post1", False),
    (">1.4.2", "1.4.2", False), (">1.4.2", "1.4.2.post1", True), (">1.4.2", "1.4.3", True),
    ("==1.0", "1.0.0", True), ("==1.0", "1.0.1", False), ("!=1.5", "1.5.0", False), ("!=1.5", "1.5.1", True),
    ("~=1.4.5", "1.4.5", True), ("~=1.4.5", "1.4.4", False), ("~=1.4.5", "1.4.99", True),
    ("~=1.4.5", "1.5", False), ("~=1.4.5", "1.5.dev0", False),
    ("~=2.2", "2.2", True), ("~=2.2", "2.9", True), ("~=2.2", "3.0", False), ("~=2.2", "2.1.9", False),
    (">=1.0,<2.0", "1.9.9", True), (">=1.0,<2.0", "2.0", False), (">=1.0,<2.0", "0.9", False),
    (">=1.0,<2.0,!=1.5", "1.5", False), (">=1.0,<2.0,!=1.5", "1.5.1", True),
    ("<1.0", "1.0rc1", True),  # documented simplification: plain total order
    ("<1.10", "1.9", True), (">=1.9", "1.10", True), ("<1.9", "1.10", False),
    (" >= 1.0 , < 2.0 ", "1.5", True),
]


def test_exact_boundary_table():
    for spec, ver, want in TABLE:
        assert SpecifierSet(spec).contains(Version(ver)) is want, (spec, ver)


def test_comma_join_is_and_not_or():
    s = SpecifierSet(">=1.0,<2.0")
    assert [s.contains(v) for v in ("0.5", "1.0", "1.5", "2.0", "3.0")] == [False, True, True, False, False]
    assert not SpecifierSet(">=3,<2").contains("2.5") and not SpecifierSet(">=3,<2").contains("3.5")


def test_malformed_specifiers_rejected():
    for bad in ["", "   ", ">=", ">=1.0,", ",>=1.0", ">=1.0,,<2", "=>1.0", "1.0", "~=1", "===1.0", ">=1.x", "==1.*",
                ">=1.0 <2.0", "!1.0", ">=1!2.0", "<=1.0+local", None]:
        with pytest.raises(SpecError):
            SpecifierSet(bad)


def test_bruteforce_release_only_vs_reference():
    rng = random.Random(21)
    ops = ["==", "!=", ">=", "<=", ">", "<", "~="]
    for _ in range(30000):
        clauses = []
        for _ in range(rng.randint(1, 3)):
            op = rng.choice(ops)
            rel = tuple(rng.randint(0, 3) for _ in range(rng.randint(2 if op == "~=" else 1, 4)))
            clauses.append((op, (rel, None, None, None)))
        v = (tuple(rng.randint(0, 3) for _ in range(rng.randint(1, 4))), None, None, None)
        spec = ",".join(op + comp_str(c) for op, c in clauses)
        assert SpecifierSet(spec).contains(Version(comp_str(v))) == ref_match(v, clauses), (spec, comp_str(v))


def test_bruteforce_with_pre_post_dev_vs_reference():
    rng = random.Random(22)
    ops = ["==", "!=", ">=", "<=", ">", "<"]
    for _ in range(20000):
        op, c, v = rng.choice(ops), rand_comp(rng, hi=2), rand_comp(rng, hi=2)
        assert SpecifierSet(op + comp_str(c)).contains(Version(comp_str(v))) == ref_match(v, [(op, c)]), (op, c, v)


def test_compatible_release_equals_its_expansion():
    rng = random.Random(23)
    for _ in range(5000):
        n = rng.randint(2, 4)
        rel = tuple(rng.randint(0, 3) for _ in range(n))
        upper = rel[: n - 2] + (rel[n - 2] + 1,)
        a = SpecifierSet("~=" + ".".join(map(str, rel)))
        b = SpecifierSet(">=" + ".".join(map(str, rel)) + ",<" + ".".join(map(str, upper)))
        v = Version(".".join(str(rng.randint(0, 4)) for _ in range(rng.randint(1, 4))))
        assert a.contains(v) == b.contains(v), (rel, v)
