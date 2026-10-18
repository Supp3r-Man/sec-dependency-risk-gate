import functools
import random

import pytest

from sec_dependency_risk_gate.reference import comp_str, ref_cmp, ref_match
from sec_dependency_risk_gate.versions import SpecError, SpecifierSet, Version, VersionError


def rand_comp(rng, maxlen=4, hi=3):
    rel = tuple(rng.randint(0, hi) for _ in range(rng.randint(1, maxlen)))
    pre = (rng.choice(["a", "b", "rc"]), rng.randint(0, 2)) if rng.random() < 0.3 else None
    post = rng.randint(0, 2) if rng.random() < 0.25 else None
    dev = rng.randint(0, 2) if rng.random() < 0.25 else None
    return (rel, pre, post, dev)


def test_pep440_ordering_chain():
    chain = ["1.0.dev456", "1.0a1", "1.0a2.dev456", "1.0a12.dev456", "1.0a12", "1.0b1.dev456", "1.0b2",
             "1.0b2.post345.dev456", "1.0b2.post345", "1.0rc1.dev456", "1.0rc1", "1.0", "1.0.post456.dev34", "1.0.post456", "1.1.dev1"]
    vs = [Version(x) for x in chain]
    for lo, hi in zip(vs, vs[1:]):
        assert lo < hi, (lo, hi)
    assert sorted(reversed(vs)) == vs


def test_trailing_zeros_equal_and_hash_consistent():
    assert Version("1.0") == Version("1.0.0") == Version("1.0.0.0") == Version(" 1.0 ")
    assert len({Version("2"), Version("2.0"), Version("2.0.0")}) == 1
    assert Version("1.0") != Version("1.0.1") and Version("1.0.0.1") > Version("1.0")


def test_numeric_not_lexicographic():
    assert Version("1.10") > Version("1.9") and "1.10" < "1.9"  # the string-compare trap
    assert Version("1.2") < Version("1.10") < Version("1.100") and Version("10.0") > Version("9.99.99")


def test_rejected_inputs():
    for bad in ["1!2.0", "0!1.0", "1.0+local", "", " ", "1.", ".1", "1..2", "v1.0", "1.0-1", "1.0_1", "1.0alpha1",
                "1.0.*", "abc", "1.0a", "1.0.post", "1.0.dev", "1,0", "1.0 2"]:
        with pytest.raises(VersionError):
            Version(bad)
    for bad in [None, 1.0, 1, ["1.0"]]:
        with pytest.raises(VersionError):
            Version(bad)


def test_component_roundtrip_property():
    rng = random.Random(11)
    for _ in range(3000):
        c = rand_comp(rng)
        v = Version(comp_str(c))
        assert (v.release, v.pre, v.post, v.dev) == c


def test_ordering_matches_reference_property():
    rng = random.Random(12)
    for _ in range(20000):
        a, b = rand_comp(rng, hi=2), rand_comp(rng, hi=2)
        va, vb = Version(comp_str(a)), Version(comp_str(b))
        assert ((va > vb) - (va < vb)) == ref_cmp(a, b), (comp_str(a), comp_str(b))
        assert (va == vb) == (ref_cmp(a, b) == 0)


def test_sorting_agrees_with_reference_sort():
    rng = random.Random(13)
    comps = [rand_comp(rng, hi=2) for _ in range(400)]
    got = [Version(comp_str(c)) for c in sorted(comps, key=functools.cmp_to_key(ref_cmp))]
    assert got == sorted(Version(comp_str(c)) for c in comps)
    assert all(a <= b for a, b in zip(got, got[1:]))
