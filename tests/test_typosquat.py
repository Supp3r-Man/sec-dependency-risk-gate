import random
from functools import lru_cache

from sec_dependency_risk_gate import corpus
from sec_dependency_risk_gate.typosquat import check_name, norm, osa

POP = {"quartz-router", "lumen-cache", "amber-parser", "nimbus-codec", "tinyq", "oakmark"}


def ref_osa(a, b):
    @lru_cache(None)
    def f(i, j):
        if i == 0 or j == 0:
            return i + j
        best = min(f(i - 1, j) + 1, f(i, j - 1) + 1, f(i - 1, j - 1) + (a[i - 1] != b[j - 1]))
        if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
            best = min(best, f(i - 2, j - 2) + 1)
        return best
    return f(len(a), len(b))


def test_osa_matches_trivial_recursive_reference():
    rng = random.Random(5)
    for _ in range(3000):
        a = "".join(rng.choice("abc-") for _ in range(rng.randint(0, 7)))
        b = "".join(rng.choice("abc-") for _ in range(rng.randint(0, 7)))
        assert osa(a, b) == ref_osa(a, b) == osa(b, a), (a, b)
    assert osa("ab", "ba") == 1 and osa("kitten", "sitting") == 3


def test_each_trick_is_detected_with_right_reason_and_target():
    cases = {"quartz-routre": "transposition", "quartzrouter": "separator", "quar-tz-router": "separator",
             "quartz-r0uter": "homoglyph", "1umen-cache": "homoglyph", "lumen-cach": "edit-distance",
             "lumen-cachee": "edit-distance", "amber-parsor": "edit-distance"}
    for name, reason in cases.items():
        hit = check_name(name, POP)
        assert hit is not None and hit[0] == reason, (name, hit)
        assert hit[1] in POP


def test_exact_normalised_and_short_names_are_not_flagged():
    for ok in ["quartz-router", "Quartz_Router", "QUARTZ.router", "quartz--router", "lumen-cache", "totally-unrelated"]:
        assert check_name(ok, POP) is None, ok
    assert norm("A_b.C--d") == "a-b-c-d"
    assert check_name("tinyp", POP) is not None and check_name("oakmarc", POP) is not None  # 5+ chars are compared
    assert check_name("zorc", {"zorb"}) is None and check_name("zorbb", {"zorb"}) is None  # 4-char names never compared


def test_distance_limit_is_exact_at_the_length_threshold():
    short = {"abcdefghijk"}  # 11 chars -> distance 1 only
    long_ = {"abcdefghijkl"}  # 12 chars -> distance 2 allowed
    assert check_name("abcdefghijx", short) and check_name("abcdefghixx", short) is None
    assert check_name("abcdefghixxl", long_) and check_name("abcdefgxxxkl", long_) is None


def test_measured_rates_on_seeded_corpus_hold():
    c = corpus.build(21)
    ty = corpus.measure_typosquat(c)
    for kind in ("transposition", "deletion", "insertion", "substitution", "separator", "homoglyph"):
        assert ty["per_kind"][kind][0] == ty["per_kind"][kind][1], kind
    assert ty["per_kind"]["combo"][0] == 0  # known gap: prefix/suffix combosquats are invisible to an edit-distance rule
    assert 0.80 <= ty["recall"] <= 0.90
    assert ty["benign_fp"] / ty["benign_n"] < 0.08 and ty["hard_fp"] / ty["hard_n"] > 0.4  # honest: siblings are flagged
