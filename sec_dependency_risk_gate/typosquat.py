"""Typosquat heuristic against a popular-package list (offline, name-only).

Rules, checked in this order against every popular name p (names normalised PEP 503 style,
so "Quartz_Router" and "quartz-router" are the SAME name and never flagged):
  separator      same letters once hyphens are removed (quartzrouter, quar-tz-router)
  homoglyph      same after 0->o 1->l 3->e 5->s
  transposition  one swap of adjacent characters
  edit-distance  Damerau/OSA distance 1 (names of 5+ chars), 2 (names of 12+ chars)
Names shorter than 5 chars are never compared (too many false positives).
It is a name heuristic only: it cannot tell a legitimate sibling ("quartz-router2") from a squat.
"""
import re


def norm(name):
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def osa(a, b):
    """Optimal string alignment distance (Levenshtein + adjacent transposition)."""
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            c = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + c)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[len(a)][len(b)]


_HOMO = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s"})


def _limit(n):
    return 0 if n < 5 else (1 if n < 12 else 2)


def _is_swap(a, b):
    if len(a) != len(b):
        return False
    diff = [i for i in range(len(a)) if a[i] != b[i]]
    return len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]


def check_name(name, popular):
    """Return (reason, popular_name) if `name` looks like a squat of a popular name, else None."""
    n = norm(name)
    if n in popular:
        return None
    best = None
    for p in sorted(popular):
        lim = _limit(len(p))
        if lim == 0:
            continue
        if n.replace("-", "") == p.replace("-", ""):
            return ("separator", p)
        if n.translate(_HOMO) == p.translate(_HOMO):
            return ("homoglyph", p)
        if _is_swap(n, p):
            return ("transposition", p)
        d = osa(n, p)
        if d <= lim and (best is None or d < best[0]):
            best = (d, p)
    return ("edit-distance", best[1]) if best else None
