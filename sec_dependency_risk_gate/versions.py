"""PEP 440-lite versions and specifiers (stdlib only).

Supported grammar (anything else raises VersionError / SpecError, never guesses):
    N(.N)*  [a|b|rc N]  [.postN]  [.devN]      e.g. 1.4.2  2.0rc1  1.0.post3  1.0a2.dev5
Rejected on purpose: epochs ("1!2.0"), local versions ("1.0+abc"), a leading "v",
alternative spellings ("alpha", "-1", "_"), wildcards ("==1.*").
Ordering follows PEP 440: trailing zeros are insignificant (1.0 == 1.0.0),
X.devN < X.aN < X.bN < X.rcN < X < X.postN.
Documented simplification: specifiers use the plain total order, so "<1.0" DOES match
1.0rc1 (pip would skip pre-releases; for an advisory gate over-reporting is the safe side).
"""
import re
from functools import total_ordering


class VersionError(ValueError):
    pass


class SpecError(ValueError):
    pass


_RE = re.compile(r"^(\d+(?:\.\d+)*)(?:(a|b|rc)(\d+))?(?:\.post(\d+))?(?:\.dev(\d+))?$")
_RANK = {"a": 0, "b": 1, "rc": 2}


@total_ordering
class Version:
    __slots__ = ("text", "release", "pre", "post", "dev", "key")

    def __init__(self, s):
        if not isinstance(s, str):
            raise VersionError(f"version must be a string, got {type(s).__name__}")
        t = s.strip().lower()
        if "!" in t:
            raise VersionError(f"epochs are not supported: {s!r}")
        if "+" in t:
            raise VersionError(f"local versions are not supported: {s!r}")
        m = _RE.match(t)
        if not m:
            raise VersionError(f"unparsable version: {s!r}")
        self.text = t
        self.release = tuple(int(x) for x in m.group(1).split("."))
        self.pre = (m.group(2), int(m.group(3))) if m.group(2) else None
        self.post = int(m.group(4)) if m.group(4) is not None else None
        self.dev = int(m.group(5)) if m.group(5) is not None else None
        rel = list(self.release)
        while len(rel) > 1 and rel[-1] == 0:
            rel.pop()
        if self.pre is None and self.post is None and self.dev is not None:
            pk = (-1, 0)  # X.devN sorts below every pre-release of X
        elif self.pre is None:
            pk = (3, 0)  # final release / post release: above all pre-releases
        else:
            pk = (_RANK[self.pre[0]], self.pre[1])
        post_k = -1 if self.post is None else self.post
        dev_k = (1, 0) if self.dev is None else (0, self.dev)
        self.key = (tuple(rel), pk, post_k, dev_k)

    def __eq__(self, other):
        return isinstance(other, Version) and self.key == other.key

    def __lt__(self, other):
        return self.key < other.key

    def __hash__(self):
        return hash(self.key)

    def __repr__(self):
        return f"Version({self.text!r})"


_OPS = ("~=", "==", "!=", ">=", "<=", ">", "<")


class Clause:
    __slots__ = ("op", "version", "raw")

    def __init__(self, raw):
        p = raw.strip()
        for op in _OPS:
            if p.startswith(op):
                break
        else:
            raise SpecError(f"no operator in clause {raw!r}")
        rest = p[len(op):].strip()
        if "*" in rest:
            raise SpecError(f"wildcards are not supported: {raw!r}")
        try:
            self.version = Version(rest)
        except VersionError as e:
            raise SpecError(f"bad version in clause {raw!r}: {e}")
        if op == "~=" and len(self.version.release) < 2:
            raise SpecError(f"~= needs at least two release segments: {raw!r}")
        self.op, self.raw = op, p

    def matches(self, v):
        op, cv = self.op, self.version
        if op == "==":
            return v == cv
        if op == "!=":
            return v != cv
        if op == ">=":
            return v >= cv
        if op == "<=":
            return v <= cv
        if op == ">":
            return v > cv
        if op == "<":
            return v < cv
        n = len(cv.release) - 1  # "~=": >= V and same release prefix of length n
        return v >= cv and (v.release + (0,) * n)[:n] == cv.release[:n]


class SpecifierSet:
    """Comma-joined clauses, all of which must match (logical AND)."""

    def __init__(self, s):
        if not isinstance(s, str) or not s.strip():
            raise SpecError("empty specifier")
        parts = s.split(",")
        if any(not p.strip() for p in parts):
            raise SpecError(f"empty clause in {s!r}")
        self.raw = s.strip()
        self.clauses = [Clause(p) for p in parts]

    def contains(self, v):
        if not isinstance(v, Version):
            v = Version(v)
        return all(c.matches(v) for c in self.clauses)
