"""Trivial reference implementation used to cross-check versions.py.

Deliberately written differently from the real code: it works on COMPONENTS, not strings
    comp = (release_tuple, pre, post, dev)   pre = ("a"|"b"|"rc", n) or None, post/dev = int or None
and compares with explicit phases and zero-padding instead of a normalised sort key.
"""


def comp_str(c):
    rel, pre, post, dev = c
    s = ".".join(str(x) for x in rel)
    if pre:
        s += f"{pre[0]}{pre[1]}"
    if post is not None:
        s += f".post{post}"
    if dev is not None:
        s += f".dev{dev}"
    return s


def _cmp(a, b):
    return (a > b) - (a < b)


def cmp_rel(a, b):
    n = max(len(a), len(b))
    return _cmp(tuple(a) + (0,) * (n - len(a)), tuple(b) + (0,) * (n - len(b)))


def _phase(c):
    _, pre, post, dev = c
    dev_flag, dev_n = (0, dev) if dev is not None else (1, 0)
    if pre is None and post is None and dev is not None:
        return (0, 0, 0, 0, 0, dev)
    if pre is not None:  # a pre-release may also carry .postN (1.0rc1.post0 > 1.0rc1)
        return (1, {"a": 0, "b": 1, "rc": 2}[pre[0]], pre[1], -1 if post is None else post, dev_flag, dev_n)
    if post is None:
        return (2, 0, 0, 0, 0, 0)
    return (3, 0, 0, post, dev_flag, dev_n)


def ref_cmp(x, y):
    return cmp_rel(x[0], y[0]) or _cmp(_phase(x), _phase(y))


def ref_clause(op, v, c):
    r = ref_cmp(v, c)
    if op == "==":
        return r == 0
    if op == "!=":
        return r != 0
    if op == ">=":
        return r >= 0
    if op == "<=":
        return r <= 0
    if op == ">":
        return r > 0
    if op == "<":
        return r < 0
    n = len(c[0]) - 1  # ~=
    return r >= 0 and (tuple(v[0]) + (0,) * n)[:n] == tuple(c[0][:n])


def ref_match(v, clauses):
    return all(ref_clause(op, v, c) for op, c in clauses)
