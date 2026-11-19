"""
PAN filter — NFKC-invariance property test.

For seeded random obfuscated renderings ``s`` of a random payment PAN,
``contains_full_pan(s)`` and ``contains_full_pan(NFKC(s))`` are both True,
for at least 2,000 cases per module copy.
"""
import functools
import os
import random
import sys
import unicodedata

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import lambdas.pan_filter.pan_filter as pan_filter_copy
import lambdas.detection_agent.pan_filter as detection_agent_pan_filter_copy
import lambdas.executor_agent.pan_filter.pan_filter as executor_agent_pan_filter_copy

_PAN_FILTER_MODULES = [
    pan_filter_copy,
    detection_agent_pan_filter_copy,
    executor_agent_pan_filter_copy,
]
_PAN_FILTER_MODULE_IDS = [
    "lambdas.pan_filter.pan_filter",
    "lambdas.detection_agent.pan_filter",
    "lambdas.executor_agent.pan_filter.pan_filter",
]

_CASES_PER_COPY = 2000


@functools.lru_cache(maxsize=1)
def _tables():
    """DIGIT_FORMS, two-digit single-code-point numerals, separator pool.
    Built once (one pass over every code point)."""
    digit_forms = {d: [] for d in range(10)}
    two_digit = {}
    pool = []
    pool_categories = {"Zs", "Pd", "Po", "Cf"}
    d4 = set()
    for lo, hi in pan_filter_copy._DEFAULT_IGNORABLE_RANGES:
        d4.update(range(lo, hi + 1))
    glyphs = {ord(c) for c in pan_filter_copy.MASK_GLYPHS}

    def nfkc_clean(ch):
        n = unicodedata.normalize("NFKC", ch)
        return not any(
            unicodedata.category(c).startswith("L") or unicodedata.digit(c, None) is not None
            for c in n
        )

    for cp in range(0x110000):
        if 0xD800 <= cp <= 0xDFFF:
            continue
        ch = chr(cp)
        d = unicodedata.digit(ch, None)
        if d is not None:
            digit_forms[d].append(ch)
            continue
        n = unicodedata.normalize("NFKC", ch)
        if len(n) == 2 and n.isascii() and n.isdigit() and 10 <= int(n) <= 50:
            two_digit.setdefault(int(n), []).append(ch)
        if (unicodedata.category(ch) in pool_categories or cp in d4 or cp in glyphs) \
                and nfkc_clean(ch):
            pool.append(ch)
    return digit_forms, two_digit, pool


def _random_payment_pan(rng):
    length = rng.randint(13, 19)
    body = [str(rng.randint(2, 6))] + [str(rng.randint(0, 9)) for _ in range(length - 2)]
    for check in "0123456789":
        cand = "".join(body) + check
        if pan_filter_copy._luhn_valid(cand):
            return cand
    raise AssertionError("unreachable")


def _render(rng, pan):
    digit_forms, two_digit, pool = _tables()
    out = []
    i = 0
    while i < len(pan):
        if out and rng.random() < 0.3:
            out.extend(rng.choice(pool) for _ in range(rng.randint(1, 3)))
        if i + 1 < len(pan) and rng.random() < 0.3:
            v = int(pan[i:i + 2])
            if v in two_digit:
                out.append(rng.choice(two_digit[v]))
                i += 2
                continue
        out.append(rng.choice(digit_forms[int(pan[i])]))
        i += 1
    return "".join(out)


@pytest.mark.parametrize("mod", _PAN_FILTER_MODULES, ids=_PAN_FILTER_MODULE_IDS)
def test_nfkc_invariance_property(mod):
    rng = random.Random(1381)
    for _ in range(_CASES_PER_COPY):
        pan = _random_payment_pan(rng)
        s = _render(rng, pan)
        assert mod.contains_full_pan(s) is True, (pan, ascii(s))
        assert mod.contains_full_pan(unicodedata.normalize("NFKC", s)) is True, (pan, ascii(s))
