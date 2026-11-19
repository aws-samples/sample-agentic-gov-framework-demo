"""
PAN filter — adversarial test matrix.

Every row of the matrix below (B = bypass, X = cross-field, F = false-positive
guard, Z = transaction-level, R = documented residual, N = N1 datetime rows),
parametrized over all three module copies. Leaf rows assert
``contains_full_pan(text)``; transaction rows assert
``filter_transactions([txn])[1]``. Also covers the demo dataset (0 rows
rejected), the N1 work bound, and the linear Step-2 algorithm's
equivalence with the iterated greatest fixed point.
"""
import json
import os
import random
import re
import sys
import time

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

P = "4532015112830366"
DATASET = os.path.join(PROJECT_ROOT, "data", "transactions_small.jsonl")


def _map_digits(base: int) -> str:
    return "".join(chr(base + int(d)) for d in P)


_SUPERSCRIPTS = {
    "0": "\u2070", "1": "\u00b9", "2": "\u00b2", "3": "\u00b3", "4": "\u2074",
    "5": "\u2075", "6": "\u2076", "7": "\u2077", "8": "\u2078", "9": "\u2079",
}

# ---------------------------------------------------------------------------
# Leaf rows: (id, text, expected contains_full_pan)
# ---------------------------------------------------------------------------
LEAF_ROWS = [
    # Bypass inputs — must flag.
    ("B01", P, True),
    ("B02", "4532-0151-1283-0366", True),
    ("B03", "4532\u200b0151\u200b1283\u200b0366", True),
    ("B04", _map_digits(0xFF10), True),
    ("B05", _map_digits(0x0660), True),
    ("B06", _map_digits(0x0966), True),
    ("B07", "4532\u00a00151\u20091283\u30000366", True),
    ("B08", "4532\u3164\u31640151\u3164\u31641283\u3164\u31640366", True),
    ("B09", "4532\u00ad0151\u202e1283\u20660366", True),
    ("B10", "4\u03035\u03033\u03032015112830366", True),
    ("B11", '4532"0151"1283"0366', True),
    ("B12", "4532015112830366xxxxxx1", True),
    ("B13", "1xxxxxx4532015112830366", True),
    ("B14", "4532015112xxxxxx830366", True),
    ("B15", "45320151********12830366", True),
    ("B16", "4532####0151\u2022\u2022\u2022\u20221283######0366", True),
    ("B17", "4532*0151*1283*0366", True),
    ("B18", "453201511283a0366", True),
    ("B19", "0000000000" + "4532a015112830366" + "0000000000", True),
    ("B20", "4532\u0445015112830366", True),
    ("B21", "4532XXXXXX015112830366", True),
    ("B22", "0000" + P + "0000", True),
    ("B23", "371449635398431", True),
    ("B24", json.dumps({"note": "xxxxxx", "card": P}), True),
    ("B25", "".join(_SUPERSCRIPTS[d] for d in P), True),
    ("B26", "4532a015112830366-7b8", True),
    ("B27", "4532015\u246a2830366", True),
    ("B28", "\u32ba\u325c0151\u246b830366", True),
    ("B29", "x 2026-01-01T00:00:00.453201-5112830366", True),
    ("B30", "45320151 2026-01-01 12830366", True),
    ("B31", "2026-01-01T00:00:00Z4532015112830366", True),
    ("B32", "45320151a2026-01-01", True),
    ("B33", "4532015112xx830366 03/27", True),
    ("B34", "\u248b\u248c\u248a\u24890151\u2488\u2489830366", True),
    ("B35", "2026-01-01,4532015112830366", True),
    ("B36", "4532015xxxxxx/112830366", True),
    ("B37", "x 2026-01-01T00:00:00.453201 -5112830366", True),
    ("B38", "x 2026-01-01T00:00:00.453201 +1430830366", True),
    ("B39", "x 2026-01-01T00:00:00.453201\t\t-5112830366", True),
    ("B40", "2026-01-01T00:00:00 Z4532015112830366", True),
    ("B41", "2026-01-01T00:00:00\t+0000 4532015112830366", True),
    ("B42", "2026-01-01T00:00:45.32015112830366Z", True),
    ("B43", "45320151 2026-01-01 00:00:00 +0000 12830366", True),
    ("B44", "4532\u30fc0151\u30fc1283\u30fc0366", True),
    ("B45", "4532\u06400151\u06401283\u06400366", True),
    ("B46", "4532\u318d0151\u318d1283\u318d0366", True),
    ("B47", "".join(chr(0x11F50 + int(d)) for d in P), True),
    # False-positive inputs — must accept.
    ("F01", "2026-08-19T03:11:39.014082", False),
    ("F02", "2026-01-01T00:00:00.000001", False),
    ("F03", "2026-08-19T03:11:39Z", False),
    ("F04", "2026-08-19T03:11:39.014082+05:30", False),
    ("F05", "2026-08-19 03:11:39", False),
    ("F06", "acc-10293847", False),
    ("F07", "acc-0fe379be", False),
    ("F08", "123e4567-e89b-12d3-a456-426614174000", False),
    ("F09", "550e8400-e29b-41d4-a716-446655440000", False),
    ("F10", "+1 (555) 123-4567", False),
    ("F11", "+44 20 7946 0958", False),
    ("F12", "4532-01**-****-0366", False),
    ("F13", "4532xxxxxxxx0366", False),
    ("F14", "453201******0366", False),
    ("F15", "4532 \u2022\u2022\u2022\u2022 \u2022\u2022\u2022\u2022 0366", False),
    ("F16", "4532########0366", False),
    ("F17", "4532 XXXX XXXX 0366", False),
    ("F18", "45320151****0366", False),
    ("F19", "1043321819600133", False),
    ("F20", "289.45", False),
    ("F21", "1724036499014", False),
    ("F22", "192.168.100.200", False),
    ("F23", "processed at 2026-08-19T03:11:39.014082", False),
    ("F24", "2026-08-19T03:11:39.014082 UTC", False),
    ("F25", "2026-08-19T03:11:39.014082+02:00[Europe/Paris]", False),
    ("F26", "2026-08-19T03:11:39.014082518Z", False),
    ("F27", "2026-08-19 03:11:39,014 INFO ok", False),
    ("F28", "ts=2026-08-19T03:11:39.014Z", False),
    ("F29", "2026-08-19T03:11:39.014082/2026-08-20T03:11:39.014082", False),
    ("F30", "2026-01-01,2026-02-01", False),
    ("F31", "2025-05-18 01:21:37.993908 +00:00", False),
    ("F32", "2026-08-19 03:11:39.014082518 +0000 UTC", False),
    ("F33", "2026-08-19T03:11:39.014082 -05:00", False),
    ("F34", "2026-08-19 03:11:39 +0530", False),
    ("F35", "2026-08-19 03:11:39.014082  +00:00", False),
    ("F36", "Tue, 20 Oct 2026 06:03:42 GMT", False),
    # Documented residuals — assert the stated value.
    ("R3a", "4532a0151b12830366", False),
    ("R3b", "4532ab015112830366", False),
    ("R3c", "4532a0151b1283c0366", False),
    ("R5", "2026-04-05T17:53:34.286179+05:30", False),
    ("R5b", "45320151ab2026-01-01", False),
    ("R5b_no_datetime", "45320151ab20260101", False),
    ("R8b", "GB82 WEST 1234 5698 7654 32", True),
    ("R8c", "2026-08-19T03:11:39.014082,289.45", True),
    ("R8d", "2026-08-19T03:11:39.014082123456Z", True),
    ("R8e", "2026-08-19T03:11:39.0140821234Z", True),
    ("R8f", "Tue, 13 Feb 2029 00:21:50 +0400", True),
    ("R8g", "[20/Mar/2031:19:52:43 +0400]", True),
    ("R8h", "2032-07-14 11:20:13.381992249 +0000 UTC m=+12685.268432214", True),
    ("R8h_without_suffix", "2032-07-14 11:20:13.381992249 +0000 UTC", False),
    ("R8i", "1920307113.905478", True),
    ("R9a", "421299******7288 03/27", True),
    ("R9b", "438323******6278 05/25", True),
    ("R9c", "447527******7742 12/27", True),
]


@pytest.mark.parametrize("mod", _PAN_FILTER_MODULES, ids=_PAN_FILTER_MODULE_IDS)
@pytest.mark.parametrize("row_id,text,expected", LEAF_ROWS, ids=[r[0] for r in LEAF_ROWS])
def test_leaf_row(mod, row_id, text, expected):
    assert mod.contains_full_pan(text) is expected, f"matrix row {row_id}"


# ---------------------------------------------------------------------------
# Transaction rows: (id, txn, expected rejected count)
# ---------------------------------------------------------------------------
_R10A_DIGITS = P
_R10_KEYS = ["k" + c for c in "abcdefghijklmnop"]

with open(DATASET, encoding="utf-8") as _fh:
    _DATASET_ROWS = [json.loads(line) for line in _fh if line.strip()]

TXN_ROWS = [
    ("X01", {"a": "x45320151", "b": "y12830366"}, 1),
    ("X02", {"a": "45320151", "b": "12830366"}, 1),
    ("X03", {"a": "4532", "b": "01511283", "c": "0366"}, 1),
    ("X04", {"a": "acc-45320151", "b": "ref-12830366"}, 1),
    ("X05", {"a": "45320151zz", "b": "qq12830366"}, 1),
    ("X06", {"a": "45320151", "n": "hello", "b": "12830366"}, 1),
    ("X07", {"a": "45320151", "ts": "2026-08-19T03:11:39.014082", "b": "12830366"}, 1),
    ("X08", {"45320151": "12830366"}, 1),
    ("X09", {"a": {"b": "45320151"}, "c": ["12830366"]}, 1),
    ("X12", {"a": 45320151, "b": 12830366}, 1),
    ("X13", {"a": "45320151", "b": "xxxxxx12830366"}, 1),
    ("X14", {P: "v"}, 1),
    ("X15", {"c": '4532"0151"1283"0366'}, 1),
    ("X16", {"c": "4532\x000151\x001283\x000366"}, 1),
    ("X17", {"a": "45320151", "ts": "processed at 2026-08-19T03:11:39.014082", "b": "12830366"}, 1),
    ("X18", {"amt": 4532015112830366.0}, 1),
    ("X19", {"a": "45320151", "ts": "2026-08-19 03:11:39.014082518 +0000 UTC", "b": "12830366"}, 1),
    ("X20", json.loads('{"amount":45320151.12830366}'), 1),
    ("X21", {"a": "4532", "b": "0151", "c": "1283", "d": "0366"}, 1),
    ("X22", {"a": "453201", "b": "5112830366"}, 1),
    ("Z01", {"txn_id": "clean-1", "sender_id": "acc-10293847",
             "receiver_id": "acc-56473829", "amount": 289.45}, 0),
    ("Z02", _DATASET_ROWS[0], 0),
    ("Z03", {"request_id": "123e4567-e89b-12d3-a456-426614174000", "ts": "2026-08-19T03:11:39Z"}, 0),
    ("Z04", {"card": "4532-01**-****-0366", "amount": 12.5}, 0),
    ("Z05", {"card": "4532xxxxxxxx0366", "txn_id": "txn-1"}, 0),
    ("Z06", {"x": "12345678", "y": "87654321", "z": "11112222"}, 0),
    ("Z07", json.loads('{"ts":1746082035.5199971}'), 0),
    ("Z08", {"ts": "2026-08-19T03:11:39.014082518Z"}, 0),
    ("Z09", json.loads(
        '{"amount":125.5,"currency":"840","mcc":"5411","pos_entry_mode":"051",'
        '"terminal_id":"40028871","stan":"004512","auth_code":"483920",'
        '"response_code":"00","zip":"94107"}'), 0),
    ("Z10", dict(zip(_R10_KEYS, "1234567812345678")), 0),
    ("R1a", {"a": "4532a0151", "b": "1283x0366"}, 0),
    ("R1b", {"a": "4532x0151", "b": "12830366"}, 0),
    ("R2a", {"a": "9945320151", "b": "12830366"}, 0),
    ("R2b", {"a": "94532", "b": "01511283", "c": "03669"}, 0),
    ("R4a", {"card": "45320151", "x": "note", "card2": "12830366"}, 0),
    ("R10a", dict(zip(_R10_KEYS, _R10A_DIGITS)), 0),
    ("R10b", dict(zip(_R10_KEYS, ["v" + d + "w" for d in _R10A_DIGITS])), 0),
    ("R10c", {"a": "453", "b": "201", "c": "511", "d": "283", "e": "036", "f": "6"}, 0),
    ("R10d", {"a": 45320151.0, "b": "12830366"}, 0),
    ("R8i_float", json.loads('{"ts":1920307113.905478}'), 0),
]


@pytest.mark.parametrize("mod", _PAN_FILTER_MODULES, ids=_PAN_FILTER_MODULE_IDS)
@pytest.mark.parametrize("row_id,txn,expected", TXN_ROWS, ids=[r[0] for r in TXN_ROWS])
def test_txn_row(mod, row_id, txn, expected):
    clean, rejected, details = mod.filter_transactions([txn])
    assert rejected == expected, f"matrix row {row_id}: details={details}"
    assert len(clean) == 1 - expected


_HEX64 = re.compile(r"[0-9a-f]{64}")


@pytest.mark.parametrize("mod", _PAN_FILTER_MODULES, ids=_PAN_FILTER_MODULE_IDS)
def test_x01_detail_has_index_and_hex_txn_ref(mod):
    _, rejected, details = mod.filter_transactions([{"a": "x45320151", "b": "y12830366"}])
    assert rejected == 1
    assert details[0]["index"] == 0
    assert _HEX64.fullmatch(details[0]["txn_ref"])
    assert details[0]["rule"] == "X4"


@pytest.mark.parametrize("mod", _PAN_FILTER_MODULES, ids=_PAN_FILTER_MODULE_IDS)
def test_x20_float_candidate_rule_is_w1(mod):
    _, rejected, details = mod.filter_transactions([json.loads('{"amount":45320151.12830366}')])
    assert rejected == 1
    assert details[0]["rule"] == "W1"


@pytest.mark.parametrize("mod", _PAN_FILTER_MODULES, ids=_PAN_FILTER_MODULE_IDS)
def test_dataset_zero_rejections(mod):
    """No row of the committed demo dataset data/transactions_small.jsonl
    is rejected. The row count is not pinned (the dataset is kept small to fit
    the AgentCore inline-payload limit); it only needs to be non-trivial."""
    n = len(_DATASET_ROWS)
    assert n >= 200, n
    clean, rejected, details = mod.filter_transactions(list(_DATASET_ROWS))
    assert rejected == 0, details[:5]
    assert len(clean) == n


# ---------------------------------------------------------------------------
# N1 work-bound rows (N01-N03) and Step-2 equivalence
# ---------------------------------------------------------------------------
_G = " " * 16_372
_D = "2026-01-01"


@pytest.mark.parametrize("mod", _PAN_FILTER_MODULES, ids=_PAN_FILTER_MODULE_IDS)
def test_n01_dead_chain_flags_quickly(mod):
    text = "".join(_D + _G for _ in range(64)) + " 9"
    assert len(text) == 1_048_450
    t0 = time.perf_counter()
    result = mod.contains_full_pan(text)
    elapsed = time.perf_counter() - t0
    assert result is True
    assert elapsed < 2.0, f"N01 took {elapsed:.2f}s"


@pytest.mark.parametrize("mod", _PAN_FILTER_MODULES, ids=_PAN_FILTER_MODULE_IDS)
def test_n02_alive_chain_accepted_quickly(mod):
    text = "".join(_D + _G for _ in range(64))
    t0 = time.perf_counter()
    result = mod.contains_full_pan(text)
    elapsed = time.perf_counter() - t0
    assert result is False
    assert elapsed < 2.0, f"N02 took {elapsed:.2f}s"


@pytest.mark.parametrize("mod", _PAN_FILTER_MODULES, ids=_PAN_FILTER_MODULE_IDS)
def test_n03_z_carry(mod):
    text = "9 2026-01-01T00:00:00Z a 2026-01-02T00:00:00"
    second = text.index("2026-01-02")
    assert mod._n1_exempt_spans(text) == [(second, len(text))]


def _reference_fixed_point(mod, text):
    """N1 Step 2 as written: the iterated greatest fixed point."""
    matches = mod._n1_valid_matches(text)
    if len(matches) > 64:
        return []
    cls = mod._leaf_classes(text)
    alive = [True] * len(matches)
    n = len(text)

    def side_safe(i, step):
        start, end = matches[i]
        pos = start - 1 if step < 0 else end
        letters = 0
        while 0 <= pos < n:
            for j, (s, e) in enumerate(matches):
                if j != i and alive[j] and ((step < 0 and pos == e - 1) or (step > 0 and pos == s)):
                    return True
            c = cls[pos]
            if c == "D":
                return False
            if c == "L":
                letters += 1
                if letters == 2:
                    return True
            pos += step
        return True

    changed = True
    while changed:
        changed = False
        for i in range(len(matches)):
            if alive[i] and not (side_safe(i, -1) and side_safe(i, 1)):
                alive[i] = False
                changed = True
    return [span for span, a in zip(matches, alive) if a]


def _random_leaf(rng):
    gaps = [" ", "  ", "a", "q", "ab", "qr", "5", "*", "x"]
    parts = []
    if rng.random() < 0.5:
        parts.append(rng.choice(["9", "12", "a", "ab", "q "]))
    for k in range(rng.randint(1, 6)):
        if k:
            parts.append(rng.choice(gaps))
        dt = "2026-%02d-%02dT%02d:%02d:%02d" % (
            rng.randint(1, 12), rng.randint(1, 28), rng.randint(0, 23),
            rng.randint(0, 59), rng.randint(0, 59))
        if rng.random() < 0.5:
            dt += "Z"
        parts.append(dt)
    if rng.random() < 0.5:
        parts.append(rng.choice(["9", "34", "a", "ab", " q"]))
    return "".join(parts)


@pytest.mark.parametrize("mod", _PAN_FILTER_MODULES, ids=_PAN_FILTER_MODULE_IDS)
def test_n1_linear_matches_fixed_point(mod):
    rng = random.Random(20261021)
    for _ in range(2000):
        leaf = _random_leaf(rng)
        assert mod._n1_exempt_spans(leaf) == _reference_fixed_point(mod, leaf), repr(leaf)
