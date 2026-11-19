#!/usr/bin/env python3
"""
Seeded false-positive harness for the PAN filter.

Measures the REAL canonical module ``lambdas.pan_filter.pan_filter`` (the
other two copies are byte-identical), not a model of it. One
generator per measured class, each keyed by a fixed seed. Tags in the row
descriptions: R5 = datetime-capacity residual (a PAN hidden inside N1-exempt
datetime digits), R8 = known false-positive class with a non-zero target,
R9 = masked card next to a short number in the same leaf.

- 401-430  group-1 leaf and transaction classes, in table order
- 431-437  R5 capacity, PAN lengths 13-19 (2,000 PANs each)
- 501-519  group-2 datetime classes
- 601-611  group-3 float-candidate classes
- 621-633  group-3 richer-schema shapes (633 = data/transactions_small.jsonl)

Leaf classes call ``contains_full_pan(str)``. Transaction shapes call
``filter_transactions([txn])`` and split rejections into W1 / X4 by the
detail's ``rule``. Float leaves are emitted as Python floats inside the
transaction dict.

Usage:
    python scripts/measure_pan_filter_fp.py                 # full run
    python scripts/measure_pan_filter_fp.py --class 513     # one row (seed or id)
    python scripts/measure_pan_filter_fp.py --n 2000        # override sample size

This is a measurement tool: it always exits 0, and a row outside tolerance
is reported in the "Within tol" column, never tuned away. It lives in
scripts/, so pytest never collects it (testpaths = tests).

Standard library only, plus the canonical module.
"""
import argparse
import datetime
import hashlib
import json
import os
import random
import sys
import time
import uuid

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

# Local measurement only: lets the module use its built-in dev HMAC key for
# txn_ref outside a deployed runtime. This is never set in a deployed runtime,
# and the key does not affect any detection decision.
os.environ.setdefault("ALLOW_LOCAL_DEV_TXN_REF_KEY", "true")

from lambdas.pan_filter import pan_filter as pf  # noqa: E402

DATASET_PATH = os.path.join(_REPO_ROOT, "data", "transactions_small.jsonl")
TOLERANCE = 1.5  # percentage points

# ---------------------------------------------------------------------------
# Value helpers
# ---------------------------------------------------------------------------

_WEEKDAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_CATEGORIES = ("entertainment", "invoice_payment", "crypto_exchange",
               "utilities", "wire_transfer", "food", "retail",
               "consulting_fee", "travel")
_ISO8583_DE3 = ("000000", "200000", "010000", "310000")

# Group-1 rows: random 2024-2026 datetimes. Group-2 rows: uniform over
# 2024-01-01 .. 2033-01-01 with uniform microseconds.
_R1_LO = datetime.datetime(2024, 1, 1)
_R1_HI = datetime.datetime(2027, 1, 1)
_R2_LO = datetime.datetime(2024, 1, 1)
_R2_HI = datetime.datetime(2033, 1, 1)
_UTC = datetime.timezone.utc


def _epoch(y, m, d):
    return int(datetime.datetime(y, m, d, tzinfo=_UTC).timestamp())


_EPOCH_2001 = _epoch(2001, 1, 1)
_EPOCH_2033 = _epoch(2033, 1, 1)
_EPOCH_2033_05_18 = 2_000_000_000  # 2033-05-18T03:33:20Z
_EPOCH_2100 = _epoch(2100, 1, 1)


def _digits(rng, n):
    return "".join(rng.choice("0123456789") for _ in range(n))


def _hex(rng, n):
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


def _dt(rng, lo, hi):
    span = int((hi - lo).total_seconds())
    return lo + datetime.timedelta(seconds=rng.randrange(span),
                                   microseconds=rng.randrange(1_000_000))


def _date(dt):
    return dt.strftime("%Y-%m-%d")


def _time(dt):
    return dt.strftime("%H:%M:%S")


def _iso_us(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")


def _offset(rng, colon):
    hh = rng.randint(0, 14)
    mm = rng.choice((0, 30, 45))
    sign = rng.choice("+-")
    return f"{sign}{hh:02d}:{mm:02d}" if colon else f"{sign}{hh:02d}{mm:02d}"


def _amount(rng):
    """Harness default: round(uniform(1, 5000), 2) as a JSON float."""
    return round(rng.uniform(1, 5000), 2)


def _luhn_ok(number):
    total = 0
    for i, ch in enumerate(reversed(number)):
        v = ord(ch) - 48
        if i % 2 == 1:
            v *= 2
            if v > 9:
                v -= 9
        total += v
    return total % 10 == 0


def _payment_mii(s):
    return s[0] in "23456" or s[:2] in ("81", "82")


def _is_payment_pan(s):
    return 13 <= len(s) <= 19 and s.isdigit() and _payment_mii(s) and _luhn_ok(s)


def _rand_pan(rng, length):
    """Uniformly random payment PAN (MII 2-6, 81, 82; Luhn-valid)."""
    while True:
        body = _digits(rng, length - 1)
        if _payment_mii(body):
            break
    for check in "0123456789":
        if _luhn_ok(body + check):
            return body + check
    raise AssertionError("unreachable")


def _masked(rng):
    pan = _rand_pan(rng, 16)
    return pan[:6] + "******" + pan[-4:]


def _uuid4(rng):
    return str(uuid.UUID(int=rng.getrandbits(128), version=4))


def _repo_txn(rng):
    """Synthetic transaction in the data/transactions_small.jsonl schema."""
    return {
        "txn_id": "txn-" + _hex(rng, 8),
        "timestamp": _iso_us(_dt(rng, _R1_LO, _R1_HI)),
        "sender_id": "acc-" + _hex(rng, 8),
        "receiver_id": "acc-" + _hex(rng, 8),
        "amount": _amount(rng),
        "merchant_category": rng.choice(_CATEGORIES),
        "is_fraud": rng.random() < 0.035,
    }


# ---------------------------------------------------------------------------
# Generators. Leaf generators return str; txn generators return a dict.
# ---------------------------------------------------------------------------

def g_uuid4(rng):
    return _uuid4(rng)


def g_hex32(rng):
    return "%032x" % rng.getrandbits(128)


def g_sha256(rng):
    # Seed 514: SHA-256 hex of 8 random bytes.
    return hashlib.sha256(rng.randbytes(8)).hexdigest()


def g_masked_alone(rng):
    return _masked(rng)


def g_masked_mmyy(rng):
    return f"{_masked(rng)} {rng.randint(1, 12):02d}/{rng.randint(25, 34):02d}"


def g_masked_amount(rng):
    return f"{_masked(rng)} ${rng.uniform(1, 9999):.2f}"


def g_epoch_us(rng):
    return {"ts": rng.randrange(_EPOCH_2001 * 10**6, _EPOCH_2033 * 10**6)}


def g_epoch_ms_before(rng):
    return {"ts": rng.randrange(_EPOCH_2001 * 1000, _EPOCH_2033_05_18 * 1000)}


def g_epoch_ms_after(rng):
    return {"ts": rng.randrange(_EPOCH_2033_05_18 * 1000, _EPOCH_2100 * 1000)}


def g_float_epoch_r1(rng):
    # Python time.time()-style float epoch, 2001-2033, as a JSON number.
    return {"ts": rng.uniform(_EPOCH_2001, _EPOCH_2033)}


def g_phone_ext(rng):
    return f"+1 {_digits(rng, 3)} {_digits(rng, 3)} {_digits(rng, 4)} x{_digits(rng, 4)}"


def g_e164_13(rng):
    return "+" + rng.choice("123456789") + _digits(rng, 12)


def g_iso_utc(rng):
    return _iso_us(_dt(rng, _R1_LO, _R1_HI)) + " UTC"


def g_iso_zone_id(rng):
    return _iso_us(_dt(rng, _R1_LO, _R1_HI)) + "+02:00[Europe/Paris]"


def g_processed_at(rng):
    return "processed at " + _iso_us(_dt(rng, _R1_LO, _R1_HI))


def g_log_line(rng):
    dt = _dt(rng, _R1_LO, _R1_HI)
    return f"{_date(dt)} {_time(dt)},{dt.microsecond // 1000:03d} INFO ok"


def g_ts_ms_z(rng):
    dt = _dt(rng, _R1_LO, _R1_HI)
    return f"ts={_date(dt)}T{_time(dt)}.{dt.microsecond // 1000:03d}Z"


def g_ns_z(rng):
    dt = _dt(rng, _R1_LO, _R1_HI)
    return f"{_date(dt)}T{_time(dt)}.{_digits(rng, 9)}Z"


def g_date_list(rng):
    return f"{_date(_dt(rng, _R1_LO, _R1_HI))},{_date(_dt(rng, _R1_LO, _R1_HI))}"


def g_interval(rng):
    return f"{_iso_us(_dt(rng, _R1_LO, _R1_HI))}/{_iso_us(_dt(rng, _R1_LO, _R1_HI))}"


def g_amount_on_iso(rng):
    return f"${rng.uniform(1, 999):.2f} on {_iso_us(_dt(rng, _R1_LO, _R1_HI))}"


def g_iso_seq(rng):
    return f"{_iso_us(_dt(rng, _R1_LO, _R1_HI))} seq {rng.randint(1000, 9999)}"


def g_iso_csv(rng):
    return f"{_iso_us(_dt(rng, _R1_LO, _R1_HI))},{rng.uniform(1, 999):.2f}"


def g_log_tid(rng):
    dt = _dt(rng, _R1_LO, _R1_HI)
    return (f"{_date(dt)} {_time(dt)},{dt.microsecond // 1000:03d} "
            f"[{rng.randint(1, 9)}] INFO ok")


def g_iso_v_tag(rng):
    return f"{_iso_us(_dt(rng, _R1_LO, _R1_HI))} v{rng.randint(1, 9)}"


def g_us_phone_pair(rng):
    def ph():
        return f"{_digits(rng, 3)}-{_digits(rng, 3)}-{_digits(rng, 4)}"
    return {"phone": ph(), "alt_phone": ph()}


def g_acc_pair(rng):
    return {"sender_id": "acc-" + _digits(rng, 8),
            "receiver_id": "acc-" + _digits(rng, 8)}


def g_same_schema(rng):
    return _repo_txn(rng)


def g_iso_whole(rng):
    return _iso_us(_dt(rng, _R1_LO, _R1_HI))


def g_masked_separate(rng):
    return {"card": _masked(rng), "amount": _amount(rng), "ref": _hex(rng, 8)}


# Group 2 (seeds 501-519)

def _r2(rng):
    return _dt(rng, _R2_LO, _R2_HI)


def g_501(rng):
    dt = _r2(rng)
    return f"{_date(dt)} {_time(dt)}.{dt.microsecond:06d} {_offset(rng, True)}"


def _go_string(rng):
    dt = _r2(rng)
    return f"{_date(dt)} {_time(dt)}.{_digits(rng, 9)} {_offset(rng, False)} UTC"


def _mono(rng):
    return f"m=+{rng.uniform(0, 100000):.9f}"


def g_502(rng):
    return _go_string(rng)


def g_503(rng):
    return f"{_go_string(rng)} {_mono(rng)}"


def g_504(rng):
    dt = _r2(rng)
    return f"{_date(dt)}T{_time(dt)}.{dt.microsecond:06d} Z"


def g_505(rng):
    dt = _r2(rng)
    return f"{_date(dt)} {_time(dt)} {_offset(rng, False)}"


def g_518(rng):
    dt = _r2(rng)
    return f"{_date(dt)} {_time(dt)}.{dt.microsecond:06d}  {_offset(rng, True)}"


def g_519(rng):
    dt = _r2(rng)
    return f"{_date(dt)} {_time(dt)}.{dt.microsecond:06d}\t{_offset(rng, True)}"


def g_506(rng):
    dt = _r2(rng)
    return f"{_date(dt)}T{_time(dt)}.{_digits(rng, 10)}Z"


def g_507(rng):
    dt = _r2(rng)
    return f"{_date(dt)}T{_time(dt)}.{_digits(rng, 12)}Z"


def g_508(rng):
    dt = _r2(rng)
    return (f"{_WEEKDAYS[dt.weekday()]}, {dt.day:02d} {_MONTHS[dt.month - 1]} "
            f"{dt.year} {_time(dt)} {_offset(rng, False)}")


def g_509(rng):
    dt = _r2(rng)
    return (f"[{dt.day:02d}/{_MONTHS[dt.month - 1]}/{dt.year}:{_time(dt)} "
            f"{_offset(rng, False)}]")


def g_515(rng):
    dt = _r2(rng)
    return (f"{_WEEKDAYS[dt.weekday()]}, {dt.day:02d} {_MONTHS[dt.month - 1]} "
            f"{dt.year} {_time(dt)} GMT")


def g_516(rng):
    return _mono(rng)


def g_517(rng):
    lo = int(_R2_LO.replace(tzinfo=_UTC).timestamp())
    hi = int(_R2_HI.replace(tzinfo=_UTC).timestamp())
    return f"{rng.randrange(lo, hi)}.{_digits(rng, 6)}"


def g_510(rng):
    return _iso_us(_r2(rng))


def g_511(rng):
    return _iso_us(_r2(rng)) + " UTC"


def g_512(rng):
    dt = _r2(rng)
    return f"{_date(dt)}T{_time(dt)}.{_digits(rng, 9)}Z"


# Group 3 float candidates (seeds 601-611). One float leaf per txn.

def _fv(v):
    return {"value": v}


def g_601(rng):
    return _fv(rng.uniform(_EPOCH_2001, _EPOCH_2033))


def g_602(rng):
    return _fv(rng.uniform(_EPOCH_2033_05_18, _EPOCH_2100))


def g_603(rng):
    return _fv(sum(_amount(rng) for _ in range(10)))


def g_604(rng):
    return _fv(sum(_amount(rng) for _ in range(3)))


def g_605(rng):
    return _fv(_amount(rng))


def g_606(rng):
    return _fv(rng.random())


def g_607(rng):
    return _fv(rng.random() * 100)


def g_608(rng):
    return _fv(rng.random() * 1e-5)


def g_609(rng):
    return _fv(rng.uniform(-90, 90))


def g_610(rng):
    return _fv(round(rng.uniform(-90, 90), 6))


def g_611(rng):
    return _fv(sum(_amount(rng) for _ in range(7)) / 7)


# Group 3 richer-schema shapes (seeds 621-632), harness defaults.

def g_621(rng):
    return {
        "amount": _amount(rng),
        "currency": "840",
        "mcc": _digits(rng, 4),
        "pos_entry_mode": "051",
        "terminal_id": _digits(rng, 8),
        "stan": _digits(rng, 6),
        "auth_code": _digits(rng, 6),
        "response_code": "00",
        "zip": _digits(rng, 5),
    }


def _line_items(rng, k):
    return {"items": [{"sku": _digits(rng, 5),
                       "qty": rng.randint(1, 99),
                       "price": _amount(rng)} for _ in range(k)]}


def g_622(rng):
    return _line_items(rng, 3)


def g_623(rng):
    return _line_items(rng, 10)


def g_624(rng):
    return {
        "txn_count_24h": rng.randint(1, 99),
        "amount_24h": _amount(rng),
        "txn_count_7d": rng.randint(1, 999),
        "amount_7d": _amount(rng),
        "distinct_merchants": rng.randint(1, 99),
    }


def g_625(rng):
    minor = int(round(_amount(rng) * 100))
    return {
        "de3": rng.choice(_ISO8583_DE3),
        "de4": f"{minor:012d}",
        "de11": _digits(rng, 6),
        "de12": _digits(rng, 6),
        "de41": "TERM0001",
        "de49": "840",
    }


def g_626(rng):
    return {
        "txn_id": _digits(rng, 8),
        "amount": _amount(rng),
        "lat": round(rng.uniform(-90, 90), 6),
        "lon": round(rng.uniform(-180, 180), 6),
        "zip": _digits(rng, 5),
    }


def g_627(rng):
    return {"features": [rng.randint(0, 999) for _ in range(10)]}


def g_628(rng):
    while True:
        ds = [rng.randint(0, 9) for _ in range(16)]
        if not _is_payment_pan("".join(map(str, ds))):
            break
    return {f"k{i}": d for i, d in enumerate(ds)}


def g_629(rng):
    txn = _repo_txn(rng)
    txn["device_id"] = _uuid4(rng)
    txn["phone"] = f"+1 {_digits(rng, 3)}-{_digits(rng, 3)}-{_digits(rng, 4)}"
    return txn


def g_630(rng):
    return {"phone": f"+44 20 {_digits(rng, 4)} {_digits(rng, 4)}",
            "amount": _amount(rng)}


def g_631(rng):
    return {"sort_code": f"{_digits(rng, 2)}-{_digits(rng, 2)}-{_digits(rng, 2)}",
            "account_number": _digits(rng, 8)}


def g_632(rng):
    return {"routing_number": _digits(rng, 9),
            "account_number": _digits(rng, 10)}


# ---------------------------------------------------------------------------
# R5 capacity: share of random payment PANs that are a contiguous
# substring of the digit stream of N1-valid datetimes, with free padding.
# Day validity approximated as 01-31 (upper bound). This is a property of the
# N1 grammar, computed with an automaton over the datetime digit
# template, not a module call.
# ---------------------------------------------------------------------------

def _field(lo, hi, width=2):
    full = frozenset(f"{v:0{width}d}" for v in range(lo, hi + 1))
    pre = frozenset(s[:k] for s in full for k in range(width))
    return full, pre


_F_YEAR = _field(1900, 2199, 4)
_F_MON = _field(1, 12)
_F_DAY = _field(1, 31)
_F_HOUR = _field(0, 23)
_F_MIN = _field(0, 59)
_F_SEC = _field(0, 60)
_F_FRAC = _field(0, 9, 1)
_F_OFFH = _field(0, 14)
_F_OFFM = (frozenset({"00", "30", "45"}), frozenset({"", "0", "3", "4"}))


def _r5_nodes(max_frac):
    """Node -> (field, successors, may_end). Successors are node names."""
    nodes = {
        "Y": (_F_YEAR, ("M",), False),
        "M": (_F_MON, ("D",), False),
        "D": (_F_DAY, ("h",), True),
        "h": (_F_HOUR, ("m",), False),
        "m": (_F_MIN, ("s", "OH"), True),
        "s": (_F_SEC, (("F1",) if max_frac else ()) + ("OH",), True),
        "OH": (_F_OFFH, ("OM",), False),
        "OM": (_F_OFFM, (), True),
    }
    for k in range(1, max_frac + 1):
        nxt = ((f"F{k + 1}",) if k < max_frac else ()) + ("OH",)
        nodes[f"F{k}"] = (_F_FRAC, nxt, True)
    return nodes


class _R5Automaton:
    _END = ("END",)

    def __init__(self, max_frac, max_chain):
        self.nodes = _r5_nodes(max_frac)
        self.max_chain = max_chain
        self.memo = {}
        start = set()
        for name, ((_full, pre), _succ, _end) in self.nodes.items():
            for p in pre:
                start.add((name, p, 1))
        self.start = frozenset(start)

    def _step(self, state, digit):
        key = (state, digit)
        out = self.memo.get(key)
        if out is not None:
            return out
        res = set()
        if state is not self._END:
            name, p, c = state
            (full, pre), succ, _ = self.nodes[name]
            p2 = p + digit
            if p2 in pre:
                res.add((name, p2, c))
            elif p2 in full:
                for nxt in succ:
                    res.add((nxt, "", c))
                if self.nodes[name][2]:
                    res.add(self._END)
                    if c < self.max_chain:
                        res.add(("Y", "", c + 1))
        out = frozenset(res)
        self.memo[key] = out
        return out

    def contains(self, digits):
        states = self.start
        for d in digits:
            nxt = set()
            for st in states:
                nxt |= self._step(st, d)
            if not nxt:
                return False
            states = nxt
        return True


_R5_CONFIGS = (
    ("1 dt, <=6 frac (earlier rule)", 6, 1),
    ("1 dt, <=9 frac", 9, 1),
    ("chain <=4, <=9 frac (chosen)", 9, 4),
)


def measure_r5(length, n, seed):
    rng = random.Random(seed)  # nosec B311 -- seeded random.Random(seed) for reproducible measurement data; SystemRandom would break reproducibility
    pans = [_rand_pan(rng, length) for _ in range(n)]
    out = []
    for _label, max_frac, max_chain in _R5_CONFIGS:
        auto = _R5Automaton(max_frac, max_chain)
        out.append(100.0 * sum(auto.contains(p) for p in pans) / n)
    return out


# ---------------------------------------------------------------------------
# Row registry: (seed, class_id, description, kind, generator, n, target)
# target = (mode, value): 'pm' = within ±TOLERANCE, 'le' = <= value + TOLERANCE,
# 'exact' = exactly value.
# ---------------------------------------------------------------------------

N_CLASS = 20_000
N_PAIR = 5_000   # paired fields and R9
N_RICH = 2_000   # richer-schema shapes 621-632
N_R5 = 2_000     # PANs per length (R5)

ROWS = [
    # Group 1 (seeds 401-430, table order).
    (401, "uuid4", "UUIDv4", "leaf", g_uuid4, N_CLASS, ("pm", 2.4)),
    (402, "hex32", "32-hex", "leaf", g_hex32, N_CLASS, ("pm", 1.9)),
    (403, "sha256", "SHA-256 hex of 8 random bytes", "leaf", g_sha256, N_CLASS, ("pm", 5.4)),
    (404, "masked-alone", "Masked BIN-6 + last-4 alone", "leaf", g_masked_alone, N_CLASS, ("pm", 0.0)),
    (405, "masked-mmyy", "Masked + ` MM/YY`, same leaf (R9)", "leaf", g_masked_mmyy, N_PAIR, ("pm", 24.0)),
    (406, "masked-amount", "Masked + ` $d.dd` ($1-$9,999), same leaf (R9)", "leaf", g_masked_amount, N_PAIR, ("pm", 52.1)),
    (407, "epoch-us", "Epoch µs integer, 2001-2033 (R8)", "txn", g_epoch_us, N_CLASS, ("pm", 26.3)),
    (408, "epoch-ms-before", "Epoch ms integer before 2033-05-18", "txn", g_epoch_ms_before, N_CLASS, ("pm", 0.0)),
    (409, "epoch-ms-after", "Epoch ms integer 2033-05-18..2100 (R8)", "txn", g_epoch_ms_after, N_CLASS, ("pm", 10.1)),
    (410, "float-epoch", "Python float epoch 2001-2033 as a JSON number", "txn", g_float_epoch_r1, N_CLASS, ("pm", 0.0)),
    (411, "phone-ext", "`+1 NNN NNN NNNN xNNNN` (R8)", "leaf", g_phone_ext, N_CLASS, ("pm", 16.3)),
    (412, "e164-13", "E.164 with 13 digits", "leaf", g_e164_13, N_CLASS, ("pm", 4.9)),
    (413, "iso-utc", "`<iso> UTC`", "leaf", g_iso_utc, N_CLASS, ("pm", 0.0)),
    (414, "iso-zone-id", "`<iso>+02:00[Europe/Paris]`", "leaf", g_iso_zone_id, N_CLASS, ("pm", 0.0)),
    (415, "processed-at", "`processed at <iso>`", "leaf", g_processed_at, N_CLASS, ("pm", 0.0)),
    (416, "log-line", "`<date> <time>,mmm INFO ok`", "leaf", g_log_line, N_CLASS, ("pm", 0.0)),
    (417, "ts-ms-z", "`ts=<iso-ms>Z`", "leaf", g_ts_ms_z, N_CLASS, ("pm", 0.0)),
    (418, "ns-z", "RFC 3339 nanosecond `….nnnnnnnnnZ`", "leaf", g_ns_z, N_CLASS, ("pm", 0.0)),
    (419, "date-list", "Date list `<date>,<date>`", "leaf", g_date_list, N_CLASS, ("pm", 0.0)),
    (420, "interval", "Interval `<iso>/<iso>`", "leaf", g_interval, N_CLASS, ("pm", 0.0)),
    (421, "amount-on-iso", "`$d.dd on <iso>`", "leaf", g_amount_on_iso, N_CLASS, ("pm", 0.0)),
    (422, "iso-seq", "`<iso> seq NNNN`", "leaf", g_iso_seq, N_CLASS, ("pm", 0.0)),
    (423, "iso-csv", "`<iso>,d.dd` (CSV in one string, R8)", "leaf", g_iso_csv, N_CLASS, ("pm", 99.0)),
    (424, "log-tid", "`… ,mmm [N] INFO ok` (R8)", "leaf", g_log_tid, N_CLASS, ("pm", 78.2)),  # was 86
    (425, "iso-v-tag", "`<iso> vN` (R8)", "leaf", g_iso_v_tag, N_CLASS, ("pm", 91.0)),
    (426, "us-phone-pair", "Adjacent US-phone field pair", "txn", g_us_phone_pair, N_PAIR, ("pm", 0.0)),
    (427, "acc8-pair", "Adjacent 8-digit `acc-` id pair (R8)", "txn", g_acc_pair, N_PAIR, ("pm", 5.0)),
    (428, "same-schema", "Same schema, synthetic (earlier figure)", "txn", g_same_schema, N_CLASS, ("pm", 1.07)),
    (429, "iso-us-whole", "Whole-leaf ISO µs", "leaf", g_iso_whole, N_CLASS, ("pm", 0.0)),
    (430, "masked-separate", "Masked card next to amount / hex id, separate fields", "txn", g_masked_separate, N_CLASS, ("pm", 0.0)),
    # R5 capacity (seeds 431-437, lengths 13-19), chosen column.
    (431, "r5-13", "R5 capacity, 13-digit PANs (chosen column)", "r5", 13, N_R5, ("pm", 77.2)),
    (432, "r5-14", "R5 capacity, 14-digit PANs (chosen column)", "r5", 14, N_R5, ("pm", 57.7)),  # was 55.2
    (433, "r5-15", "R5 capacity, 15-digit PANs (chosen column)", "r5", 15, N_R5, ("pm", 33.1)),  # was 35.2
    (434, "r5-16", "R5 capacity, 16-digit PANs (chosen column)", "r5", 16, N_R5, ("pm", 25.3)),  # was 22.8
    (435, "r5-17", "R5 capacity, 17-digit PANs (chosen column)", "r5", 17, N_R5, ("pm", 12.9)),
    (436, "r5-18", "R5 capacity, 18-digit PANs (chosen column)", "r5", 18, N_R5, ("pm", 7.5)),
    (437, "r5-19", "R5 capacity, 19-digit PANs (chosen column)", "r5", 19, N_R5, ("pm", 4.2)),
    # Group 2 (seeds 501-519).
    (501, "r2-space-colon-offset", "`<date> <time>.ffffff ±HH:MM`", "leaf", g_501, N_CLASS, ("pm", 0.0)),
    (502, "r2-go-string", "Go `String()` `….fffffffff ±HHMM UTC`", "leaf", g_502, N_CLASS, ("pm", 0.0)),
    (503, "r2-go-monotonic", "Go `String()` + ` m=+N.NNNNNNNNN` (R8)", "leaf", g_503, N_CLASS, ("pm", 15.0)),
    (504, "r2-space-z", "`<iso>.ffffff Z`", "leaf", g_504, N_CLASS, ("pm", 0.0)),
    (505, "r2-space-no-frac", "`<date> <time> ±HHMM`", "leaf", g_505, N_CLASS, ("pm", 0.0)),
    (506, "r2-frac10", "10 fraction digits + `Z` (R8)", "leaf", g_506, N_CLASS, ("pm", 95.6)),
    (507, "r2-frac12", "12 fraction digits + `Z` (R8)", "leaf", g_507, N_CLASS, ("pm", 97.7)),
    (508, "r2-rfc2822", "RFC 2822 with numeric offset (R8)", "leaf", g_508, N_CLASS, ("pm", 19.1)),
    (509, "r2-clf", "Apache CLF `[dd/Mon/YYYY:HH:MM:SS ±HHMM]` (R8)", "leaf", g_509, N_CLASS, ("pm", 18.9)),
    (510, "r2-iso-us", "Regression: whole-leaf ISO µs", "leaf", g_510, N_CLASS, ("pm", 0.0)),
    (511, "r2-iso-utc", "Regression: `<iso> UTC`", "leaf", g_511, N_CLASS, ("pm", 0.0)),
    (512, "r2-ns-z", "Regression: `….nnnnnnnnnZ`", "leaf", g_512, N_CLASS, ("pm", 0.0)),
    (513, "r2-uuid4", "Regression: UUIDv4", "leaf", g_uuid4, N_CLASS, ("pm", 2.4)),
    (514, "r2-sha256", "Regression: SHA-256 hex of 8 random bytes", "leaf", g_sha256, N_CLASS, ("pm", 5.4)),
    (515, "r2-http-date", "HTTP-date `…, dd Mon YYYY HH:MM:SS GMT`", "leaf", g_515, N_CLASS, ("pm", 0.0)),
    (516, "r2-monotonic", "`m=+N.NNNNNNNNN` alone (R8)", "leaf", g_516, N_CLASS, ("pm", 14.8)),
    (517, "r2-string-epoch", "String epoch `\"NNNNNNNNNN.ffffff\"` (R8)", "leaf", g_517, N_CLASS, ("pm", 17.3)),
    (518, "r2-two-spaces", "`….ffffff  ±HH:MM` (two spaces)", "leaf", g_518, N_CLASS, ("pm", 0.0)),
    (519, "r2-tab", "`….ffffff\\t±HH:MM` (tab)", "leaf", g_519, N_CLASS, ("pm", 0.0)),
    # Group 3 float candidates (seeds 601-611), one float per txn.
    (601, "f-epoch-2001-2033", "Float epoch 2001-2033", "txn", g_601, N_CLASS, ("pm", 0.0)),
    (602, "f-epoch-2033-2100", "Float epoch 2033-05-18..2100 (R8)", "txn", g_602, N_CLASS, ("pm", 10.1)),
    (603, "f-sum10", "Sum of 10 cent amounts (R8)", "txn", g_603, N_CLASS, ("pm", 0.6)),
    (604, "f-sum3", "Sum of 3 cent amounts (R8)", "txn", g_604, N_CLASS, ("pm", 0.7)),
    (605, "f-amount", "Single 2-dp amount", "txn", g_605, N_CLASS, ("pm", 0.0)),
    # Targets for 606-609 and 611 are the
    # full leaf rule (part-by-part W1 + int||frac candidate), not the
    # candidate alone. Previous candidate-only targets in trailing comments.
    (606, "f-random", "`random()` (R8)", "txn", g_606, N_CLASS, ("pm", 44.2)),  # was 0
    (607, "f-random-x100", "`random()*100` (R8)", "txn", g_607, N_CLASS, ("pm", 23.2)),  # was 5.9
    (608, "f-random-1e-5", "`random()*1e-5` (R8)", "txn", g_608, N_CLASS, ("pm", 58.4)),  # was 5.8
    (609, "f-lat-full", "Full-precision latitude (R8)", "txn", g_609, N_CLASS, ("pm", 24.3)),  # was 6.1
    (610, "f-lat-6dp", "6-dp latitude", "txn", g_610, N_CLASS, ("pm", 0.0)),
    (611, "f-mean7", "Mean of 7 amounts (R8)", "txn", g_611, N_CLASS, ("pm", 10.3)),  # was 7.2
    # Group 3 richer-schema shapes (seeds 621-633).
    (621, "card-auth", "Card-auth message (R8)", "txn", g_621, N_RICH, ("pm", 6.3)),
    (622, "order-3", "Order, 3 line items", "txn", g_622, N_RICH, ("pm", 0.0)),
    (623, "order-10", "Order, 10 line items", "txn", g_623, N_RICH, ("pm", 0.0)),
    (624, "velocity", "Velocity features", "txn", g_624, N_RICH, ("pm", 0.0)),
    (625, "iso8583", "ISO 8583 data elements", "txn", g_625, N_RICH, ("pm", 0.0)),
    (626, "geo", "`{txn_id, amount, lat, lon, zip}`", "txn", g_626, N_RICH, ("pm", 0.0)),
    (627, "features", "`{\"features\": [10 ints 0-999]}` (exact)", "txn", g_627, N_RICH, ("exact", 0.0)),
    (628, "k0-k15", "`k0…k15`, one digit each, not a PAN (exact)", "txn", g_628, N_RICH, ("exact", 0.0)),
    (629, "repo-uuid-phone", "Repo schema + `device_id` UUIDv4 + US phone", "txn", g_629, N_RICH, ("le", 7.4)),
    (630, "uk-phone-amount", "UK phone `+44 20 NNNN NNNN` + amount", "txn", g_630, N_RICH, ("le", 9.9)),
    (631, "sort-code-account", "UK sort code + 8-digit account (R8)", "txn", g_631, N_RICH, ("pm", 5.9)),
    (632, "ach", "ACH routing 9 + account 10 (R8)", "txn", g_632, N_RICH, ("pm", 4.6)),
    (633, "dataset", "`data/transactions_small.jsonl` (exact)", "dataset", None, 518, ("exact", 0.0)),
]


# ---------------------------------------------------------------------------
# Measurement
# ---------------------------------------------------------------------------

def _load_dataset():
    with open(DATASET_PATH, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _count_rules(details):
    w1 = sum(1 for d in details if d["rule"] == "W1")
    x4 = sum(1 for d in details if d["rule"] == "X4")
    return w1, x4


def measure_row(row, n_override=None):
    """Return a result dict for one registry row."""
    seed, class_id, desc, kind, gen, n_default, target = row
    n = n_override if (n_override and kind != "dataset") else n_default
    res = {"seed": seed, "class_id": class_id, "desc": desc, "n": n,
           "target": target, "w1": None, "x4": None, "extra": None}
    if kind == "dataset":
        txns = _load_dataset()
        _clean, rejected, details = pf.filter_transactions(txns)
        res["n"] = len(txns)
        res["hits"] = rejected
        res["w1"], res["x4"] = _count_rules(details)
    elif kind == "r5":
        cols = measure_r5(gen, n, seed)
        res["pct"] = cols[-1]
        res["extra"] = cols
        return _judge(res)
    elif kind == "leaf":
        rng = random.Random(seed)  # nosec B311 -- seeded random.Random(seed) for reproducible measurement data; SystemRandom would break reproducibility
        hits = 0
        for _ in range(n):
            if pf.contains_full_pan(gen(rng)):
                hits += 1
        res["hits"] = hits
        res["w1"], res["x4"] = hits, 0
    else:  # txn
        rng = random.Random(seed)  # nosec B311 -- seeded random.Random(seed) for reproducible measurement data; SystemRandom would break reproducibility
        hits = w1 = x4 = 0
        for _ in range(n):
            _clean, rejected, details = pf.filter_transactions([gen(rng)])
            if rejected:
                hits += 1
                a, b = _count_rules(details)
                w1 += a
                x4 += b
        res["hits"], res["w1"], res["x4"] = hits, w1, x4
    res["pct"] = 100.0 * res["hits"] / res["n"] if res["n"] else 0.0
    return _judge(res)


def _judge(res):
    mode, value = res["target"]
    pct = res["pct"]
    if mode == "exact":
        ok = res.get("hits", None) == 0 if value == 0.0 else abs(pct - value) < 1e-9
        res["target_str"] = f"exactly {value:g}%"
    elif mode == "le":
        ok = pct <= value + TOLERANCE
        res["target_str"] = f"≤ {value:g}%"
    else:
        ok = abs(pct - value) <= TOLERANCE
        res["target_str"] = f"{value:g}%"
    res["ok"] = ok
    return res


def _fmt_row(res):
    w1 = "—" if res["w1"] is None else str(res["w1"])
    x4 = "—" if res["x4"] is None else str(res["x4"])
    return (f"| {res['seed']} | {res['desc']} | {res['n']} | "
            f"{res['pct']:.2f} | {w1} | {x4} | {res['target_str']} | "
            f"{'yes' if res['ok'] else 'NO'} |")


def _select(rows, cls):
    out = [r for r in rows if str(r[0]) == cls or r[1] == cls]
    if not out:
        raise SystemExit(f"unknown --class {cls!r}; use a seed or a class id")
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--n", type=int, default=None,
                    help="override the sample size of every sampled row")
    ap.add_argument("--class", dest="cls", default=None,
                    help="run one row, by seed (e.g. 513) or class id (e.g. r2-uuid4)")
    args = ap.parse_args(argv)
    if args.n is not None and args.n <= 0:
        ap.error("--n must be positive")

    rows = _select(ROWS, args.cls) if args.cls else ROWS
    t0 = time.perf_counter()
    results = []
    print("| Seed | Class | n | Measured % | W1 | X4 | Target | Within tol |")
    print("|---|---|---|---|---|---|---|---|")
    for row in rows:
        res = measure_row(row, args.n)
        results.append(res)
        print(_fmt_row(res), flush=True)

    r5 = [r for r in results if r["extra"] is not None]
    if r5:
        print()
        print("R5 capacity detail (all three columns):")
        print()
        print("| Seed | PAN length | " + " | ".join(c[0] for c in _R5_CONFIGS) + " |")
        print("|---|---|" + "---|" * len(_R5_CONFIGS))
        for r in r5:
            length = int(r["class_id"].split("-")[1])
            cols = " | ".join(f"{v:.2f}" for v in r["extra"])
            print(f"| {r['seed']} | {length} | {cols} |")

    if args.cls is None:
        ds = next(r for r in results if r["seed"] == 633)
        print()
        print(f"dataset: {ds['hits']}/{ds['n']} (W1 {ds['w1']}, X4 {ds['x4']})")

    misses = [r for r in results if not r["ok"]]
    print()
    if misses:
        print("Outside tolerance: " + ", ".join(
            f"{r['seed']} ({r['pct']:.2f}% vs {r['target_str']})" for r in misses))
    else:
        print("Outside tolerance: none")
    print(f"elapsed: {time.perf_counter() - t0:.1f} s")
    return 0


if __name__ == "__main__":
    main()
    sys.exit(0)
