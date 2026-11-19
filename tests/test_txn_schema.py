"""
txn_schema.canonicalize: every reason
code, amount quantization and precision, timestamp canonicalization,
duplicates, dropped fields and the regression over the shipped sample data.
"""
import json
import os
import re
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from lambdas.detection_agent import txn_schema as ts  # noqa: E402

_RUN13 = re.compile(r"\d{13,}")


def _txn(**overrides):
    base = {"txn_id": "t-1", "sender_id": "acc-1", "receiver_id": "acc-2",
            "amount": 100.0, "timestamp": "2026-01-01T00:00:00",
            "merchant_category": "retail"}
    base.update(overrides)
    return base


def _one(txn):
    canonical, rejections, stats = ts.canonicalize([txn])
    return canonical, rejections, stats


def _code(txn):
    _, rejections, _ = _one(txn)
    assert len(rejections) == 1, rejections
    assert rejections[0]["index"] == 0
    return rejections[0]["reason_code"]


def test_valid_txn_projected_to_allowed_fields():
    canonical, rejections, stats = _one(_txn(memo="hello", is_fraud=False))
    assert rejections == []
    assert canonical == [{"txn_id": "t-1", "sender_id": "acc-1", "receiver_id": "acc-2",
                          "amount": 100.0, "timestamp": "2026-01-01T00:00:00",
                          "merchant_category": "retail"}]
    assert set(canonical[0]) <= set(ts.ALLOWED_FIELDS)
    assert stats == {"fields_dropped": 2, "duplicates_rejected": 0, "schema_rejected": 0}


def test_not_object():
    _, rejections, stats = ts.canonicalize(["x", 1, None, [1]])
    assert [r["reason_code"] for r in rejections] == [ts.NOT_OBJECT] * 4
    assert stats["schema_rejected"] == 4


@pytest.mark.parametrize("field", ["sender_id", "receiver_id", "txn_id"])
@pytest.mark.parametrize("value", [1, None, ["a"], {"a": 1}, True])
def test_id_type(field, value):
    assert _code(_txn(**{field: value})) == ts.ID_TYPE


@pytest.mark.parametrize("field", ["sender_id", "receiver_id"])
def test_required_id_missing_is_id_type(field):
    txn = _txn()
    del txn[field]
    assert _code(txn) == ts.ID_TYPE


@pytest.mark.parametrize("value", ["acc 1", "acc\u2010001", "acc/1", "", "a" * 65,
                                   "\u0664\u0665", "acc\u200b1", "αβγ"])
def test_id_charset(value):
    assert _code(_txn(sender_id=value)) == ts.ID_CHARSET


def test_id_digits_cap():
    assert _code(_txn(sender_id="a" + "1" * 13)) == ts.ID_DIGITS
    assert _code(_txn(sender_id="4532a0151b12830366")) == ts.ID_DIGITS
    canonical, rejections, _ = _one(_txn(sender_id="a" + "1" * 12))
    assert rejections == [] and canonical[0]["sender_id"] == "a" + "1" * 12


def test_fullwidth_digits_normalize_then_hit_digit_cap():
    fullwidth = "\uff14\uff15\uff13\uff12\uff10\uff11\uff15\uff11\uff11\uff12\uff18\uff13\uff10\uff13\uff16\uff16"
    assert _code(_txn(txn_id=fullwidth)) == ts.ID_DIGITS


def test_id_normalization_nfkc_casefold_strip():
    canonical, _, _ = _one(_txn(sender_id="  ACC-0001 ", receiver_id="Acc-0002"))
    assert canonical[0]["sender_id"] == "acc-0001"
    assert canonical[0]["receiver_id"] == "acc-0002"


def test_self_loop_after_normalization():
    assert _code(_txn(sender_id="ACC-1", receiver_id="acc-1")) == ts.SELF_LOOP


@pytest.mark.parametrize("value", [True, False, "100", None, float("nan"), float("inf"),
                                   float("-inf"), -1, 0, 0.0, 1_000_000_000.01, 10 ** 400,
                                   0.0001])
def test_amount_rejected(value):
    assert _code(_txn(amount=value)) == ts.AMOUNT


def test_amount_missing():
    txn = _txn()
    del txn["amount"]
    assert _code(txn) == ts.AMOUNT


def test_amount_precision_rejected_pan_carrier():
    assert _code(_txn(amount=4532015.112830366)) == ts.AMOUNT_PRECISION
    assert _code(_txn(amount=10.005)) == ts.AMOUNT_PRECISION


@pytest.mark.parametrize("value,stored", [(100.10000000000001, 100.1), (1234.5, 1234.5),
                                          (7, 7.0), (0.01, 0.01), (99.999999, 100.0)])
def test_amount_quantized(value, stored):
    canonical, rejections, _ = _one(_txn(amount=value))
    assert rejections == []
    assert canonical[0]["amount"] == stored
    assert isinstance(canonical[0]["amount"], float)


def test_max_amount_carries_no_13_digit_run():
    canonical, rejections, _ = _one(_txn(amount=1_000_000_000.0))
    assert rejections == []
    stored = canonical[0]["amount"]
    assert stored == 1_000_000_000.0
    assert _RUN13.search(str(stored)) is None
    assert _RUN13.search(repr(stored)) is None


@pytest.mark.parametrize("value", [None, 1, "not a date", "1999-12-31T23:59:59",
                                   "2101-01-01T00:00:00", "2026-01-01T00:00:00" + " " * 30,
                                   "2026-13-01T00:00:00"])
def test_timestamp_rejected(value):
    assert _code(_txn(timestamp=value)) == ts.TIMESTAMP


def test_timestamp_canonical_naive_utc_seconds():
    canonical, rejections, _ = _one(_txn(timestamp="2026-04-05T17:53:34.286179+05:30"))
    assert rejections == []
    stored = canonical[0]["timestamp"]
    assert stored == "2026-04-05T12:23:34"
    assert len(re.sub(r"\D", "", stored)) == 14
    assert _RUN13.search(stored) is None


def test_timestamp_microseconds_dropped():
    canonical, _, _ = _one(_txn(timestamp="2026-08-19T03:11:39.014082"))
    assert canonical[0]["timestamp"] == "2026-08-19T03:11:39"


@pytest.mark.parametrize("value", [1, None, "Not Valid", "a" * 33, "retail1"])
def test_category_rejected(value):
    assert _code(_txn(merchant_category=value)) == ts.CATEGORY


def test_category_optional_default_and_casefold():
    txn = _txn()
    del txn["merchant_category"]
    canonical, _, _ = _one(txn)
    assert canonical[0]["merchant_category"] == ""
    canonical, _, _ = _one(_txn(merchant_category="Wire_Transfer"))
    assert canonical[0]["merchant_category"] == "wire_transfer"


def test_duplicate_txn_id_keeps_first():
    txns = [_txn(txn_id="T-1", amount=10.0), _txn(txn_id="t-1", amount=20.0), _txn(txn_id="t-2")]
    canonical, rejections, stats = ts.canonicalize(txns)
    assert [c["txn_id"] for c in canonical] == ["t-1", "t-2"]
    assert canonical[0]["amount"] == 10.0
    assert rejections == [{"index": 1, "reason_code": ts.DUPLICATE_TXN_ID}]
    assert stats["duplicates_rejected"] == 1
    assert stats["schema_rejected"] == 1


def test_missing_txn_id_assigned_auto_index():
    a, b = _txn(), _txn()
    del a["txn_id"], b["txn_id"]
    canonical, rejections, _ = ts.canonicalize([a, b])
    assert rejections == []
    assert [c["txn_id"] for c in canonical] == ["auto-0", "auto-1"]


def test_pan_in_projection_defense_in_depth(monkeypatch):
    monkeypatch.setattr(ts, "_scan_transaction", lambda txn: "X4")
    assert _code(_txn()) == ts.PAN_IN_PROJECTION


def test_never_raises_on_odd_shapes():
    odd = [{}, {"sender_id": object()}, {"amount": object(), "sender_id": "a", "receiver_id": "b"},
           {"timestamp": object(), "sender_id": "a", "receiver_id": "b", "amount": 1}]
    canonical, rejections, _ = ts.canonicalize(odd)
    assert canonical == [] and len(rejections) == 4


def test_sample_data_canonicalizes_without_rejections():
    path = os.path.join(PROJECT_ROOT, "data", "transactions_small.jsonl")
    with open(path, encoding="utf-8") as f:
        rows = [json.loads(line) for line in f if line.strip()]
    canonical, rejections, stats = ts.canonicalize(rows)
    assert rejections == []
    assert len(canonical) == len(rows) == 218
    # is_fraud on every line is the only non-schema field.
    assert stats["fields_dropped"] == 218
