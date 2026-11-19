"""
Audit reader and SOX lookup use keyed index reads only.

- read_audit_trail_live(session=...): by_day_ts Query (today, then
  yesterday) for detection/compliance/executor, by_event_type Query per
  hold/release event type for governance-audit, then BatchGetItem for the
  returned keys. Never Scan. Narratives are redacted without the auditor
  role. Errors render a class + reference, never exception text.
- _find_sox_audit_record(..., session=...): executor-audit by_day_ts Query
  over one or two UTC days, newest first, bounded pages, never Scan; the
  record (with violation_type from the index projection) is still found.
"""
import json
import os
import sys
from datetime import datetime, timedelta, timezone

import boto3
import pytest
from botocore.exceptions import ClientError

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import app.invoke_live as invoke_live  # noqa: E402

NOW = datetime(2026, 8, 19, 12, 0, 0, tzinfo=timezone.utc)
LEAKY = ("User: arn:aws:sts::123456789012:assumed-role/secret-role/x is not authorized "
         "on table executor-audit in us-east-1")


def _eq_values(condition) -> dict:
    """{attribute: value} for the eq() terms of a boto3 key condition."""
    from boto3.dynamodb.conditions import And, Equals
    out = {}
    stack = [condition]
    while stack:
        cond = stack.pop()
        if isinstance(cond, And):
            stack.extend(cond.get_expression()["values"])
        elif isinstance(cond, Equals):
            attr, value = cond.get_expression()["values"]
            out[attr.name] = value
    return out


class FakeTable:
    """Items carry record_day / event_type; query() honours the index key and
    Limit (newest first), scan() always fails the test."""

    def __init__(self, name, items, key_attr):
        self.name, self.items, self.key_attr = name, items, key_attr
        self.queries = []

    def scan(self, **kwargs):
        raise AssertionError(f"{self.name}: scan must never be called")

    def query(self, **kwargs):
        self.queries.append(kwargs)
        eq = _eq_values(kwargs["KeyConditionExpression"])
        if kwargs["IndexName"] == "by_day_ts":
            matched = [i for i in self.items if i.get("record_day") == eq["record_day"]]
        else:
            assert kwargs["IndexName"] == "by_event_type"
            matched = [i for i in self.items if i.get("event_type") == eq["event_type"]]
        matched.sort(key=lambda i: i["timestamp"], reverse=kwargs.get("ScanIndexForward") is False)
        limit = kwargs.get("Limit", len(matched))
        # Index reads return projected attributes only: keys + index keys.
        projected = [{k: i[k] for k in (self.key_attr, "record_day", "event_type", "timestamp") if k in i}
                     for i in matched[:limit]]
        return {"Items": projected}


class FakeDynamo:
    def __init__(self, tables, fail=None):
        self.tables = tables
        self.fail = fail or {}
        self.batch_calls = []

    def Table(self, name):
        if name in self.fail:
            raise self.fail[name]
        return self.tables[name]

    def batch_get_item(self, RequestItems):
        self.batch_calls.append(RequestItems)
        responses = {}
        for name, request in RequestItems.items():
            table = self.tables[name]
            wanted = {k[table.key_attr] for k in request["Keys"]}
            responses[name] = [i for i in table.items if i[table.key_attr] in wanted]
        return {"Responses": responses, "UnprocessedKeys": {}}


class FakeSession:
    def __init__(self, dynamo):
        self.dynamo = dynamo

    def resource(self, service, **kwargs):
        assert service == "dynamodb"
        return self.dynamo

    def client(self, service, **kwargs):
        raise AssertionError("the audit reader uses the dynamodb resource only")


@pytest.fixture(autouse=True)
def _no_ambient(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("ambient boto3 must never be used")
    for name in ("client", "resource", "Session"):
        monkeypatch.setattr(boto3, name, refuse)


def _ts(minutes_ago):
    return (NOW - timedelta(minutes=minutes_ago)).isoformat()


def _day(minutes_ago):
    return (NOW - timedelta(minutes=minutes_ago)).date().isoformat()


def _tables(gov_items=None, compliance_items=None):
    det = [{"detection_id": f"det-{i}", "record_day": _day(i * 300), "timestamp": _ts(i * 300)} for i in range(8)]
    comp = compliance_items or [{
        "compliance_id": "cmp-1", "record_day": _day(5), "timestamp": _ts(5),
        "clusters_assessed": [{"cluster_id": "c1", "sar_narrative": "SECRET NARRATIVE TEXT"}],
    }]
    exe = [{"action_id": "a-1", "record_day": _day(1), "timestamp": _ts(1), "action_taken": "FILED"}]
    gov = gov_items if gov_items is not None else [
        {"event_id": "hold-1", "event_type": "GOVERNANCE_HOLD", "timestamp": _ts(30)},
    ]
    return {
        "detection-results": FakeTable("detection-results", det, "detection_id"),
        "compliance-decisions": FakeTable("compliance-decisions", comp, "compliance_id"),
        "executor-audit": FakeTable("executor-audit", exe, "action_id"),
        "governance-audit": FakeTable("governance-audit", gov, "event_id"),
    }


def _read(tables, **kwargs):
    dynamo = FakeDynamo(tables, fail=kwargs.pop("fail", None))
    result = invoke_live.read_audit_trail_live(session=FakeSession(dynamo), now=NOW, **kwargs)
    return result, dynamo


# ─── Audit reader ────────────────────────────────────────────────────────────

def test_reader_uses_index_query_and_batch_get_never_scan():
    tables = _tables()
    result, dynamo = _read(tables, include_narratives=True)
    for name in ("detection-results", "compliance-decisions", "executor-audit"):
        assert tables[name].queries and all(q["IndexName"] == "by_day_ts" for q in tables[name].queries)
        assert all(q["ScanIndexForward"] is False for q in tables[name].queries)
    assert {name for call in dynamo.batch_calls for name in call} == set(tables)
    assert [r["action_id"] for r in result["executor-audit"]] == ["a-1"]
    # Full items come from BatchGetItem, not from the index projection.
    assert result["compliance-decisions"][0]["clusters_assessed"][0]["sar_narrative"] == "SECRET NARRATIVE TEXT"


def test_reader_reads_newest_five_and_falls_back_to_yesterday():
    tables = _tables()
    result, _ = _read(tables, include_narratives=True)
    ids = [r["detection_id"] for r in result["detection-results"]]
    assert len(ids) == invoke_live.AUDIT_READ_LIMIT == 5
    assert ids == sorted(ids, key=lambda d: int(d.split("-")[1]))  # newest first
    days = [_eq_values(q["KeyConditionExpression"])["record_day"] for q in tables["detection-results"].queries]
    assert days[0] == NOW.date().isoformat()
    # Records are 5 h apart: today holds 3 (12:00, 07:00, 02:00), so yesterday is read for 2 more.
    assert len(days) == 2 and days[1] == (NOW - timedelta(days=1)).date().isoformat()


def test_governance_read_by_event_type_flood_cannot_displace_hold():
    flood = [{"event_id": f"nonce-{i}", "event_type": "NONCE_CONSUMED", "timestamp": _ts(i / 100)}
             for i in range(1000)]
    hold = {"event_id": "hold-1", "event_type": "GOVERNANCE_HOLD", "timestamp": _ts(60)}
    tables = _tables(gov_items=flood + [hold])
    result, _ = _read(tables)
    queried = [_eq_values(q["KeyConditionExpression"])["event_type"] for q in tables["governance-audit"].queries]
    assert queried == list(invoke_live.GOVERNANCE_READ_EVENT_TYPES)
    assert "GOVERNANCE_HOLD" in queried and "RELEASE_REQUESTED" in queried
    assert all(q["IndexName"] == "by_event_type" and q["Limit"] == 5 for q in tables["governance-audit"].queries)
    assert [r["event_id"] for r in result["governance-audit"]] == ["hold-1"]


def test_narratives_redacted_without_auditor_role():
    result, _ = _read(_tables())
    narrative = result["compliance-decisions"][0]["clusters_assessed"][0]["sar_narrative"]
    assert narrative == invoke_live.REDACTED_NARRATIVE
    assert "SECRET NARRATIVE TEXT" not in json.dumps(result)


def test_table_error_renders_class_and_reference_only(caplog):
    error = ClientError({"Error": {"Code": "AccessDeniedException", "Message": LEAKY}}, "Query")
    result, _ = _read(_tables(), fail={"executor-audit": error})
    (entry,) = result["executor-audit"]
    assert set(entry) == {"error_code", "error_ref"} and entry["error_code"] == "AccessDenied"
    for needle in ("123456789012", "secret-role", "us-east-1"):
        assert needle not in json.dumps(result)
    assert any(entry["error_ref"] in r.getMessage() for r in caplog.records)  # detail kept server-side
    assert result["detection-results"]  # other tables still read


def test_audit_read_keys_lists_ids_only():
    result, _ = _read(_tables())
    keys = invoke_live.audit_read_keys(result)
    assert keys["executor-audit"] == ["a-1"] and keys["governance-audit"] == ["hold-1"]
    assert "SECRET" not in json.dumps(keys)


def test_local_reader_redacts_and_never_returns_exception_text(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCAL_OUTPUT_DIR", str(tmp_path))
    (tmp_path / "compliance_result.json").write_text(json.dumps(
        {"compliance_id": "c", "clusters_assessed": [{"sar_narrative": "SECRET NARRATIVE TEXT"}]}))
    (tmp_path / "detection_result.json").write_text("{not json")
    result = invoke_live.read_audit_trail_local()
    assert result["compliance-decisions"][0]["clusters_assessed"][0]["sar_narrative"] == \
        invoke_live.REDACTED_NARRATIVE
    assert set(result["detection-results"][0]) == {"error_code", "error_ref"}
    full = invoke_live.read_audit_trail_local(include_narratives=True)
    assert full["compliance-decisions"][0]["clusters_assessed"][0]["sar_narrative"] == "SECRET NARRATIVE TEXT"


# ─── SOX demo lookup ─────────────────────────────────────────────────────────

class SoxIndex:
    """executor-audit/index/by_day_ts: keys + action_taken, event_hash,
    violation_type only (the real INCLUDE projection)."""

    PROJECTED = ("action_id", "record_day", "timestamp", "action_taken", "event_hash", "violation_type")

    def __init__(self, items, pages=1):
        self.items, self.pages = items, pages
        self.queries = []

    def scan(self, **kwargs):
        raise AssertionError("scan must never be called")

    def query(self, **kwargs):
        self.queries.append(kwargs)
        assert kwargs["IndexName"] == "by_day_ts" and kwargs["ScanIndexForward"] is False
        assert "FilterExpression" in kwargs
        day = _eq_values(kwargs["KeyConditionExpression"])["record_day"]
        rows = [{k: i[k] for k in self.PROJECTED if k in i} for i in self.items if i["record_day"] == day]
        page = {"Items": rows}
        if len(self.queries) < self.pages:
            page["LastEvaluatedKey"] = {"action_id": "more"}
        return page


class SoxSession:
    def __init__(self, table):
        self.table = table

    def resource(self, service, **kwargs):
        dynamo = type("R", (), {})()
        dynamo.Table = lambda name: self.table
        return dynamo


def _sox_item(action_id, ts, event_hash="sha256:abc"):
    return {"action_id": action_id, "record_day": ts.date().isoformat(), "timestamp": ts.isoformat(),
            "action_taken": "SOX_VIOLATION_REJECTED", "event_hash": event_hash,
            "violation_type": "Unexpected key 'action' in request envelope (not on allow-list)",
            "payload_body": "never projected"}


def test_sox_lookup_queries_index_and_returns_newest_with_violation_type(monkeypatch):
    start = datetime.now(timezone.utc)
    table = SoxIndex([_sox_item("older", start), _sox_item("newest", start + timedelta(seconds=1)),
                      _sox_item("other", start, event_hash="sha256:other")])
    record = invoke_live._find_sox_audit_record("sha256:abc", start, session=SoxSession(table))
    assert record["action_id"] == "newest"
    assert "Unexpected key 'action'" in record["violation_type"]
    assert "payload_body" not in record
    assert table.queries


def test_sox_lookup_just_after_midnight_queries_both_days(monkeypatch):
    # Days are {day(request_start - AUDIT_CLOCK_SKEW_SECONDS), day(now)}
    # 3 s after midnight the skew window reaches yesterday.
    start = datetime(2026, 8, 20, 0, 0, 3, tzinfo=timezone.utc)
    table = SoxIndex([])
    monkeypatch.setattr(invoke_live, "AUDIT_LOOKUP_DELAYS", (0,))

    class _Now(datetime):
        @classmethod
        def now(cls, tz=None):
            return start + timedelta(seconds=1)
    monkeypatch.setattr(invoke_live, "datetime", _Now)
    assert invoke_live._find_sox_audit_record("sha256:abc", start, session=SoxSession(table)) is None
    days = [_eq_values(q["KeyConditionExpression"])["record_day"] for q in table.queries]
    assert days == ["2026-08-20", "2026-08-19"]
    # Exactly at the skew boundary only today is in the window.
    table.queries.clear()
    invoke_live._find_sox_audit_record("sha256:abc", start + timedelta(seconds=2), session=SoxSession(table))
    assert [_eq_values(q["KeyConditionExpression"])["record_day"] for q in table.queries] == ["2026-08-20"]


def test_sox_lookup_pages_are_bounded(monkeypatch):
    monkeypatch.setattr(invoke_live, "AUDIT_LOOKUP_DELAYS", (0,))
    table = SoxIndex([], pages=10_000)
    invoke_live._find_sox_audit_record("sha256:abc", datetime.now(timezone.utc), session=SoxSession(table))
    assert len(table.queries) == invoke_live.AUDIT_LOOKUP_MAX_PAGES == 10
