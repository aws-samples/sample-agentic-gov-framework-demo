"""
fsi-drift-metric-publisher: the only drift
metric publisher. A datapoint exists only when a stored VERIFIED decision
record exists; the Timestamp is the stream's write time. Mocked AWS only.
"""
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest
from botocore.exceptions import ClientError

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import lambdas.drift_metric_publisher.handler as pub  # noqa: E402

CREATED = 1730000000.0
CREATED_DT = datetime(2024, 10, 27, 3, 33, 20, tzinfo=timezone.utc)


def counts(clusters=25, disputes=15, guardrail_hits=1, challenger_failures=0, output_rejections=0):
    return {"clusters": Decimal(clusters), "disputes": Decimal(disputes),
            "guardrail_hits": Decimal(guardrail_hits), "challenger_failures": Decimal(challenger_failures),
            "output_rejections": Decimal(output_rejections)}


def item(status="VERIFIED", drift=None, compliance_id="cid-1"):
    stored_ts = (CREATED_DT - timedelta(minutes=8)).isoformat()  # old-code run-start timestamp
    return {"compliance_id": compliance_id, "timestamp": stored_ts, "provenance_status": status,
            "drift_counts": counts() if drift is None else drift,
            "sar_narrative": "SECRET NARRATIVE"}


def record(compliance_id="cid-1", event="INSERT", seq="111", created=CREATED):
    ddb = {"Keys": {"compliance_id": {"S": compliance_id}}, "SequenceNumber": seq}
    if created is not None:
        ddb["ApproximateCreationDateTime"] = created
    return {"eventName": event, "dynamodb": ddb}


class FakeTable:
    def __init__(self, items, error=None):
        self.items, self.error, self.calls = items, error, []

    def get_item(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        found = self.items.get(kwargs["Key"]["compliance_id"])
        return {"Item": found} if found else {}


class FakeCloudWatch:
    def __init__(self, error=None):
        self.error, self.calls = error, []

    def put_metric_data(self, **kwargs):
        if self.error:
            raise self.error
        self.calls.append(kwargs)


@pytest.fixture
def aws(monkeypatch):
    state = {"table": FakeTable({"cid-1": item()}), "cw": FakeCloudWatch()}

    class _Resource:
        def Table(self, name):
            assert name == pub.COMPLIANCE_TABLE
            return state["table"]

    def resource(service, **kwargs):
        assert service == "dynamodb"
        return _Resource()

    def client(service, **kwargs):
        assert service == "cloudwatch"
        return state["cw"]

    monkeypatch.setattr(pub.boto3, "resource", resource)
    monkeypatch.setattr(pub.boto3, "client", client)
    return state


def _error(code="ThrottlingException"):
    return ClientError({"Error": {"Code": code, "Message": "boom"}}, "Op")


def test_verified_insert_publishes_once_with_write_time(aws):
    assert pub.handler({"Records": [record()]}) == {"batchItemFailures": []}
    (call,) = aws["cw"].calls
    assert call["Namespace"] == "FSI/AgenticCompliance"
    data = {m["MetricName"]: m for m in call["MetricData"]}
    assert set(data) == {
        "ComplianceInvocations", "ChallengerOutputRejectedCount", "ChallengerDisputeCount",
        "ClustersAssessed", "GuardrailInterventionCount", "ChallengerFailureCount",
        "DetectionVolumeMultiplier", "ClustersPerInvocation", "SubFloorInvocations",
        "ChallengerDisputeRate", "GuardrailInterventionRate"}
    assert data["ClustersPerInvocation"]["Value"] == 25 and data["SubFloorInvocations"]["Value"] == 0
    assert data["ChallengerDisputeCount"]["Value"] == 15 and data["ClustersAssessed"]["Value"] == 25
    # Timestamp is the stream write time even though the item's own
    # timestamp is 8 minutes older.
    assert {m["Timestamp"] for m in call["MetricData"]} == {CREATED_DT}
    for m in call["MetricData"]:
        assert "Dimensions" not in m


def test_get_item_projection_and_consistent_read(aws):
    pub.handler({"Records": [record()]})
    (call,) = aws["table"].calls
    assert call == {"Key": {"compliance_id": "cid-1"}, "ConsistentRead": True,
                    "ProjectionExpression": "compliance_id, #ts, drift_counts, provenance_status",
                    "ExpressionAttributeNames": {"#ts": "timestamp"}}


def test_sub_floor_invocation_has_no_rates(aws):
    aws["table"].items["cid-1"] = item(drift=counts(clusters=5, disputes=5, guardrail_hits=0))
    pub.handler({"Records": [record()]})
    data = {m["MetricName"]: m["Value"] for m in aws["cw"].calls[0]["MetricData"]}
    assert "ChallengerDisputeRate" not in data and "GuardrailInterventionRate" not in data
    assert data["SubFloorInvocations"] == 1 and data["ClustersPerInvocation"] == 5


@pytest.mark.parametrize("case", ["unverified", "modify", "marker", "missing"])
def test_records_that_publish_nothing(aws, case):
    rec = record()
    if case == "unverified":
        aws["table"].items["cid-1"] = item(status="UNVERIFIED")
    elif case == "modify":
        rec = record(event="MODIFY")
    elif case == "marker":
        rec = record(compliance_id="detection#det-1")
    elif case == "missing":
        rec = record(compliance_id="cid-unknown")
    assert pub.handler({"Records": [rec]}) == {"batchItemFailures": []}
    assert aws["cw"].calls == []


@pytest.mark.parametrize("drift", [
    {**counts(), "clusters": "25"},
    {**counts(), "disputes": True},
    {**counts(), "disputes": Decimal(-1)},
    {**counts(), "disputes": Decimal(26)},
    {**counts(), "extra": Decimal(1)},
    {k: v for k, v in counts().items() if k != "output_rejections"},
    {**counts(), "clusters": Decimal(10001), "disputes": Decimal(0)},
    {**counts(), "clusters": Decimal("25.5")},
    "not a dict",
])
def test_malformed_counts_publish_nothing(aws, drift):
    aws["table"].items["cid-1"] = item(drift=drift)
    assert pub.handler({"Records": [record()]}) == {"batchItemFailures": []}
    assert aws["cw"].calls == []


@pytest.mark.parametrize("created", [None, "not-a-number"])
def test_bad_creation_time_is_skipped(aws, created):
    assert pub.handler({"Records": [record(created=created)]}) == {"batchItemFailures": []}
    assert aws["cw"].calls == []


def test_put_error_reports_the_record(aws):
    aws["cw"].error = _error()
    assert pub.handler({"Records": [record(seq="42")]}) == {"batchItemFailures": [{"itemIdentifier": "42"}]}


def test_get_item_error_reports_the_record(aws):
    aws["table"].error = _error("ProvisionedThroughputExceededException")
    assert pub.handler({"Records": [record(seq="43")]}) == {"batchItemFailures": [{"itemIdentifier": "43"}]}


def test_logs_never_carry_item_contents(aws, caplog):
    caplog.set_level(logging.INFO)
    aws["table"].items["cid-2"] = item(compliance_id="cid-2", drift="bad")
    aws["table"].items["cid-3"] = item(compliance_id="cid-3", status="UNVERIFIED")
    pub.handler({"Records": [record(), record("cid-2", seq="2"), record("cid-3", seq="3")]})
    aws["cw"].error = _error()
    pub.handler({"Records": [record()]})
    assert "SECRET NARRATIVE" not in caplog.text and "drift_counts" not in caplog.text.replace(
        "malformed drift_counts", "")


def test_timestamp_conversion():
    assert pub._creation_time(record()) == CREATED_DT


def test_decimal_counts_validate():
    assert pub.validate_drift_counts(counts()) == {
        "clusters": 25, "disputes": 15, "guardrail_hits": 1, "challenger_failures": 0, "output_rejections": 0}


def test_floor_is_a_code_constant(monkeypatch):
    monkeypatch.setenv("MIN_CLUSTERS_FOR_RATE", "1")
    import importlib
    assert importlib.reload(pub).MIN_CLUSTERS_FOR_RATE == 20
