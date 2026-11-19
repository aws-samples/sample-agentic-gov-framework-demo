"""
fsi-audit-archiver: stream record -> one immutable JSON object in the WORM
archive bucket. Fake S3 and DynamoDB clients only; nothing calls AWS.
"""
import base64
import hashlib
import hmac
import json
import logging
import os
import random
import secrets
import sys
import uuid
from decimal import Decimal

import pytest
from boto3.dynamodb.types import TypeSerializer
from botocore.exceptions import ClientError, EndpointConnectionError

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import lambdas.audit_archiver.handler as arc  # noqa: E402
from circuit_breaker.identity_proof import nonce_event_id  # noqa: E402
import lambdas.executor_agent.handler as executor  # noqa: E402
from lambdas.compliance_agent.sar_prompts import get_prompt_fingerprint  # noqa: E402
from governance_common.payload_limits import REQUEST_REF_RE, new_request_ref  # noqa: E402

ACCT = "123456789012"
BUCKET = "archive-bucket"
KEY_ARN = f"arn:aws:kms:us-east-1:{ACCT}:key/1234abcd-12ab-34cd-56ef-1234567890ab"
TABLE_LIST = ["detection-results", "compliance-decisions", "executor-audit", "governance-audit", "operator-audit"]
TABLES = ",".join(TABLE_LIST)
STREAM_LABEL = "2024-10-27T00:00:00.000"
STREAM_ARNS = ",".join(f"arn:aws:dynamodb:us-east-1:{ACCT}:table/{t}/stream/{STREAM_LABEL}" for t in TABLE_LIST)
CREATED = 1730000000.0  # 2024-10-27T03:33:20Z
# PAN vectors from the existing PAN filter tests (Luhn-valid test card numbers).
PANS = ["4111111111111111", "5500005555555559", "378282246310005", "4111 1111 1111 1111",
        "4111-1111-1111-1111", "6011111111111117"]
LOCK_PARAMS = ("ObjectLockMode", "ObjectLockRetainUntilDate", "ObjectLockLegalHoldStatus")
_ser = TypeSerializer()


def typed(item: dict) -> dict:
    return {k: _ser.serialize(v) for k, v in item.items()}


def precondition_failed():
    return ClientError({"Error": {"Code": "PreconditionFailed", "Message": "At least one of the pre-conditions"},
                        "ResponseMetadata": {"HTTPStatusCode": 412}}, "PutObject")


def client_error(code, status, op="PutObject"):
    return ClientError({"Error": {"Code": code, "Message": "x"}, "ResponseMetadata": {"HTTPStatusCode": status}}, op)


class _Shape:
    def __init__(self, members):
        self.members = members


class _Model:
    def __init__(self, if_none_match=True):
        self.if_none_match = if_none_match

    def operation_model(self, name):
        assert name == "PutObject"
        members = {"Bucket": 1, "Key": 1, "Body": 1}
        if self.if_none_match:
            members["IfNoneMatch"] = 1
        return type("Op", (), {"input_shape": _Shape(members)})()


class FakeS3:
    def __init__(self, if_none_match=True):
        self.meta = type("Meta", (), {"service_model": _Model(if_none_match)})()
        self.objects = {}
        self.puts = []
        self.put_errors = []   # consumed in order; None = normal behavior
        self.head_error = None

    def put_object(self, **kwargs):
        self.puts.append(kwargs)
        if self.put_errors:
            err = self.put_errors.pop(0)
            if err is not None:
                raise err
        assert kwargs["IfNoneMatch"] == "*"
        if kwargs["Key"] in self.objects:
            raise precondition_failed()
        self.objects[kwargs["Key"]] = {"Body": kwargs["Body"], "Metadata": dict(kwargs["Metadata"])}
        return {}

    def head_object(self, Bucket, Key):
        if self.head_error:
            raise self.head_error
        return {"Metadata": dict(self.objects[Key]["Metadata"])}


# What the fake source tables hold: (table, key value) -> typed item. record()
# seeds it from the NewImage it builds (a genuine write); forged-record tests
# overwrite or clear the entry. Reset per test by the env fixture.
SOURCE = {}


class FakeDDB:
    def __init__(self, item=None, error=None):
        self.item = item      # explicit override: served for every compliance-decisions key
        self.error = error
        self.calls = []

    def get_item(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        if self.item is not None and kwargs["TableName"] == "compliance-decisions":
            return {"Item": typed(self.item)}
        (value,) = [v["S"] for v in kwargs["Key"].values()]
        found = SOURCE.get((kwargs["TableName"], value))
        return {"Item": found} if found is not None else {}


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("ARCHIVE_BUCKET", BUCKET)
    monkeypatch.setenv("ARCHIVE_KMS_KEY_ARN", KEY_ARN)
    monkeypatch.setenv("ARCHIVE_TABLES", TABLES)
    monkeypatch.setenv("EXPECTED_STREAM_ARNS", STREAM_ARNS)
    SOURCE.clear()
    s3, ddb = FakeS3(), FakeDDB()
    monkeypatch.setattr(arc, "_S3", s3)
    monkeypatch.setattr(arc, "_DDB", ddb)
    return {"s3": s3, "ddb": ddb}


def record(table="executor-audit", event="INSERT", event_id=None, seq="100", keys=None, image=None,
           created=CREATED):
    keys = keys if keys is not None else {"action_id": {"S": "11111111-2222-4333-8444-555555555555"}}
    ddb = {"Keys": keys, "SequenceNumber": seq, "ApproximateCreationDateTime": created,
           "StreamViewType": "NEW_IMAGE" if table != "compliance-decisions" else "KEYS_ONLY"}
    if image is not None:
        ddb["NewImage"] = image
    if image is not None and table != "compliance-decisions":
        values = [v.get("S") for v in keys.values() if isinstance(v, dict)]
        if len(values) == 1 and isinstance(values[0], str):
            SOURCE[(table, values[0])] = image  # a genuine write: the table holds the image
    return {"eventID": event_id or uuid.uuid4().hex, "eventName": event,
            "eventSource": "aws:dynamodb",
            "eventSourceARN": f"arn:aws:dynamodb:us-east-1:{ACCT}:table/{table}/stream/{STREAM_LABEL}",
            "dynamodb": ddb}


def executor_image(**extra):
    item = {"action_id": "11111111-2222-4333-8444-555555555555", "action_taken": "SAR_FILED",
            "timestamp": "2024-10-27T03:33:20+00:00", "amount": Decimal("1.50"),
            "tags": {"b", "a", "c"}, "event_hash": hashlib.sha256(b"x").hexdigest()}
    item.update(extra)
    return typed(item)


def emf_lines(capsys):
    out = []
    for line in capsys.readouterr().out.splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            pass
    return out


def metrics(capsys):
    names = []
    for doc in emf_lines(capsys):
        for m in doc["_aws"]["CloudWatchMetrics"][0]["Metrics"]:
            names.append(m["Name"])
    return names


def body_of(env, key):
    return json.loads(env["s3"].objects[key]["Body"])


# ─── Layout, body, headers ───────────────────────────────────────────────────
def test_object_key_layout_and_hour_partition(env):
    r = record(event_id="evt-1", image=executor_image())
    assert arc.handler({"Records": [r]}) == {"batchItemFailures": []}
    assert list(env["s3"].objects) == ["executor-audit/2024/10/27/03/evt-1.json"]
    r2 = record(event_id="evt-2", image=executor_image(), created=CREATED + 3600 * 21)
    arc.handler({"Records": [r2]})
    assert "executor-audit/2024/10/28/00/evt-2.json" in env["s3"].objects


def test_canonical_body_and_item_hash(env):
    r = record(event_id="evt-1", seq="555", image=executor_image())
    arc.handler({"Records": [r]})
    put = env["s3"].puts[0]
    data = put["Body"]
    body = json.loads(data)
    assert data == arc.canonical_json(body)
    assert body["schema"] == "fsi-audit-archive/v1"
    assert body["table"] == "executor-audit" and body["event_id"] == "evt-1"
    assert body["event_name"] == "INSERT" and body["sequence_number"] == "555"
    assert body["approximate_creation_time"] == "2024-10-27T03:33:20Z"
    assert body["image_source"] == "get_item_verified"
    assert body["keys"] == {"action_id": {"S": "11111111-2222-4333-8444-555555555555"}}
    assert body["item"]["tags"] == {"SS": ["a", "b", "c"]}
    assert body["item"]["amount"] == {"N": "1.50"}
    assert body["item_sha256"] == hashlib.sha256(arc.canonical_json(body["item"])).hexdigest()


def test_put_headers_and_metadata(env):
    arc.handler({"Records": [record(event_id="evt-1", image=executor_image())]})
    (put,) = env["s3"].puts
    data = put["Body"]
    assert put["Bucket"] == BUCKET and put["IfNoneMatch"] == "*"
    assert put["ChecksumAlgorithm"] == "SHA256"
    assert put["ChecksumSHA256"] == base64.b64encode(hashlib.sha256(data).digest()).decode()
    assert put["ServerSideEncryption"] == "aws:kms" and put["SSEKMSKeyId"] == KEY_ARN
    md = put["Metadata"]
    assert set(md) == {"content-sha256", "image-source", "identity-sha256"}
    assert md["content-sha256"] == hashlib.sha256(data).hexdigest()
    assert md["image-source"] == "get_item_verified"
    assert md["identity-sha256"] == hashlib.sha256(arc.canonical_json({
        "table": "executor-audit", "event_id": "evt-1", "event_name": "INSERT",
        "sequence_number": "100"})).hexdigest()


def test_never_sends_object_lock_parameters(env):
    """Retention comes only from the bucket's default Object Lock rule."""
    env["ddb"].item = {"compliance_id": "c-1", "narrative": "n"}
    def own(i, **extra):  # a distinct key per record
        return dict(keys={"action_id": {"S": f"id-{i}"}}, image=executor_image(action_id=f"id-{i}", **extra))
    records = [record(event_id="a", **own(1)),
               record(table="compliance-decisions", event="MODIFY", event_id="b",
                      keys={"compliance_id": {"S": "c-1"}}),
               record(event="REMOVE", event_id="c", keys={"action_id": {"S": "id-3"}}),
               record(event_id="d", **own(4, note=PANS[0]))]
    assert arc.handler({"Records": records}) == {"batchItemFailures": []}
    env["s3"].objects.clear()
    env["ddb"].item = None
    env["s3"].put_errors = [precondition_failed()]
    env["s3"].objects["executor-audit/2024/10/27/03/e.json"] = {"Body": b"", "Metadata": {}}
    arc.handler({"Records": [record(event_id="e", image=executor_image())]})
    assert len(env["s3"].puts) >= 6
    for put in env["s3"].puts:
        assert not set(LOCK_PARAMS) & set(put), put.keys()
        assert put["IfNoneMatch"] == "*"


def test_binary_and_nested_values_normalize(env):
    image = {"action_id": {"S": "x"}, "blob": {"B": base64.b64encode(b"\x00\x01").decode()},
             "nested": {"M": {"l": {"L": [{"N": "2"}, {"BOOL": True}, {"NULL": True}]},
                              "ns": {"NS": ["3", "1"]}}}}
    arc.handler({"Records": [record(event_id="evt", image=image)]})
    body = body_of(env, "executor-audit/2024/10/27/03/evt.json")
    assert body["item"]["nested"]["M"]["ns"] == {"NS": ["1", "3"]}
    assert body["item"]["blob"] == {"B": "AAE="}


# ─── Idempotency and conflicts ───────────────────────────────────────────────
def test_retry_with_identical_content_is_success(env, capsys):
    r = record(event_id="evt", image=executor_image())
    arc.handler({"Records": [r]})
    assert arc.handler({"Records": [r]}) == {"batchItemFailures": []}
    assert list(env["s3"].objects) == ["executor-audit/2024/10/27/03/evt.json"]
    assert "ArchiveConflicts" not in metrics(capsys)


def test_conflict_with_different_hash_is_kept_and_alarmed(env, capsys):
    arc.handler({"Records": [record(event_id="evt", image=executor_image())]})
    changed = record(event_id="evt", image=executor_image(action_taken="FORGED"))
    assert arc.handler({"Records": [changed]}) == {"batchItemFailures": []}
    conflicts = [k for k in env["s3"].objects if k.startswith("_conflicts/")]
    assert len(conflicts) == 1
    content = env["s3"].objects[conflicts[0]]["Metadata"]["content-sha256"]
    assert conflicts[0] == f"_conflicts/executor-audit/evt/{content}.json"
    assert body_of(env, "executor-audit/2024/10/27/03/evt.json")["item"]["action_taken"] == {"S": "SAR_FILED"}
    assert metrics(capsys).count("ArchiveConflicts") == 1


def test_conflict_already_kept_is_success(env, capsys):
    arc.handler({"Records": [record(event_id="evt", image=executor_image())]})
    changed = record(event_id="evt", image=executor_image(action_taken="FORGED"))
    arc.handler({"Records": [changed]})
    assert arc.handler({"Records": [changed]}) == {"batchItemFailures": []}
    assert len([k for k in env["s3"].objects if k.startswith("_conflicts/")]) == 1


def test_different_identity_same_key_is_a_conflict(env, capsys):
    arc.handler({"Records": [record(event_id="evt", seq="100", image=executor_image())]})
    arc.handler({"Records": [record(event_id="evt", seq="999", image=executor_image())]})
    assert len([k for k in env["s3"].objects if k.startswith("_conflicts/")]) == 1
    assert "ArchiveConflicts" in metrics(capsys)


def test_get_item_snapshot_superseded_is_success_without_alarm(env, capsys):
    keys = {"compliance_id": {"S": "c-1"}}
    env["ddb"].item = {"compliance_id": "c-1", "completed_clusters": {"a"}}
    r = record(table="compliance-decisions", event="MODIFY", event_id="evt", keys=keys)
    arc.handler({"Records": [r]})
    env["ddb"].item = {"compliance_id": "c-1", "completed_clusters": {"a", "b"}}
    assert arc.handler({"Records": [r]}) == {"batchItemFailures": []}
    names = metrics(capsys)
    assert "ArchiveSnapshotSuperseded" in names and "ArchiveConflicts" not in names
    assert not [k for k in env["s3"].objects if k.startswith("_conflicts/")]


@pytest.mark.parametrize("error", [
    client_error("ConditionalRequestConflict", 409),
    client_error("InternalError", 500),
    client_error("SlowDown", 503),
    client_error("AccessDenied", 403),
    client_error("KMS.KMSInvalidStateException", 400),
    EndpointConnectionError(endpoint_url="https://s3"),
])
def test_put_errors_are_batch_failures_and_stop(env, capsys, error):
    env["s3"].put_errors = [error]
    first = record(event_id="a", seq="100", image=executor_image())
    second = record(event_id="b", seq="200", image=executor_image())
    assert arc.handler({"Records": [first, second]}) == {"batchItemFailures": [{"itemIdentifier": "100"}]}
    assert len(env["s3"].puts) == 1  # stopped at the first failure
    assert "ArchiveRecordFailures" in metrics(capsys)


def test_head_object_error_is_a_batch_failure(env, capsys):
    r = record(event_id="evt", image=executor_image())
    arc.handler({"Records": [r]})
    env["s3"].head_error = client_error("InternalError", 500, "HeadObject")
    assert arc.handler({"Records": [r]}) == {"batchItemFailures": [{"itemIdentifier": "100"}]}
    assert "ArchiveRecordFailures" in metrics(capsys)


def test_conflict_write_failure_is_a_batch_failure(env, capsys):
    arc.handler({"Records": [record(event_id="evt", image=executor_image())]})
    env["s3"].put_errors = [None, client_error("InternalError", 500)]
    changed = record(event_id="evt", image=executor_image(action_taken="FORGED"))
    assert arc.handler({"Records": [changed]}) == {"batchItemFailures": [{"itemIdentifier": "100"}]}
    assert "ArchiveRecordFailures" in metrics(capsys)


# ─── KEYS_ONLY -> GetItem, REMOVE, missing images ────────────────────────────
def test_keys_only_path_reads_full_item_consistently(env):
    keys = {"compliance_id": {"S": "c-1"}}
    env["ddb"].item = {"compliance_id": "c-1", "sar_narrative": "Structured cash deposits", "record_day": "2024-10-27"}
    r = record(table="compliance-decisions", event_id="evt", keys=keys)
    assert arc.handler({"Records": [r]}) == {"batchItemFailures": []}
    assert env["ddb"].calls == [{"TableName": "compliance-decisions", "Key": keys, "ConsistentRead": True}]
    body = body_of(env, "compliance-decisions/2024/10/27/03/evt.json")
    assert body["image_source"] == "get_item_consistent"
    assert body["item"]["sar_narrative"] == {"S": "Structured cash deposits"}


def test_keys_only_missing_item_is_refused_and_alarmed(env, capsys):
    r = record(table="compliance-decisions", event_id="evt", keys={"compliance_id": {"S": "c-1"}})
    assert arc.handler({"Records": [r]}) == {"batchItemFailures": []}
    assert not env["s3"].puts  # no caller-chosen bytes sealed
    names = metrics(capsys)
    assert "ArchiveItemMissing" in names and "ArchiveSourceRefused" in names


def test_keys_only_get_item_error_is_a_batch_failure(env, capsys):
    env["ddb"].error = client_error("ProvisionedThroughputExceededException", 400, "GetItem")
    r = record(table="compliance-decisions", event_id="evt", seq="7", keys={"compliance_id": {"S": "c-1"}})
    assert arc.handler({"Records": [r]}) == {"batchItemFailures": [{"itemIdentifier": "7"}]}
    assert not env["s3"].puts
    assert "ArchiveRecordFailures" in metrics(capsys)


@pytest.mark.parametrize("table,attr", [
    ("detection-results", "detection_id"), ("compliance-decisions", "compliance_id"),
    ("executor-audit", "action_id"), ("governance-audit", "event_id"), ("operator-audit", "event_id")])
def test_every_table_is_re_read_with_a_consistent_get_item(env, table, attr):
    keys = {attr: {"S": "k-1"}}
    image = {attr: {"S": "k-1"}, "note": {"S": "n"}}
    env["ddb"].item = None
    SOURCE[(table, "k-1")] = typed({attr: "k-1", "note": "n"})
    r = record(table=table, event_id="evt", keys=keys, image=None if table == "compliance-decisions" else image)
    assert arc.handler({"Records": [r]}) == {"batchItemFailures": []}
    assert env["ddb"].calls == [{"TableName": table, "Key": keys, "ConsistentRead": True}]
    (body,) = [json.loads(o["Body"]) for o in env["s3"].objects.values()]
    assert body["item"] == {attr: {"S": "k-1"}, "note": {"S": "n"}}


# ─── The archive holds only what the archiver read from the table ───────────
FORGED = "FORGED-EVIDENCE"


def _refused(env, capsys, records, reasons=("ArchiveSourceRefused",)):
    assert arc.handler({"Records": records}) == {"batchItemFailures": []}
    assert not env["s3"].puts and not env["s3"].objects  # nothing written, ever
    names = metrics(capsys)
    for reason in reasons:
        assert reason in names


def test_forged_image_that_differs_from_the_table_is_refused(env, capsys, caplog):
    caplog.set_level(logging.DEBUG)
    genuine = executor_image()
    r = record(event_id="evt", image=genuine)
    r["dynamodb"]["NewImage"] = executor_image(action_taken=FORGED)  # attacker-authored
    _refused(env, capsys, [r])
    assert FORGED not in caplog.text


def test_forged_image_extra_attribute_is_refused(env, capsys):
    r = record(event_id="evt", image=executor_image())
    r["dynamodb"]["NewImage"] = executor_image(extra={"S": FORGED})
    _refused(env, capsys, [r])


def test_forged_record_for_a_key_that_does_not_exist_is_refused(env, capsys):
    r = record(event_id="evt", image=executor_image())
    SOURCE.clear()
    _refused(env, capsys, [r], ("ArchiveSourceRefused", "ArchiveItemMissing"))


@pytest.mark.parametrize("event", ["INSERT", "MODIFY"])
def test_keys_only_forged_record_for_a_missing_key_is_refused(env, capsys, event):
    r = record(table="compliance-decisions", event=event, event_id="evt", keys={"compliance_id": {"S": "nope"}})
    _refused(env, capsys, [r], ("ArchiveSourceRefused", "ArchiveItemMissing"))


def test_refusal_does_not_stop_the_batch_or_fail_it(env, capsys):
    bad = record(event_id="bad", seq="1", image=executor_image())
    bad["dynamodb"]["NewImage"] = executor_image(action_taken=FORGED)
    good = record(event_id="good", seq="2", keys={"action_id": {"S": "other"}},
                  image={"action_id": {"S": "other"}, "note": {"S": "ok"}})
    assert arc.handler({"Records": [bad, good]}) == {"batchItemFailures": []}
    assert list(env["s3"].objects) == ["executor-audit/2024/10/27/03/good.json"]
    assert "ArchiveSourceRefused" in metrics(capsys)


def test_digest_is_over_the_item_read_from_the_table(env):
    r = record(event_id="evt", image=executor_image())
    arc.handler({"Records": [r]})
    body = body_of(env, "executor-audit/2024/10/27/03/evt.json")
    read = arc.normalize_item(SOURCE[("executor-audit", "11111111-2222-4333-8444-555555555555")])
    assert body["item"] == read
    assert body["item_sha256"] == hashlib.sha256(arc.canonical_json(read)).hexdigest()


def test_keys_only_digest_is_over_the_get_item_result(env):
    env["ddb"].item = {"compliance_id": "c-1", "sar_narrative": "n"}
    r = record(table="compliance-decisions", event_id="evt", keys={"compliance_id": {"S": "c-1"}})
    arc.handler({"Records": [r]})
    body = body_of(env, "compliance-decisions/2024/10/27/03/evt.json")
    assert body["item_sha256"] == hashlib.sha256(arc.canonical_json(body["item"])).hexdigest()
    assert body["item"] == arc.normalize_item(typed(env["ddb"].item))


def test_keys_only_stream_image_if_present_is_ignored(env):
    env["ddb"].item = {"compliance_id": "c-1", "sar_narrative": "real"}
    r = record(table="compliance-decisions", event_id="evt", keys={"compliance_id": {"S": "c-1"}},
               image={"compliance_id": {"S": "c-1"}, "sar_narrative": {"S": FORGED}})
    arc.handler({"Records": [r]})
    assert FORGED not in env["s3"].objects["compliance-decisions/2024/10/27/03/evt.json"]["Body"].decode()


def test_wrong_event_source_is_refused(env, capsys):
    for bad in (None, "aws:sqs", "aws:dynamodb ", "AWS:DYNAMODB"):
        r = record(event_id="evt", image=executor_image())
        if bad is None:
            r.pop("eventSource")
        else:
            r["eventSource"] = bad
        _refused(env, capsys, [r])


@pytest.mark.parametrize("arn", [
    "not-an-arn",
    f"arn:aws:dynamodb:us-east-1:{ACCT}:table/other-table/stream/{STREAM_LABEL}",
    f"arn:aws:dynamodb:us-east-1:{ACCT}:table/executor-audit/stream/2099-01-01T00:00:00.000",   # wrong stream
    f"arn:aws:dynamodb:us-east-1:999999999999:table/executor-audit/stream/{STREAM_LABEL}",      # other account
    f"arn:aws:dynamodb:us-west-2:{ACCT}:table/executor-audit/stream/{STREAM_LABEL}",            # other region
    None, 5,
])
def test_wrong_event_source_arn_is_refused(env, capsys, arn):
    r = record(event_id="evt", image=executor_image())
    r["eventSourceARN"] = arn
    _refused(env, capsys, [r])


def test_arn_of_another_archived_table_for_this_key_shape_is_refused(env, capsys):
    """A real stream ARN for table A with table B's key attribute is not a key of A."""
    r = record(table="governance-audit", event_id="evt", keys={"action_id": {"S": "x"}}, image={"action_id": {"S": "x"}})
    _refused(env, capsys, [r])


@pytest.mark.parametrize("keys", [
    {"4111111111111111": {"S": "x"}},
    {"action_id": {"S": "a"}, "extra": {"S": "b"}},
    {"action_id": {"N": "5"}},
    {"action_id": {"S": ""}},
    {"action_id": {"S": "x" * 513}},
])
def test_wrong_key_shape_is_refused(env, capsys, keys):
    r = record(event_id="evt", keys=keys, image=executor_image())
    _refused(env, capsys, [r])


def test_remove_of_an_existing_item_is_refused_and_writes_nothing(env, capsys):
    arc.handler({"Records": [record(event_id="seed", image=executor_image())]})
    env["s3"].objects.clear()
    env["s3"].puts.clear()
    capsys.readouterr()
    r = record(event="REMOVE", event_id="evt")  # the item still exists: forged
    r["dynamodb"]["OldImage"] = executor_image(action_taken=FORGED)
    assert arc.handler({"Records": [r]}) == {"batchItemFailures": []}
    assert not env["s3"].puts
    names = metrics(capsys)
    assert "ArchiveSourceRefused" in names and "AuditRecordRemoved" not in names


def test_remove_tombstone_never_contains_caller_item_content(env):
    r = record(event="REMOVE", event_id="evt")
    r["dynamodb"]["OldImage"] = executor_image(action_taken=FORGED)
    r["dynamodb"]["NewImage"] = executor_image(action_taken=FORGED)
    arc.handler({"Records": [r]})
    raw = env["s3"].objects["executor-audit/2024/10/27/03/evt.json"]["Body"].decode()
    assert FORGED not in raw
    assert json.loads(raw)["item"] is None and "item_sha256" not in json.loads(raw)


def test_genuine_overwrite_refuses_the_stale_record_and_archives_the_current(env, capsys):
    """PutItem can replace an item (no writer does). The older record's image no
    longer matches the table, so it is refused and alarmed; the newer matches."""
    old = record(event_id="old", seq="1", image=executor_image(action_taken="OLD"))
    new = record(event_id="new", event="MODIFY", seq="2", image=executor_image(action_taken="NEW"))
    assert arc.handler({"Records": [old, new]}) == {"batchItemFailures": []}
    assert list(env["s3"].objects) == ["executor-audit/2024/10/27/03/new.json"]
    assert "ArchiveSourceRefused" in metrics(capsys)


def test_get_item_error_on_a_new_image_table_is_a_batch_failure(env, capsys):
    env["ddb"].error = client_error("ProvisionedThroughputExceededException", 400, "GetItem")
    r = record(event_id="evt", seq="7", image=executor_image())
    assert arc.handler({"Records": [r]}) == {"batchItemFailures": [{"itemIdentifier": "7"}]}
    assert not env["s3"].puts


def test_remove_is_a_tombstone_and_alarmed(env, capsys):
    r = record(event="REMOVE", event_id="evt")
    assert arc.handler({"Records": [r]}) == {"batchItemFailures": []}
    body = body_of(env, "executor-audit/2024/10/27/03/evt.json")
    assert body["image_source"] == "remove_event" and body["item"] is None
    assert body["keys"] == {"action_id": {"S": "11111111-2222-4333-8444-555555555555"}}
    assert "AuditRecordRemoved" in metrics(capsys)


def test_missing_new_image_is_a_batch_failure(env, capsys):
    assert arc.handler({"Records": [record(event_id="evt", seq="9")]}) == {
        "batchItemFailures": [{"itemIdentifier": "9"}]}
    assert not env["s3"].puts


# ─── Validation and configuration ────────────────────────────────────────────
def _mutations():
    def drop(path):
        def f(r):
            target = r
            for p in path[:-1]:
                target = target[p]
            target.pop(path[-1])
        return f

    def set_(path, value):
        def f(r):
            target = r
            for p in path[:-1]:
                target = target[p]
            target[path[-1]] = value
        return f
    return {
        "no_event_id": drop(["eventID"]),
        "bad_event_id": set_(["eventID"], "../../etc"),
        "bad_event_name": set_(["eventName"], "UPSERT"),
        "no_keys": set_(["dynamodb", "Keys"], {}),
        "bad_seq": set_(["dynamodb", "SequenceNumber"], "12a"),
        "no_created": drop(["dynamodb", "ApproximateCreationDateTime"]),
        "bool_created": set_(["dynamodb", "ApproximateCreationDateTime"], True),
        "bad_key_type": set_(["dynamodb", "Keys"], {"action_id": {"Q": "x"}}),
    }


@pytest.mark.parametrize("name", sorted(_mutations()))
def test_malformed_records_are_batch_failures(env, capsys, name):
    r = record(event_id="evt", seq="42", image=executor_image())
    _mutations()[name](r)
    # The record's own sequence number (an unknown one makes Lambda retry the batch).
    expected = r["dynamodb"]["SequenceNumber"]
    assert arc.handler({"Records": [r]}) == {"batchItemFailures": [{"itemIdentifier": expected}]}
    assert not env["s3"].puts
    assert "ArchiveRecordFailures" in metrics(capsys)


def test_non_object_record_fails_the_whole_batch(env):
    assert arc.handler({"Records": ["junk"]}) == {"batchItemFailures": [{"itemIdentifier": ""}]}


@pytest.mark.parametrize("var", ["ARCHIVE_BUCKET", "ARCHIVE_KMS_KEY_ARN", "ARCHIVE_TABLES", "EXPECTED_STREAM_ARNS"])
def test_missing_env_fails_closed(env, monkeypatch, capsys, var):
    monkeypatch.delenv(var)
    r = record(event_id="evt", seq="5", image=executor_image())
    assert arc.handler({"Records": [r]}) == {"batchItemFailures": [{"itemIdentifier": "5"}]}
    assert not env["s3"].puts
    assert "ArchiveRecordFailures" in metrics(capsys)


@pytest.mark.parametrize("arns", [
    f"arn:aws:dynamodb:us-east-1:{ACCT}:table/not-archived/stream/{STREAM_LABEL}",
    ",".join(STREAM_ARNS.split(",")[:4]),   # one archived table has no expected stream
    STREAM_ARNS + ",junk",
])
def test_bad_expected_stream_arns_fail_closed(env, monkeypatch, arns):
    monkeypatch.setenv("EXPECTED_STREAM_ARNS", arns)
    assert arc.handler({"Records": [record(event_id="e", image=executor_image())]})["batchItemFailures"]
    assert not env["s3"].puts


def test_no_if_none_match_in_model_fails_closed(env, monkeypatch, capsys):
    s3 = FakeS3(if_none_match=False)
    monkeypatch.setattr(arc, "_S3", s3)
    records = [record(event_id="a", seq="1", image=executor_image()),
               record(event_id="b", seq="2", image=executor_image())]
    assert arc.handler({"Records": records}) == {"batchItemFailures": [{"itemIdentifier": "1"}]}
    assert s3.puts == []
    assert "ArchiveRecordFailures" in metrics(capsys)


def test_real_botocore_model_supports_if_none_match():
    import boto3
    client = boto3.client("s3", region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="x")
    assert arc.if_none_match_supported(client)


def test_emf_shape(capsys):
    arc.emit_metric("PanRefused")
    (doc,) = emf_lines(capsys)
    assert doc["PanRefused"] == 1
    (directive,) = doc["_aws"]["CloudWatchMetrics"]
    assert directive == {"Namespace": "FSI/AuditArchive", "Dimensions": [[]],
                         "Metrics": [{"Name": "PanRefused", "Unit": "Count"}]}
    assert isinstance(doc["_aws"]["Timestamp"], int)


def test_logs_carry_no_item_values(env, caplog, capsys):
    caplog.set_level(logging.DEBUG)
    secret = "SECRET-NARRATIVE-VALUE"
    env["s3"].put_errors = [client_error("InternalError", 500)]
    arc.handler({"Records": [record(event_id="evt", image=executor_image(narrative=secret))]})
    arc.handler({"Records": [record(event="REMOVE", event_id="evt2")]})
    arc.handler({"Records": [record(event_id="evt3", image=executor_image(narrative=PANS[0]))]})
    out = capsys.readouterr().out
    for text in (caplog.text, out):
        assert secret not in text and PANS[0] not in text
        assert "11111111-2222-4333-8444-555555555555" not in text


# ─── PAN defense ─────────────────────────────────────────────────────────────
def _assert_refused(env, key, location, capsys):
    body = body_of(env, key)
    assert body["image_source"] == "pan_refused" and body["pan_location"] == location
    assert body["item"] is None and "item_sha256" not in body
    assert env["s3"].objects[key]["Metadata"]["image-source"] == "pan_refused"
    assert "PanRefused" in metrics(capsys)
    return body


@pytest.mark.parametrize("pan", PANS)
@pytest.mark.parametrize("where", ["S", "N", "nested_map", "list", "string_set", "attribute_name", "id_field"])
def test_pan_in_item_is_refused(env, capsys, pan, where):
    digits = "".join(c for c in pan if c.isdigit())
    extra = {
        "S": {"note": {"S": pan}},
        "N": {"amount": {"N": digits}},
        "nested_map": {"meta": {"M": {"inner": {"M": {"memo": {"S": f"card {pan} used"}}}}}},
        "list": {"history": {"L": [{"S": "ok"}, {"M": {"x": {"S": pan}}}]}},
        "string_set": {"labels": {"SS": ["a", pan]}},
        "attribute_name": {pan: {"S": "v"}},
        "id_field": {"txn_id": {"S": pan}},
    }[where]
    image = {"action_id": {"S": "11111111-2222-4333-8444-555555555555"}, **extra}
    assert arc.handler({"Records": [record(event_id="evt", image=image)]}) == {"batchItemFailures": []}
    body = _assert_refused(env, "executor-audit/2024/10/27/03/evt.json", "item", capsys)
    assert body["keys"] == {"action_id": {"S": "11111111-2222-4333-8444-555555555555"}}
    assert digits not in env["s3"].objects["executor-audit/2024/10/27/03/evt.json"]["Body"].decode()


@pytest.mark.parametrize("keys", [
    {"action_id": {"S": "4111111111111111"}},
    {"action_id": {"S": "nonce#4111111111111111"}},
])
def test_pan_in_keys_nulls_keys(env, capsys, caplog, keys):
    caplog.set_level(logging.DEBUG)
    image = {**keys, "note": {"S": "fine"}}
    r = record(event_id="evt", keys=keys, image=image)
    assert arc.handler({"Records": [r]}) == {"batchItemFailures": []}
    obj = env["s3"].objects["executor-audit/2024/10/27/03/evt.json"]
    body = _assert_refused(env, "executor-audit/2024/10/27/03/evt.json", "both", capsys)
    assert body["keys"] is None
    for text in (obj["Body"].decode(), json.dumps(obj["Metadata"]), caplog.text):
        assert "4111111111111111" not in text


def test_pan_only_in_key_reports_keys(env, capsys):
    keys = {"action_id": {"S": "4111111111111111"}}
    r = record(event_id="evt", keys=keys, image={"note": {"S": "fine"}})
    arc.handler({"Records": [r]})
    _assert_refused(env, "executor-audit/2024/10/27/03/evt.json", "keys", capsys)


def test_pan_refusal_on_get_item_and_remove_paths(env, capsys):
    env["ddb"].item = {"compliance_id": "c-1", "sar_narrative": "card 4111111111111111"}
    r = record(table="compliance-decisions", event_id="evt", keys={"compliance_id": {"S": "c-1"}})
    arc.handler({"Records": [r]})
    _assert_refused(env, "compliance-decisions/2024/10/27/03/evt.json", "item", capsys)
    env["ddb"].item = None
    rm = record(event="REMOVE", event_id="rm", keys={"action_id": {"S": "5500005555555559"}})
    arc.handler({"Records": [rm]})
    assert body_of(env, "executor-audit/2024/10/27/03/rm.json")["keys"] is None


@pytest.mark.parametrize("value", [
    "4111111111111111",                                  # bare PAN in an id field
    "nonce#4111111111111111",                            # nonce prefix but not a digest
    "sha256:4111111111111111",                           # digest prefix but not a digest
    "4111111111111111#rejections#0001",                  # chunk suffix on a non-uuid
    "detection#4111111111111111",                        # prefix on a non-uuid
    "11111111-2222-4333-8444-555555555555 4111111111111111",
])
@pytest.mark.parametrize("name", ["event_id", "detection_id", "txn_ref", "event_hash", "completed_clusters",
                                  "prompt_fingerprint", "fingerprint"])
def test_exempt_names_still_scan_non_format_values(name, value):
    assert arc.item_has_pan({name: {"S": value}})


def test_pan_as_completed_clusters_member_is_refused(env, capsys):
    env["ddb"].item = {"compliance_id": "c-1",
                       "completed_clusters": {str(uuid.uuid4()), "4111111111111111"}}
    r = record(table="compliance-decisions", event="MODIFY", event_id="evt", keys={"compliance_id": {"S": "c-1"}})
    arc.handler({"Records": [r]})
    _assert_refused(env, "compliance-decisions/2024/10/27/03/evt.json", "item", capsys)


def test_list_members_are_scanned_under_the_containing_name():
    # Exempt only because the containing attribute is an id field ...
    assert not arc.item_has_pan({"cluster_ids_ref": {"L": [{"S": hashlib.sha256(b"1").hexdigest()}]}})
    # ... a PAN member of the same list is refused.
    assert arc.item_has_pan({"cluster_ids_ref": {"L": [{"S": "4111111111111111"}]}})
    # A free-text containing name never exempts its members.
    digests = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(400)]
    assert any(arc.contains_full_pan(d) for d in digests)
    assert arc.item_has_pan({"notes": {"SS": digests}})


# ─── Statistical acceptance: real writer id formats give zero refusals ───────
def _writer_items(rng: random.Random):
    """(keys, item) pairs in the formats the five writers actually emit."""
    hmac_key = secrets.token_bytes(32)

    def txn_ref():
        # pan_filter._txn_ref: HMAC-SHA256, full 64-hex digest.
        return hmac.new(hmac_key, secrets.token_bytes(8), hashlib.sha256).hexdigest()

    def ts():
        return f"2026-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}T{rng.randint(0, 23):02d}:" \
               f"{rng.randint(0, 59):02d}:{rng.randint(0, 59):02d}.{rng.randint(0, 999999):06d}+00:00"

    def completed():
        members = set()
        for _ in range(rng.randint(1, 20)):
            if rng.random() < 0.5:
                members.add(executor._completion_key(str(uuid.uuid4())))
            else:
                members.add(executor._completion_key({"unhashable": rng.random()}))
        return members

    shapes = []
    for _ in range(2000):   # governance-audit identity-proof nonces
        eid = nonce_event_id(secrets.token_urlsafe(32))
        shapes.append(({"event_id": eid}, {"event_id": eid, "expires_at": Decimal(rng.randint(1, 2 ** 31)),
                                           "action": "TRIP"}))
    for _ in range(2000):   # detection-results overflow chunks
        parent = str(uuid.uuid4())
        did = f"{parent}#{rng.choice(['rejections', 'schema-rejections'])}#{rng.randint(1, 9999):04d}"
        refs = [{"index": Decimal(rng.randint(0, 100000)), "txn_ref": txn_ref(), "rule": "W1"}
                for _ in range(rng.randint(1, 5))]
        shapes.append(({"detection_id": did}, {"detection_id": did, "record_type": "PAN_REJECTION_REFS",
                                               "parent_detection_id": parent, "refs": refs}))
    for _ in range(2000):   # compliance-decisions with completed_clusters
        cid = str(uuid.uuid4())
        shapes.append(({"compliance_id": cid}, {
            "compliance_id": cid, "detection_id": str(uuid.uuid4()), "timestamp": ts(),
            "record_day": ts()[:10], "completed_clusters": completed(),
            "lease_expires_at": Decimal(rng.randint(1_700_000_000, 1_900_000_000)),
            "clusters": [{"cluster_id": str(uuid.uuid4()), "decision": "FILE_SAR"} for _ in range(3)]}))
    for _ in range(2000):   # executor-audit
        aid = str(uuid.uuid4())
        shapes.append(({"action_id": aid}, {
            "action_id": aid, "timestamp": ts(), "record_day": ts()[:10], "action_taken": "SAR_FILED",
            "event_hash": hashlib.sha256(secrets.token_bytes(16)).hexdigest(),
            "payload_sha256": "sha256:" + hashlib.sha256(secrets.token_bytes(16)).hexdigest(),
            "provenance_chain": {"detection_id": str(uuid.uuid4()), "compliance_id": str(uuid.uuid4()),
                                 "action_id": aid}}))
    for _ in range(2000):   # governance / operator audit events
        prefix = rng.choice(["", "detection#", "release-request#", "release-approval#", "reconcile#",
                             "alarm-uncorroborated#"])
        eid = prefix + str(uuid.uuid4())
        shapes.append(({"event_id": eid}, {
            "event_id": eid, "timestamp": ts(), "record_day": ts()[:10],
            # Writers store the console's ref as console_request_ref, and
            # only refs that pass payload_limits.request_ref_ok reach them.
            "console_request_ref": new_request_ref(),
            "release_request_id": "release-request#" + str(uuid.uuid4()),
            "dispatch_token_sha256": hashlib.sha256(secrets.token_bytes(8)).hexdigest(),
            "epoch": Decimal(rng.randint(1_700_000_000, 1_900_000_000))}))
    return shapes


def test_ten_thousand_writer_records_give_zero_refusals():
    rng = random.Random(20261104)
    shapes = _writer_items(rng)
    assert len(shapes) == 10_000
    refused = [i for i, (keys, item) in enumerate(shapes)
               if arc.item_has_pan(arc.normalize_item(typed(keys)))
               or arc.item_has_pan(arc.normalize_item(typed(item)))]
    assert refused == []


def test_detection_items_with_500_rejection_refs_give_zero_refusals():
    key = secrets.token_bytes(32)
    for _ in range(20):
        did = str(uuid.uuid4())
        refs = [{"index": Decimal(i), "txn_ref": hmac.new(key, str(i).encode(), hashlib.sha256).hexdigest(),
                 "rule": "W1"} for i in range(500)]
        item = {"detection_id": did, "pan_rejection_refs": refs, "pan_rejection_ref_chunks": Decimal(0)}
        assert not arc.item_has_pan(arc.normalize_item(typed(item)))


def _decision_with_fingerprints(rng: random.Random, clusters: int):
    """A compliance-decisions item shaped like the compliance agent's
    clusters_assessed output: a SAR and a challenger prompt_fingerprint
    (sar_prompts.get_prompt_fingerprint, sha256 hex) per cluster."""
    def meta(model):
        return {"model_id": model, "latency_ms": Decimal(rng.randint(100, 20000)), "guardrail_action": "NONE",
                "prompt_fingerprint": get_prompt_fingerprint(secrets.token_hex(rng.randint(8, 64)))}
    cid = str(uuid.uuid4())
    return {
        "compliance_id": cid, "detection_id": str(uuid.uuid4()), "record_day": "2026-11-05",
        "clusters_assessed": [{
            "cluster_id": str(uuid.uuid4()), "decision": rng.choice(["FILE_SAR", "NEEDS_REVIEW"]),
            "sar_narrative": "This Suspicious Activity Report is filed pursuant to 31 CFR 1020.320.",
            "model_metadata": {"sar_call": meta("us.anthropic.claude-sonnet-4-5-20250929-v1:0"),
                               "challenger_call": meta("us.amazon.nova-pro-v1:0")},
        } for _ in range(clusters)],
    }


def test_twenty_thousand_prompt_fingerprints_give_zero_refusals():
    rng = random.Random(20261105)
    items = [_decision_with_fingerprints(rng, rng.randint(1, 5)) for _ in range(4000)]
    fingerprints = [c["model_metadata"][call]["prompt_fingerprint"]
                    for item in items for c in item["clusters_assessed"] for call in ("sar_call", "challenger_call")]
    assert len(fingerprints) >= 20_000
    # Sanity: these digests do trip the bare PAN detector (~5 %), so the exemption is what keeps them.
    assert sum(arc.contains_full_pan(f) for f in fingerprints) > 100
    assert [i for i, item in enumerate(items) if arc.item_has_pan(arc.normalize_item(typed(item)))] == []


@pytest.mark.parametrize("pan", PANS)
def test_pan_next_to_fingerprints_is_still_refused(env, capsys, pan):
    rng = random.Random(7)
    # A PAN in a non-exempt attribute of a list member (clusters_assessed[i].sar_narrative) ...
    item = _decision_with_fingerprints(rng, 3)
    item["clusters_assessed"][1]["sar_narrative"] = f"card {pan} used"
    assert arc.item_has_pan(arc.normalize_item(typed(item)))
    # ... a PAN as a plain list member ...
    item = _decision_with_fingerprints(rng, 2)
    item["notes"] = ["ok", pan]
    assert arc.item_has_pan(arc.normalize_item(typed(item)))
    # ... and a PAN in a fingerprint-named field or as a member of a fingerprint-named list.
    item = _decision_with_fingerprints(rng, 2)
    item["clusters_assessed"][0]["model_metadata"]["sar_call"]["prompt_fingerprint"] = pan
    assert arc.item_has_pan(arc.normalize_item(typed(item)))
    assert arc.item_has_pan({"prompt_fingerprint": {"L": [{"S": get_prompt_fingerprint("a")}, {"S": pan}]}})
    # A name that only contains "fingerprint" without ending in it is not an id field.
    assert arc.item_has_pan({"fingerprint_note": {"S": hashlib.sha256(b"x").hexdigest() + " " + pan}})
    # End to end on the GetItem path the compliance-decisions table uses.
    env["ddb"].item = _decision_with_fingerprints(rng, 2)
    env["ddb"].item["clusters_assessed"][0]["sar_narrative"] = f"card {pan} used"
    r = record(table="compliance-decisions", event_id="evt", keys={"compliance_id": {"S": "c-1"}})
    arc.handler({"Records": [r]})
    _assert_refused(env, "compliance-decisions/2024/10/27/03/evt.json", "item", capsys)


def test_decision_with_fingerprints_archives_in_full(env, capsys):
    rng = random.Random(11)
    # Pick an item whose fingerprints would have tripped the old name list.
    while True:
        item = _decision_with_fingerprints(rng, 3)
        if any(arc.contains_full_pan(c["model_metadata"][call]["prompt_fingerprint"])
               for c in item["clusters_assessed"] for call in ("sar_call", "challenger_call")):
            break
    env["ddb"].item = item
    r = record(table="compliance-decisions", event_id="evt", keys={"compliance_id": {"S": item["compliance_id"]}})
    assert arc.handler({"Records": [r]}) == {"batchItemFailures": []}
    body = body_of(env, "compliance-decisions/2024/10/27/03/evt.json")
    assert body["image_source"] == "get_item_consistent" and body["item"] is not None
    assert "PanRefused" not in metrics(capsys)


def test_exemption_is_needed_for_these_formats():
    """Sanity: without the exemption the same generators would be refused."""
    samples = [nonce_event_id(secrets.token_urlsafe(16)) for _ in range(2000)]
    assert any(arc.contains_full_pan(s) for s in samples)


# ─── Caller-supplied request refs are always scanned ─────────────────────────
PAN_SHAPED_REFS = ["abcdef01-4111-4111-a111-111111111111", "10a3d6b2-aa05-411a-b271-5945795e8229"]


@pytest.mark.parametrize("ref", PAN_SHAPED_REFS)
@pytest.mark.parametrize("name", ["console_request_ref", "request_ref"])
def test_pan_shaped_request_ref_is_never_exempt(name, ref):
    assert REQUEST_REF_RE.fullmatch(ref) and arc.contains_full_pan(ref)
    assert arc.item_has_pan({"action_id": {"S": str(uuid.uuid4()).replace("4", "a")}, name: {"S": ref}})


@pytest.mark.parametrize("ref", PAN_SHAPED_REFS)
def test_pan_shaped_console_request_ref_is_refused_not_archived(env, capsys, ref):
    image = {"action_id": {"S": "11111111-2222-4333-8444-555555555555"}, "console_request_ref": {"S": ref}}
    assert arc.handler({"Records": [record(event_id="evt", image=image)]}) == {"batchItemFailures": []}
    _assert_refused(env, "executor-audit/2024/10/27/03/evt.json", "item", capsys)
    assert ref not in env["s3"].objects["executor-audit/2024/10/27/03/evt.json"]["Body"].decode()


def test_normal_console_request_refs_archive_in_full(env, capsys):
    for i in range(50):
        image = {"action_id": {"S": "11111111-2222-4333-8444-555555555555"},
                 "console_request_ref": {"S": new_request_ref()}}
        assert arc.handler({"Records": [record(event_id=f"e{i}", image=image)]}) == {"batchItemFailures": []}
        assert body_of(env, f"executor-audit/2024/10/27/03/e{i}.json")["item"] is not None
    assert "PanRefused" not in metrics(capsys)
