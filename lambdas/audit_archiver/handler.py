"""
Immutable audit archiver (fsi-audit-archiver).
============================================================================
BLUEPRINT 5 — DEPLOYMENT CONTROL (immutable regulatory retention)
============================================================================
Consumes the DynamoDB streams of the five audit tables and writes one JSON
object per stream record to the WORM archive bucket (S3 Object Lock,
COMPLIANCE mode, SSE-KMS with a dedicated CMK):

    <table>/YYYY/MM/DD/HH/<eventID>.json

The time path comes from the record's ApproximateCreationDateTime (UTC), so
the key is deterministic across retries. Writes use If-None-Match: * — in a
versioned bucket Object Lock does not stop a second PUT to the same key, the
conditional write does. A 412 is a success only if the stored object is the
same record with the same content (or a re-read snapshot of a GetItem table);
anything else is kept under _conflicts/ and alarmed.

SOURCE OF TRUTH: the archiver archives only what it read itself
from the source table. For every table it takes the key from the stream
record, runs GetItem (ConsistentRead=True) and archives that item; item_sha256
is computed over it. On the four NEW_IMAGE tables the stream image must equal
the item read (they are append-only: PutItem only, no UpdateItem), otherwise
the record is refused. A record that is not from one of the five expected
stream ARNs (EXPECTED_STREAM_ARNS), has the wrong eventSource, forges an
image, names an item that does not exist, or claims a REMOVE of an item that
still exists is REFUSED: nothing is written to S3 (no attacker-chosen bytes
are ever sealed), the refusal is logged and counted (ArchiveSourceRefused,
ArchiveItemMissing) and alarmed, and the batch continues. A direct invoker
can forge the event source and ARN, so the GetItem re-read is the real
control; the ARN check only rejects careless or foreign events.
compliance-decisions (KEYS_ONLY; the executor UpdateItems its lease and
completion attributes) is archived as the item's current version at read
time, as before; a retry that reads a newer version keeps the first snapshot.

Retention comes only from the bucket's default Object Lock rule: the archiver
never sends ObjectLockMode, ObjectLockRetainUntilDate or
ObjectLockLegalHoldStatus.

PCI: before any write the record's keys and item are scanned with the shared
PAN filter (contains_full_pan). A match refuses the content (a placeholder
object without it is written, PanRefused is alarmed); redacting would
misrepresent the source record.

Logs carry only the table, the event id and exception type names, never item
content. Metrics are CloudWatch EMF lines (namespace FSI/AuditArchive).
============================================================================
"""
import base64
import hashlib
import json
import logging
import os
import re
import time
from datetime import datetime, timezone

import boto3
from botocore.exceptions import BotoCoreError, ClientError

if __package__:  # imported as lambdas.audit_archiver.handler (tests)
    from .pan_filter import contains_full_pan
else:  # Lambda: the asset root is on sys.path
    from pan_filter import contains_full_pan

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

SCHEMA = "fsi-audit-archive/v1"
METRIC_NAMESPACE = "FSI/AuditArchive"
CONFLICTS_PREFIX = "_conflicts/"

IMAGE_VERIFIED = "get_item_verified"  # NEW_IMAGE tables: item read == stream image
IMAGE_GET_ITEM = "get_item_consistent"  # KEYS_ONLY table: item as read
IMAGE_REMOVE = "remove_event"
IMAGE_PAN_REFUSED = "pan_refused"

EVENT_NAMES = frozenset({"INSERT", "MODIFY", "REMOVE"})
_EVENT_ID_RE = re.compile(r"[A-Za-z0-9-]{1,128}")
_SEQUENCE_RE = re.compile(r"[0-9]{1,64}")
_SOURCE_ARN_RE = re.compile(
    r"arn:aws[\w-]*:dynamodb:[^:]+:[0-9]{12}:table/([A-Za-z0-9_.-]{3,255})/stream/.+")
_TABLE_NAME_RE = re.compile(r"[A-Za-z0-9_.-]{3,255}")
EVENT_SOURCE = "aws:dynamodb"
# The single partition-key attribute of each audit table. A record's Keys must
# be exactly this one string attribute, bounded in length.
KEY_ATTRIBUTE = {
    "detection-results": "detection_id",
    "compliance-decisions": "compliance_id",
    "executor-audit": "action_id",
    "governance-audit": "event_id",
    "operator-audit": "event_id",
}
KEYS_ONLY_TABLES = frozenset({"compliance-decisions"})
_MAX_KEY_LEN = 512

# ─── PAN exemption for system-generated identifiers ──────────────────────────
# contains_full_pan is a whole-leaf detector, so random ids and digests
# trigger it at a few percent (a uuid4 has ~2 %, a sha256 hex ~5 %). A leaf
# skips the scan only when BOTH its attribute name is an id/hash field AND its
# value fullmatches one of this closed list of machine formats the writers
# emit:
#   <uuid>                      event/action/compliance/cluster ids
#   <prefix>#<uuid>             detection#, release-request#, release-approval#,
#                               reconcile#, alarm-uncorroborated# event ids
#   <uuid>#rejections#NNNN      detection-results overflow chunk keys
#   <uuid>#schema-rejections#NNNN
#   <sha256 hex>                event_hash, payload digests, txn_ref HMACs,
#                               prompt_fingerprint (sar_prompts.get_prompt_fingerprint)
#   sha256:<sha256 hex>         hashed completed_clusters members
#   nonce#<sha256 hex>          governance-audit identity-proof nonce keys
# Members of L/SS/NS are checked under the name of the attribute that
# contains them; a map member is checked under its own key. Attribute names
# themselves are always scanned. Any other value in an id field is scanned.
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_HEX64 = r"[0-9a-f]{64}"
_EXEMPT_VALUE = re.compile(
    rf"(?:[a-z-]+#)?{_UUID}"
    rf"|{_UUID}#(?:rejections|schema-rejections)#[0-9]{{4}}"
    rf"|(?:sha256:|nonce#)?{_HEX64}"
)
_EXEMPT_NAME = re.compile(r"(?:[a-z0-9]+_)*(?:id|ref|hash|sha256|fingerprint)|completed_clusters")
# Caller-supplied correlation refs are never exempt, whatever their shape: a
# uuid-shaped value can still encode a planted card number. The agents
# refuse a PAN-shaped request_ref and the console regenerates one, so a hit
# here means something bypassed them (refused + alarmed, never archived).
_ALWAYS_SCANNED_NAMES = frozenset({"request_ref", "console_request_ref"})


class RecordError(Exception):
    """The record can't be archived now: report a batch item failure."""


class Refused(Exception):
    """The record is not provably from the source table: archive nothing,
    count it, alarm, and move on (a retry could never make it genuine)."""


# ─── AWS clients (tests replace these) ───────────────────────────────────────
_S3 = None
_DDB = None


def _s3():
    global _S3
    if _S3 is None:
        _S3 = boto3.client("s3")
    return _S3


def _ddb():
    global _DDB
    if _DDB is None:
        _DDB = boto3.client("dynamodb")
    return _DDB


# ─── Metrics and logs ────────────────────────────────────────────────────────
def emit_metric(name: str, value: int = 1) -> None:
    """One CloudWatch EMF line, no dimensions (the alarms use none)."""
    print(json.dumps({
        "_aws": {
            "Timestamp": int(time.time() * 1000),
            "CloudWatchMetrics": [{
                "Namespace": METRIC_NAMESPACE,
                "Dimensions": [[]],
                "Metrics": [{"Name": name, "Unit": "Count"}],
            }],
        },
        name: value,
    }, separators=(",", ":")))


def _fail(reason: str, table: str = None, event_id: str = None) -> None:
    logger.error("archive_record_failed reason=%s table=%s event_id=%s", reason, table, event_id)
    emit_metric("ArchiveRecordFailures")


def _refuse(reason: str, table: str = None, event_id: str = None) -> None:
    """Alarmed refusal. event_id is logged only if it passed the id regex."""
    logger.error("archive_source_refused reason=%s table=%s event_id=%s", reason, table, event_id)
    emit_metric("ArchiveSourceRefused")


# ─── Configuration ───────────────────────────────────────────────────────────
def _config():
    """Validated env, or None (every record then fails closed)."""
    bucket = os.environ.get("ARCHIVE_BUCKET", "").strip()
    key_arn = os.environ.get("ARCHIVE_KMS_KEY_ARN", "").strip()
    tables = [t.strip() for t in os.environ.get("ARCHIVE_TABLES", "").split(",") if t.strip()]
    arns = [a.strip() for a in os.environ.get("EXPECTED_STREAM_ARNS", "").split(",") if a.strip()]
    if not bucket or not key_arn.startswith("arn:") or not tables or not arns:
        return None
    if not all(_TABLE_NAME_RE.fullmatch(t) for t in tables) or not set(tables) <= set(KEY_ATTRIBUTE):
        return None
    covered = set()
    for arn in arns:
        match = _SOURCE_ARN_RE.fullmatch(arn)
        if not match or match.group(1) not in tables:
            return None
        covered.add(match.group(1))
    if covered != set(tables):  # every archived table has an expected stream
        return None
    return {"bucket": bucket, "key_arn": key_arn, "tables": frozenset(tables),
            "stream_arns": frozenset(arns)}


def if_none_match_supported(s3) -> bool:
    """True only if the loaded botocore model has PutObject.IfNoneMatch.

    Without it a conditional write is impossible and the archiver never
    falls back to an unconditional PUT."""
    try:
        members = s3.meta.service_model.operation_model("PutObject").input_shape.members
    except Exception:  # noqa: BLE001 -- any model problem fails closed
        return False
    return "IfNoneMatch" in members


# ─── Canonical form ──────────────────────────────────────────────────────────
def canonical_json(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _b64(value) -> str:
    if isinstance(value, (bytes, bytearray)):
        return base64.b64encode(bytes(value)).decode("ascii")
    if isinstance(value, str):
        return value
    raise ValueError("binary attribute")


def normalize_attribute(av):
    """Typed AttributeValue JSON, identical for the stream and GetItem paths:
    sets sorted, binary as base64. Malformed input raises ValueError."""
    if not isinstance(av, dict) or len(av) != 1:
        raise ValueError("attribute value")
    ((kind, value),) = av.items()
    if kind in ("S", "N"):
        if not isinstance(value, str):
            raise ValueError("attribute value")
        return {kind: value}
    if kind == "B":
        return {"B": _b64(value)}
    if kind in ("SS", "NS"):
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ValueError("attribute value")
        return {kind: sorted(value)}
    if kind == "BS":
        if not isinstance(value, list):
            raise ValueError("attribute value")
        return {"BS": sorted(_b64(v) for v in value)}
    if kind == "M":
        return {"M": normalize_item(value)}
    if kind == "L":
        if not isinstance(value, list):
            raise ValueError("attribute value")
        return {"L": [normalize_attribute(v) for v in value]}
    if kind in ("NULL", "BOOL"):
        if not isinstance(value, bool):
            raise ValueError("attribute value")
        return {kind: value}
    raise ValueError("attribute type")


def normalize_item(item):
    if not isinstance(item, dict):
        raise ValueError("item")
    out = {}
    for name, av in item.items():
        if not isinstance(name, str):
            raise ValueError("attribute name")
        out[name] = normalize_attribute(av)
    return out


# ─── PAN scan ────────────────────────────────────────────────────────────────
def _leaf_has_pan(name: str, value: str) -> bool:
    if (name not in _ALWAYS_SCANNED_NAMES and _EXEMPT_NAME.fullmatch(name)
            and _EXEMPT_VALUE.fullmatch(value)):
        return False
    return contains_full_pan(value)


def _attribute_has_pan(name: str, av: dict) -> bool:
    """Scan one normalized attribute value under `name` (S, N, SS, NS, L and
    M recursively; B, BS, BOOL and NULL carry no text)."""
    ((kind, value),) = av.items()
    if kind in ("S", "N"):
        return _leaf_has_pan(name, value)
    if kind in ("SS", "NS"):
        return any(_leaf_has_pan(name, v) for v in value)
    if kind == "L":
        return any(_attribute_has_pan(name, v) for v in value)
    if kind == "M":
        return item_has_pan(value)
    return False


def item_has_pan(item: dict) -> bool:
    """True if any attribute name or (non-exempt) value holds a full PAN."""
    for name, av in item.items():
        if contains_full_pan(name) or _attribute_has_pan(name, av):
            return True
    return False


# ─── Record parsing ──────────────────────────────────────────────────────────
def _parse(record, config):
    """Validated fields of one stream record; RecordError if malformed."""
    if not isinstance(record, dict):
        raise RecordError("record_not_object")
    event_id = record.get("eventID")
    if not isinstance(event_id, str) or not _EVENT_ID_RE.fullmatch(event_id):
        raise RecordError("event_id")
    event_name = record.get("eventName")
    if event_name not in EVENT_NAMES:
        raise RecordError("event_name")
    arn = record.get("eventSourceARN")
    if record.get("eventSource") != EVENT_SOURCE:
        raise Refused("event_source")
    match = _SOURCE_ARN_RE.fullmatch(arn) if isinstance(arn, str) else None
    if not match or arn not in config["stream_arns"]:
        raise Refused("event_source_arn")
    table = match.group(1)
    ddb = record.get("dynamodb")
    if not isinstance(ddb, dict):
        raise RecordError("dynamodb")
    keys = ddb.get("Keys")
    if not isinstance(keys, dict) or not keys:
        raise RecordError("keys")
    sequence = ddb.get("SequenceNumber")
    if not isinstance(sequence, str) or not _SEQUENCE_RE.fullmatch(sequence):
        raise RecordError("sequence_number")
    created = ddb.get("ApproximateCreationDateTime")
    if isinstance(created, bool) or not isinstance(created, (int, float)) or created < 0:
        raise RecordError("approximate_creation_time")
    try:
        created_at = datetime.fromtimestamp(created, tz=timezone.utc)
        normalized_keys = normalize_item(keys)
    except (ValueError, OverflowError, OSError):
        raise RecordError("malformed") from None
    # Exactly the table's one string partition key: anything else can't be a
    # key of that table (GetItem would only fail with a ValidationException).
    key_value = keys.get(KEY_ATTRIBUTE[table])
    if (set(keys) != {KEY_ATTRIBUTE[table]} or not isinstance(key_value, dict)
            or set(key_value) != {"S"} or not isinstance(key_value["S"], str)
            or not 1 <= len(key_value["S"]) <= _MAX_KEY_LEN):
        raise Refused("key_shape")
    return {
        "table": table, "event_id": event_id, "event_name": event_name,
        "sequence": sequence, "created_at": created_at, "keys": normalized_keys,
        "raw_keys": keys, "new_image": ddb.get("NewImage"),
    }


def _iso(dt: datetime) -> str:
    base = dt.strftime("%Y-%m-%dT%H:%M:%S")
    return f"{base}.{dt.microsecond:06d}Z" if dt.microsecond else f"{base}Z"


def object_key(table: str, created_at: datetime, event_id: str) -> str:
    return f"{table}/{created_at:%Y/%m/%d/%H}/{event_id}.json"


# ─── Image resolution ────────────────────────────────────────────────────────
def _read_source_item(fields):
    """The item as the archiver itself reads it: GetItem by the record's key,
    strongly consistent. Normalized item, or None if it doesn't exist."""
    try:
        response = _ddb().get_item(TableName=fields["table"], Key=fields["raw_keys"], ConsistentRead=True)
    except (ClientError, BotoCoreError) as exc:
        raise RecordError(f"get_item:{type(exc).__name__}") from None
    item = response.get("Item") if isinstance(response, dict) else None
    if not item:
        return None
    try:
        return normalize_item(item)
    except ValueError:
        raise RecordError("malformed_item") from None


def _resolve_image(fields, config):
    """(image_source, item or None) for the record. Only ever returns content
    read from the source table; raises Refused if the record can't be tied to it.

    Tables that never update items (detection-results, executor-audit,
    governance-audit, operator-audit: PutItem-only grants, writers use unique
    ids) must hold exactly the stream's new image. compliance-decisions is
    updated in place by the executor (lease and completion attributes), so its
    KEYS_ONLY record is archived as the item's version at read time."""
    table, event_name = fields["table"], fields["event_name"]
    image = fields["new_image"]
    stream_item = None
    if event_name != "REMOVE" and table not in KEYS_ONLY_TABLES:
        if not isinstance(image, dict) or not image:
            raise RecordError("new_image_missing")
        try:
            stream_item = normalize_item(image)
        except ValueError:
            raise RecordError("malformed_item") from None
    item = _read_source_item(fields)
    if event_name == "REMOVE":
        if item is not None:
            raise Refused("remove_of_existing_item")
        # TTL isn't configured on these tables and no writer deletes, so a
        # delete is a tamper signal: tombstone (shape-checked keys only) + alarm.
        logger.error("audit_record_removed table=%s event_id=%s", table, fields["event_id"])
        emit_metric("AuditRecordRemoved")
        return IMAGE_REMOVE, None
    if item is None:
        logger.error("archive_item_missing table=%s event_id=%s", table, fields["event_id"])
        emit_metric("ArchiveItemMissing")
        raise Refused("item_missing")
    if table in KEYS_ONLY_TABLES:
        return IMAGE_GET_ITEM, item
    if item != stream_item:
        raise Refused("image_mismatch")
    return IMAGE_VERIFIED, item


def build_body(fields, image_source, item):
    """Canonical archive body bytes plus its metadata."""
    keys = fields["keys"]
    keys_pan = item_has_pan(keys)
    item_pan = item is not None and item_has_pan(item)
    body = {
        "schema": SCHEMA,
        "table": fields["table"],
        "event_id": fields["event_id"],
        "event_name": fields["event_name"],
        "sequence_number": fields["sequence"],
        "approximate_creation_time": _iso(fields["created_at"]),
    }
    if keys_pan or item_pan:
        image_source = IMAGE_PAN_REFUSED
        body.update({
            "image_source": IMAGE_PAN_REFUSED,
            "pan_location": "both" if keys_pan and item_pan else ("keys" if keys_pan else "item"),
            "keys": None if keys_pan else keys,
            "item": None,
        })
        logger.error("pan_refused table=%s event_id=%s", fields["table"], fields["event_id"])
        emit_metric("PanRefused")
    else:
        body.update({"image_source": image_source, "keys": keys, "item": item})
        if item is not None:
            body["item_sha256"] = sha256_hex(canonical_json(item))
    data = canonical_json(body)
    # The identity hash never includes keys, so no unkeyed hash of a key value exists.
    identity = sha256_hex(canonical_json({
        "table": fields["table"], "event_id": fields["event_id"],
        "event_name": fields["event_name"], "sequence_number": fields["sequence"],
    }))
    metadata = {"content-sha256": sha256_hex(data), "image-source": image_source,
                "identity-sha256": identity}
    return data, metadata


# ─── S3 writes ───────────────────────────────────────────────────────────────
def _error_code(exc: ClientError) -> str:
    error = exc.response.get("Error", {}) if isinstance(exc.response, dict) else {}
    return str(error.get("Code", ""))


def _status(exc: ClientError) -> int:
    meta = exc.response.get("ResponseMetadata", {}) if isinstance(exc.response, dict) else {}
    return meta.get("HTTPStatusCode", 0)


def _is_precondition_failed(exc: ClientError) -> bool:
    return _error_code(exc) == "PreconditionFailed" or _status(exc) == 412


def _put(config, key: str, data: bytes, metadata: dict) -> bool:
    """Conditional PUT. True = written, False = the key already exists (412).
    Any other error propagates. No Object Lock parameters are ever sent."""
    try:
        _s3().put_object(
            Bucket=config["bucket"],
            Key=key,
            Body=data,
            ContentType="application/json",
            IfNoneMatch="*",
            ChecksumAlgorithm="SHA256",
            ChecksumSHA256=base64.b64encode(hashlib.sha256(data).digest()).decode("ascii"),
            Metadata=metadata,
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId=config["key_arn"],
        )
        return True
    except ClientError as exc:
        if _is_precondition_failed(exc):
            return False
        raise


def _archive(fields, config) -> None:
    image_source, item = _resolve_image(fields, config)
    data, metadata = build_body(fields, image_source, item)
    key = object_key(fields["table"], fields["created_at"], fields["event_id"])
    try:
        if _put(config, key, data, metadata):
            return
        existing = _s3().head_object(Bucket=config["bucket"], Key=key).get("Metadata", {}) or {}
        same_identity = existing.get("identity-sha256") == metadata["identity-sha256"]
        if same_identity and existing.get("content-sha256") == metadata["content-sha256"]:
            logger.info("archive_duplicate table=%s event_id=%s", fields["table"], fields["event_id"])
            return
        if (same_identity and existing.get("image-source") == IMAGE_GET_ITEM
                and metadata["image-source"] == IMAGE_GET_ITEM):
            # A re-read of a GetItem-table item modified between retries: the
            # first read-time snapshot is kept (documented; metric, no alarm).
            logger.info("archive_snapshot_superseded table=%s event_id=%s",
                        fields["table"], fields["event_id"])
            emit_metric("ArchiveSnapshotSuperseded")
            return
        conflict_key = (f"{CONFLICTS_PREFIX}{fields['table']}/{fields['event_id']}/"
                        f"{metadata['content-sha256']}.json")
        _put(config, conflict_key, data, metadata)  # 412 here: already kept (hash in key)
        logger.error("archive_conflict table=%s event_id=%s", fields["table"], fields["event_id"])
        emit_metric("ArchiveConflicts")
    except (ClientError, BotoCoreError) as exc:
        raise RecordError(f"s3:{type(exc).__name__}:{_error_code(exc) if isinstance(exc, ClientError) else ''}") \
            from None


def _sequence_of(record) -> str:
    ddb = record.get("dynamodb") if isinstance(record, dict) else None
    sequence = ddb.get("SequenceNumber") if isinstance(ddb, dict) else None
    # An empty identifier makes Lambda retry the whole batch (fail closed).
    return sequence if isinstance(sequence, str) else ""


def handler(event, context=None):
    records = event.get("Records") if isinstance(event, dict) else None
    if not isinstance(records, list):
        _fail("event_shape")
        return {"batchItemFailures": [{"itemIdentifier": ""}]}
    if not records:
        return {"batchItemFailures": []}
    config = _config()
    if config is None or not if_none_match_supported(_s3()):
        _fail("configuration" if config is None else "if_none_match_unsupported")
        return {"batchItemFailures": [{"itemIdentifier": _sequence_of(records[0])}]}
    for record in records:
        fields = None
        try:
            fields = _parse(record, config)
            _archive(fields, config)
        except Refused as exc:
            # Nothing written; keep going (a refused record is never retried).
            event_id = record.get("eventID") if isinstance(record, dict) else None
            _refuse(str(exc), fields and fields["table"],
                    event_id if isinstance(event_id, str) and _EVENT_ID_RE.fullmatch(event_id) else None)
        except RecordError as exc:
            _fail(str(exc), fields and fields["table"], fields and fields["event_id"])
            # Stop at the first failure; idempotency makes reprocessing safe.
            return {"batchItemFailures": [{"itemIdentifier": _sequence_of(record)}]}
    return {"batchItemFailures": []}
