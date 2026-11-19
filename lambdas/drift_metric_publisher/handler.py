"""
Drift metric publisher.

============================================================================
BLUEPRINT 4 — DRIFT CONTROL (the only drift-metric publisher)
============================================================================
fsi-drift-metric-publisher consumes the KEYS_ONLY stream of
compliance-decisions. For each INSERT of a decision record it reads the
stored drift counters by key and publishes them to FSI/AgenticCompliance.
Its role is the only stack principal with cloudwatch:PutMetricData on that
namespace (apart from the opt-in demo console grant), so a drift datapoint
exists only when a stored decision record exists. No agent role publishes.

The metric Timestamp is always the stream record's ApproximateCreationDateTime
(the write time), never a field of the record. Rates are published only at
or above MIN_CLUSTERS_FOR_RATE, and per-invocation metrics
(ClustersPerInvocation, SubFloorInvocations) make workload shaping visible
in the per-invocation distribution, not only in Sum aggregates.
============================================================================
"""
import logging
import os
from datetime import datetime, timezone
from decimal import Decimal

import boto3
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

REGION = os.environ.get("AWS_REGION", "us-east-1")
COMPLIANCE_TABLE = os.environ.get("COMPLIANCE_TABLE", "compliance-decisions")
DRIFT_NAMESPACE = "FSI/AgenticCompliance"
VERIFIED = "VERIFIED"

# Code constants (no env read): the floor and the count keys are part of the
# signal's integrity, not deployment configuration.
MIN_CLUSTERS_FOR_RATE = 20
DRIFT_COUNT_KEYS = ("clusters", "disputes", "guardrail_hits", "challenger_failures", "output_rejections")
MAX_COUNT = 10000

_PROJECTION = "compliance_id, #ts, drift_counts, provenance_status"


def validate_drift_counts(raw):
    """The stored drift counts as plain ints, or None when malformed.

    Valid only when: a dict with exactly DRIFT_COUNT_KEYS; every value an
    integral int/Decimal (bool rejected) in [0, MAX_COUNT]; every other count
    <= clusters. Kept identical to circuit_breaker/handler.validate_drift_counts
    (tests/test_drift_counts_parity.py).
    """
    if not isinstance(raw, dict) or set(raw) != set(DRIFT_COUNT_KEYS):
        return None
    counts = {}
    for key in DRIFT_COUNT_KEYS:
        value = raw[key]
        if isinstance(value, bool) or not isinstance(value, (int, Decimal)):
            return None
        if isinstance(value, Decimal):
            if not value.is_finite() or value != value.to_integral_value():
                return None
            value = int(value)
        if value < 0 or value > MAX_COUNT:
            return None
        counts[key] = value
    if any(counts[k] > counts["clusters"] for k in DRIFT_COUNT_KEYS if k != "clusters"):
        return None
    return counts


def build_metric_data(counts: dict, timestamp: datetime) -> list:
    """The drift datapoints for one stored decision (same metric names, units
    and no dimensions as before), plus the per-invocation shaping metrics."""
    clusters = counts["clusters"]

    def datum(name, value, unit="Count"):
        return {"MetricName": name, "Value": value, "Unit": unit, "Timestamp": timestamp}

    data = [
        datum("ComplianceInvocations", 1),
        datum("ChallengerOutputRejectedCount", counts["output_rejections"]),
        datum("ChallengerDisputeCount", counts["disputes"]),
        datum("ClustersAssessed", clusters),
        datum("GuardrailInterventionCount", counts["guardrail_hits"]),
        datum("ChallengerFailureCount", counts["challenger_failures"]),
        datum("DetectionVolumeMultiplier", 1.0, "None"),
        # Per-invocation distribution (SampleCount and
        # percentiles), so many sub-floor or padded invocations are visible.
        datum("ClustersPerInvocation", clusters),
        datum("SubFloorInvocations", 1 if clusters < MIN_CLUSTERS_FOR_RATE else 0),
    ]
    if clusters >= MIN_CLUSTERS_FOR_RATE:
        data.append(datum("ChallengerDisputeRate", counts["disputes"] / clusters, "None"))
        data.append(datum("GuardrailInterventionRate", counts["guardrail_hits"] / clusters, "None"))
    return data


def _creation_time(record):
    try:
        value = float(record["dynamodb"]["ApproximateCreationDateTime"])
        return datetime.fromtimestamp(value, timezone.utc)
    except (KeyError, TypeError, ValueError, OverflowError, OSError):
        return None


def handler(event, context=None):
    """DynamoDB stream batch -> PutMetricData per VERIFIED INSERT.

    Returns {"batchItemFailures": [{"itemIdentifier": <SequenceNumber>}]}
    for records whose GetItem or PutMetricData failed (retried by the event
    source mapping, then the DLQ). Skipped records are never retried. Logs
    never carry item contents.
    """
    table = boto3.resource("dynamodb", region_name=REGION).Table(COMPLIANCE_TABLE)
    cloudwatch = boto3.client("cloudwatch", region_name=REGION)
    failures = []
    for record in (event or {}).get("Records", []) or []:
        if not isinstance(record, dict) or record.get("eventName") != "INSERT":
            continue
        ddb = record.get("dynamodb") or {}
        sequence = ddb.get("SequenceNumber")
        compliance_id = ((ddb.get("Keys") or {}).get("compliance_id") or {}).get("S")
        if not isinstance(compliance_id, str) or compliance_id.startswith("detection#"):
            continue
        try:
            item = table.get_item(
                Key={"compliance_id": compliance_id},
                ConsistentRead=True,
                ProjectionExpression=_PROJECTION,
                ExpressionAttributeNames={"#ts": "timestamp"},
            ).get("Item")
        except (ClientError, BotoCoreError) as e:
            logger.error("Drift publisher GetItem failed (%s)", type(e).__name__)
            failures.append({"itemIdentifier": sequence})
            continue
        if not item or item.get("provenance_status") != VERIFIED:
            logger.info("Drift publisher: %s is missing or not VERIFIED; skipped", compliance_id)
            continue
        counts = validate_drift_counts(item.get("drift_counts"))
        if counts is None:
            logger.error("Drift publisher: %s has malformed drift_counts; skipped", compliance_id)
            continue
        created = _creation_time(record)
        if created is None:
            logger.error("Drift publisher: %s has no usable ApproximateCreationDateTime; skipped",
                         compliance_id)
            continue
        try:
            cloudwatch.put_metric_data(Namespace=DRIFT_NAMESPACE,
                                       MetricData=build_metric_data(counts, created))
        except (ClientError, BotoCoreError) as e:
            logger.error("Drift publisher PutMetricData failed (%s)", type(e).__name__)
            failures.append({"itemIdentifier": sequence})
    return {"batchItemFailures": failures}
