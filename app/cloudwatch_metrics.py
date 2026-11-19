"""
CloudWatch Metrics — Shared helper for publishing drift metrics and querying alarm states.

Used by:
- Dashboard breach simulation buttons (publish breaching raw-count datapoints;
  gated in app/invoke_live.publish_breach_metric_live)
- Dashboard alarm display (query real alarm states)

Every call runs under the caller's explicit boto3 session (the operator's own
AWS authority, app/console_identity.governance_session); ambient host
credentials are never used. The console never force-sets alarm state: alarms
return to OK on their own, and who may change alarm state is IAM's decision.

Namespace: FSI/AgenticCompliance
Alarm names:
- fsi-challenger-dispute-rate-breach     (ChallengerDisputeCount / ClustersAssessed > 0.51, >= 20 clusters)
- fsi-guardrail-intervention-rate-breach (GuardrailInterventionCount / ClustersAssessed > 0.10, >= 20 clusters)
- fsi-detection-volume-anomaly           (DetectionVolumeMultiplier > 3.0)
Each: 1-minute periods, 2 of 3 datapoints breaching.
"""
import logging
import os
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

REGION = os.environ.get("AWS_REGION", "us-east-1")
NAMESPACE = "FSI/AgenticCompliance"

# Alarm names (must match CDK definitions in agents_stack.py)
ALARM_NAMES = {
    "challenger": "fsi-challenger-dispute-rate-breach",
    "guardrail": "fsi-guardrail-intervention-rate-breach",
    "volume": "fsi-detection-volume-anomaly",
}

# What each breach-simulation button publishes, per datapoint. These are the
# exact metrics the deployed alarms evaluate (cdk/agents_stack.py), with the
# same names, namespace, no dimensions and units as the compliance agent's
# publish_drift_metrics (lambdas/compliance_agent/handler.py):
#   challenger: IF(ClustersAssessed >= 20, ChallengerDisputeCount / ClustersAssessed, 0) > 0.51
#   guardrail:  IF(ClustersAssessed >= 20, GuardrailInterventionCount / ClustersAssessed, 0) > 0.10
#   volume:     Maximum(DetectionVolumeMultiplier) > 3.0
# All three use 1-minute periods and need 2 breaching datapoints out of 3, so
# one datapoint alone can never trip an alarm. The rate alarms ignore any
# minute with fewer than 20 clusters assessed.
BREACH_DATAPOINTS = {
    "challenger": [("ClustersAssessed", 20, "Count"), ("ChallengerDisputeCount", 12, "Count")],
    "guardrail": [("ClustersAssessed", 20, "Count"), ("GuardrailInterventionCount", 4, "Count")],
    "volume": [("DetectionVolumeMultiplier", 4.2, "None")],
}


def breach_metric_data(metric_key: str, timestamp: Optional[datetime] = None) -> list:
    """MetricData entries for ONE breaching datapoint of the given alarm."""
    if metric_key not in BREACH_DATAPOINTS:
        raise ValueError(f"Unknown metric key: {metric_key}")
    timestamp = timestamp or datetime.now(timezone.utc)
    return [
        {"MetricName": name, "Value": value, "Unit": unit, "Timestamp": timestamp}
        for name, value, unit in BREACH_DATAPOINTS[metric_key]
    ]


def publish_breach_datapoint(metric_key: str, timestamp: Optional[datetime] = None, *, session) -> bool:
    """
    Publish one breaching datapoint for an alarm (see BREACH_DATAPOINTS)
    under ``session`` (required; never ambient credentials).

    Args:
        metric_key: One of 'challenger', 'guardrail', 'volume'
        timestamp: Datapoint timestamp (default: now, UTC)

    Returns:
        True if published successfully, False otherwise.
    """
    try:
        metric_data = breach_metric_data(metric_key, timestamp)
    except ValueError:
        logger.error("Unknown breach metric key")
        return False
    try:
        cloudwatch = session.client("cloudwatch", region_name=REGION)
        cloudwatch.put_metric_data(Namespace=NAMESPACE, MetricData=metric_data)
        logger.info("Published breach datapoint for %s: %s", metric_key,
                    ", ".join(f"{m['MetricName']}={m['Value']}" for m in metric_data))
        return True
    except Exception as e:
        logger.error("Failed to publish breach datapoint for %s", metric_key, exc_info=e)
        return False


# Every alarm the breaker trusts as an automatic trigger (cdk/agents_stack.py
# TRUSTED_ALARM_NAMES): the three above plus the 1-hour sustained-dispute alarm.
TRUSTED_DRIFT_ALARMS = {
    **ALARM_NAMES,
    "sustained": "fsi-challenger-dispute-rate-sustained",
}


def get_alarm_states(*, session, alarm_names: Optional[dict] = None) -> dict:
    """
    Query the current state of the circuit breaker alarms (``alarm_names``,
    default the three rate/volume alarms) from CloudWatch under ``session`` (required; never ambient credentials).

    Returns:
        Dict mapping alarm key to state info:
        {
            "challenger": {"state": "ALARM"|"OK"|"INSUFFICIENT_DATA", "reason": "...", "updated": "..."},
            "guardrail": {"state": "OK", ...},
            "volume": {"state": "OK", ...},
        }
    """
    names = alarm_names or ALARM_NAMES
    try:
        cloudwatch = session.client("cloudwatch", region_name=REGION)
        response = cloudwatch.describe_alarms(
            AlarmNames=list(names.values()),
        )

        # Build lookup from alarm name to key
        name_to_key = {v: k for k, v in names.items()}

        states = {}
        for alarm in response.get("MetricAlarms", []):
            key = name_to_key.get(alarm["AlarmName"])
            if key:
                states[key] = {
                    "state": alarm.get("StateValue", "INSUFFICIENT_DATA"),
                    "reason": alarm.get("StateReason", ""),
                    "updated": alarm.get("StateUpdatedTimestamp", "").isoformat()
                    if alarm.get("StateUpdatedTimestamp") else "",
                }

        # Fill in any missing alarms (not yet created or not found)
        for key in names:
            if key not in states:
                states[key] = {
                    "state": "INSUFFICIENT_DATA",
                    "reason": "Alarm not found",
                    "updated": "",
                }

        return states
    except Exception as e:
        # Never put exception text in the result: it is rendered by the
        # console. Full detail stays in the server log.
        logger.error("Failed to query alarm states", exc_info=e)
        return {
            key: {"state": "UNKNOWN", "reason": "Query failed", "updated": ""}
            for key in names
        }

