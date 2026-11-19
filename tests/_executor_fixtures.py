"""Shared executor test fixtures: a fixed dispatch
token and its stored sha256, stored compliance records as the compliance
agent writes them for a VERIFIED run, and executor request events that
carry the token. No real boto3 client is ever constructed here."""
import copy
import hashlib
import os

from botocore.exceptions import ClientError

# 43 url-safe characters, the shape of secrets.token_urlsafe(32).
TOKEN = "Tq3vX9bLm2Kp7Rz0Wc5Yd8Hf1Ns4Gj6Ua_Eo-Ix3Vb2"  # gitleaks:allow -- fake fixture: random-looking string made up for tests, grants nothing
TOKEN_SHA256 = hashlib.sha256(TOKEN.encode("ascii")).hexdigest()

# What a VERIFIED compliance write adds to the decision item.
VERIFIED_FIELDS = {"provenance_status": "VERIFIED", "dispatch_token_sha256": TOKEN_SHA256}


def stored_record(clusters, compliance_id="comp-1", detection_id="det-1", **extra):
    """A stored VERIFIED compliance-decisions item for `clusters`."""
    record = {
        "compliance_id": compliance_id,
        "detection_id": detection_id,
        "clusters_assessed": list(clusters),
    }
    record.update(VERIFIED_FIELDS)
    record.update(extra)
    return record


def event(clusters, compliance_id="comp-1", detection_id="det-1", mode="live", token=TOKEN, **extra):
    """An executor request event whose compliance_output carries the
    dispatch token (omitted when token is None)."""
    compliance_output = {
        "compliance_id": compliance_id,
        "detection_id": detection_id,
        "clusters_assessed": [dict(c) for c in clusters],
    }
    if token is not None:
        compliance_output["dispatch_token"] = token
    compliance_output.update(extra)
    return {"mode": mode, "compliance_output": compliance_output}


CLUSTER_SAR = {
    "cluster_id": "cluster-a",
    "decision": "FILE_SAR",
    "sar_narrative": "Stored SAR narrative A",
    "challenger_rationale": "Stored rationale A",
    "challenger_opinion": "AGREE",
    "challenger_failed": False,
    "guardrail_triggered": False,
    "model_metadata": {"sar_call": {"model_id": "m", "latency_ms": 1}},
}
CLUSTER_REVIEW = dict(CLUSTER_SAR, cluster_id="cluster-r", decision="NEEDS_REVIEW",
                      challenger_opinion="DISPUTE")
CLUSTER_BREAKER = dict(CLUSTER_SAR, cluster_id="cluster-b", decision="CIRCUIT_BREAKER",
                       sar_narrative="", challenger_opinion="DISPUTE")


class FakeExecutorAws:
    """Fake boto3 layer for the executor handler: the compliance-decisions
    table (GetItem + the three lease UpdateItem shapes), the executor-audit
    table (put_item captured through the REAL write_audit_record) and a
    CloudWatch client. Side effects are stubbed; every call lands in
    `events` in order. Any other AWS client raises."""

    def __init__(self, record=None):
        self.record = copy.deepcopy(record)
        self.events = []
        self.audit_items = []
        self.updates = []
        self.metrics = []
        self.audit_fail = None  # callable(item) -> bool
        self.state = None       # executor_processed

    # ── boto3 surface ──
    def resource(self, service, *a, **k):
        assert service == "dynamodb", service
        return self

    def Table(self, name):  # noqa: N802 — boto3 API shape
        return _AuditTable(self) if name == "executor-audit" else _ComplianceTable(self)

    def client(self, service, *a, **k):
        if service != "cloudwatch":
            raise AssertionError(f"unexpected AWS client {service}")
        return self

    def put_metric_data(self, Namespace, MetricData):  # noqa: N803
        self.metrics.extend(m["MetricName"] for m in MetricData)

    # ── helpers ──
    def install(self, monkeypatch, ex):
        monkeypatch.setattr(ex.boto3, "resource", self.resource)
        monkeypatch.setattr(ex.boto3, "client", self.client)
        monkeypatch.setattr(os.path, "isdir",
                            lambda p, _orig=os.path.isdir: False if p == "/var/task" else _orig(p))

        def fake_sar(cluster, mode):
            self.events.append(("sar", cluster.get("cluster_id")))
            return {"status": "filed"}

        def fake_escalate(cluster, mode):
            self.events.append(("escalate", cluster.get("cluster_id")))
            return {"status": "escalated"}

        def fake_breaker(mode):
            self.events.append(("breaker", None))
            return {"status": "GOVERNANCE_HOLD"}

        monkeypatch.setattr(ex, "execute_file_sar", fake_sar)
        monkeypatch.setattr(ex, "execute_escalate", fake_escalate)
        monkeypatch.setattr(ex, "execute_circuit_breaker", fake_breaker)
        return self

    def kinds(self):
        return [e[0] for e in self.events]

    def side_effects(self):
        return [e for e in self.events if e[0] in ("sar", "escalate", "breaker")]

    def claimed(self):
        return any("executor_processed = :in_progress" in u["UpdateExpression"] for u in self.updates)

    def finalized(self):
        return any(":done" in u["UpdateExpression"] for u in self.updates)

    def audits(self, action_taken):
        return [i for i in self.audit_items if i.get("action_taken") == action_taken]


class _AuditTable:
    def __init__(self, aws):
        self.aws = aws

    def put_item(self, Item):  # noqa: N803
        self.aws.events.append(("audit", Item.get("action_taken")))
        if self.aws.audit_fail is not None and self.aws.audit_fail(Item):
            raise RuntimeError("audit table unavailable")
        self.aws.audit_items.append(Item)
        return {}


class _ComplianceTable:
    def __init__(self, aws):
        self.aws = aws

    def get_item(self, Key, ConsistentRead=False, ProjectionExpression=None):  # noqa: N803
        self.aws.events.append(("get_item", ProjectionExpression))
        if self.aws.record is None:
            return {}
        item = copy.deepcopy(self.aws.record)
        if ProjectionExpression:
            item = {k: v for k, v in item.items() if k == ProjectionExpression}
        return {"Item": item}

    def update_item(self, **kwargs):
        self.aws.events.append(("update", kwargs["UpdateExpression"]))
        self.aws.updates.append(kwargs)
        expr = kwargs["UpdateExpression"]
        if expr.startswith("SET executor_processed = :in_progress"):
            if self.aws.state in ("IN_PROGRESS", True):
                raise ClientError({"Error": {"Code": "ConditionalCheckFailedException",
                                             "Message": "already processed"}}, "UpdateItem")
            self.aws.state = "IN_PROGRESS"
        elif ":done" in expr:
            self.aws.state = True
        return {}
