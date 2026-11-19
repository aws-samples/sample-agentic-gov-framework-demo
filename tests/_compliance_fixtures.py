"""Shared helpers for the compliance-agent remediation tests: a
fake AWS layer (DynamoDB resource + client, CloudWatch, Bedrock) that records
every call in order, stored detection items, and the compliance shim
do_POST harness. No real boto3 client is ever constructed."""
import copy
import importlib.util
import io
import json
import os
from decimal import Decimal

from botocore.exceptions import ClientError

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CHAMPION = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"
CHALLENGER = "us.amazon.nova-pro-v1:0"
NARRATIVE = ("Transaction monitoring identified a suspicious circular structuring "
             "pattern across masked accounts, warranting a SAR filing.")
SAR_OK = json.dumps({"sar_narrative": NARRATIVE, "typology_classification": "circular_structuring",
                     "regulatory_references": ["BSA-1"], "red_flags_identified": ["rapid cycling"]})
AGREE_HIGH = json.dumps({"verdict": "AGREE", "confidence": "HIGH", "rationale": "Independently concurs."})
DISPUTE_HIGH = json.dumps({"verdict": "DISPUTE", "confidence": "HIGH", "rationale": "Plausible payroll."})


def cluster(cid="c1", typology="circular_structuring", **extra):
    base = {
        "cluster_id": cid,
        "accounts": ["acc-a", "acc-b", "acc-c"],
        "account_count": 3,
        "typology": typology,
        "total_amount_usd": 27000.0,
        "time_span_seconds": 10.0,
        "merchant_categories": ["wire_transfer"],
        "confidence_factors": {"avg_intra_amount": 9000.0, "circular_ratio": 1.0,
                               "fan_out_max": 1, "fan_in_max": 1},
    }
    base.update(extra)
    return base


def detection_output(clusters=None, detection_id="det-0001"):
    return {"detection_id": detection_id, "timestamp": "2026-01-01T00:00:00+00:00",
            "flagged_clusters": [cluster()] if clusters is None else clusters}


def stored_item(output, **extra):
    """What the detection agent stored: Decimal numbers, plus extras such as
    input_quality / record_day."""
    # DynamoDB returns every number (integral or not) as Decimal.
    item = _decimalize(copy.deepcopy(output))
    item.update(_decimalize(extra))
    return item


def _decimalize(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return Decimal(str(value))
    if isinstance(value, dict):
        return {k: _decimalize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_decimalize(v) for v in value]
    return value


def converse_reply(text):
    return {"stopReason": "end_turn", "output": {"message": {"content": [{"text": text}]}}}


class FakeBedrock:
    def __init__(self, aws, sar_text=SAR_OK, challenger_text=AGREE_HIGH):
        self.aws = aws
        self.sar_text = sar_text
        self.challenger_text = challenger_text
        self.calls = []

    def converse(self, **kwargs):
        self.calls.append(kwargs)
        self.aws.events.append(("converse", kwargs["modelId"]))
        text = self.sar_text if kwargs["modelId"] == CHAMPION else self.challenger_text
        return converse_reply(text)


class _Table:
    def __init__(self, aws, name):
        self.aws, self.name = aws, name

    def get_item(self, Key, ConsistentRead=False):
        self.aws.events.append(("get_item", self.name, dict(Key), ConsistentRead))
        if self.aws.get_item_error is not None:
            raise self.aws.get_item_error
        key = next(iter(Key.values()))
        item = self.aws.tables.get(self.name, {}).get(key)
        return {"Item": copy.deepcopy(item)} if item is not None else {}

    def put_item(self, Item, ConditionExpression=None):
        self.aws.events.append(("put_item", self.name, ConditionExpression))
        if self.aws.write_error is not None:
            raise self.aws.write_error
        self.aws.puts.append(Item)


class _Resource:
    def __init__(self, aws):
        self.aws = aws

    def Table(self, name):
        return _Table(self.aws, name)


class _DynamoClient:
    def __init__(self, aws):
        self.aws = aws

    def transact_write_items(self, TransactItems):
        self.aws.events.append(("transact_write_items",))
        if self.aws.write_error is not None:
            raise self.aws.write_error
        self.aws.transactions.append(TransactItems)


class _CloudWatch:
    def __init__(self, aws):
        self.aws = aws

    def put_metric_data(self, Namespace, MetricData):
        self.aws.events.append(("put_metric_data",))
        self.aws.metrics.append({m["MetricName"]: m["Value"] for m in MetricData})


class FakeAws:
    """Install with install(monkeypatch, handler_module)."""

    def __init__(self):
        self.events = []
        self.tables = {"detection-results": {}, "compliance-decisions": {}}
        self.puts = []
        self.transactions = []
        self.metrics = []
        self.clients_built = []
        self.get_item_error = None
        self.write_error = None
        self.bedrock = FakeBedrock(self)

    def install(self, monkeypatch, handler_module, durable=True):
        if durable:
            monkeypatch.setenv("WRITE_AUDIT", "true")
        else:
            monkeypatch.delenv("WRITE_AUDIT", raising=False)
        monkeypatch.setattr(handler_module, "GUARDRAIL_ID", "gr-test")
        monkeypatch.setattr(handler_module, "GUARDRAIL_VERSION", "1")
        monkeypatch.setattr(handler_module, "MODEL_ID", CHAMPION)
        monkeypatch.setattr(handler_module, "CHALLENGER_MODEL_ID", CHALLENGER)
        monkeypatch.setattr(handler_module, "DETECTION_TABLE", "detection-results")
        monkeypatch.setattr(handler_module, "COMPLIANCE_TABLE", "compliance-decisions")

        def client(service, *a, **k):
            self.clients_built.append(service)
            return {"bedrock-runtime": self.bedrock, "dynamodb": _DynamoClient(self),
                    "cloudwatch": _CloudWatch(self)}[service]

        def resource(service, *a, **k):
            self.clients_built.append("resource:" + service)
            return _Resource(self)

        monkeypatch.setattr(handler_module.boto3, "client", client)
        monkeypatch.setattr(handler_module.boto3, "resource", resource)
        return self

    def store_detection(self, output, **extra):
        self.tables["detection-results"][output["detection_id"]] = stored_item(output, **extra)

    def store_marker(self, detection_id):
        self.tables["compliance-decisions"][f"detection#{detection_id}"] = {
            "compliance_id": f"detection#{detection_id}", "record_type": "DETECTION_DECISION_MARKER"}

    def kinds(self):
        return [e[0] for e in self.events]

    def decision_item(self):
        """The decision item from the single transaction (deserialized)."""
        from boto3.dynamodb.types import TypeDeserializer
        deser = TypeDeserializer()
        assert len(self.transactions) == 1, self.transactions
        put = self.transactions[0][0]["Put"]
        return {k: deser.deserialize(v) for k, v in put["Item"].items()}


def canceled(reasons=("None", "ConditionalCheckFailed")):
    return ClientError(
        {"Error": {"Code": "TransactionCanceledException", "Message": "cancelled"},
         "CancellationReasons": [{"Code": r} for r in reasons]},
        "TransactWriteItems",
    )


def load_compliance_shim():
    path = os.path.join(PROJECT_ROOT, "agentcore", "compliance_agent", "main.py")
    spec = importlib.util.spec_from_file_location("_compliance_shim_fixture", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def post(shim, payload):
    """Drive AgentHandler.do_POST with a JSON body; returns (status, body)."""
    body = json.dumps(payload).encode()
    req = object.__new__(shim.AgentHandler)
    req.path = "/invocations"
    req.headers = {"Content-Length": str(len(body))}
    req.rfile = io.BytesIO(body)
    req.wfile = io.BytesIO()
    statuses = []
    req.send_response = statuses.append
    req.send_header = lambda k, v: None
    req.end_headers = lambda: None
    req.do_POST()
    raw = req.wfile.getvalue()
    return statuses[0], (json.loads(raw) if raw else None)
