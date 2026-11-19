"""Shared helpers for the detection-ingress tests: a fake
DynamoDB resource that records every put_item in call order, a valid ring of
transactions, and a loader for the detection /invocations shim."""
import importlib.util
import io
import json
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
P = "4532015112830366"
# Every 13-19-digit substring of P (P has 16 digits).
P_SUBSTRINGS = sorted({P[i:j] for i in range(len(P)) for j in range(i + 13, len(P) + 1)})


class FakeTable:
    def __init__(self, items, fail_when=None):
        self._items = items
        self._fail_when = fail_when

    def put_item(self, Item):
        if self._fail_when is not None and self._fail_when(Item):
            raise RuntimeError("ddb down")
        self._items.append(Item)


class FakeResource:
    def __init__(self, items, fail_when=None):
        self._items = items
        self._fail_when = fail_when

    def Table(self, name):
        return FakeTable(self._items, self._fail_when)


def capture_audit(monkeypatch, handler_module, fail_when=None):
    """Enable WRITE_AUDIT and capture every DynamoDB item the handler writes."""
    items = []
    monkeypatch.setenv("WRITE_AUDIT", "true")
    monkeypatch.setattr(handler_module.boto3, "resource",
                        lambda *a, **k: FakeResource(items, fail_when))
    return items


def ring_txns(prefix="acc-r", n=3, amount=9000.0, start_second=0, category="wire_transfer"):
    """A circular_structuring ring of n accounts (n distinct txns, <120 s)."""
    return [
        {"txn_id": f"{prefix}-t{i}", "sender_id": f"{prefix}{i}",
         "receiver_id": f"{prefix}{(i + 1) % n}", "amount": amount,
         "timestamp": f"2026-01-01T00:00:{start_second + i * 5:02d}",
         "merchant_category": category}
        for i in range(n)
    ]


def main_item(items, detection_id):
    mains = [i for i in items if i["detection_id"] == detection_id]
    assert len(mains) == 1, items
    return mains[0]


def load_detection_shim():
    path = os.path.join(PROJECT_ROOT, "agentcore", "detection_agent", "main.py")
    spec = importlib.util.spec_from_file_location("_detection_shim_fixture", path)
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


def keys_recursive(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            yield from keys_recursive(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from keys_recursive(v)
