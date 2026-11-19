"""
Shared fakes for the circuit breaker tests.

FakeBreakerAws replaces circuit_breaker.handler's boto3.client/boto3.resource
with in-memory IAM / STS / CloudWatch / DynamoDB fakes that append to one
ordered call log, so tests can assert ordering (audit before detach, no write
before identity) and that nothing reaches AWS. Identity proofs are stubbed at
handler.identity_proof.verify_identity (real verification is covered by
tests/test_breaker_identity_proof.py).
"""
import copy
import os
import sys
from datetime import datetime as _RealDatetime, timedelta as _timedelta
from decimal import Decimal

from botocore.exceptions import ClientError

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import circuit_breaker.handler as cb  # noqa: E402

gs = cb.governance_state

ACCOUNT = "123456789012"
DENY_ARN = f"arn:aws:iam::{ACCOUNT}:policy/governance-hold-deny-all"

# role name -> (RoleId, Path) as iam:GetRole would report them.
ROLES = {
    "fsi-breaker-operator": ("AROAOPERATOR000000001", "/fsi-breaker/"),
    "fsi-breaker-approver": ("AROAAPPROVER000000001", "/fsi-breaker/"),
    "fsi-breaker-break-glass": ("AROABREAKGLASS0000001", "/fsi-breaker/"),
    "fsi-console-operator": ("AROACONSOLEOP00000001", "/fsi-console/"),
    "fsi-console-operator-hosted": ("AROACONSOLEHOST000001", "/fsi-console/"),
    "AWSReservedSSO_FsiBreakerApprover_abc123": ("AROASSOAPPROVER000001", "/aws-reserved/sso.amazonaws.com/"),
    "AWSReservedSSO_FsiBreakerOperator_abc123": ("AROASSOOPERATOR000001", "/aws-reserved/sso.amazonaws.com/"),
}


def client_error(code, op="Op"):
    return ClientError({"Error": {"Code": code, "Message": "boom"}}, op)


def principal(role, session, role_id=None, account=ACCOUNT):
    """A VerifiedPrincipal for an assumed-role session of ``role``."""
    return cb.identity_proof.VerifiedPrincipal(
        arn=f"arn:aws:sts::{account}:assumed-role/{role}/{session}",
        role_id=role_id or ROLES.get(role, ("AROAUNKNOWN0000000001", "/"))[0],
        account=account, session=session)


class FakeIam:
    def __init__(self, log, held=()):
        self.log, self.held = log, set(held)
        self.roles = {name: {"RoleName": name, "RoleId": rid, "Path": path}
                      for name, (rid, path) in ROLES.items()}
        self.detach_error = {}
        self.attach_error = {}   # role -> exception, raised once
        self.list_error = {}     # role -> exception

    def attach_role_policy(self, RoleName, PolicyArn):
        self.log.append(("attach", RoleName))
        if RoleName in self.attach_error:
            raise self.attach_error.pop(RoleName)
        self.held.add(RoleName)

    def detach_role_policy(self, RoleName, PolicyArn):
        self.log.append(("detach", RoleName))
        if RoleName in self.detach_error:
            raise self.detach_error[RoleName]
        self.held.discard(RoleName)

    def list_attached_role_policies(self, RoleName, **kwargs):
        if RoleName in self.list_error:
            raise self.list_error[RoleName]
        return {"AttachedPolicies": [{"PolicyArn": DENY_ARN, "PolicyName": "governance-hold-deny-all"}]
                if RoleName in self.held else []}

    def get_role(self, RoleName):
        self.log.append(("get_role", RoleName))
        if RoleName not in self.roles:
            raise client_error("NoSuchEntity", "GetRole")
        return {"Role": dict(self.roles[RoleName])}


class FakeGovernanceTable:
    def __init__(self, log):
        self.log, self.items = log, {}
        self.hold_queries = 0
        self.put_error = {}  # event_type -> exception
        self.on_put = {}     # event_type -> callable(item), run once after the write
        self.query_error = None
        self.index_hidden = set()  # event_ids not yet visible in by_event_type (index lag)

    def put_item(self, Item, ConditionExpression=None):
        self.log.append(("put", Item["event_type"], Item["event_id"]))
        if Item["event_type"] in self.put_error:
            raise self.put_error[Item["event_type"]]
        if ConditionExpression and Item["event_id"] in self.items:
            raise client_error("ConditionalCheckFailedException", "PutItem")
        self.items[Item["event_id"]] = dict(Item)
        hook = self.on_put.pop(Item["event_type"], None)
        if hook is not None:
            hook(Item)

    def get_item(self, Key, ConsistentRead=False):
        self.log.append(("get_item", Key["event_id"], ConsistentRead))
        item = self.items.get(Key["event_id"])
        return {"Item": dict(item)} if item else {}

    def query(self, **kwargs):
        assert kwargs["IndexName"] == "by_event_type"
        event_type = kwargs["KeyConditionExpression"].get_expression()["values"][1]
        if self.query_error is not None:
            raise self.query_error
        if event_type == "GOVERNANCE_HOLD":
            self.hold_queries += 1
            self.log.append(("query_holds",))
        else:
            self.log.append(("query_events", event_type))
        events = sorted((i for i in self.items.values()
                         if i["event_type"] == event_type and i["event_id"] not in self.index_hidden),
                        key=lambda i: str(i.get("timestamp", "")), reverse=True)
        return {"Items": [dict(i) for i in events[:1]]}

    def by_type(self, event_type):
        return [i for i in self.items.values() if i["event_type"] == event_type]


class FakeStateTable:
    """governance-state. update_item evaluates exactly the
    circuit_breaker.governance_state expressions (any other expression fails
    the test) and honours ReturnValuesOnConditionCheckFailure."""

    def __init__(self, log):
        self.log, self.item = log, None
        self.get_errors = []      # per get_item call: exception to raise, or None
        self.update_errors = []   # per update_item call: exception to raise, or None
        self.before_update = []   # callables(kind), each run once before an update applies

    def get_item(self, Key, ConsistentRead=False):
        assert Key == gs.STATE_KEY
        self.log.append(("state_get", ConsistentRead))
        if self.get_errors:
            error = self.get_errors.pop(0)
            if error is not None:
                raise error
        return {"Item": copy.deepcopy(self.item)} if self.item else {}

    def update_item(self, Key, UpdateExpression, ExpressionAttributeNames, ExpressionAttributeValues,
                    ConditionExpression=None, ReturnValues=None, ReturnValuesOnConditionCheckFailure=None):
        assert Key == gs.STATE_KEY and ExpressionAttributeNames == {"#s": "status"}
        kind, condition = {
            gs.CLAIM_TRIP_UPDATE: ("trip", None),
            gs.CLAIM_RELEASE_UPDATE: ("release", gs.CLAIM_RELEASE_CONDITION),
            gs.CLAIM_BREAK_GLASS_UPDATE: ("break_glass", gs.CLAIM_BREAK_GLASS_CONDITION),
        }[UpdateExpression]
        assert ConditionExpression == condition
        self.log.append(("state_update", kind))
        if self.before_update:
            self.before_update.pop(0)(kind)
        if self.update_errors:
            error = self.update_errors.pop(0)
            if error is not None:
                raise error
        v, old = ExpressionAttributeValues, self.item
        if kind == "trip":
            assert ReturnValues == "UPDATED_NEW"
            item = dict(old or {"state_id": "breaker"})
            item["generation"] = Decimal(int(item.get("generation", v[":zero"])) + v[":one"])
            item.update({"status": v[":held"], "hold_event_id": v[":eid"], "trip_started_at": v[":start"],
                         "held_at": v[":now"], "updated_at": v[":now"]})
            self.item = item
            return {"Attributes": {k: item[k] for k in ("generation", "status", "hold_event_id",
                                                        "trip_started_at", "held_at", "updated_at")}}
        ok = (old is not None and old.get("generation") == v[":g"]
              and old.get("hold_event_id") == v[":eid"]
              and (kind == "break_glass" or old.get("status") == v[":held"]))
        if not ok:
            response = {"Error": {"Code": "ConditionalCheckFailedException", "Message": "failed"}}
            if ReturnValuesOnConditionCheckFailure == "ALL_OLD" and old is not None:
                response["Item"] = copy.deepcopy(old)
            raise ClientError(response, "UpdateItem")
        item = dict(old)
        if kind == "release":
            item.update({"status": v[":released"], "released_generation": v[":g"],
                         "release_request_id": v[":rid"], "released_by": v[":by"],
                         "released_at": v[":now"], "updated_at": v[":now"]})
        else:
            item.update({"status": v[":released"], "break_glass_id": v[":bgid"],
                         "break_glass_by": v[":by"], "break_glass_at": v[":now"], "updated_at": v[":now"]})
        self.item = item
        return {}

    def claim(self, hold_event_id, held_at):
        """A trip's claim, as claim_trip makes it."""
        gen = int((self.item or {}).get("generation", 0)) + 1
        self.item = {"state_id": "breaker", **{k: v for k, v in (self.item or {}).items()
                                               if k.startswith(("released", "release_", "break_glass"))},
                     "generation": Decimal(gen), "status": "HELD", "hold_event_id": hold_event_id,
                     "trip_started_at": held_at, "held_at": held_at, "updated_at": held_at}
        return gen


class _ClockMeta(type):
    # Real datetimes still pass isinstance(x, handler.datetime).
    def __instancecheck__(cls, obj):
        return isinstance(obj, _RealDatetime)


class Clock:
    """Controllable wall clock for circuit_breaker.handler: install() swaps
    handler.datetime for a subclass whose now() returns ``self.t`` (then
    advances it by ``step``)."""

    def __init__(self, start, step=None):
        self.t, self.step = start, step or _timedelta(0)

    def set(self, value):
        self.t = value

    def advance(self, seconds):
        self.t += _timedelta(seconds=seconds)

    def now(self):
        value = self.t
        self.t += self.step
        return value

    def install(self, monkeypatch):
        clock = self

        class _ClockDatetime(_RealDatetime, metaclass=_ClockMeta):
            @classmethod
            def now(cls, tz=None):
                return clock.now()
        monkeypatch.setattr(cb, "datetime", _ClockDatetime)
        return self


def decision(clusters, disputes=0, guardrail_hits=0, *, minutes_ago=1.0, now=None, status="VERIFIED",
             compliance_id=None, counts=None):
    """A stored compliance decision as the by_day_ts index projects it."""
    from datetime import datetime, timedelta, timezone
    ts = (now or datetime.now(timezone.utc)) - timedelta(minutes=minutes_ago)
    drift = counts if counts is not None else {
        "clusters": clusters, "disputes": disputes, "guardrail_hits": guardrail_hits,
        "challenger_failures": 0, "output_rejections": 0}
    return {"compliance_id": compliance_id or f"c-{minutes_ago}-{clusters}-{disputes}",
            "record_day": ts.date().isoformat(), "timestamp": ts.isoformat(),
            "provenance_status": status, "drift_counts": drift}


def corroborating_decisions(now=None):
    """Records that corroborate every trusted alarm: two breaching minutes
    (25 clusters, 15 disputes, 5 guardrail hits each)."""
    return [decision(25, 15, 5, minutes_ago=1, now=now), decision(25, 15, 5, minutes_ago=2, now=now)]


def _key_bounds(condition):
    """(record_day, timestamp lower bound) from Key(record_day).eq & Key(timestamp).gte."""
    day_cond, ts_cond = condition.get_expression()["values"]
    return day_cond.get_expression()["values"][1], ts_cond.get_expression()["values"][1]


class FakeComplianceTable:
    """by_day_ts index: filters on the key condition and sorts by timestamp
    (descending when ScanIndexForward=False), like DynamoDB."""

    def __init__(self, log):
        self.log, self.items, self.calls, self.error = log, corroborating_decisions(), [], None
        self.page_size = None

    def query(self, **kwargs):
        self.calls.append(kwargs)
        self.log.append(("query_compliance",))
        if self.error:
            raise self.error
        day, start = _key_bounds(kwargs["KeyConditionExpression"])
        matching = sorted((dict(i) for i in self.items
                           if i.get("record_day") == day and str(i.get("timestamp", "")) >= start),
                          key=lambda i: i["timestamp"], reverse=not kwargs.get("ScanIndexForward", True))
        offset = kwargs.get("ExclusiveStartKey", {}).get("offset", 0)
        if self.page_size is None:
            return {"Items": matching[offset:]}
        page = matching[offset:offset + self.page_size]
        result = {"Items": page}
        if offset + self.page_size < len(matching):
            result["LastEvaluatedKey"] = {"offset": offset + self.page_size}
        return result


class FakeCloudWatch:
    def __init__(self, log):
        self.log, self.metrics = log, []
        self.alarm_pages = [[]]  # describe_alarms MetricAlarms, one list per page
        self.describe_calls = []
        self.describe_error = None

    def describe_alarms(self, **kwargs):
        self.describe_calls.append(kwargs)
        self.log.append(("describe_alarms",))
        if self.describe_error is not None:
            raise self.describe_error
        index = int(kwargs.get("NextToken", "0"))
        page = {"MetricAlarms": list(self.alarm_pages[index])}
        if index + 1 < len(self.alarm_pages):
            page["NextToken"] = str(index + 1)
        return page

    def put_metric_data(self, Namespace, MetricData):
        self.log.append(("metric", Namespace, MetricData[0]["MetricName"]))
        self.metrics.append((Namespace, MetricData))


class FakeBreakerAws:
    def __init__(self, held=()):
        self.log = []
        self.iam = FakeIam(self.log, held)
        self.gov = FakeGovernanceTable(self.log)
        self.state = FakeStateTable(self.log)
        self.compliance = FakeComplianceTable(self.log)
        self.cw = FakeCloudWatch(self.log)
        self.verified = []  # (action, target) passed to verify_identity
        self.tokens = {}    # nonce -> VerifiedPrincipal
        self.used = set()
        self.configs = []   # (service or "table:<name>", botocore Config) per client built
        self.sleeps = []

    # boto3 stand-ins
    def client(self, service, **kwargs):
        self.configs.append((service, kwargs.get("config")))
        if service == "iam":
            return self.iam
        if service == "cloudwatch":
            return self.cw
        if service == "sts":
            class _Sts:
                def get_caller_identity(_self):
                    return {"Account": ACCOUNT}
            return _Sts()
        raise AssertionError(f"unexpected boto3 client {service}")

    def resource(self, service, **kwargs):
        assert service == "dynamodb"
        aws = self
        config = kwargs.get("config")

        class _Resource:
            def Table(self, name):
                aws.configs.append(("table:" + name, config))
                if name == cb.STATE_TABLE:
                    return aws.state
                return aws.gov if name == cb.AUDIT_TABLE else aws.compliance
        return _Resource()

    def verify_identity(self, url, header_value, expected_action, expected_target, **kwargs):
        self.verified.append((expected_action, expected_target))
        self.log.append(("verify", expected_action))
        vp = self.tokens.get(header_value)
        if vp is None or header_value in self.used:
            return None
        self.used.add(header_value)
        return vp

    def install(self, monkeypatch, *, entry="human", stub_identity=True):
        monkeypatch.setattr(cb, "_resolve_mode", lambda event: "live")
        monkeypatch.setattr(cb.boto3, "client", self.client)
        monkeypatch.setattr(cb.boto3, "resource", self.resource)
        monkeypatch.setattr(cb, "resolve_deny_policy_arn", lambda: DENY_ARN)
        monkeypatch.setattr(cb, "_own_account", None)
        # The corroboration retry sleeps 3 s; record instead of sleeping.
        self.sleeps = []
        monkeypatch.setattr(cb.time, "sleep", self.sleeps.append)
        cb.authz.clear_cache()
        if entry is None:
            monkeypatch.delenv("BREAKER_ENTRY", raising=False)
        else:
            monkeypatch.setenv("BREAKER_ENTRY", entry)
        if stub_identity:
            monkeypatch.setattr(cb.identity_proof, "verify_identity", self.verify_identity)
        return self

    # helpers
    def proof(self, vp, name):
        """Event fields for a (stubbed) identity proof of ``vp``."""
        nonce = f"nonce-{name}-{len(self.tokens)}"
        self.tokens[nonce] = vp
        return {"caller_identity_presigned_url": "https://sts.us-east-1.amazonaws.com/",
                "caller_identity_nonce": nonce}

    def record_hold(self, event_id="hold-A", timestamp="2026-01-01T00:00:00+00:00"):
        """A completed, claimed trip: hold record, deny-all on every role and
        the state item claimed for ``event_id``. Re-recording the hold the
        item already names re-marks it HELD at the same generation (the same
        hold re-attached, not a new trip)."""
        self.gov.items[event_id] = {"event_id": event_id, "event_type": "GOVERNANCE_HOLD",
                                    "timestamp": timestamp}
        self.iam.held.update(cb.AGENT_ROLES)
        if self.state.item and self.state.item.get("hold_event_id") == event_id:
            self.state.item["status"] = "HELD"
        else:
            self.state.claim(event_id, timestamp)

    def kinds(self):
        return [entry[0] for entry in self.log]
