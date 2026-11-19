"""
Two-person release, manual trip authorization, local simulation and the
out-of-band break-glass script. Live mode with mocked IAM / DynamoDB / identity;
nothing reaches AWS.
"""
import email.utils
import importlib.util
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _breaker_fixtures import (  # noqa: E402
    ACCOUNT, DENY_ARN, PROJECT_ROOT, FakeBreakerAws, FakeGovernanceTable, FakeIam, FakeStateTable, cb,
    client_error, principal,
)

ALICE_OP = principal("fsi-breaker-operator", "alice")
ALICE_AP = principal("fsi-breaker-approver", "alice")
BOB_AP = principal("fsi-breaker-approver", "bob")
CAROL_OP = principal("fsi-breaker-operator", "carol")
ALICE_SSO_AP = principal("AWSReservedSSO_FsiBreakerApprover_abc123", "alice@example.com")
BOB_SSO_AP = principal("AWSReservedSSO_FsiBreakerApprover_abc123", "bob@example.com")


@pytest.fixture
def aws(monkeypatch):
    a = FakeBreakerAws().install(monkeypatch)
    a.record_hold("hold-A")
    return a


def _request(aws, vp=ALICE_OP):
    return cb.handler({"action": "request_release", **aws.proof(vp, "req")})


def _approve(aws, request_id, vp=BOB_AP, proof=None):
    return cb.handler({"action": "approve_release", "release_request_id": request_id,
                       **(proof or aws.proof(vp, "approve"))})


def _detaches(aws):
    return [e for e in aws.log if e[0] == "detach"]


# ─── Request ─────────────────────────────────────────────────────────────────

def test_a_request_by_operator_returns_202_with_id(aws):
    result = _request(aws)
    assert result["status"] == "RELEASE_PENDING" and result["http_status"] == 202
    assert cb.RELEASE_REQUEST_ID_RE.fullmatch(result["release_request_id"])
    (item,) = aws.gov.by_type("RELEASE_REQUESTED")
    assert item["event_id"] == "release-request#" + result["release_request_id"]
    assert item["requested_by"] == ALICE_OP.arn
    assert item["requested_by_individual"] == "alice" and item["requested_by_channel"] == "iam-user"
    assert item["hold_event_id"] == "hold-A" and item["status"] == "PENDING"
    assert aws.verified == [("request_release", "active-hold")]
    assert _detaches(aws) == []


def test_h_request_with_no_active_hold_is_409(aws):
    aws.iam.held.clear()
    result = _request(aws)
    assert result["http_status"] == 409 and result["code"] == "NO_ACTIVE_HOLD"
    assert not aws.gov.by_type("RELEASE_REQUESTED")


def test_l_request_without_recorded_hold_state_is_409(aws):
    aws.gov.items.clear()  # roles still held, but no hold recorded
    aws.state.item = None
    result = _request(aws)
    assert result["http_status"] == 409 and result["code"] == "HOLD_EVENT_UNKNOWN"
    assert not aws.gov.by_type("RELEASE_REQUESTED")


def test_request_by_console_host_session_is_403(aws):
    hosted = principal("fsi-console-operator-hosted", "cognito-abc")
    result = _request(aws, hosted)
    assert result["http_status"] == 403
    assert not aws.gov.by_type("RELEASE_REQUESTED")


def test_request_with_unverified_identity_is_403_and_writes_nothing(aws):
    result = cb.handler({"action": "request_release", "caller_identity_presigned_url": "x",
                         "caller_identity_nonce": "unknown"})
    assert result["http_status"] == 403
    assert not [e for e in aws.log if e[0] == "put"]


# ─── Approve ─────────────────────────────────────────────────────────────────

def test_b_same_individual_in_approver_role_is_refused(aws):
    rid = _request(aws)["release_request_id"]
    result = _approve(aws, rid, ALICE_AP)
    assert result["http_status"] == 403 and result["code"] == "SECOND_APPROVER_REQUIRED"
    assert _detaches(aws) == [] and not aws.gov.by_type("RELEASE_APPROVED")


def test_c_distinct_approver_releases_with_audit_before_detach(aws):
    rid = _request(aws)["release_request_id"]
    result = _approve(aws, rid)
    assert result["status"] == "ACTIVE"
    assert sorted(e[1] for e in _detaches(aws)) == sorted(cb.AGENT_ROLES)
    released_at = next(i for i, e in enumerate(aws.log) if e[:2] == ("put", "GOVERNANCE_HOLD_RELEASED"))
    first_detach = next(i for i, e in enumerate(aws.log) if e[0] == "detach")
    assert released_at < first_detach
    (released,) = aws.gov.by_type("GOVERNANCE_HOLD_RELEASED")
    assert released["requested_by"] == ALICE_OP.arn and released["approved_by"] == BOB_AP.arn
    assert released["release_request_id"] == rid
    assert released["prior_hold_event_id"] == "hold-A" != "UNKNOWN"
    (approved,) = aws.gov.by_type("RELEASE_APPROVED")
    assert approved["approved_by"] == BOB_AP.arn and approved["requested_by"] == ALICE_OP.arn
    (completed,) = aws.gov.by_type("GOVERNANCE_HOLD_RELEASE_COMPLETED")
    assert sorted(completed["roles_detached"]) == sorted(cb.AGENT_ROLES)
    assert completed["final_status"] == "ACTIVE" and completed["detach_failures"] == {}
    assert result["requested_by"] == ALICE_OP.arn and result["approved_by"] == BOB_AP.arn
    assert "newer_hold_detected" not in result and "audit_incomplete" not in result
    assert ("approve_release", rid) in aws.verified


def test_d_second_approval_of_same_request_is_409(aws):
    rid = _request(aws)["release_request_id"]
    _approve(aws, rid)
    aws.record_hold("hold-A")  # still the same hold, re-held for the test
    result = _approve(aws, rid, principal("fsi-breaker-approver", "dave"))
    # The completed release of this hold is refused before the approval write.
    assert result["http_status"] == 409 and result["code"] == "HOLD_ALREADY_RELEASED"
    assert len(_detaches(aws)) == len(cb.AGENT_ROLES)


def test_e_expired_request_is_403(aws):
    rid = _request(aws)["release_request_id"]
    aws.gov.items[f"release-request#{rid}"]["expires_at"] = (
        datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    result = _approve(aws, rid)
    assert result["http_status"] == 403 and result["code"] == "REQUEST_EXPIRED"
    assert _detaches(aws) == []


def test_f_operator_only_principal_cannot_approve(aws):
    rid = _request(aws)["release_request_id"]
    result = _approve(aws, rid, CAROL_OP)
    assert result["http_status"] == 403
    assert _detaches(aws) == [] and not aws.gov.by_type("RELEASE_APPROVED")


def test_g_reused_nonce_is_403_and_acts_once(aws):
    rid = _request(aws)["release_request_id"]
    proof = aws.proof(BOB_AP, "approve")
    assert _approve(aws, rid, proof=proof)["status"] == "ACTIVE"
    aws.record_hold("hold-A")
    result = _approve(aws, rid, proof=proof)
    assert result["http_status"] == 403
    assert len(_detaches(aws)) == len(cb.AGENT_ROLES)


def test_i_cross_channel_approval_is_refused(aws):
    rid = _request(aws)["release_request_id"]  # alice, iam-user
    for approver in (ALICE_SSO_AP, BOB_SSO_AP):
        result = _approve(aws, rid, approver)
        assert result["http_status"] == 403 and result["code"] == "SECOND_APPROVER_REQUIRED"
    assert _detaches(aws) == []


def test_sso_request_and_sso_approval_by_distinct_people(aws):
    sso_op = principal("AWSReservedSSO_FsiBreakerOperator_abc123", "alice@example.com")
    rid = _request(aws, sso_op)["release_request_id"]
    assert aws.gov.items[f"release-request#{rid}"]["requested_by_channel"] == "sso"
    assert _approve(aws, rid, BOB_SSO_AP)["status"] == "ACTIVE"


def test_j_request_for_an_older_hold_is_stale(aws):
    rid = _request(aws)["release_request_id"]
    aws.record_hold("hold-B", "2026-01-02T00:00:00+00:00")
    result = _approve(aws, rid)
    assert result["http_status"] == 409 and result["code"] == "STALE_REQUEST"
    assert not aws.gov.by_type("RELEASE_APPROVED") and _detaches(aws) == []


def test_k_hold_gone_at_approval_is_409(aws):
    rid = _request(aws)["release_request_id"]
    aws.iam.held.clear()
    result = _approve(aws, rid)
    assert result["http_status"] == 409 and result["code"] == "NO_ACTIVE_HOLD"
    assert not aws.gov.by_type("RELEASE_APPROVED") and _detaches(aws) == []


def test_m_stored_request_without_channel_is_403(aws):
    rid = _request(aws)["release_request_id"]
    del aws.gov.items[f"release-request#{rid}"]["requested_by_channel"]
    result = _approve(aws, rid)
    assert result["http_status"] == 403
    assert _detaches(aws) == []


def test_n_newer_hold_before_detach_aborts(aws):
    """A trip claims the state after the approval checks: the release claim
    loses and nothing is detached."""
    rid = _request(aws)["release_request_id"]
    aws.gov.on_put["RELEASE_APPROVED"] = lambda item: aws.record_hold("hold-B", "2026-01-02T00:00:00+00:00")
    result = _approve(aws, rid)
    assert result["http_status"] == 409 and result["code"] == "RELEASE_SUPERSEDED"
    assert aws.gov.by_type("RELEASE_APPROVED") and aws.gov.by_type("GOVERNANCE_HOLD_RELEASED")
    (completed,) = aws.gov.by_type("GOVERNANCE_HOLD_RELEASE_COMPLETED")
    assert completed["final_status"] == "SUPERSEDED" and completed["roles_detached"] == []
    assert _detaches(aws) == [] and aws.state.item["hold_event_id"] == "hold-B"


def test_o_newer_hold_after_detach_is_reported_and_restored(aws, caplog):
    rid = _request(aws)["release_request_id"]
    original = aws.iam.detach_role_policy

    def detach(RoleName, PolicyArn):
        original(RoleName=RoleName, PolicyArn=PolicyArn)
        if RoleName == cb.AGENT_ROLES[-1]:  # a trip claims after the last detach
            aws.state.claim("hold-B", "2026-01-02T00:00:00+00:00")
    aws.iam.detach_role_policy = detach
    with caplog.at_level(logging.ERROR):
        result = _approve(aws, rid)
    assert result["code"] == "RELEASE_SUPERSEDED" and result["newer_hold_detected"] is True
    assert aws.iam.held == set(cb.AGENT_ROLES)
    (completed,) = aws.gov.by_type("GOVERNANCE_HOLD_RELEASE_COMPLETED")
    assert completed["hold_event_id_after"] == "hold-B" and completed["final_status"] == "SUPERSEDED"
    assert len([r for r in caplog.records if "newer hold" in r.getMessage()]) == 1


@pytest.mark.parametrize("bad_id", [None, "", "x" * 36, "ABCDEF" + "0" * 30, "../" * 12])
def test_malformed_request_id_is_400_without_identity_check(aws, bad_id):
    result = cb.handler({"action": "approve_release", "release_request_id": bad_id,
                         **aws.proof(BOB_AP, "approve")})
    assert result["http_status"] == 400
    assert aws.verified == []


def test_unknown_request_is_404(aws):
    result = _approve(aws, "0" * 8 + "-0000-4000-8000-" + "0" * 12)
    assert result["http_status"] == 404 and result["code"] == "UNKNOWN_REQUEST"


def test_approval_reads_request_consistently(aws):
    rid = _request(aws)["release_request_id"]
    _approve(aws, rid)
    assert ("get_item", f"release-request#{rid}", True) in aws.log


def test_release_pre_record_failure_aborts_without_detach(aws):
    rid = _request(aws)["release_request_id"]
    aws.gov.put_error["GOVERNANCE_HOLD_RELEASED"] = RuntimeError("ddb down")
    result = _approve(aws, rid)
    assert result["http_status"] == 500 and result["status"] == "GOVERNANCE_HOLD"
    assert _detaches(aws) == []


# ─── re_enable is gone ───────────────────────────────────────────────────────

@pytest.mark.parametrize("entry", ["human", "automated", None])
def test_re_enable_action_is_410_and_iam_untouched(monkeypatch, entry):
    aws = FakeBreakerAws().install(monkeypatch, entry=entry)
    aws.record_hold()
    result = cb.handler({"action": "re_enable"})
    assert result["status"] == "REJECTED" and result["http_status"] == 410
    assert _detaches(aws) == [] and aws.verified == []


def test_live_re_enable_function_raises():
    with pytest.raises(ValueError, match="approve_release"):
        cb.re_enable(mode="live", releasing_principal="arn:aws:iam::123456789012:user/x")


# ─── Manual trip ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("vp", [ALICE_OP, BOB_AP, principal("fsi-console-operator-hosted", "cognito-1")])
def test_manual_trip_by_trip_capable_role(monkeypatch, vp):
    aws = FakeBreakerAws().install(monkeypatch)
    result = cb.handler({"action": "invoke", "trigger_reason_code": "OPERATOR_PRECAUTION",
                         **aws.proof(vp, "trip")})
    assert result["status"] == "GOVERNANCE_HOLD" and result["triggered_by"] == vp.arn
    assert aws.verified == [("trip", "trip")]
    (hold,) = aws.gov.by_type("GOVERNANCE_HOLD")
    assert hold["triggered_by"] == vp.arn and hold["trigger_source"] == "MANUAL:OPERATOR_PRECAUTION"
    assert hold["trigger_reason"] == cb.KNOWN_MANUAL_TRIGGER_REASONS["OPERATOR_PRECAUTION"]
    intent_at = next(i for i, e in enumerate(aws.log) if e[:2] == ("put", "GOVERNANCE_HOLD_INTENT"))
    assert intent_at < next(i for i, e in enumerate(aws.log) if e[0] == "attach")


@pytest.mark.parametrize("vp", [
    principal("random-role", "mallory"),
    principal("fsi-breaker-operator", "alice", account="999999999999"),
    principal("fsi-breaker-operator", "alice", role_id="AROAOTHERROLEID000001"),
])
def test_manual_trip_by_unclassified_principal_is_403(monkeypatch, vp):
    aws = FakeBreakerAws().install(monkeypatch)
    result = cb.handler({"action": "invoke", "trigger_reason_code": "OPERATOR_PRECAUTION",
                         **aws.proof(vp, "trip")})
    assert result["http_status"] == 403
    assert "attach" not in aws.kinds()


# ─── Local simulation ────────────────────────────────────────────────────────

@pytest.fixture
def local_files(monkeypatch, tmp_path):
    monkeypatch.setattr(cb, "STATE_FILE", str(tmp_path / "state.json"))
    monkeypatch.setattr(cb, "RELEASE_REQUEST_FILE", str(tmp_path / "request.json"))


def test_local_two_person_release(local_files):
    cb.handler({"action": "invoke", "mode": "local", "trigger_reason": "demo"})
    rid = cb.request_release_local("alice")["release_request_id"]
    same = cb.approve_release_local(rid, "alice")
    assert same["http_status"] == 403 and same["code"] == "SECOND_APPROVER_REQUIRED"
    assert cb.get_status("local")["status"] == "GOVERNANCE_HOLD"
    done = cb.approve_release_local(rid, "bob")
    assert done["status"] == "ACTIVE" and done["approved_by"] == "bob"
    assert cb.get_status("local")["status"] == "ACTIVE"


def test_local_request_after_retrip_is_stale(local_files):
    cb.handler({"action": "invoke", "mode": "local", "trigger_reason": "demo"})
    rid = cb.request_release_local("alice")["release_request_id"]
    cb.handler({"action": "invoke", "mode": "local", "trigger_reason": "again"})
    result = cb.approve_release_local(rid, "bob")
    assert result["http_status"] == 409 and result["code"] == "STALE_REQUEST"
    assert cb.get_status("local")["status"] == "GOVERNANCE_HOLD"


def test_local_request_without_hold_and_expiry(local_files):
    assert cb.request_release_local("alice")["code"] == "NO_ACTIVE_HOLD"
    cb.handler({"action": "invoke", "mode": "local", "trigger_reason": "demo"})
    rid = cb.request_release_local("alice")["release_request_id"]
    later = datetime.now(timezone.utc) + timedelta(seconds=cb.RELEASE_REQUEST_TTL_SECONDS + 1)
    assert cb.approve_release_local(rid, "bob", now=later)["code"] == "REQUEST_EXPIRED"


def test_local_actions_reachable_through_handler(local_files, monkeypatch):
    monkeypatch.delenv("BREAKER_ENTRY", raising=False)
    cb.handler({"action": "invoke", "mode": "local", "trigger_reason": "demo"})
    rid = cb.handler({"action": "request_release", "mode": "local", "principal_id": "alice"})[
        "release_request_id"]
    result = cb.handler({"action": "approve_release", "mode": "local", "principal_id": "bob",
                         "release_request_id": rid})
    assert result["status"] == "ACTIVE"


# ─── Out-of-band break-glass script ──────────────────────────────────────────

def _load_break_glass():
    path = os.path.join(PROJECT_ROOT, "scripts", "break_glass_release.py")
    spec = importlib.util.spec_from_file_location("break_glass_release", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _Session:
    """boto3.Session stand-in. STS answers with a Date header ``date_offset``
    seconds from the local clock (None: no header); Table("governance-state")
    is the state fake, any other table the audit fake."""

    def __init__(self, role, iam, table, state, session_name="alice", date_offset=0.0):
        role_id = iam.roles.get(role, {}).get("RoleId", "AROAUNKNOWN0000000001")
        self.identity = {"Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{role}/{session_name}",
                         "UserId": f"{role_id}:{session_name}", "Account": ACCOUNT}
        self.iam, self.table, self.state, self.date_offset = iam, table, state, date_offset

    def client(self, service, **kwargs):
        if service == "iam":
            return self.iam
        assert service == "sts"
        identity, offset = self.identity, self.date_offset

        class _Sts:
            def get_caller_identity(self):
                if offset is None:
                    return dict(identity)
                date = email.utils.formatdate(time.time() + offset, usegmt=True)
                return {**identity, "ResponseMetadata": {"HTTPHeaders": {"date": date}}}
        return _Sts()

    def resource(self, service, **kwargs):
        table, state = self.table, self.state

        class _Res:
            def Table(self, name):
                return state if name == "governance-state" else table
        return _Res()


@pytest.fixture
def glass(monkeypatch):
    module = _load_break_glass()
    module.authz.clear_cache()
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    log = []
    iam = FakeIam(log, held=module.AGENT_ROLES)
    table = FakeGovernanceTable(log)

    def run(role="fsi-breaker-break-glass", argv=None, date_offset=0.0):
        monkeypatch.setattr(module.boto3, "Session",
                            lambda: _Session(role, iam, table, run.state, date_offset=date_offset))
        return module.main(argv if argv is not None else
                           ["--incident-id", "INC-1234", "--i-understand-this-is-out-of-band"])
    run.state = FakeStateTable(log)
    return module, run, iam, table, log


def test_break_glass_refuses_other_identity(glass):
    _, run, iam, table, log = glass
    assert run(role="fsi-breaker-approver") == 1
    assert not table.items and not [e for e in log if e[0] == "detach"]


@pytest.mark.parametrize("argv", [["--i-understand-this-is-out-of-band"],
                                  ["--incident-id", "INC-1234"],
                                  ["--incident-id", "inc 1", "--i-understand-this-is-out-of-band"]])
def test_break_glass_requires_arguments(glass, argv):
    _, run, iam, table, log = glass
    assert run(argv=argv) == 2
    assert not log


def test_break_glass_audit_failure_aborts_before_detach(glass):
    _, run, iam, table, log = glass
    table.put_error["BREAK_GLASS_RELEASE_STARTED"] = RuntimeError("ddb down")
    assert run() == 2
    assert not [e for e in log if e[0] == "detach"]


def test_break_glass_success_records_before_and_after(glass):
    module, run, iam, table, log = glass
    assert run() == 0
    started = next(i for i, e in enumerate(log) if e[:2] == ("put", "BREAK_GLASS_RELEASE_STARTED"))
    detaches = [i for i, e in enumerate(log) if e[0] == "detach"]
    completed = next(i for i, e in enumerate(log) if e[:2] == ("put", "BREAK_GLASS_RELEASE_COMPLETED"))
    assert started < detaches[0] and detaches[-1] < completed and len(detaches) == 3
    (done,) = table.by_type("BREAK_GLASS_RELEASE_COMPLETED")
    assert sorted(done["roles_verified_detached"]) == sorted(module.AGENT_ROLES)
    assert done["incident_id"] == "INC-1234" and done["released_by"].endswith("/fsi-breaker-break-glass/alice")


def test_break_glass_partial_detach_exits_3(glass):
    module, run, iam, table, log = glass
    iam.detach_error[module.AGENT_ROLES[1]] = client_error("AccessDenied", "DetachRolePolicy")
    assert run() == 3
    (done,) = table.by_type("BREAK_GLASS_RELEASE_COMPLETED")
    assert done["roles_still_held"] == [module.AGENT_ROLES[1]]
    assert DENY_ARN.endswith("governance-hold-deny-all")


# ─── Break-glass and the governance-state item ───────────────────────────────

def _held(run, table, minutes_ago=10, event_id="hold-A"):
    at = (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()
    table.items[event_id] = {"event_id": event_id, "event_type": "GOVERNANCE_HOLD", "timestamp": at}
    run.state.claim(event_id, at)


def _glass_detaches(log):
    return [e for e in log if e[0] == "detach"]


def test_break_glass_claims_the_state_with_its_own_fields(glass):
    module, run, iam, table, log = glass
    _held(run, table)
    assert run() == 0
    item = run.state.item
    assert item["status"] == "RELEASED" and item["generation"] == 1
    assert item["break_glass_id"] == "INC-1234" and item["break_glass_by"].endswith("/fsi-breaker-break-glass/alice")
    assert "break_glass_at" in item
    assert not {"release_request_id", "released_by", "released_at"} & set(item)
    (started,) = table.by_type("BREAK_GLASS_RELEASE_STARTED")
    (done,) = table.by_type("BREAK_GLASS_RELEASE_COMPLETED")
    assert started["hold_generation"] == 1 and done["hold_generation_after"] == 1
    assert done["outcome"] == "DETACHED"
    claim_at = log.index(("state_update", "break_glass"))
    assert log.index(("put", "BREAK_GLASS_RELEASE_STARTED", started["event_id"])) < claim_at
    assert claim_at < next(i for i, e in enumerate(log) if e[0] == "detach")


def test_break_glass_works_when_the_state_is_already_released(glass):
    _, run, iam, table, log = glass
    _held(run, table)
    run.state.item["status"] = "RELEASED"
    assert run() == 0 and run.state.item["break_glass_id"] == "INC-1234"


def test_break_glass_superseded_before_detach_exits_4(glass):
    module, run, iam, table, log = glass
    _held(run, table)
    run.state.before_update = [lambda kind: run.state.claim("hold-B", "2026-01-02T00:00:00+00:00")]
    assert run() == module.EXIT_SUPERSEDED == 4
    assert _glass_detaches(log) == [] and iam.held == set(module.AGENT_ROLES)
    (done,) = table.by_type("BREAK_GLASS_RELEASE_COMPLETED")
    assert done["roles_verified_detached"] == [] and done["outcome"] == "SUPERSEDED"
    assert done["hold_generation_after"] == 2


def test_break_glass_claim_error_after_started_exits_2_with_a_record(glass):
    _, run, iam, table, log = glass
    _held(run, table)
    run.state.update_errors = [client_error("InternalServerError", "UpdateItem")]
    assert run() == 2
    assert _glass_detaches(log) == []
    (done,) = table.by_type("BREAK_GLASS_RELEASE_COMPLETED")
    assert done["roles_verified_detached"] == [] and done["outcome"] == "STATE_CLAIM_FAILED"


def test_break_glass_newer_generation_after_detach_exits_5_over_3(glass):
    module, run, iam, table, log = glass
    _held(run, table)
    iam.detach_error[module.AGENT_ROLES[1]] = client_error("AccessDenied", "DetachRolePolicy")
    original = iam.detach_role_policy

    def detach(RoleName, PolicyArn):
        if RoleName == module.AGENT_ROLES[0]:
            run.state.claim("hold-B", datetime.now(timezone.utc).isoformat())
        return original(RoleName=RoleName, PolicyArn=PolicyArn)
    iam.detach_role_policy = detach
    assert run() == module.EXIT_SUPERSEDED_AFTER == 5
    (done,) = table.by_type("BREAK_GLASS_RELEASE_COMPLETED")
    assert done["outcome"] == "SUPERSEDED_AFTER" and done["hold_generation_after"] == 2


def test_break_glass_state_absent_then_present_counts_as_changed(glass):
    module, run, iam, table, log = glass
    original = iam.detach_role_policy

    def detach(RoleName, PolicyArn):
        if run.state.item is None:
            run.state.claim("hold-new", datetime.now(timezone.utc).isoformat())
        return original(RoleName=RoleName, PolicyArn=PolicyArn)
    iam.detach_role_policy = detach
    assert run() == 5
    assert ("state_update", "break_glass") not in log  # absent at step 1: no claim


def test_break_glass_state_read_failure_exits_2_with_nothing_written(glass, capsys):
    _, run, iam, table, log = glass
    _held(run, table)
    run.state.get_errors = [client_error("AccessDeniedException", "GetItem")]
    assert run() == 2
    assert not table.items.keys() - {"hold-A"} and _glass_detaches(log) == []
    assert "state read failed" in capsys.readouterr().out


@pytest.mark.parametrize("offset", [10.0, -10.0, None, -4.5])
def test_break_glass_refuses_a_clock_off_aws_time(glass, offset, capsys):
    """Date header 10 s ahead or behind (or missing): exit 2, nothing written."""
    _, run, iam, table, log = glass
    _held(run, table)
    assert run(date_offset=offset) == 2
    assert not table.by_type("BREAK_GLASS_RELEASE_STARTED") and _glass_detaches(log) == []
    assert ("state_get", True) not in log
    assert "local clock differs from AWS by" in capsys.readouterr().out


@pytest.mark.parametrize("offset", [-1.9, 0.0, 1.0])
def test_break_glass_accepts_header_truncation_and_latency(glass, offset):
    """A Date header up to ~2 s behind local time after the call (1 s
    truncation plus latency) is a synced clock."""
    _, run, iam, table, log = glass
    _held(run, table)
    assert run(date_offset=offset) == 0


def test_break_glass_adopts_a_trip_whose_claims_failed(glass, monkeypatch):
    """An unclaimed trip that started before the break-glass is adopted,
    so the sweep does not re-attach over the release."""
    module, run, iam, table, log = glass
    _held(run, table, minutes_ago=20)
    started = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    table.items["intent-T"] = {"event_id": "intent-T", "event_type": "GOVERNANCE_HOLD_INTENT",
                               "timestamp": started}
    assert cb.hold_sweep.unclaimed_hold(table, run.state.item) is not None
    assert run() == 0 and iam.held == set()
    metrics = []
    result = cb.hold_sweep.reconcile_hold(
        iam, table, roles=list(module.AGENT_ROLES), deny_policy_arn=DENY_ARN, trigger="schedule",
        emit_metric=lambda name, value: metrics.append(name),
        now=datetime.now(timezone.utc) + timedelta(minutes=10),
        read_state=lambda: cb.governance_state.read(run.state))
    assert result == {"status": "NO_HOLD"} and iam.held == set() and metrics == []
