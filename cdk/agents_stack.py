"""
Agents Stack — AgentCore Runtimes for the three compliance agents.

Migration: Lambda → Amazon Bedrock AgentCore Runtime.
Each agent is deployed as a direct-code-deploy AgentCore Runtime with its own
IAM execution role enforcing least-privilege NHI governance.

Retained as Lambda:
- PAN Ingress Filter (lightweight, event-driven, no session needed)
- Circuit Breaker (CloudWatch alarm-triggered, IAM-heavy, no session needed)

Note: AgentCore Runtime is a CfnResource (L1) until CDK L2 constructs are
released. The Custom::AgentCoreRuntime pattern wraps the boto3 API calls.
"""
import re

import jsii
from aws_cdk import (
    Stack,
    Duration,
    CfnOutput,
    RemovalPolicy,
    aws_lambda as _lambda,
    aws_iam as iam,
    aws_cloudwatch as cloudwatch,
    aws_cloudwatch_actions as cw_actions,
    aws_bedrock as bedrock,
    aws_events as events,
    aws_events_targets as events_targets,
    aws_kms as kms,
    aws_lambda_event_sources as lambda_event_sources,
    aws_logs as logs,
    aws_s3 as s3,
    aws_secretsmanager as secretsmanager,
    aws_sqs as sqs,
)
from constructs import Construct

from data_stack import COMPLIANCE_READER_ROLE_NAME, KMS_KEY_ADMIN_ACTIONS
from lambda_logging import grant_lambda_log_writes, lambda_log_group


# AgentCore Runtime log-group prefix. Real runtime log groups look like
# /aws/bedrock-agentcore/runtimes/ComplianceAgent-<id>-DEFAULT.
AGENTCORE_RUNTIME_LOG_GROUP_PREFIX = "/aws/bedrock-agentcore/runtimes/"

AGENT_ROLE_NAMES = ("detection-agent-role", "compliance-agent-role", "executor-agent-role")
AGENTCORE_RUNTIME_NAMES = ("DetectionAgent", "ComplianceAgent", "ExecutorAgent")
# Runtime ARNs pinned by cdk/deploy_agentcore_runtimes.py; the only runtimes
# the console invokes. Must equal governance_common/runtime_pins.py.
RUNTIME_ARNS_PARAMETER = "/fsi/governance/agentcore-runtime-arns"
DRIFT_NAMESPACE = "FSI/AgenticCompliance"
GOVERNANCE_INTEGRITY_NAMESPACE = "FSI/GovernanceIntegrity"
BREAK_GLASS_ROLE_PATH = "/fsi-breaker/"
BREAK_GLASS_ROLE_NAME = "fsi-breaker-break-glass"
# Timeout of the three breaker-asset functions: corroboration (10 s) or the
# recheck pre-trip phase (12 s), plus the 21.5 s trip path, plus a 5 s
# margin. Must equal circuit_breaker/handler.py BREAKER_TIMEOUT_SECONDS.
BREAKER_TIMEOUT_SECONDS = 45
# The one governance-state item the breaker claims (dynamodb:LeadingKeys).
GOVERNANCE_STATE_KEYS = ["breaker"]
CONSOLE_ROLE_PATH = "/fsi-console/"
# Alarms whose ARNs the breaker accepts as automatic triggers (each also has
# the automated breaker as its alarm action).
TRUSTED_ALARM_NAMES = (
    "fsi-challenger-dispute-rate-breach",
    "fsi-guardrail-intervention-rate-breach",
    "fsi-detection-volume-anomaly",
    "fsi-challenger-dispute-rate-sustained",
)
HOLD_CHANGES_LOG_GROUP = "/fsi/governance/hold-changes"

# Trust for every human-assumable governance role: an IAM user of this account
# with MFA whose role session name is their own IAM user name, so the session
# name identifies the individual.
HUMAN_MFA_TRUST_CONDITIONS = {
    "Bool": {"aws:MultiFactorAuthPresent": "true"},
    "StringEquals": {"sts:RoleSessionName": "${aws:username}"},
}
# Sessions minted by the console host (alb-cognito mode) for a Cognito user.
CONSOLE_HOST_TRUST_CONDITIONS = {
    "StringLike": {"sts:RoleSessionName": "cognito-*", "sts:SourceIdentity": "cognito-*"},
}
HUMAN_ROLE_MAX_SESSION = Duration.hours(1)

# Sample-size floor of the rate alarms. Must equal MIN_CLUSTERS_FOR_RATE in
# lambdas/drift_metric_publisher/handler.py and MIN_CLUSTERS_FOR_CORROBORATION
# in circuit_breaker/handler.py (a test pins all three).
MIN_CLUSTERS_FOR_ALARM_RATE = 20
# The only drift-metric publisher. Explicit physical names: the
# ops-doc SCPs (steps 3, 5, 6) match on them.
DRIFT_PUBLISHER_FUNCTION_NAME = "fsi-drift-metric-publisher"
DRIFT_PUBLISHER_ROLE_NAME = "fsi-drift-metric-publisher-role"
BREAKER_ALARM_RECHECK_RULE_NAME = "fsi-breaker-alarm-recheck"
# Reconciling sweep: same breaker asset, its own attach-only role.
HOLD_SWEEP_FUNCTION_NAME = "fsi-governance-hold-sweep"
PAN_FILTER_FUNCTION_NAME = "fsi-pan-filter"
CIRCUIT_BREAKER_FUNCTION_NAME = "fsi-circuit-breaker"
CIRCUIT_BREAKER_HUMAN_FUNCTION_NAME = "fsi-circuit-breaker-human"
HOLD_SWEEP_ROLE_NAME = "governance-hold-sweep-role"
HOLD_SWEEP_RULE_NAME = "fsi-governance-hold-sweep"
HOLD_SWEEP_PERIOD_MINUTES = 5
# Sweep periods without a heartbeat before fsi-hold-sweep-not-running fires.
HOLD_SWEEP_LIVENESS_PERIODS = 3
# Must equal circuit_breaker/handler.py HOLD_SWEEP_HEARTBEAT_METRIC.
HOLD_SWEEP_HEARTBEAT_METRIC = "HoldSweepHeartbeat"

_IAM_ROLE_ARN_RE = re.compile(r"arn:aws:iam::\d{12}:role/[\w+=,.@/-]{1,512}")
DEFAULT_PAN_FILTER_RESERVED_CONCURRENCY = 10


def context_flag(value) -> bool:
    """CDK context booleans arrive as True or the string "true"; default off."""
    return value in (True, "true")


def context_role_arn(value, key: str):
    """Optional IAM role ARN from CDK context; malformed -> ValueError at synth."""
    if value in (None, ""):
        return None
    if not isinstance(value, str) or not _IAM_ROLE_ARN_RE.fullmatch(value):
        raise ValueError(f"CDK context {key} must be an IAM role ARN")
    return value


def context_reserved_concurrency(value):
    """pan_filter_reserved_concurrency: default 10; 0 -> not set."""
    if value in (None, ""):
        return DEFAULT_PAN_FILTER_RESERVED_CONCURRENCY
    if isinstance(value, bool):
        raise ValueError("CDK context pan_filter_reserved_concurrency must be a non-negative integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise ValueError(
            "CDK context pan_filter_reserved_concurrency must be a non-negative integer") from None
    if parsed < 0:
        raise ValueError("CDK context pan_filter_reserved_concurrency must be a non-negative integer")
    return parsed or None


@jsii.implements(events.IRuleTarget)
class _LogGroupRuleTarget:
    """EventBridge -> CloudWatch Logs target without a custom resource.

    aws_events_targets.CloudWatchLogGroup synthesizes a
    Custom::CloudwatchLogResourcePolicy backed by a singleton Lambda + role;
    the log group's resource policy is a direct logs.CfnResourcePolicy instead
    (see AgentsStack), so this target only needs the ARN."""

    def __init__(self, log_group: logs.ILogGroup):
        self._log_group = log_group

    def bind(self, rule, id=None):  # noqa: A002 - jsii interface signature
        return events.RuleTargetConfig(arn=self._log_group.log_group_arn)


def _add_agentcore_runtime_log_statements(role: iam.Role, region: str, account: str) -> None:
    """Grant an AgentCore Runtime execution role its CloudWatch Logs access.

    Mirrors the logs statements of the documented AgentCore Runtime
    execution role (direct code deploy), scoped exactly as AWS documents
    them, instead of logs:* on "*" (cdk_nag AwsSolutions-IAM5 / Checkov
    CKV_AWS_111):
    https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-permissions.html
    """
    log_group_arn = (
        f"arn:aws:logs:{region}:{account}:log-group:"
        f"{AGENTCORE_RUNTIME_LOG_GROUP_PREFIX}*"
    )
    role.add_to_policy(iam.PolicyStatement(
        actions=["logs:CreateLogGroup", "logs:DescribeLogStreams"],
        resources=[log_group_arn],
    ))
    # DescribeLogGroups is a list call, so AWS documents it on log-group:*.
    role.add_to_policy(iam.PolicyStatement(
        actions=["logs:DescribeLogGroups"],
        resources=[f"arn:aws:logs:{region}:{account}:log-group:*"],
    ))
    role.add_to_policy(iam.PolicyStatement(
        actions=["logs:CreateLogStream", "logs:PutLogEvents"],
        resources=[f"{log_group_arn}:log-stream:*"],
    ))


class AgentsStack(Stack):
    """AgentCore Runtimes and supporting Lambda functions for FSI Compliance."""

    def __init__(self, scope: Construct, construct_id: str, data_stack, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Optional CDK context (validated up front; see cdk/README.md).
        allow_console_drift_injection = context_flag(
            self.node.try_get_context("allow_console_drift_injection"))
        console_host_role_arn = context_role_arn(
            self.node.try_get_context("console_host_role_arn"), "console_host_role_arn")
        ci_role_arn = context_role_arn(self.node.try_get_context("ci_role_arn"), "ci_role_arn")
        pan_filter_reserved_concurrency = context_reserved_concurrency(
            self.node.try_get_context("pan_filter_reserved_concurrency"))

        # S3 bucket for AgentCore code deployment packages
        self.code_bucket = s3.Bucket(
            self, "AgentCodeBucket",
            bucket_name=None,  # Auto-generated
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )
        # ═════════════════════════════════════════════════════════════════════
        # BLUEPRINT 1 — DATA & ACCESS CONTROLS (Non-Human Identity governance)
        # ═════════════════════════════════════════════════════════════════════
        # Three separate agent IAM roles, each least-privilege, enforcing a
        # one-way data flow across the pipeline:
        #   NHI #1 Detection  → write-only to detection-results; CANNOT invoke Bedrock
        #   NHI #2 Compliance → read detection / write compliance; CANNOT file SARs
        #   NHI #3 Executor   → read compliance / write SAR+audit; CANNOT reason (no Bedrock)
        # No role can read raw transactions AND invoke the model AND file a SAR.
        # ═════════════════════════════════════════════════════════════════════
        # ─────────────────────────────────────────────────────────────────────
        # NHI #1: Detection Agent Role (AgentCore Runtime)
        # ─────────────────────────────────────────────────────────────────────
        detection_role = iam.Role(
            self, "DetectionAgentRole",
            role_name="detection-agent-role",
            # The circuit breaker never assumes this role — it only calls
            # iam:AttachRolePolicy/DetachRolePolicy/ListAttachedRolePolicies
            # against it (see circuit_breaker_role below), which doesn't
            # require a trust relationship. Trusting lambda.amazonaws.com
            # with no aws:SourceArn/SourceAccount condition would let any
            # in-account principal with lambda:CreateFunction + iam:PassRole
            # run arbitrary code as this role — removed.
            assumed_by=iam.ServicePrincipal("bedrock-agentcore.amazonaws.com"),
            # No AWS managed policies (cdk_nag AwsSolutions-IAM4): this is an
            # AgentCore Runtime role, not a Lambda role, so
            # AWSLambdaBasicExecutionRole (logs:* on "*") is not attached.
            # Logging is granted by _add_agentcore_runtime_log_statements()
            # below, scoped to the AgentCore runtime log groups. With zero
            # managed policies, a governance hold is still detected the same
            # way: by the presence of governance-hold-deny-all.
        )
        # CAN: Write to detection results table — PutItem only, not
        # UpdateItem/DeleteItem. grant_write_data() includes delete, which
        # would let the audited agent erase its own audit records;
        # the agent only ever needs to create new items.
        data_stack.detection_table.grant(detection_role, "dynamodb:PutItem")
        # CAN: Read code from S3 deployment bucket
        self.code_bucket.grant_read(detection_role)
        # CAN: Write CloudWatch logs (AgentCore runtime log groups only)
        _add_agentcore_runtime_log_statements(detection_role, self.region, self.account)
        # CANNOT: Invoke Bedrock (no policy attached)
        # CANNOT: Write to SAR filing (no S3 policy)

        # ─────────────────────────────────────────────────────────────────────
        # NHI #2: Compliance Agent Role (AgentCore Runtime)
        # ─────────────────────────────────────────────────────────────────────
        compliance_role = iam.Role(
            self, "ComplianceAgentRole",
            role_name="compliance-agent-role",
            # See detection_role above — lambda.amazonaws.com trust removed;
            # the circuit breaker only attaches/detaches policies on this
            # role, it never assumes it.
            assumed_by=iam.ServicePrincipal("bedrock-agentcore.amazonaws.com"),
            # No AWS managed policies — see detection_role above (IAM4).
        )
        # CAN: GetItem the recorded detection (provenance check by exact
        # detection_id) — no Scan/Query/BatchGetItem.
        data_stack.detection_table.grant(compliance_role, "dynamodb:GetItem")
        # PutItem only — see detection_role grant above. The
        # compliance agent must never be able to overwrite or delete its
        # own prior decisions. TransactWriteItems (decision + single-decision
        # marker) is authorized per item by this PutItem.
        data_stack.compliance_table.grant(compliance_role, "dynamodb:PutItem")
        # CAN: read only its own single-decision markers (detection#<id>)
        # for the duplicate-decision pre-check; never another
        # decision record.
        compliance_role.add_to_policy(iam.PolicyStatement(
            actions=["dynamodb:GetItem"],
            resources=[data_stack.compliance_table.table_arn],
            conditions={
                "ForAllValues:StringLike": {"dynamodb:LeadingKeys": ["detection#*"]},
            },
        ))
        # CAN: Invoke Bedrock with guardrail — scoped to exactly the two
        # approved inference profiles (data/approved_models.json) rather than
        # "*", so IAM backs the model-risk registry instead of merely
        # trusting the handler's own validate_model() check.
        # ApplyGuardrail is scoped to this account/region's guardrails; the
        # specific guardrail ARN is added once the guardrail resource below
        # is created (see the statement added after self.guardrail).
        approved_model_arns = [
            f"arn:aws:bedrock:{self.region}:{self.account}:inference-profile/us.anthropic.claude-sonnet-4-5-20250929-v1:0",
            f"arn:aws:bedrock:{self.region}:{self.account}:inference-profile/us.amazon.nova-pro-v1:0",
            # Inference profiles route to on-demand model ARNs in each
            # supported region; grant those foundation-model ARNs too so the
            # Converse call underneath the profile is authorized.
            f"arn:aws:bedrock:*::foundation-model/anthropic.claude-sonnet-4-5-20250929-v1:0",
            f"arn:aws:bedrock:*::foundation-model/amazon.nova-pro-v1:0",
        ]
        compliance_role.add_to_policy(iam.PolicyStatement(
            # The Converse API is authorized by bedrock:InvokeModel; there is
            # no bedrock:Converse IAM action (Access Analyzer INVALID_ACTION).
            actions=["bedrock:InvokeModel"],
            resources=approved_model_arns,
        ))
        # CANNOT: Publish drift metrics. fsi-drift-metric-publisher
        # (below) is the only drift-metric publisher; it derives datapoints
        # from the stored VERIFIED decision records.
        # CAN: Read code from S3 deployment bucket
        self.code_bucket.grant_read(compliance_role)
        # CAN: Write CloudWatch logs (AgentCore runtime log groups only)
        _add_agentcore_runtime_log_statements(compliance_role, self.region, self.account)
        # CANNOT: Write to SAR filing (no S3 policy)
        # CANNOT: Modify detection results (read-only grant above)

        # ─────────────────────────────────────────────────────────────────────
        # NHI #3: Executor Agent Role (AgentCore Runtime)
        # ─────────────────────────────────────────────────────────────────────
        executor_role = iam.Role(
            self, "ExecutorAgentRole",
            role_name="executor-agent-role",
            # See detection_role above — lambda.amazonaws.com trust removed;
            # the circuit breaker only attaches/detaches policies on this
            # role, it never assumes it.
            assumed_by=iam.ServicePrincipal("bedrock-agentcore.amazonaws.com"),
            # No AWS managed policies — see detection_role above (IAM4).
        )
        # CAN: Read compliance decisions, write audit trail, write SAR to S3, send to SQS
        # GetItem only: the executor never Scans, Queries or
        # BatchGets compliance-decisions (provenance lookup + completion
        # state are both GetItem).
        data_stack.compliance_table.grant(executor_role, "dynamodb:GetItem")
        # UpdateItem only, on the compliance-decisions table ARN only:
        # the one-time-use replay lease claim/finalize
        # (claim_compliance_id_for_processing / finalize_compliance_id_processed
        # in lambdas/executor_agent/handler.py) are conditional UpdateItem
        # calls. No PutItem/DeleteItem/BatchWriteItem and no index ARNs — the
        # executor still cannot create or delete compliance records.
        #
        # Restricted to the attributes the executor actually
        # writes or evaluates in a condition, so a compromised executor
        # cannot overwrite the compliance verdict (clusters_assessed,
        # detection_id, ...). Must equal COMPLIANCE_TABLE_WRITE_ATTRIBUTES in
        # lambdas/executor_agent/handler.py (a test enforces this). The three
        # UpdateItem calls, all keyed on compliance_id:
        #   claim:    SET executor_processed, lease_expires_at (cond. on both)
        #   record:   ADD completed_clusters (cond. on executor_processed,
        #             lease_expires_at) — per-cluster completion
        #   finalize: SET executor_processed REMOVE lease_expires_at
        # The partition key must be listed for dynamodb:Attributes. No
        # dynamodb:ReturnValues condition: the handler never passes
        # ReturnValues and the role already holds full read via
        # grant_read_data.
        executor_role.add_to_policy(iam.PolicyStatement(
            actions=["dynamodb:UpdateItem"],
            resources=[data_stack.compliance_table.table_arn],
            conditions={
                "ForAllValues:StringEquals": {
                    "dynamodb:Attributes": [
                        "compliance_id",
                        "completed_clusters",
                        "executor_processed",
                        "lease_expires_at",
                    ],
                },
            },
        ))
        # PutItem only — see detection_role grant above. The
        # executor's own module docstring claims it "CANNOT modify detection
        # or compliance records"; grant_write_data's UpdateItem/DeleteItem
        # would let it delete entries from executor-audit, contradicting
        # that claim.
        data_stack.audit_table.grant(executor_role, "dynamodb:PutItem")
        # PutObject only — see the audit_table grant above.
        # grant_write() expands to s3:DeleteObject*/
        # DeleteObjectVersion in addition to PutObject, which would let a
        # compromised/prompt-injected executor delete filed SAR evidence
        # the bucket's own RETAIN/versioned config (cdk/data_stack.py)
        # treats as immutable for the 7-year BSA retention window. Scoped
        # to the filings/ prefix the executor actually writes under
        # (lambdas/executor_agent/handler.py).
        executor_role.add_to_policy(iam.PolicyStatement(
            actions=["s3:PutObject", "s3:AbortMultipartUpload"],
            resources=[f"{data_stack.sar_bucket.bucket_arn}/filings/*"],
        ))
        data_stack.analyst_queue.grant_send_messages(executor_role)
        # CAN: Read code from S3 deployment bucket
        self.code_bucket.grant_read(executor_role)
        # CAN: Invoke the circuit breaker Lambda to trip the kill switch.
        # The executor's own routing (CIRCUIT_BREAKER decision)
        # reaches the breaker over this SigV4-authenticated boto3 call rather
        # than importing the breaker's module by path — the grant is scoped
        # to exactly this one function, never a wildcard.
        executor_role.add_to_policy(iam.PolicyStatement(
            actions=["lambda:InvokeFunction"],
            resources=[f"arn:aws:lambda:{self.region}:{self.account}:function:fsi-circuit-breaker"],
        ))
        # CAN: Write CloudWatch logs (AgentCore runtime log groups only)
        _add_agentcore_runtime_log_statements(executor_role, self.region, self.account)
        # CANNOT: Invoke Bedrock (no policy attached)
        # CANNOT: Read raw transactions (no S3 source access)

        # ─────────────────────────────────────────────────────────────────────
        # NHI #0: PAN Filter Role (retained as Lambda — ingress boundary)
        # ─────────────────────────────────────────────────────────────────────
        pan_filter_role = iam.Role(
            self, "PanFilterRole",
            role_name="pan-filter-role",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            # No AWSLambdaBasicExecutionRole (logs:* on "*"): logs go to the
            # function's own group only (cdk/lambda_logging.py).
        )
        grant_lambda_log_writes(pan_filter_role, PAN_FILTER_FUNCTION_NAME)

        # ─────────────────────────────────────────────────────────────────────
        # Circuit Breaker Role (retained as Lambda — alarm-triggered)
        # ─────────────────────────────────────────────────────────────────────
        circuit_breaker_role = iam.Role(
            self, "CircuitBreakerRole",
            role_name="circuit-breaker-role",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            # No AWSLambdaBasicExecutionRole (logs:* on "*"): logs go to the
            # two breaker functions' own groups only (cdk/lambda_logging.py).
        )
        grant_lambda_log_writes(circuit_breaker_role, CIRCUIT_BREAKER_FUNCTION_NAME,
                                CIRCUIT_BREAKER_HUMAN_FUNCTION_NAME)
        # Governance Hold deny-all policy (attached to agent roles when circuit
        # breaker fires). Defined here, before the circuit breaker's grant
        # below, so the grant can pin iam:PolicyARN to this exact policy.
        self.deny_all_policy = iam.ManagedPolicy(
            self, "GovernanceHoldDenyAll",
            managed_policy_name="governance-hold-deny-all",
            statements=[
                iam.PolicyStatement(
                    effect=iam.Effect.DENY,
                    actions=["*"],
                    resources=["*"],
                ),
            ],
        )

        # CAN: Attach/detach ONLY the governance-hold-deny-all policy on agent
        # roles — never any other managed policy. Without the iam:PolicyARN
        # condition, IAM evaluates only the role being modified as the
        # resource, so the grant would authorize attaching ANY managed policy
        # (including AdministratorAccess) to these roles.
        # iam:ListAttachedRolePolicies does not accept iam:PolicyARN, so it is
        # a separate, unconditioned statement.
        circuit_breaker_role.add_to_policy(iam.PolicyStatement(
            actions=["iam:AttachRolePolicy", "iam:DetachRolePolicy"],
            resources=[
                detection_role.role_arn,
                compliance_role.role_arn,
                executor_role.role_arn,
            ],
            conditions={
                "ArnEquals": {"iam:PolicyARN": self.deny_all_policy.managed_policy_arn},
            },
        ))
        circuit_breaker_role.add_to_policy(iam.PolicyStatement(
            actions=["iam:ListAttachedRolePolicies"],
            resources=[
                detection_role.role_arn,
                compliance_role.role_arn,
                executor_role.role_arn,
            ],
        ))
        # PutItem only — the circuit breaker appends GOVERNANCE_HOLD /
        # GOVERNANCE_HOLD_RELEASED events and must never overwrite or delete
        # prior governance-audit records.
        data_stack.governance_table.grant(circuit_breaker_role, "dynamodb:PutItem")
        # Two-person release and identity binding:
        # RoleId/path binding of human sessions (authz.classify) ...
        circuit_breaker_role.add_to_policy(iam.PolicyStatement(
            actions=["iam:GetRole"],
            resources=[
                f"arn:aws:iam::{self.account}:role{BREAK_GLASS_ROLE_PATH}*",
                f"arn:aws:iam::{self.account}:role{CONSOLE_ROLE_PATH}*",
                f"arn:aws:iam::{self.account}:role/aws-reserved/sso.amazonaws.com/*",
            ],
        ))
        # ... the pending release request and a release's COMPLETED record
        # (consistent reads, by key only) ...
        circuit_breaker_role.add_to_policy(iam.PolicyStatement(
            actions=["dynamodb:GetItem"],
            resources=[data_stack.governance_table.table_arn],
            conditions={"ForAllValues:StringLike": {"dynamodb:LeadingKeys": [
                "release-request#*", "completed-*"]}},
        ))
        # ... the governance-state item that serializes trip and release
        # (conditional UpdateItem on one key; no Put, no Delete) ...
        circuit_breaker_role.add_to_policy(iam.PolicyStatement(
            actions=["dynamodb:GetItem", "dynamodb:UpdateItem"],
            resources=[data_stack.governance_state_table.table_arn],
            conditions={"ForAllValues:StringEquals": {"dynamodb:LeadingKeys": GOVERNANCE_STATE_KEYS}},
        ))
        # ... the latest GOVERNANCE_HOLD event ...
        circuit_breaker_role.add_to_policy(iam.PolicyStatement(
            actions=["dynamodb:Query"],
            resources=[f"{data_stack.governance_table.table_arn}/index/by_event_type"],
        ))
        # ... and trip corroboration from VERIFIED compliance records:
        # drift counters only, never narratives.
        circuit_breaker_role.add_to_policy(iam.PolicyStatement(
            actions=["dynamodb:Query"],
            resources=[f"{data_stack.compliance_table.table_arn}/index/by_day_ts"],
            conditions={
                "ForAllValues:StringEquals": {"dynamodb:Attributes": [
                    "compliance_id", "record_day", "timestamp", "drift_counts", "provenance_status"]},
                "StringEqualsIfExists": {"dynamodb:Select": "SPECIFIC_ATTRIBUTES"},
            },
        ))
        circuit_breaker_role.add_to_policy(iam.PolicyStatement(
            actions=["cloudwatch:PutMetricData"],
            resources=["*"],  # PutMetricData has no resource-level scoping
            conditions={"StringEquals": {"cloudwatch:namespace": GOVERNANCE_INTEGRITY_NAMESPACE}},
        ))
        # recheck_alarms: state of exactly the four trusted
        # trigger alarms, never fsi-*.
        circuit_breaker_role.add_to_policy(iam.PolicyStatement(
            actions=["cloudwatch:DescribeAlarms"],
            resources=[f"arn:aws:cloudwatch:{self.region}:{self.account}:alarm:{name}"
                       for name in TRUSTED_ALARM_NAMES],
        ))

        # ─────────────────────────────────────────────────────────────────────
        # BLUEPRINT 1 — DATA & ACCESS CONTROLS (Bedrock Guardrail)
        # Model-layer data control: BLOCKS credit/debit card numbers and SSNs
        # (CHD/PII) in model I/O, denies prompt-attack + misconduct content, and
        # word-filters injection phrases ("ignore previous instructions", etc.).
        # This is the second CHD boundary — after the PAN ingress filter — so no
        # sensitive data leaks through the LLM into a SAR narrative.
        # ─────────────────────────────────────────────────────────────────────
        self.guardrail = bedrock.CfnGuardrail(
            self, "ComplianceGuardrail",
            name="fsi-compliance-guardrail",
            blocked_input_messaging="Your input was blocked by the compliance guardrail. "
                                    "Injection attempts are logged and escalated.",
            blocked_outputs_messaging="The model output was blocked by the compliance guardrail.",
            content_policy_config=bedrock.CfnGuardrail.ContentPolicyConfigProperty(
                filters_config=[
                    bedrock.CfnGuardrail.ContentFilterConfigProperty(
                        type="PROMPT_ATTACK",
                        input_strength="MEDIUM",
                        output_strength="NONE",
                    ),
                    bedrock.CfnGuardrail.ContentFilterConfigProperty(
                        type="MISCONDUCT",
                        input_strength="MEDIUM",
                        output_strength="MEDIUM",
                    ),
                ],
            ),
            word_policy_config=bedrock.CfnGuardrail.WordPolicyConfigProperty(
                words_config=[
                    bedrock.CfnGuardrail.WordConfigProperty(text="ignore previous instructions"),
                    bedrock.CfnGuardrail.WordConfigProperty(text="admin mode"),
                    bedrock.CfnGuardrail.WordConfigProperty(text="you are now"),
                    bedrock.CfnGuardrail.WordConfigProperty(text="disregard all"),
                ],
            ),
            sensitive_information_policy_config=bedrock.CfnGuardrail.SensitiveInformationPolicyConfigProperty(
                regexes_config=[
                    bedrock.CfnGuardrail.RegexConfigProperty(
                        name="FakeRegulatoryReference",
                        pattern="REG-\\d{4}-EXEMPT-\\d+",
                        action="BLOCK",
                        description="Blocks fake regulatory exemption references",
                    ),
                ],
                pii_entities_config=[
                    bedrock.CfnGuardrail.PiiEntityConfigProperty(
                        type="CREDIT_DEBIT_CARD_NUMBER",
                        action="BLOCK",
                    ),
                    bedrock.CfnGuardrail.PiiEntityConfigProperty(
                        type="US_SOCIAL_SECURITY_NUMBER",
                        action="BLOCK",
                    ),
                ],
            ),
        )

        # CAN: Apply this specific guardrail only — scoped by ARN rather than
        # "*", now that the guardrail resource exists to reference.
        compliance_role.add_to_policy(iam.PolicyStatement(
            actions=["bedrock:ApplyGuardrail"],
            resources=[self.guardrail.attr_guardrail_arn],
        ))

        # Publish a numbered guardrail version. Without this,
        # cdk/deploy_agentcore_runtimes.py pins the runtime's GUARDRAIL_VERSION
        # to a hardcoded "1" even though no CfnGuardrailVersion resource ever
        # created that version — guardrailed Converse calls either fail
        # closed outright (version "1" doesn't exist) or, if callers fall
        # back to an unset GUARDRAIL_VERSION, silently use the mutable DRAFT
        # guardrail instead, so version pinning was never actually enforced
        # either way. This resource publishes the CURRENT DRAFT guardrail
        # config as an immutable numbered version at deploy time; its real
        # attr_version is the one source of truth for what to pin in the
        # runtime env (wired through deploy_agentcore_runtimes.py below).
        self.guardrail_version = bedrock.CfnGuardrailVersion(
            self, "ComplianceGuardrailVersion",
            guardrail_identifier=self.guardrail.attr_guardrail_id,
            description="Published version of fsi-compliance-guardrail for runtime pinning.",
        )

        # ─────────────────────────────────────────────────────────────────────
        # AgentCore Runtimes — deployed via deploy_agentcore_runtimes.py
        # ─────────────────────────────────────────────────────────────────────
        # AgentCore Runtime does NOT have native CloudFormation support yet.
        # After `cdk deploy` provisions IAM roles, data resources, and the code
        # bucket, run:
        #   python cdk/deploy_agentcore_runtimes.py
        # to create the 3 AgentCore Runtimes via the boto3 API.

        # ─────────────────────────────────────────────────────────────────────
        # txn_ref HMAC key — generated by Secrets Manager, so no
        # key value exists in source, in the synthesized template, or in any
        # runtime environment. Only the two roles whose code imports the PAN
        # filter may read it: detection-agent-role (DetectionAgent bundles
        # lambdas/detection_agent/pan_filter.py) and pan-filter-role
        # (fsi-pan-filter). compliance/executor/circuit-breaker get no grant:
        # the runtimes only call contains_full_pan (request_ref check, via
        # governance_common), which needs no key. An explicit GetSecretValue statement is
        # used instead of grant_read, which would also add DescribeSecret.
        # ─────────────────────────────────────────────────────────────────────
        self.txn_ref_hmac_secret = secretsmanager.Secret(
            self, "TxnRefHmacSecret",
            description=(
                "PAN filter txn_ref HMAC key — generated by CDK, "
                "never in source or runtime env"
            ),
            generate_secret_string=secretsmanager.SecretStringGenerator(
                password_length=64,
                exclude_punctuation=True,
                include_space=False,
            ),
            removal_policy=RemovalPolicy.RETAIN,
        )
        detection_role.add_to_policy(iam.PolicyStatement(
            actions=["secretsmanager:GetSecretValue"],
            resources=[self.txn_ref_hmac_secret.secret_arn],
        ))
        pan_filter_role.add_to_policy(iam.PolicyStatement(
            actions=["secretsmanager:GetSecretValue"],
            resources=[self.txn_ref_hmac_secret.secret_arn],
        ))

        # ─────────────────────────────────────────────────────────────────────
        # Lambda Functions (retained — PAN Filter + Circuit Breaker)
        # ─────────────────────────────────────────────────────────────────────

        # PAN Ingress Filter — lightweight, pure-stdlib, no external deps
        self.pan_filter_fn = _lambda.Function(
            self, "PanFilterAgent",
            function_name=PAN_FILTER_FUNCTION_NAME,
            # python3.13 so fsi-pan-filter and the AgentCore runtimes share the
            # same Unicode 15.1 unicodedata tables.
            runtime=_lambda.Runtime.PYTHON_3_13,
            handler="handler.handler",
            code=_lambda.Code.from_asset("../lambdas/pan_filter"),
            role=pan_filter_role,
            log_group=lambda_log_group(self, "PanFilterLogGroup", PAN_FILTER_FUNCTION_NAME),
            timeout=Duration.seconds(10),
            # 512 MB (about 4x the CPU share of 128 MB) so a worst-case
            # MAX_TEXT_CHARS (1 MiB) text scan finishes well inside the 10 s
            # timeout. Deployed timing unmeasured.
            memory_size=512,
            # Bounds the account-concurrency blast radius and the boolean
            # oracle's query rate. Context
            # pan_filter_reserved_concurrency (default 10; 0 -> unset) exists
            # for accounts whose unreserved concurrency would drop below 100.
            reserved_concurrent_executions=pan_filter_reserved_concurrency,
            environment={
                "TXN_REF_HMAC_SECRET_ARN": self.txn_ref_hmac_secret.secret_arn,
            },
        )

        # Dead-letter queue for the circuit breaker (cdk_nag LambdaDLQ /
        # Checkov CKV_AWS_116). The breaker is invoked ASYNCHRONOUSLY by the
        # three drift alarms below; without a DLQ, an invocation that still
        # fails after Lambda's 2 async retries (e.g. GovernanceHoldEnforcement
        # Error on a partial trip) is silently dropped. The Lambda's
        # dead_letter_queue (DeadLetterConfig) is used rather than an
        # EventInvokeConfig on_failure destination because it is the setting
        # both cdk_nag LambdaDLQ and CKV_AWS_116 check for, and CDK grants
        # the role sqs:SendMessage on this queue only.
        self.circuit_breaker_dlq = sqs.Queue(
            self, "CircuitBreakerDLQ",
            queue_name="fsi-circuit-breaker-dlq",
            encryption=sqs.QueueEncryption.SQS_MANAGED,
            enforce_ssl=True,
            retention_period=Duration.days(14),
        )

        # Circuit breaker: the same asset deployed twice.
        # fsi-circuit-breaker (BREAKER_ENTRY=automated) serves the
        # alarm events, auto_trip, check and status; only the executor role
        # and the alarm actions can invoke it. fsi-circuit-breaker-human
        # (BREAKER_ENTRY=human) serves the manual trip, request_release,
        # approve_release and status; only the human breaker/console roles
        # can invoke it. Authorization of human actions is server-side (STS
        # identity proof + role classification), so the env carries no
        # principal allow-lists.
        breaker_environment = {
            "AUDIT_TABLE": data_stack.governance_table.table_name,
            "GOVERNANCE_STATE_TABLE": data_stack.governance_state_table.table_name,
            "COMPLIANCE_TABLE": data_stack.compliance_table.table_name,
            "DETECTION_ROLE": "detection-agent-role",
            "COMPLIANCE_ROLE": "compliance-agent-role",
            "EXECUTOR_ROLE": "executor-agent-role",
            "DENY_POLICY_ARN": self.deny_all_policy.managed_policy_arn,
            # Allow-list of the alarm ARNs the breaker will accept as
            # automatic triggers. Constructed from the alarm
            # names below — CloudWatch alarm ARNs are deterministic, so we
            # don't need the alarm objects (which reference this function)
            # to build them, avoiding a circular dependency.
            "TRUSTED_ALARM_ARNS": ",".join(
                f"arn:aws:cloudwatch:{self.region}:{self.account}:alarm:{name}"
                for name in TRUSTED_ALARM_NAMES
            ),
            # Automated SERVICE principal(s) authorized to trip the breaker
            # via action=="auto_trip": the executor role this
            # same stack creates, mirroring its lambda:InvokeFunction grant on
            # fsi-circuit-breaker. Trip only; it can never release.
            "TRUSTED_AUTOMATED_TRIP_PRINCIPAL_ARNS": executor_role.role_arn,
        }

        def breaker_function(construct_id: str, function_name: str, entry: str,
                             role: iam.IRole = circuit_breaker_role) -> _lambda.Function:
            return _lambda.Function(
                self, construct_id,
                function_name=function_name,
                # python3.13 to match fsi-pan-filter and the AgentCore runtimes
                # (cdk_nag AwsSolutions-L1).
                runtime=_lambda.Runtime.PYTHON_3_13,
                handler="handler.handler",
                code=_lambda.Code.from_asset("../circuit_breaker"),
                role=role,
                log_group=lambda_log_group(self, construct_id + "LogGroup", function_name),
                timeout=Duration.seconds(BREAKER_TIMEOUT_SECONDS),
                memory_size=128,
                # Async retry_attempts left at Lambda's default (2).
                dead_letter_queue=self.circuit_breaker_dlq,
                environment={**breaker_environment, "BREAKER_ENTRY": entry},
            )

        self.circuit_breaker_fn = breaker_function(
            "CircuitBreaker", CIRCUIT_BREAKER_FUNCTION_NAME, "automated")
        # No alarm action ever targets the human function.
        self.circuit_breaker_human_fn = breaker_function(
            "CircuitBreakerHuman", CIRCUIT_BREAKER_HUMAN_FUNCTION_NAME, "human")

        # ─────────────────────────────────────────────────────────────────────
        # Reconciling sweep: while the governance hold is active,
        # re-attach governance-hold-deny-all to any agent role missing it.
        # Its role can attach (only the deny-all, PolicyARN-pinned) and list,
        # and has NO iam:DetachRolePolicy: "never detach" is enforced by IAM
        # as well as by code. No human role can invoke it.
        # ─────────────────────────────────────────────────────────────────────
        sweep_role = iam.Role(
            self, "GovernanceHoldSweepRole",
            role_name=HOLD_SWEEP_ROLE_NAME,
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            # No AWSLambdaBasicExecutionRole (logs:* on "*"): logs go to the
            # function's own group only (cdk/lambda_logging.py).
        )
        grant_lambda_log_writes(sweep_role, HOLD_SWEEP_FUNCTION_NAME)
        agent_role_arns_for_sweep = [detection_role.role_arn, compliance_role.role_arn, executor_role.role_arn]
        sweep_role.add_to_policy(iam.PolicyStatement(
            actions=["iam:AttachRolePolicy"],
            resources=agent_role_arns_for_sweep,
            conditions={"ArnEquals": {"iam:PolicyARN": self.deny_all_policy.managed_policy_arn}},
        ))
        sweep_role.add_to_policy(iam.PolicyStatement(
            actions=["iam:ListAttachedRolePolicies"],
            resources=agent_role_arns_for_sweep,
        ))
        sweep_role.add_to_policy(iam.PolicyStatement(
            actions=["dynamodb:Query"],
            resources=[f"{data_stack.governance_table.table_arn}/index/by_event_type"],
        ))
        sweep_role.add_to_policy(iam.PolicyStatement(
            actions=["dynamodb:PutItem"],
            resources=[data_stack.governance_table.table_arn],
            conditions={"ForAllValues:StringLike": {"dynamodb:LeadingKeys": ["reconcile#*"]}},
        ))
        # Reads the governance-state item; never writes it.
        sweep_role.add_to_policy(iam.PolicyStatement(
            actions=["dynamodb:GetItem"],
            resources=[data_stack.governance_state_table.table_arn],
            conditions={"ForAllValues:StringEquals": {"dynamodb:LeadingKeys": GOVERNANCE_STATE_KEYS}},
        ))
        sweep_role.add_to_policy(iam.PolicyStatement(
            actions=["cloudwatch:PutMetricData"],
            resources=["*"],  # PutMetricData has no resource-level scoping
            conditions={"StringEquals": {"cloudwatch:namespace": GOVERNANCE_INTEGRITY_NAMESPACE}},
        ))
        self.hold_sweep_fn = breaker_function(
            "GovernanceHoldSweepFn", HOLD_SWEEP_FUNCTION_NAME, "sweep", role=sweep_role)
        events.Rule(
            self, "GovernanceHoldSweep",
            rule_name=HOLD_SWEEP_RULE_NAME,
            description="Re-attach the governance hold to any agent role missing it (attach-only)",
            schedule=events.Schedule.rate(Duration.minutes(HOLD_SWEEP_PERIOD_MINUTES)),
            targets=[events_targets.LambdaFunction(
                self.hold_sweep_fn,
                event=events.RuleTargetInput.from_object({"action": "reconcile_hold"}),
                dead_letter_queue=self.circuit_breaker_dlq,
                retry_attempts=2,
            )],
        )

        # Re-evaluation while a trusted alarm stays in ALARM: an
        # alarm action fires once per transition, so the automated breaker
        # re-runs corroboration every 2 minutes (attach-only).
        events.Rule(
            self, "BreakerAlarmRecheck",
            rule_name=BREAKER_ALARM_RECHECK_RULE_NAME,
            description="Re-corroborate trusted drift alarms that stay in ALARM (attach-only)",
            schedule=events.Schedule.rate(Duration.minutes(2)),
            targets=[events_targets.LambdaFunction(
                self.circuit_breaker_fn,
                event=events.RuleTargetInput.from_object({"action": "recheck_alarms"}),
                dead_letter_queue=self.circuit_breaker_dlq,
                retry_attempts=2,
            )],
        )

        # ─────────────────────────────────────────────────────────────────────
        # Drift metric publisher: the ONLY principal in the stack
        # with cloudwatch:PutMetricData on FSI/AgenticCompliance (apart from
        # the opt-in demo console grant). Driven by the KEYS_ONLY stream of
        # compliance-decisions, so a datapoint exists only when a stored
        # decision record exists; it reads four drift attributes by key.
        # ─────────────────────────────────────────────────────────────────────
        drift_publisher_role = iam.Role(
            self, "DriftMetricPublisherRole",
            role_name=DRIFT_PUBLISHER_ROLE_NAME,
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            # No AWSLambdaBasicExecutionRole (logs:* on "*"): logs go to the
            # function's own group only (cdk/lambda_logging.py).
        )
        grant_lambda_log_writes(drift_publisher_role, DRIFT_PUBLISHER_FUNCTION_NAME)
        drift_publisher_role.add_to_policy(iam.PolicyStatement(
            actions=["dynamodb:GetItem"],
            resources=[data_stack.compliance_table.table_arn],
            conditions={
                "ForAllValues:StringEquals": {"dynamodb:Attributes": [
                    "compliance_id", "timestamp", "drift_counts", "provenance_status"]},
                "StringEqualsIfExists": {"dynamodb:Select": "SPECIFIC_ATTRIBUTES"},
            },
        ))
        drift_publisher_role.add_to_policy(iam.PolicyStatement(
            actions=["cloudwatch:PutMetricData"],
            resources=["*"],  # PutMetricData has no resource-level scoping
            conditions={"StringEquals": {"cloudwatch:namespace": DRIFT_NAMESPACE}},
        ))
        drift_publisher_dlq = sqs.Queue(
            self, "DriftMetricPublisherDLQ",
            queue_name="fsi-drift-metric-publisher-dlq",
            encryption=sqs.QueueEncryption.SQS_MANAGED,
            enforce_ssl=True,
            retention_period=Duration.days(14),
        )
        self.drift_publisher_fn = _lambda.Function(
            self, "DriftMetricPublisher",
            function_name=DRIFT_PUBLISHER_FUNCTION_NAME,
            runtime=_lambda.Runtime.PYTHON_3_13,
            handler="handler.handler",
            code=_lambda.Code.from_asset("../lambdas/drift_metric_publisher"),
            role=drift_publisher_role,
            log_group=lambda_log_group(self, "DriftMetricPublisherLogGroup", DRIFT_PUBLISHER_FUNCTION_NAME),
            timeout=Duration.seconds(30),
            memory_size=128,
            dead_letter_queue=drift_publisher_dlq,
            environment={"COMPLIANCE_TABLE": data_stack.compliance_table.table_name},
        )
        self.drift_publisher_fn.add_event_source(lambda_event_sources.DynamoEventSource(
            data_stack.compliance_table,
            starting_position=_lambda.StartingPosition.LATEST,
            batch_size=100,
            bisect_batch_on_error=True,
            retry_attempts=3,
            max_record_age=Duration.hours(1),
            report_batch_item_failures=True,
            on_failure=lambda_event_sources.SqsDlq(drift_publisher_dlq),
            filters=[_lambda.FilterCriteria.filter({"eventName": _lambda.FilterRule.is_equal("INSERT")})],
        ))

        # ═════════════════════════════════════════════════════════════════════
        # BLUEPRINT 4 — DRIFT CONTROL (automated circuit breaker)
        # ═════════════════════════════════════════════════════════════════════
        # Three CloudWatch alarms watch the drift metrics emitted by the
        # compliance agent and auto-fire the circuit breaker Lambda when a threshold
        # is breached — no human needed to trigger:
        #   dispute rate  > 51%  → model disagreement too high
        #   guardrail rate > 10% → too many blocked outputs (attack / degradation)
        #   volume         > 3x  → detection volume anomaly
        # The circuit breaker is asymmetric: automated to trip, manual to reset.
        # ═════════════════════════════════════════════════════════════════════
        # CloudWatch Alarms — Drift-based Circuit Breaker Trigger (unchanged)
        # ─────────────────────────────────────────────────────────────────────

        drift_namespace = "FSI/AgenticCompliance"
        # Review-only alarms notify on-call through fsi-governance-alarms
        # (cdk/governance_alarms.py). The four trusted drift alarms below keep
        # the automated breaker as their ONLY action: containment unchanged.
        notify_on_call = cw_actions.SnsAction(data_stack.alarm_topic.topic)

        # MIN_CLUSTERS_FOR_ALARM_RATE (module level) must match
        # MIN_CLUSTERS_FOR_RATE in lambdas/drift_metric_publisher/handler.py.
        # The publisher's floor
        # only gated the pre-divided *Rate metrics it publishes; the alarm's own
        # MathExpression recomputed the rate from the unfloored raw counts
        # (disputes / MAX([clusters, 1])), so a single low-volume minute (e.g.
        # one DISPUTE cluster) could still publish a 1.0 datapoint and, across
        # two such minutes, breach the alarm. The floor is now baked into the
        # alarm math itself via IF(), so no amount of per-minute undersampling
        # can produce a breaching datapoint.

        # A single request with one disputed cluster used to
        # publish ChallengerDisputeRate=1.0, and evaluation_periods=1 let that
        # one datapoint alone satisfy the alarm and trip the fleet-wide kill
        # switch. Three changes make the trip resistant to a single sample:
        #   (1) the rate is computed alarm-side via metric math over the raw
        #       counts (ChallengerDisputeCount / ClustersAssessed), which the
        #       drift metric publisher publishes alongside a sample-size floor
        #       (see build_metric_data in lambdas/drift_metric_publisher/handler.py);
        #   (2) the alarm math itself re-applies that same sample-size floor
        #       so a low-volume minute always contributes 0,
        #       never a spurious 1.0, regardless of what the handler floor
        #       gates on the publishing side;
        #   (3) evaluation_periods=3 with datapoints_to_alarm=2 means at least
        #       2 of the last 3 one-minute periods must breach, not just one.

        # Alarm: Challenger dispute rate > 51%, sustained across periods
        dispute_count_metric = cloudwatch.Metric(
            namespace=drift_namespace,
            metric_name="ChallengerDisputeCount",
            statistic="Sum",
            period=Duration.minutes(1),
        )
        clusters_assessed_metric = cloudwatch.Metric(
            namespace=drift_namespace,
            metric_name="ClustersAssessed",
            statistic="Sum",
            period=Duration.minutes(1),
        )
        dispute_rate_expression = cloudwatch.MathExpression(
            # Floor is in the alarm math, not just the publisher.
            # A minute with fewer than MIN_CLUSTERS_FOR_ALARM_RATE clusters
            # assessed always contributes 0 to this metric, so it can never
            # be the breaching datapoint, no matter how many disputes it had.
            expression=f"IF(clusters >= {MIN_CLUSTERS_FOR_ALARM_RATE}, disputes / clusters, 0)",
            using_metrics={
                "disputes": dispute_count_metric,
                "clusters": clusters_assessed_metric,
            },
            period=Duration.minutes(1),
        )
        dispute_alarm = cloudwatch.Alarm(
            self, "DisputeRateAlarm",
            alarm_name="fsi-challenger-dispute-rate-breach",
            metric=dispute_rate_expression,
            threshold=0.51,
            evaluation_periods=3,
            datapoints_to_alarm=2,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            alarm_description="Challenger dispute rate exceeded 51% in at least 2 of the last "
                               "3 minutes — triggers circuit breaker",
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )

        # Alarm: Guardrail intervention rate > 10%, sustained across periods
        guardrail_count_metric = cloudwatch.Metric(
            namespace=drift_namespace,
            metric_name="GuardrailInterventionCount",
            statistic="Sum",
            period=Duration.minutes(1),
        )
        guardrail_rate_expression = cloudwatch.MathExpression(
            # Same alarm-side floor as dispute_rate_expression —
            # see comment above.
            expression=f"IF(clusters >= {MIN_CLUSTERS_FOR_ALARM_RATE}, guardrail_hits / clusters, 0)",
            using_metrics={
                "guardrail_hits": guardrail_count_metric,
                "clusters": clusters_assessed_metric,
            },
            period=Duration.minutes(1),
        )
        guardrail_alarm = cloudwatch.Alarm(
            self, "GuardrailRateAlarm",
            alarm_name="fsi-guardrail-intervention-rate-breach",
            metric=guardrail_rate_expression,
            threshold=0.10,
            evaluation_periods=3,
            datapoints_to_alarm=2,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            alarm_description="Guardrail intervention rate exceeded 10% in at least 2 of the last "
                               "3 minutes — triggers circuit breaker",
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )

        # Alarm: Detection volume spike > 3x baseline
        #
        # This alarm was missed when the sibling dispute/guardrail alarms
        # above were hardened against a single-datapoint trip:
        # it was left as raw Maximum, evaluation_periods=1, with default
        # missing-data handling — and its ARN is on the breaker's
        # TRUSTED_ALARM_ARNS allow-list above, so one injected
        # DetectionVolumeMultiplier datapoint could trip the fleet-wide hold.
        # evaluation_periods=3 / datapoints_to_alarm=2 is applied here, the
        # same resistance-to-a-single-sample property the sibling alarms
        # have, and treat_missing_data=NOT_BREACHING so a gap in reporting
        # cannot itself count toward an ALARM evaluation.
        #
        # Unlike ChallengerDisputeRate/GuardrailInterventionRate,
        # DetectionVolumeMultiplier is published as an already-computed
        # ratio (lambdas/drift_metric_publisher/handler.py:build_metric_data)
        # with no accompanying raw numerator/denominator count metric to
        # apply the same MIN_CLUSTERS_FOR_ALARM_RATE metric-math floor to —
        # there is nothing here analogous to ChallengerDisputeCount /
        # ClustersAssessed to floor against. The multi-period /
        # multi-datapoint requirement below is the applicable part of the
        # sibling alarms' hardening pattern for this metric shape.
        volume_alarm = cloudwatch.Alarm(
            self, "VolumeAnomalyAlarm",
            alarm_name="fsi-detection-volume-anomaly",
            metric=cloudwatch.Metric(
                namespace=drift_namespace,
                metric_name="DetectionVolumeMultiplier",
                statistic="Maximum",
                period=Duration.minutes(1),
            ),
            threshold=3.0,
            evaluation_periods=3,
            datapoints_to_alarm=2,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            alarm_description="Detection volume exceeded 3x baseline in at least 2 of the last "
                               "3 minutes — triggers circuit breaker",
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )

        # Alarm: challenger replies rejected by the strict output schema.
        # Rejections are excluded from the dispute
        # count so they can't trip the breaker; this alarm surfaces a
        # formatting regression or JSON-breaking injection for review.
        # Notifies on-call only; it never invokes the breaker and is NOT in
        # TRUSTED_ALARM_ARNS.
        output_rejected_alarm = cloudwatch.Alarm(
            self, "ChallengerOutputRejectedAlarm",
            alarm_name="fsi-challenger-output-rejected",
            metric=cloudwatch.MathExpression(
                expression=f"IF(clusters >= {MIN_CLUSTERS_FOR_ALARM_RATE}, rejected / clusters, 0)",
                using_metrics={
                    "rejected": cloudwatch.Metric(
                        namespace=drift_namespace,
                        metric_name="ChallengerOutputRejectedCount",
                        statistic="Sum",
                        period=Duration.hours(1),
                    ),
                    "clusters": cloudwatch.Metric(
                        namespace=drift_namespace,
                        metric_name="ClustersAssessed",
                        statistic="Sum",
                        period=Duration.hours(1),
                    ),
                },
                period=Duration.hours(1),
            ),
            threshold=0.20,
            evaluation_periods=1,
            datapoints_to_alarm=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            alarm_description="More than 20% of challenger replies failed output schema "
                               "validation over 1 hour — review only, never trips the breaker",
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )
        output_rejected_alarm.add_alarm_action(notify_on_call)

        # Alarm: low-volume SUSTAINED dispute drift. The per-minute
        # alarm above ignores minutes with < 20 clusters, so drift kept under
        # 20 clusters/min would never alarm; this one evaluates the same floor
        # over a 1-hour Sum. Wired to the breaker and in TRUSTED_ALARM_ARNS.
        sustained_dispute_alarm = cloudwatch.Alarm(
            self, "DisputeRateSustainedAlarm",
            alarm_name="fsi-challenger-dispute-rate-sustained",
            metric=cloudwatch.MathExpression(
                expression=f"IF(clusters >= {MIN_CLUSTERS_FOR_ALARM_RATE}, disputes / clusters, 0)",
                using_metrics={
                    "disputes": cloudwatch.Metric(
                        namespace=drift_namespace,
                        metric_name="ChallengerDisputeCount",
                        statistic="Sum",
                        period=Duration.hours(1),
                    ),
                    "clusters": cloudwatch.Metric(
                        namespace=drift_namespace,
                        metric_name="ClustersAssessed",
                        statistic="Sum",
                        period=Duration.hours(1),
                    ),
                },
                period=Duration.hours(1),
            ),
            threshold=0.51,
            evaluation_periods=1,
            datapoints_to_alarm=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            alarm_description="Challenger dispute rate exceeded 51% over 1 hour (low-volume "
                               "sustained drift) — triggers circuit breaker",
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )

        # Wire the trusted alarms to invoke the AUTOMATED circuit breaker only.
        # use_unique_permission_id avoids construct ID collision when multiple
        # alarms target the same Lambda function.
        dispute_alarm.add_alarm_action(
            cw_actions.LambdaAction(self.circuit_breaker_fn, use_unique_permission_id=True))
        guardrail_alarm.add_alarm_action(
            cw_actions.LambdaAction(self.circuit_breaker_fn, use_unique_permission_id=True))
        volume_alarm.add_alarm_action(
            cw_actions.LambdaAction(self.circuit_breaker_fn, use_unique_permission_id=True))
        sustained_dispute_alarm.add_alarm_action(
            cw_actions.LambdaAction(self.circuit_breaker_fn, use_unique_permission_id=True))

        # Review-only integrity alarms. Each one's only action is
        # the on-call topic, and none is in TRUSTED_ALARM_ARNS: none can
        # invoke the breaker.
        def action_less_alarm(construct_id, alarm_name, metric, description,
                              threshold=0, comparison=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD):
            alarm = cloudwatch.Alarm(
                self, construct_id,
                alarm_name=alarm_name,
                metric=metric,
                threshold=threshold,
                evaluation_periods=1,
                datapoints_to_alarm=1,
                comparison_operator=comparison,
                alarm_description=description,
                treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
            )
            alarm.add_alarm_action(notify_on_call)
            return alarm

        def integrity_metric(name, minutes=5):
            return cloudwatch.Metric(namespace=GOVERNANCE_INTEGRITY_NAMESPACE, metric_name=name,
                                     statistic="Sum", period=Duration.minutes(minutes))

        # A trusted drift alarm that durable VERIFIED compliance records did
        # not corroborate (forged datapoints or an injected breach): the hold
        # was NOT attached and an ALARM_UNCORROBORATED event was recorded.
        action_less_alarm(
            "UncorroboratedDriftAlarm", "fsi-uncorroborated-drift-alarm",
            integrity_metric("UncorroboratedAlarm"),
            "A drift alarm fired that VERIFIED compliance records did not corroborate; the hold "
            "was NOT attached. Review the ALARM_UNCORROBORATED event")
        action_less_alarm(
            "CorroborationUnavailableAlarm", "fsi-corroboration-unavailable",
            integrity_metric("CorroborationUnavailable"),
            "The breaker could not read the compliance records to corroborate a drift alarm "
            "(the alarm path tripped anyway; a recheck deferred)")
        action_less_alarm(
            "DriftShapingSuspectedAlarm", "fsi-drift-shaping-suspected",
            integrity_metric("ShapingSuspected"),
            "Compliance invocations in a drift alarm window exceeded 3x the baseline rate "
            "(possible workload shaping); review the corroboration record")
        action_less_alarm(
            "DriftPublisherDlqAlarm", "fsi-drift-metric-publisher-dlq-not-empty",
            drift_publisher_dlq.metric_approximate_number_of_messages_visible(
                period=Duration.minutes(5), statistic="Maximum"),
            "Drift metric publisher stream records failed after all retries; drift metrics "
            "are missing for those decisions")
        action_less_alarm(
            "DriftPublisherIteratorAgeAlarm", "fsi-drift-metric-publisher-iterator-age",
            self.drift_publisher_fn.metric("IteratorAge", statistic="Maximum",
                                           period=Duration.minutes(5)),
            "The drift metric publisher is more than 15 minutes behind the compliance stream",
            threshold=900000)
        action_less_alarm(
            "DriftPublisherErrorsAlarm", "fsi-drift-metric-publisher-errors",
            self.drift_publisher_fn.metric_errors(statistic="Sum", period=Duration.minutes(5)),
            "The drift metric publisher failed; drift metrics may be missing")
        action_less_alarm(
            "HoldReconciledAlarm", "fsi-hold-reconciled",
            integrity_metric("HoldReconciled"),
            "The governance-hold sweep re-attached the deny-all to an agent role that was "
            "missing it; review the GOVERNANCE_HOLD_RECONCILED event and CloudTrail")
        action_less_alarm(
            "HoldSweepFailedAlarm", "fsi-hold-sweep-failed",
            integrity_metric("HoldSweepFailed", minutes=15),
            "The governance-hold sweep could not read the hold state; containment is not being "
            "reconciled")
        # Liveness: every completed scheduled sweep emits one
        # HoldSweepHeartbeat. Missing data is breaching, so a disabled or
        # deleted schedule, a failing function or a sweep that errors pages
        # on-call after three sweep periods without a heartbeat.
        hold_sweep_not_running = cloudwatch.Alarm(
            self, "HoldSweepNotRunningAlarm",
            alarm_name="fsi-hold-sweep-not-running",
            metric=integrity_metric(HOLD_SWEEP_HEARTBEAT_METRIC, minutes=HOLD_SWEEP_PERIOD_MINUTES),
            threshold=1,
            evaluation_periods=HOLD_SWEEP_LIVENESS_PERIODS,
            datapoints_to_alarm=HOLD_SWEEP_LIVENESS_PERIODS,
            comparison_operator=cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD,
            alarm_description="The governance-hold sweep has not completed a run for "
                              f"{HOLD_SWEEP_LIVENESS_PERIODS} sweep periods; drifted agent roles "
                              "are not being re-contained. Check the fsi-governance-hold-sweep "
                              "rule (enabled?) and the function's errors",
            treat_missing_data=cloudwatch.TreatMissingData.BREACHING,
        )
        hold_sweep_not_running.add_alarm_action(notify_on_call)
        # Trip/release serialization on the governance-state item.
        action_less_alarm(
            "NewerHoldDetectedAlarm", "fsi-newer-hold-detected",
            integrity_metric("NewerHoldDetected"),
            "A newer hold was claimed while a release was detaching; the release re-attached the "
            "deny-all. Check the COMPLETED record's reattach_failures and review the newer hold")
        action_less_alarm(
            "HoldReleaseSupersededAlarm", "fsi-hold-release-superseded",
            integrity_metric("ReleaseSuperseded"),
            "An approved release lost to a newer hold (before or after its detach); review the "
            "newer hold before requesting again")
        action_less_alarm(
            "HoldStateWriteFailedAlarm", "fsi-hold-state-write-failed",
            integrity_metric("HoldStateWriteFailed"),
            "A trip could not claim the governance-state item, or the sweep or recheck found a "
            "trip that never did; the hold is enforced, release stays blocked until a re-trip")
        action_less_alarm(
            "HoldStateReadFailedAlarm", "fsi-hold-state-read-failed",
            integrity_metric("HoldStateReadFailed"),
            "A release could not re-read the governance-state item after its detach; the sweep "
            "restores any newer hold within one cycle. Review the COMPLETED record")
        # Dilution detection: invocation volume above its anomaly band. L1,
        # because ANOMALY_DETECTION_BAND needs ThresholdMetricId.
        cloudwatch.CfnAlarm(
            self, "ComplianceInvocationSurgeAlarm",
            alarm_name="fsi-compliance-invocation-surge",
            alarm_description="ComplianceInvocations above its anomaly band (possible dilution "
                              "of a drift signal by padded runs); review only",
            metrics=[
                cloudwatch.CfnAlarm.MetricDataQueryProperty(
                    id="m1", return_data=True,
                    metric_stat=cloudwatch.CfnAlarm.MetricStatProperty(
                        metric=cloudwatch.CfnAlarm.MetricProperty(
                            namespace=DRIFT_NAMESPACE, metric_name="ComplianceInvocations"),
                        period=300, stat="Sum")),
                cloudwatch.CfnAlarm.MetricDataQueryProperty(
                    id="ad1", return_data=True, expression="ANOMALY_DETECTION_BAND(m1, 3)"),
            ],
            threshold_metric_id="ad1",
            comparison_operator="GreaterThanUpperThreshold",
            evaluation_periods=1,
            datapoints_to_alarm=1,
            treat_missing_data="notBreaching",
            alarm_actions=[data_stack.alarm_topic.topic.topic_arn],
        )

        # Alarm: a circuit breaker invocation landed in the DLQ (a kill-switch
        # trip failed after all async retries). Its only action is the
        # on-call topic: it must never invoke the circuit breaker itself.
        breaker_dlq_alarm = cloudwatch.Alarm(
            self, "CircuitBreakerDlqAlarm",
            alarm_name="fsi-circuit-breaker-dlq-not-empty",
            metric=self.circuit_breaker_dlq.metric_approximate_number_of_messages_visible(
                period=Duration.minutes(5),
                statistic="Maximum",
            ),
            threshold=0,
            evaluation_periods=1,
            datapoints_to_alarm=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            alarm_description="A circuit breaker (kill switch) invocation failed after all "
                               "async retries and is in fsi-circuit-breaker-dlq; investigate "
                               "and trip manually if required",
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )
        breaker_dlq_alarm.add_alarm_action(notify_on_call)

        # ═════════════════════════════════════════════════════════════════════
        # Human governance identities, signing keys, read scoping.
        # Every human role: inline policies only, max session 1 h. No human
        # role can invoke fsi-circuit-breaker (the automated entry point);
        # human lambda:InvokeFunction grants name fsi-circuit-breaker-human
        # (and, for the console operators, fsi-pan-filter) only.
        # ═════════════════════════════════════════════════════════════════════
        def human_role(construct_id: str, role_name: str, description: str, path: str = None):
            kwargs = {"path": path} if path else {}
            return iam.Role(
                self, construct_id,
                role_name=role_name,
                description=description,
                assumed_by=iam.AccountRootPrincipal().with_conditions(HUMAN_MFA_TRUST_CONDITIONS),
                max_session_duration=HUMAN_ROLE_MAX_SESSION,
                **kwargs,
            )

        def allow_set_source_identity_in_trust(role: iam.Role) -> None:
            # The console host is the only trusted principal (assumed_by), so
            # add sts:SetSourceIdentity to that one statement; see
            # add_console_host_trust below for why it must share the block.
            role.node.default_child.add_property_override(
                "AssumeRolePolicyDocument.Statement.0.Action", ["sts:AssumeRole", "sts:SetSourceIdentity"])

        def add_console_host_trust(role: iam.Role) -> None:
            # One statement for both actions: a condition on sts:SourceIdentity
            # needs sts:SetSourceIdentity in the same action block (Access
            # Analyzer MISSING_ACTION_FOR_CONDITION_KEY). Same grant as two
            # statements with identical principal and conditions.
            role.assume_role_policy.add_statements(iam.PolicyStatement(
                actions=["sts:AssumeRole", "sts:SetSourceIdentity"],
                principals=[iam.ArnPrincipal(console_host_role_arn)],
                conditions=CONSOLE_HOST_TRUST_CONDITIONS,
            ))

        model_risk_approver_role = human_role(
            "ModelRiskApproverRole", "fsi-model-risk-approver",
            "Model Risk approver: signs the approved-models registry")
        gate_signer_role = human_role(
            "DeployGateSignerRole", "fsi-deploy-gate-signer",
            "Deploy gate signer: signs the compliance gate artifact")
        if ci_role_arn:
            # CI runs the gate on its own role credentials: no MFA/session-name
            # conditions are satisfiable there, so the CI principal is one
            # specific role ARN, never the account root.
            gate_signer_role.assume_role_policy.add_statements(iam.PolicyStatement(
                actions=["sts:AssumeRole"],
                principals=[iam.ArnPrincipal(ci_role_arn)],
            ))

        def signing_key(construct_id: str, alias: str, signer: iam.Role, description: str) -> kms.Key:
            # Asymmetric keys can't auto-rotate (a KMS5 hit, if any, is accepted).
            return kms.Key(
                self, construct_id,
                alias=alias,
                description=description,
                key_spec=kms.KeySpec.ECC_NIST_P256,
                key_usage=kms.KeyUsage.SIGN_VERIFY,
                removal_policy=RemovalPolicy.RETAIN,
                policy=iam.PolicyDocument(statements=[
                    iam.PolicyStatement(
                        sid="KeyAdministration",
                        principals=[iam.AccountRootPrincipal()],
                        actions=KMS_KEY_ADMIN_ACTIONS,
                        resources=["*"],
                    ),
                    iam.PolicyStatement(
                        sid="SignerRoleSigns",
                        principals=[signer],
                        actions=["kms:Sign"],
                        resources=["*"],
                    ),
                    iam.PolicyStatement(
                        sid="AccountPrincipalsVerify",
                        principals=[iam.AccountRootPrincipal()],
                        actions=["kms:Verify", "kms:GetPublicKey", "kms:DescribeKey"],
                        resources=["*"],
                    ),
                ]),
            )

        self.registry_signing_key = signing_key(
            "RegistrySigningKey", "alias/fsi-model-registry-signing", model_risk_approver_role,
            "Signs data/approved_models.json (Model Risk approver only)")
        self.gate_signing_key = signing_key(
            "GateSigningKey", "alias/fsi-deploy-gate-signing", gate_signer_role,
            "Signs the compliance gate artifact (deploy gate signer only)")

        model_risk_approver_role.add_to_policy(iam.PolicyStatement(
            actions=["kms:Sign", "kms:DescribeKey", "kms:Verify"],
            resources=[self.registry_signing_key.key_arn],
        ))
        # The gate's own AWS reads are hard FAILs when denied, so the signer
        # holds exactly those reads plus the two key operations.
        gate_signer_role.add_to_policy(iam.PolicyStatement(
            actions=["kms:Sign", "kms:DescribeKey"],
            resources=[self.gate_signing_key.key_arn],
        ))
        gate_signer_role.add_to_policy(iam.PolicyStatement(
            actions=["kms:Verify", "kms:DescribeKey"],
            resources=[self.registry_signing_key.key_arn],
        ))
        # The IAM service prefix is bedrock-agentcore for the control plane
        # too (the boto3 client is named bedrock-agentcore-control).
        gate_signer_role.add_to_policy(iam.PolicyStatement(
            actions=["bedrock-agentcore:ListAgentRuntimes"],
            resources=["*"],  # list API, no resource-level scoping
        ))
        gate_signer_role.add_to_policy(iam.PolicyStatement(
            actions=["bedrock-agentcore:GetAgentRuntime"],
            resources=[f"arn:aws:bedrock-agentcore:{self.region}:{self.account}:runtime/ComplianceAgent-*"],
        ))
        gate_signer_role.add_to_policy(iam.PolicyStatement(
            actions=["iam:GetRole"],
            resources=[detection_role.role_arn, compliance_role.role_arn, executor_role.role_arn],
        ))
        gate_signer_role.add_to_policy(iam.PolicyStatement(
            actions=["cloudformation:DescribeStacks"],
            resources=[f"arn:aws:cloudformation:{self.region}:{self.account}:stack/FsiComplianceAgents/*"],
        ))

        # Agents verify the gate artifact (runtime attestation); compliance
        # also verifies the registry; the executor encrypts SAR filings.
        for agent_role in (detection_role, compliance_role, executor_role):
            agent_role.add_to_policy(iam.PolicyStatement(
                actions=["kms:Verify", "kms:DescribeKey"],
                resources=[self.gate_signing_key.key_arn],
            ))
        compliance_role.add_to_policy(iam.PolicyStatement(
            actions=["kms:Verify", "kms:DescribeKey"],
            resources=[self.registry_signing_key.key_arn],
        ))
        executor_role.add_to_policy(iam.PolicyStatement(
            actions=["kms:GenerateDataKey", "kms:Encrypt"],
            resources=[data_stack.sar_key.key_arn],
        ))

        # Read-only audit role. Default path "/", so the
        # deterministic ARN in the SAR key and bucket policies matches.
        audit_tables = (
            data_stack.detection_table,
            data_stack.compliance_table,
            data_stack.audit_table,
            data_stack.governance_table,
            data_stack.operator_audit_table,
        )
        audit_indexes = (
            (data_stack.detection_table, "by_day_ts"),
            (data_stack.compliance_table, "by_day_ts"),
            (data_stack.audit_table, "by_day_ts"),
            (data_stack.governance_table, "by_event_type"),
            (data_stack.operator_audit_table, "by_day_ts"),
        )
        compliance_reader_role = human_role(
            "ComplianceReaderRole", COMPLIANCE_READER_ROLE_NAME,
            "Read-only audit and SAR filings reader")
        if console_host_role_arn:
            add_console_host_trust(compliance_reader_role)
        compliance_reader_role.add_to_policy(iam.PolicyStatement(
            actions=["dynamodb:GetItem", "dynamodb:BatchGetItem"],
            resources=[t.table_arn for t in audit_tables],
        ))
        compliance_reader_role.add_to_policy(iam.PolicyStatement(
            actions=["dynamodb:Query"],
            resources=[f"{t.table_arn}/index/{name}" for t, name in audit_indexes],
        ))
        compliance_reader_role.add_to_policy(iam.PolicyStatement(
            actions=["s3:GetObject"],
            resources=[data_stack.sar_bucket.arn_for_objects("filings/*")],
        ))
        compliance_reader_role.add_to_policy(iam.PolicyStatement(
            actions=["kms:Decrypt"],
            resources=[data_stack.sar_key.key_arn],
        ))
        # Examiner path to the immutable audit archive: read, list, and
        # verify retention/checksums. Read-only; the archive key and bucket
        # policies also name this role.
        archive = data_stack.audit_archive
        compliance_reader_role.add_to_policy(iam.PolicyStatement(
            actions=["s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectRetention",
                     "s3:GetObjectAttributes"],
            resources=[archive.bucket.arn_for_objects("*")],
        ))
        compliance_reader_role.add_to_policy(iam.PolicyStatement(
            actions=["s3:ListBucket", "s3:ListBucketVersions"],
            resources=[archive.bucket.bucket_arn],
        ))
        compliance_reader_role.add_to_policy(iam.PolicyStatement(
            actions=["kms:Decrypt"],
            resources=[archive.key.key_arn],
            conditions={"StringEquals": {"kms:ViaService": f"s3.{self.region}.amazonaws.com"}},
        ))

        # Console operator roles. The same statements on both,
        # except that drift-injection PutMetricData exists only on the direct
        # operator role and only with context allow_console_drift_injection.
        def add_console_operator_statements(role: iam.Role, allow_drift_injection: bool) -> None:
            runtime_prefix = f"arn:aws:bedrock-agentcore:{self.region}:{self.account}:runtime"
            runtime_arns = []
            for name in AGENTCORE_RUNTIME_NAMES:
                runtime_arns.append(f"{runtime_prefix}/{name}-*")
                runtime_arns.append(f"{runtime_prefix}/{name}-*/runtime-endpoint/*")
            role.add_to_policy(iam.PolicyStatement(
                actions=["bedrock-agentcore:InvokeAgentRuntime"],
                resources=runtime_arns,
            ))
            # The pinned runtime ARNs (one parameter, read only). Replaces
            # ListAgentRuntimes: the console never looks runtimes up by name.
            role.add_to_policy(iam.PolicyStatement(
                actions=["ssm:GetParameter"],
                resources=[f"arn:aws:ssm:{self.region}:{self.account}:parameter{RUNTIME_ARNS_PARAMETER}"],
            ))
            role.add_to_policy(iam.PolicyStatement(
                actions=["dynamodb:PutItem"],
                resources=[data_stack.operator_audit_table.table_arn],
            ))
            role.add_to_policy(iam.PolicyStatement(
                actions=["dynamodb:Query"],
                resources=[f"{data_stack.audit_table.table_arn}/index/by_day_ts"],
            ))
            role.add_to_policy(iam.PolicyStatement(
                actions=["iam:ListAttachedRolePolicies"],
                resources=[detection_role.role_arn, compliance_role.role_arn, executor_role.role_arn],
            ))
            role.add_to_policy(iam.PolicyStatement(
                actions=["cloudwatch:DescribeAlarms"],
                resources=[f"arn:aws:cloudwatch:{self.region}:{self.account}:alarm:fsi-*"],
            ))
            role.add_to_policy(iam.PolicyStatement(
                actions=["bedrock:InvokeModel"],  # authorizes Converse
                resources=approved_model_arns,
            ))
            role.add_to_policy(iam.PolicyStatement(
                actions=["bedrock:ApplyGuardrail"],
                resources=[self.guardrail.attr_guardrail_arn],
            ))
            # The PAN filter page and the HUMAN breaker entry point only —
            # never fsi-circuit-breaker (alarm / auto_trip paths).
            role.add_to_policy(iam.PolicyStatement(
                actions=["lambda:InvokeFunction"],
                resources=[self.pan_filter_fn.function_arn, self.circuit_breaker_human_fn.function_arn],
            ))
            if allow_drift_injection:
                # Demo-only standing exception (D4 live drift demo), still
                # gated in the console by CONSOLE_ALLOW_DRIFT_INJECTION.
                role.add_to_policy(iam.PolicyStatement(
                    actions=["cloudwatch:PutMetricData"],
                    resources=["*"],
                    conditions={"StringEquals": {"cloudwatch:namespace": DRIFT_NAMESPACE}},
                ))

        console_operator_role = human_role(
            "ConsoleOperatorRole", "fsi-console-operator",
            "Console operator (local console mode, the operator's own IAM user session)",
            path="/fsi-console/")
        add_console_operator_statements(console_operator_role, allow_console_drift_injection)
        if console_host_role_arn:
            console_operator_hosted_role = iam.Role(
                self, "ConsoleOperatorHostedRole",
                role_name="fsi-console-operator-hosted",
                path="/fsi-console/",
                description="Console operator sessions minted by the console host for a Cognito user",
                assumed_by=iam.ArnPrincipal(console_host_role_arn).with_conditions(
                    CONSOLE_HOST_TRUST_CONDITIONS),
                max_session_duration=HUMAN_ROLE_MAX_SESSION,
            )
            allow_set_source_identity_in_trust(console_operator_hosted_role)
            # Never PutMetricData, regardless of context.
            add_console_operator_statements(console_operator_hosted_role, False)
            # Operator-audit writer for hosted principals without the operator
            # role: an auditor-only principal records its own
            # AUDIT_READ / SIGN_IN through this role, never the operator-hosted
            # one. PutItem on operator-audit only; authz.RULES match exact
            # role names, so it holds no breaker capability.
            console_audit_writer_hosted_role = iam.Role(
                self, "ConsoleAuditWriterHostedRole",
                role_name="fsi-console-audit-writer-hosted",
                path="/fsi-console/",
                description="Operator-audit writes for hosted console principals without the operator role",
                assumed_by=iam.ArnPrincipal(console_host_role_arn).with_conditions(
                    CONSOLE_HOST_TRUST_CONDITIONS),
                max_session_duration=HUMAN_ROLE_MAX_SESSION,
            )
            allow_set_source_identity_in_trust(console_audit_writer_hosted_role)
            console_audit_writer_hosted_role.add_to_policy(iam.PolicyStatement(
                actions=["dynamodb:PutItem"],
                resources=[data_stack.operator_audit_table.table_arn],
            ))

        # Breaker human roles. Operator and approver
        # invoke ONLY the human entry point; the approver never trusts the
        # console host (approvals never go through the host, whatever the
        # context). Break-glass is the out-of-band release path
        # (scripts/break_glass_release.py), assumed only during an incident.
        for construct_id, role_name, description in (
            ("BreakerOperatorRole", "fsi-breaker-operator",
             "Breaker operator: manual trip and release requests (fsi-circuit-breaker-human only)"),
            ("BreakerApproverRole", "fsi-breaker-approver",
             "Breaker approver: second person of a two-person release (fsi-circuit-breaker-human only)"),
        ):
            breaker_human_role = human_role(construct_id, role_name, description, path=BREAK_GLASS_ROLE_PATH)
            breaker_human_role.add_to_policy(iam.PolicyStatement(
                actions=["lambda:InvokeFunction"],
                resources=[self.circuit_breaker_human_fn.function_arn],
            ))
        break_glass_role = human_role(
            "BreakerBreakGlassRole", BREAK_GLASS_ROLE_NAME,
            "Out-of-band governance-hold release (incident only; every assumption alarms)",
            path=BREAK_GLASS_ROLE_PATH)
        agent_role_arns = [detection_role.role_arn, compliance_role.role_arn, executor_role.role_arn]
        break_glass_role.add_to_policy(iam.PolicyStatement(
            actions=["iam:DetachRolePolicy"],
            resources=agent_role_arns,
            conditions={"ArnEquals": {"iam:PolicyARN": self.deny_all_policy.managed_policy_arn}},
        ))
        break_glass_role.add_to_policy(iam.PolicyStatement(
            actions=["iam:ListAttachedRolePolicies"],
            resources=agent_role_arns,
        ))
        break_glass_role.add_to_policy(iam.PolicyStatement(
            actions=["iam:GetRole"],
            resources=[f"arn:aws:iam::{self.account}:role{BREAK_GLASS_ROLE_PATH}*"],
        ))
        break_glass_role.add_to_policy(iam.PolicyStatement(
            actions=["dynamodb:PutItem"],
            resources=[data_stack.governance_table.table_arn],
        ))
        # Claims the governance-state item for the out-of-band release.
        break_glass_role.add_to_policy(iam.PolicyStatement(
            actions=["dynamodb:GetItem", "dynamodb:UpdateItem"],
            resources=[data_stack.governance_state_table.table_arn],
            conditions={"ForAllValues:StringEquals": {"dynamodb:LeadingKeys": GOVERNANCE_STATE_KEYS}},
        ))
        break_glass_role.add_to_policy(iam.PolicyStatement(
            actions=["sts:GetCallerIdentity"],
            resources=["*"],
        ))

        # ─────────────────────────────────────────────────────────────────────
        # Separate monitoring of governance-hold changes: any
        # attach/detach on an agent role not made by the breaker, and every
        # break-glass role assumption. EventBridge -> a dedicated log group
        # (direct resource policy, no custom-resource Lambda) -> metric
        # filters -> two alarms that notify on-call (never the breaker).
        # IAM CloudTrail events are delivered in us-east-1.
        # ─────────────────────────────────────────────────────────────────────
        hold_changes_log_group = logs.LogGroup(
            self, "HoldChangesLogGroup",
            log_group_name=HOLD_CHANGES_LOG_GROUP,
            retention=logs.RetentionDays.ONE_YEAR,
            removal_policy=RemovalPolicy.RETAIN,
        )
        hold_changes_target = _LogGroupRuleTarget(hold_changes_log_group)
        hold_change_rule = events.Rule(
            self, "HoldChangeRule",
            description="Attach/DetachRolePolicy on the agent roles (governance hold changes)",
            event_pattern=events.EventPattern(
                source=["aws.iam"],
                detail_type=["AWS API Call via CloudTrail"],
                detail={
                    "eventSource": ["iam.amazonaws.com"],
                    "eventName": ["AttachRolePolicy", "DetachRolePolicy"],
                    "requestParameters": {"roleName": list(AGENT_ROLE_NAMES)},
                },
            ),
            targets=[hold_changes_target],
        )
        break_glass_role_arn = (
            f"arn:aws:iam::{self.account}:role{BREAK_GLASS_ROLE_PATH}{BREAK_GLASS_ROLE_NAME}")
        break_glass_rule = events.Rule(
            self, "BreakGlassAssumeRoleRule",
            description="sts:AssumeRole on the out-of-band break-glass role",
            event_pattern=events.EventPattern(
                source=["aws.sts"],
                detail_type=["AWS API Call via CloudTrail"],
                detail={
                    "eventSource": ["sts.amazonaws.com"],
                    "eventName": ["AssumeRole"],
                    "requestParameters": {"roleArn": [break_glass_role_arn]},
                },
            ),
            targets=[hold_changes_target],
        )
        logs.CfnResourcePolicy(
            self, "HoldChangesLogsPolicy",
            policy_name="fsi-governance-hold-changes-events",
            policy_document=Stack.of(self).to_json_string({
                "Version": "2012-10-17",
                "Statement": [{
                    "Sid": "HoldChangeRulesDeliver",
                    "Effect": "Allow",
                    "Principal": {"Service": ["events.amazonaws.com", "delivery.logs.amazonaws.com"]},
                    "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                    "Resource": hold_changes_log_group.log_group_arn,
                    "Condition": {"ArnEquals": {"aws:SourceArn": [
                        hold_change_rule.rule_arn, break_glass_rule.rule_arn,
                    ]}},
                }],
            }),
        )
        hold_change_events = '($.detail.eventName = "AttachRolePolicy") || ($.detail.eventName = "DetachRolePolicy")'
        hold_change_total = logs.MetricFilter(
            self, "HoldChangeTotalFilter",
            log_group=hold_changes_log_group,
            metric_namespace=GOVERNANCE_INTEGRITY_NAMESPACE,
            metric_name="HoldChangeTotal",
            metric_value="1",
            filter_pattern=logs.FilterPattern.literal("{ " + hold_change_events + " }"),
        )
        # A != on sessionIssuer.userName would miss IAM-user/root events (no
        # sessionContext), so count totals and subtract the breaker's own.
        # Sweep ATTACHES are the breaker's too (fsi-hold-reconciled alerts on
        # them); a sweep-role detach still counts as out-of-band.
        hold_change_by_breaker = logs.MetricFilter(
            self, "HoldChangeByBreakerFilter",
            log_group=hold_changes_log_group,
            metric_namespace=GOVERNANCE_INTEGRITY_NAMESPACE,
            metric_name="HoldChangeByBreaker",
            metric_value="1",
            filter_pattern=logs.FilterPattern.literal(
                "{ ((" + hold_change_events + ") && "
                '($.detail.userIdentity.sessionContext.sessionIssuer.userName = "circuit-breaker-role")) || '
                '(($.detail.eventName = "AttachRolePolicy") && '
                f'($.detail.userIdentity.sessionContext.sessionIssuer.userName = "{HOLD_SWEEP_ROLE_NAME}")) }}'),
        )
        break_glass_assumed = logs.MetricFilter(
            self, "BreakGlassAssumedFilter",
            log_group=hold_changes_log_group,
            metric_namespace=GOVERNANCE_INTEGRITY_NAMESPACE,
            metric_name="BreakGlassAssumed",
            metric_value="1",
            filter_pattern=logs.FilterPattern.literal('{ $.detail.eventName = "AssumeRole" }'),
        )
        five_minutes = Duration.minutes(5)
        # Both alarms notify on-call only (like the DLQ alarm): they must
        # never invoke the breaker.
        out_of_band_alarm = cloudwatch.Alarm(
            self, "OutOfBandHoldChangeAlarm",
            alarm_name="fsi-out-of-band-hold-change",
            metric=cloudwatch.MathExpression(
                expression="FILL(total,0) - FILL(breaker,0)",
                using_metrics={
                    "total": hold_change_total.metric(statistic="Sum", period=five_minutes),
                    "breaker": hold_change_by_breaker.metric(statistic="Sum", period=five_minutes),
                },
                period=five_minutes,
            ),
            threshold=0,
            evaluation_periods=1,
            datapoints_to_alarm=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
            alarm_description="A governance-hold policy was attached/detached on an agent role by "
                               "something other than the circuit breaker; review CloudTrail",
        )
        break_glass_alarm = cloudwatch.Alarm(
            self, "BreakGlassAssumedAlarm",
            alarm_name="fsi-break-glass-assumed",
            metric=break_glass_assumed.metric(statistic="Sum", period=five_minutes),
            threshold=0,
            evaluation_periods=1,
            datapoints_to_alarm=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
            alarm_description="The out-of-band break-glass role was assumed; second-person "
                               "incident review required within 24 h",
        )
        for alarm in (out_of_band_alarm, break_glass_alarm):
            alarm.add_alarm_action(notify_on_call)

        # ─────────────────────────────────────────────────────────────────────
        # Outputs
        # ─────────────────────────────────────────────────────────────────────
        CfnOutput(self, "CodeBucketName", value=self.code_bucket.bucket_name)
        CfnOutput(self, "RegistrySigningKeyArn", value=self.registry_signing_key.key_arn)
        CfnOutput(self, "GateSigningKeyArn", value=self.gate_signing_key.key_arn)
        CfnOutput(self, "DetectionRoleArn", value=detection_role.role_arn)
        CfnOutput(self, "ComplianceRoleArn", value=compliance_role.role_arn)
        CfnOutput(self, "ExecutorRoleArn", value=executor_role.role_arn)
        CfnOutput(self, "GuardrailId", value=self.guardrail.attr_guardrail_id)
        # Real published version number — deploy_agentcore_runtimes.py
        # reads this instead of hardcoding "1", so the runtime is only ever
        # pinned to a version that actually exists.
        CfnOutput(self, "GuardrailVersion", value=self.guardrail_version.attr_version)
        CfnOutput(self, "DenyPolicyArn", value=self.deny_all_policy.managed_policy_arn)
        # The ARN is not sensitive; deploy_agentcore_runtimes.py reads it and
        # sets TXN_REF_HMAC_SECRET_ARN on the DetectionAgent runtime.
        CfnOutput(self, "TxnRefHmacSecretArn", value=self.txn_ref_hmac_secret.secret_arn)


# ─────────────────────────────────────────────────────────────────────────────
# DEPLOYMENT SCRIPT (run after CDK deploy to create AgentCore Runtimes)
# ─────────────────────────────────────────────────────────────────────────────
#
# AgentCore Runtime does not yet have native CloudFormation support.
# After `cdk deploy` provisions the IAM roles, S3 bucket, and supporting infra,
# run the following to deploy the agents to AgentCore:
#
#   python cdk/deploy_agentcore_runtimes.py
#
# Or use the AgentCore CLI:
#   cd agentcore && agentcore deploy
#
# See docs/AGENTCORE_MIGRATION.md for full instructions.
# ─────────────────────────────────────────────────────────────────────────────
