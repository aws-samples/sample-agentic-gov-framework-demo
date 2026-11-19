"""
Data Stack — DynamoDB tables, S3 bucket, SQS queue for the compliance pipeline.

Note: This is a reference skeleton. Review IAM policies and encryption settings
before deploying to production.
"""
from aws_cdk import (
    Stack,
    RemovalPolicy,
    aws_dynamodb as dynamodb,
    aws_kms as kms,
    aws_s3 as s3,
    aws_sqs as sqs,
    aws_iam as iam,
    Duration,
)
from constructs import Construct

from audit_archive import AuditArchive, RETENTION_CONTEXT_KEY, context_retention_days
from governance_alarms import ALARM_EMAIL_CONTEXT_KEY, GovernanceAlarmTopic, context_alarm_email

# Deterministic role names (created in agents_stack.py, which depends on this
# stack). The SAR key and bucket policies reference them by ARN string with
# the account-root-principal + aws:PrincipalArn pattern, so this stack never
# needs a reverse reference and deploys before the roles exist.
EXECUTOR_ROLE_NAME = "executor-agent-role"
COMPLIANCE_READER_ROLE_NAME = "fsi-compliance-reader"

# Key administration only: no kms:Decrypt/Encrypt/GenerateDataKey*/ReEncrypt*
# for the account root, so data-plane use must be granted per role.
KMS_KEY_ADMIN_ACTIONS = [
    # kms:CreateAlias, not kms:Create*: kms:CreateGrant would let an account
    # principal grant itself Sign/Decrypt without a key-policy change. No
    # integrated service needs a grant on these keys (S3 SSE-KMS, KMS Sign).
    "kms:CreateAlias", "kms:Describe*", "kms:Enable*", "kms:List*", "kms:Put*",
    "kms:Update*", "kms:Revoke*", "kms:Disable*", "kms:Get*", "kms:Delete*",
    "kms:TagResource", "kms:UntagResource", "kms:ScheduleKeyDeletion",
    "kms:CancelKeyDeletion",
]


def _by_day_ts_keys():
    """Partition/sort keys of every by_day_ts GSI (record_day = UTC YYYY-MM-DD)."""
    return {
        "partition_key": dynamodb.Attribute(name="record_day", type=dynamodb.AttributeType.STRING),
        "sort_key": dynamodb.Attribute(name="timestamp", type=dynamodb.AttributeType.STRING),
    }


class DataStack(Stack):
    """Data layer for the FSI Agentic Compliance pipeline."""

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Validated up front (see cdk/README.md): 90..36500, default in cdk.json.
        audit_archive_retention_days = context_retention_days(
            self.node.try_get_context(RETENTION_CONTEXT_KEY))
        alarm_email = context_alarm_email(self.node.try_get_context(ALARM_EMAIL_CONTEXT_KEY))

        # Notification target of every review-only governance/integrity alarm
        # (here and in agents_stack.py); see cdk/governance_alarms.py.
        self.alarm_topic = GovernanceAlarmTopic(
            self, "GovernanceAlarms",
            key_admin_actions=KMS_KEY_ADMIN_ACTIONS,
            alarm_email=alarm_email,
        )

        # ═════════════════════════════════════════════════════════════════════
        # BLUEPRINT 1 — DATA & ACCESS CONTROLS (data at rest)
        # All audit stores use DynamoDB with encryption at rest (AWS-managed by
        # default; use a KMS CMK in production) and access is granted only via
        # the least-privilege agent roles in agents_stack.py — never broadly.
        #
        # BLUEPRINT 5 — DEPLOYMENT CONTROL (durability / immutability)
        # Every table enables Point-in-Time Recovery (PITR) AND is RETAIN +
        # deletion_protection=True, so the regulatory audit trail survives
        # both a stack update/replacement and an accidental `cdk destroy`.
        # A table that must genuinely be torn down (demo/test
        # account cleanup) needs an explicit out-of-band
        # `update-table --no-deletion-protection-enabled` plus a stack update
        # removing it — never a single `cdk destroy --all`.
        # ═════════════════════════════════════════════════════════════════════

        # Detection results table
        self.detection_table = dynamodb.Table(
            self, "DetectionResults",
            table_name="detection-results",
            partition_key=dynamodb.Attribute(
                name="detection_id", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            point_in_time_recovery=True,
            removal_policy=RemovalPolicy.RETAIN,
            deletion_protection=True,
            # Feeds the immutable audit archive (in-place update, no replacement).
            stream=dynamodb.StreamViewType.NEW_IMAGE,
        )

        # Compliance decisions table
        self.compliance_table = dynamodb.Table(
            self, "ComplianceDecisions",
            table_name="compliance-decisions",
            partition_key=dynamodb.Attribute(
                name="compliance_id", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            point_in_time_recovery=True,
            removal_policy=RemovalPolicy.RETAIN,
            deletion_protection=True,
            # KEYS_ONLY: drives fsi-drift-metric-publisher, the
            # only drift-metric publisher; it reads four drift attributes by
            # key, never the narratives. fsi-audit-archiver is the second (and
            # last allowed) consumer and GetItems the full record by key.
            stream=dynamodb.StreamViewType.KEYS_ONLY,
        )

        # Executor audit table
        self.audit_table = dynamodb.Table(
            self, "ExecutorAudit",
            table_name="executor-audit",
            partition_key=dynamodb.Attribute(
                name="action_id", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            point_in_time_recovery=True,
            removal_policy=RemovalPolicy.RETAIN,
            deletion_protection=True,
            # Feeds the immutable audit archive (in-place update, no replacement).
            stream=dynamodb.StreamViewType.NEW_IMAGE,
        )

        # Governance audit table (circuit breaker events)
        self.governance_table = dynamodb.Table(
            self, "GovernanceAudit",
            table_name="governance-audit",
            partition_key=dynamodb.Attribute(
                name="event_id", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            point_in_time_recovery=True,
            removal_policy=RemovalPolicy.RETAIN,
            deletion_protection=True,
            # Feeds the immutable audit archive (in-place update, no replacement).
            stream=dynamodb.StreamViewType.NEW_IMAGE,
        )

        # Governance state: one mutable item (state_id "breaker") that the
        # circuit breaker's trip and release claim with conditional writes on
        # a generation number, so a release can only lift the hold it was
        # approved for. Kept out of governance-audit, which is append-only
        # and archived: no stream, no GSI. Every transition is also recorded
        # in governance-audit (intent, hold, released, completed records).
        self.governance_state_table = dynamodb.Table(
            self, "GovernanceState",
            table_name="governance-state",
            partition_key=dynamodb.Attribute(
                name="state_id", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True,
            ),
            removal_policy=RemovalPolicy.RETAIN,
            deletion_protection=True,
        )

        # Operator audit table (console governance actions).
        # Same durability bar as the other audit tables.
        self.operator_audit_table = dynamodb.Table(
            self, "OperatorAudit",
            table_name="operator-audit",
            partition_key=dynamodb.Attribute(
                name="event_id", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True,
            ),
            removal_policy=RemovalPolicy.RETAIN,
            deletion_protection=True,
            stream=dynamodb.StreamViewType.NEW_IMAGE,
        )

        # ─── Keyed audit read path ─────────────────
        # Readers Query these indexes instead of scanning. Exactly ONE new GSI
        # per existing table: CloudFormation/DynamoDB allow only one GSI
        # creation per table update. Marker and nonce items carry no
        # record_day and so stay out of by_day_ts.
        self.detection_table.add_global_secondary_index(
            index_name="by_day_ts",
            projection_type=dynamodb.ProjectionType.KEYS_ONLY,
            **_by_day_ts_keys(),
        )
        self.compliance_table.add_global_secondary_index(
            index_name="by_day_ts",
            projection_type=dynamodb.ProjectionType.INCLUDE,
            # compliance_id is the table key and is always projected.
            non_key_attributes=["drift_counts", "provenance_status"],
            **_by_day_ts_keys(),
        )
        self.audit_table.add_global_secondary_index(
            index_name="by_day_ts",
            projection_type=dynamodb.ProjectionType.INCLUDE,
            # Everything the SOX demo lookup reads. The executor enforces that
            # violation_type holds only fixed text, field names, locations and
            # cluster indices (at most 256 chars), never payload values.
            non_key_attributes=["action_taken", "event_hash", "violation_type"],
            **_by_day_ts_keys(),
        )
        self.governance_table.add_global_secondary_index(
            index_name="by_event_type",
            partition_key=dynamodb.Attribute(name="event_type", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="timestamp", type=dynamodb.AttributeType.STRING),
            projection_type=dynamodb.ProjectionType.ALL,
        )
        self.operator_audit_table.add_global_secondary_index(
            index_name="by_day_ts",
            projection_type=dynamodb.ProjectionType.ALL,
            **_by_day_ts_keys(),
        )

        # SAR filings CMK. The root may administer the key but
        # not use it; each data-plane use is delegated to exactly one role via
        # aws:PrincipalArn, and that role also needs a matching identity
        # statement (agents_stack.py). Rotation on, RETAIN.
        executor_role_arn = f"arn:aws:iam::{self.account}:role/{EXECUTOR_ROLE_NAME}"
        reader_role_arn = f"arn:aws:iam::{self.account}:role/{COMPLIANCE_READER_ROLE_NAME}"
        via_s3 = {"kms:ViaService": f"s3.{self.region}.amazonaws.com"}
        self.sar_key = kms.Key(
            self, "SarFilingsKey",
            alias="alias/fsi-sar-filings",
            description="SAR filings bucket encryption key",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.RETAIN,
            policy=iam.PolicyDocument(statements=[
                iam.PolicyStatement(
                    sid="KeyAdministration",
                    principals=[iam.AccountRootPrincipal()],
                    actions=KMS_KEY_ADMIN_ACTIONS,
                    resources=["*"],
                ),
                iam.PolicyStatement(
                    sid="ExecutorEncryptsFilings",
                    principals=[iam.AccountRootPrincipal()],
                    actions=["kms:GenerateDataKey", "kms:Encrypt"],
                    resources=["*"],
                    conditions={
                        "ArnEquals": {"aws:PrincipalArn": [executor_role_arn]},
                        "StringEquals": via_s3,
                    },
                ),
                iam.PolicyStatement(
                    sid="ComplianceReaderDecryptsFilings",
                    principals=[iam.AccountRootPrincipal()],
                    actions=["kms:Decrypt"],
                    resources=["*"],
                    conditions={
                        "ArnEquals": {"aws:PrincipalArn": [reader_role_arn]},
                        "StringEquals": via_s3,
                    },
                ),
            ]),
        )

        # SAR filing bucket
        # BLUEPRINT 1 + 5 — encrypted, SSL-enforced, public-access-blocked
        # (Data Control) and versioned so filed SARs are immutable/recoverable
        # for the 7-year BSA retention window (Deployment Control). RETAIN +
        # no auto_delete_objects so the bucket and its filings genuinely
        # survive stack teardown, matching the "immutable" claim this
        # comment makes — Object Lock in compliance mode is the
        # next step for true WORM retention and is tracked separately.
        # SSE-KMS with the SAR CMK: s3:GetObject alone no longer
        # reads a filing. In-place update; existing objects keep SSE-S3.
        self.sar_bucket = s3.Bucket(
            self, "SarFilings",
            bucket_name=None,  # Auto-generated unique name
            encryption=s3.BucketEncryption.KMS,
            encryption_key=self.sar_key,
            bucket_key_enabled=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            versioned=True,
            removal_policy=RemovalPolicy.RETAIN,
        )
        # Only fsi-compliance-reader may read filings. A Deny on a
        # condition key, not a grant: no Principal:* allow is introduced.
        self.sar_bucket.add_to_resource_policy(iam.PolicyStatement(
            sid="DenyFilingReadsExceptComplianceReader",
            effect=iam.Effect.DENY,
            principals=[iam.AnyPrincipal()],
            actions=["s3:GetObject", "s3:GetObjectVersion"],
            resources=[self.sar_bucket.arn_for_objects("filings/*")],
            conditions={"ArnNotEquals": {"aws:PrincipalArn": [reader_role_arn]}},
        ))

        # Analyst review queue — carries AML case detail (cluster id,
        # challenger rationale, decision, guardrail status). Brought up to the
        # same confidentiality/durability bar the SAR bucket already meets:
        # KMS-managed encryption at rest, a dead-letter queue so
        # undeliverable escalations are retained rather than lost, and a
        # TLS-only (aws:SecureTransport) access policy.
        self.analyst_dlq = sqs.Queue(
            self, "AnalystDLQ",
            queue_name="fsi-analyst-review-dlq",
            encryption=sqs.QueueEncryption.KMS_MANAGED,
            retention_period=Duration.days(14),
        )
        self.analyst_queue = sqs.Queue(
            self, "AnalystQueue",
            queue_name="fsi-analyst-review",
            visibility_timeout=Duration.seconds(300),
            retention_period=Duration.days(14),
            encryption=sqs.QueueEncryption.KMS_MANAGED,
            dead_letter_queue=sqs.DeadLetterQueue(
                max_receive_count=5,
                queue=self.analyst_dlq,
            ),
        )
        # Deny any non-TLS access to the queue (and its DLQ).
        for _queue in (self.analyst_queue, self.analyst_dlq):
            _queue.add_to_resource_policy(iam.PolicyStatement(
                effect=iam.Effect.DENY,
                principals=[iam.AnyPrincipal()],
                actions=["sqs:*"],
                resources=[_queue.queue_arn],
                conditions={"Bool": {"aws:SecureTransport": "false"}},
            ))
        # Only the executor agent may enqueue an escalation: any other
        # principal's SendMessage (and SendMessageBatch, which is authorized
        # by sqs:SendMessage) is denied, whatever its identity policy says.
        # Analysts still cross-check each message's action_id against
        # executor-audit (docs/SECURITY_OPERATIONAL_STEPS.md).
        self.analyst_queue.add_to_resource_policy(iam.PolicyStatement(
            sid="DenySendExceptExecutor",
            effect=iam.Effect.DENY,
            principals=[iam.AnyPrincipal()],
            actions=["sqs:SendMessage"],
            resources=[self.analyst_queue.queue_arn],
            conditions={"ArnNotEquals": {"aws:PrincipalArn": [executor_role_arn]}},
        ))

        # ─── Immutable audit archive (WORM, S3 Object Lock COMPLIANCE) ────────
        # All five audit tables stream to fsi-audit-archiver; see
        # cdk/audit_archive.py and docs/SECURITY_OPERATIONAL_STEPS.md step 10.
        # Demo retention only. For production set retention per the applicable
        # regulation (e.g. SEC 17a-4 / FINRA 4511: 6 years, BSA/FinCEN SAR
        # records: 5 years, SOX audit records: 7 years) — confirm with your
        # compliance team.
        self.audit_archive = AuditArchive(
            self, "AuditArchiveLayer",
            tables=(
                self.detection_table,
                self.compliance_table,
                self.audit_table,
                self.governance_table,
                self.operator_audit_table,
            ),
            reader_role_arn=reader_role_arn,
            retention_days=audit_archive_retention_days,
            key_admin_actions=KMS_KEY_ADMIN_ACTIONS,
            alarm_action=self.alarm_topic.action,
        )

        # ─── Outputs (consumed by deploy_agentcore_runtimes.py) ───────────────
        from aws_cdk import CfnOutput

        CfnOutput(self, "SarBucketName", value=self.sar_bucket.bucket_name)
        # Read by the deploy script into the executor's SAR_KMS_KEY_ARN.
        CfnOutput(self, "SarFilingsKeyArn", value=self.sar_key.key_arn)
        CfnOutput(self, "AnalystQueueUrl", value=self.analyst_queue.queue_url)
        CfnOutput(self, "AuditArchiveBucketName", value=self.audit_archive.bucket.bucket_name)
        CfnOutput(self, "AuditArchiveKeyArn", value=self.audit_archive.key.key_arn)
        CfnOutput(self, "GovernanceAlarmTopicArn", value=self.alarm_topic.topic.topic_arn)
