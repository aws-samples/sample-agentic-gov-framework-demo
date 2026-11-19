"""
Immutable audit archive (WORM) for the five DynamoDB audit tables.

Every audit table streams to one Lambda, fsi-audit-archiver, which writes one
JSON object per stream record into a dedicated S3 bucket with Object Lock in
COMPLIANCE mode, encrypted with a dedicated customer-managed KMS key. The
agents keep writing only to DynamoDB, so the audit pipeline never waits on S3;
archive failures are retried, bisected, sent to an encrypted DLQ and alarmed.

Everything here is private: Block Public Access on, TLS only, every bucket
policy statement is a Deny, the key policy delegates data-plane use to exactly
two roles, and the bucket, its policy and the key are RETAIN.
"""
import json
import os

from aws_cdk import (
    Duration,
    RemovalPolicy,
    Stack,
    aws_cloudwatch as cloudwatch,
    aws_iam as iam,
    aws_kms as kms,
    aws_lambda as _lambda,
    aws_lambda_event_sources as lambda_event_sources,
    aws_s3 as s3,
    aws_sqs as sqs,
)
from constructs import Construct

from lambda_logging import grant_lambda_log_writes, lambda_log_group

# Explicit physical names: the ops-doc SCPs and the compliance gate match on them.
ARCHIVER_FUNCTION_NAME = "fsi-audit-archiver"
ARCHIVER_ROLE_NAME = "fsi-audit-archiver-role"
ARCHIVER_DLQ_NAME = "fsi-audit-archiver-dlq"
ARCHIVE_KEY_ALIAS = "alias/fsi-audit-archive"
METRIC_NAMESPACE = "FSI/AuditArchive"

RETENTION_CONTEXT_KEY = "audit_archive_retention_days"
MIN_RETENTION_DAYS = 90
MAX_RETENTION_DAYS = 36500
_CDK_JSON = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cdk.json")

# Deny-to-everyone object actions. No legal hold, retention change or
# governance bypass without a reviewed bucket-policy change.
OBJECT_LOCKDOWN_ACTIONS = [
    "s3:DeleteObject",
    "s3:DeleteObjectVersion",
    "s3:DeleteObjectTagging",
    "s3:DeleteObjectVersionTagging",
    "s3:PutObjectRetention",
    "s3:PutObjectLegalHold",
    "s3:BypassGovernanceRetention",
]
# Bucket protection settings only CloudFormation's execution role may change.
# The account root can always change or delete a bucket policy (S3 behavior),
# which is the recovery path if a custom bootstrap doesn't match the pattern.
BUCKET_PROTECTION_ACTIONS = [
    "s3:PutBucketObjectLockConfiguration",
    "s3:PutLifecycleConfiguration",
    "s3:PutBucketVersioning",
    "s3:PutEncryptionConfiguration",  # IAM action for the PutBucketEncryption API
    "s3:PutBucketPublicAccessBlock",
    "s3:PutBucketOwnershipControls",
    "s3:PutBucketPolicy",
    "s3:DeleteBucketPolicy",
]

# (alarm name, metric source, threshold). Built in AuditArchive._alarms.
ALARM_NAMES = (
    "fsi-audit-archiver-dlq-not-empty",
    "fsi-audit-archiver-errors",
    "fsi-audit-archive-record-failures",
    "fsi-audit-archiver-iterator-age",
    "fsi-audit-archive-conflict",
    "fsi-audit-archive-pan-refused",
    "fsi-audit-archive-record-removed",
    "fsi-audit-archive-item-missing",
    "fsi-audit-archive-source-refused",
)
EMF_ALARMS = {
    "fsi-audit-archive-record-failures": "ArchiveRecordFailures",
    "fsi-audit-archive-conflict": "ArchiveConflicts",
    "fsi-audit-archive-pan-refused": "PanRefused",
    "fsi-audit-archive-record-removed": "AuditRecordRemoved",
    "fsi-audit-archive-item-missing": "ArchiveItemMissing",
    "fsi-audit-archive-source-refused": "ArchiveSourceRefused",
}
ITERATOR_AGE_THRESHOLD_MS = 900_000


def _retention_from_cdk_json():
    """The single configured default: cdk.json context audit_archive_retention_days."""
    try:
        with open(_CDK_JSON, encoding="utf-8") as f:
            return json.load(f).get("context", {}).get(RETENTION_CONTEXT_KEY)
    except (OSError, ValueError):
        return None


def context_retention_days(value) -> int:
    """audit_archive_retention_days: an int (or int string) in 90..36500.

    Absent -> the value in cdk/cdk.json (90 for this demo). A missing,
    boolean, non-integer or out-of-range value fails the synth, so a
    `-c audit_archive_retention_days=30` override cannot synthesize.
    """
    if value in (None, ""):
        value = _retention_from_cdk_json()
    message = (f"CDK context {RETENTION_CONTEXT_KEY} must be an integer in "
               f"{MIN_RETENTION_DAYS}..{MAX_RETENTION_DAYS} (set it in cdk/cdk.json)")
    if value is None or isinstance(value, bool):
        raise ValueError(message)
    if isinstance(value, str) and not value.strip().isdigit():
        raise ValueError(message)
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise ValueError(message) from None
    if isinstance(value, float) and value != parsed:
        raise ValueError(message)
    if not MIN_RETENTION_DAYS <= parsed <= MAX_RETENTION_DAYS:
        raise ValueError(message)
    return parsed


class AuditArchive(Construct):
    """WORM archive bucket, CMK, archiver Lambda, five stream ESMs, DLQ, alarms."""

    def __init__(self, scope: Construct, construct_id: str, *, tables,
                 reader_role_arn: str, retention_days: int, key_admin_actions,
                 alarm_action=None) -> None:
        super().__init__(scope, construct_id)
        stack = Stack.of(self)
        account, region = stack.account, stack.region
        archiver_role_arn = f"arn:aws:iam::{account}:role/{ARCHIVER_ROLE_NAME}"
        cfn_exec_role_pattern = f"arn:aws:iam::{account}:role/cdk-*-cfn-exec-role-{account}-{region}"
        via_s3 = {"kms:ViaService": f"s3.{region}.amazonaws.com"}

        # ─── Dedicated CMK: root administers, two roles use it via S3 only ───
        self.key = kms.Key(
            self, "AuditArchiveKey",
            alias=ARCHIVE_KEY_ALIAS,
            description="Immutable audit archive bucket encryption key",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.RETAIN,
            policy=iam.PolicyDocument(statements=[
                iam.PolicyStatement(
                    sid="KeyAdministration",
                    principals=[iam.AccountRootPrincipal()],
                    actions=list(key_admin_actions),
                    resources=["*"],
                ),
                iam.PolicyStatement(
                    sid="ArchiverUsesKeyViaS3",
                    principals=[iam.AccountRootPrincipal()],
                    actions=["kms:GenerateDataKey", "kms:Decrypt"],
                    resources=["*"],
                    conditions={
                        "ArnEquals": {"aws:PrincipalArn": [archiver_role_arn]},
                        "StringEquals": via_s3,
                    },
                ),
                iam.PolicyStatement(
                    sid="ComplianceReaderDecryptsViaS3",
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

        # ─── WORM bucket ─────────────────────────────────────────────────────
        # Demo retention only. For production set retention per the applicable
        # regulation (e.g. SEC 17a-4 / FINRA 4511: 6 years, BSA/FinCEN SAR
        # records: 5 years, SOX audit records: 7 years) — confirm with your
        # compliance team.
        # Configured by cdk.json context audit_archive_retention_days. COMPLIANCE
        # mode: nobody, including the account root, can delete a locked object
        # version or shorten its retention, so the value can only be raised.
        # Object Lock can only be enabled at bucket creation (this bucket is new).
        self.bucket = s3.Bucket(
            self, "AuditArchive",
            bucket_name=None,  # auto-generated: a redeploy never collides with the retained bucket
            object_lock_enabled=True,
            object_lock_default_retention=s3.ObjectLockRetention.compliance(Duration.days(retention_days)),
            versioned=True,
            encryption=s3.BucketEncryption.KMS,
            encryption_key=self.key,
            bucket_key_enabled=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            object_ownership=s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
            # RETAIN and no auto_delete_objects: `cdk destroy` leaves the bucket
            # (and its locked objects) in place and never tries to empty it.
            removal_policy=RemovalPolicy.RETAIN,
        )
        any_principal = [iam.AnyPrincipal()]
        objects = self.bucket.arn_for_objects("*")
        # Every statement is a Deny; no Principal:* Allow exists.
        self.bucket.add_to_resource_policy(iam.PolicyStatement(
            sid="DenyObjectDeleteAndLockChanges",
            effect=iam.Effect.DENY, principals=any_principal,
            actions=OBJECT_LOCKDOWN_ACTIONS, resources=[objects],
        ))
        self.bucket.add_to_resource_policy(iam.PolicyStatement(
            sid="DenyBucketProtectionChangesExceptCfn",
            effect=iam.Effect.DENY, principals=any_principal,
            actions=BUCKET_PROTECTION_ACTIONS, resources=[self.bucket.bucket_arn],
            conditions={"ArnNotLike": {"aws:PrincipalArn": [cfn_exec_role_pattern]}},
        ))
        self.bucket.add_to_resource_policy(iam.PolicyStatement(
            sid="DenyPutExceptArchiver",
            effect=iam.Effect.DENY, principals=any_principal,
            actions=["s3:PutObject"], resources=[objects],
            conditions={"ArnNotEquals": {"aws:PrincipalArn": [archiver_role_arn]}},
        ))
        self.bucket.add_to_resource_policy(iam.PolicyStatement(
            sid="DenyReadsExceptArchiverAndReader",
            effect=iam.Effect.DENY, principals=any_principal,
            actions=["s3:GetObject", "s3:GetObjectVersion"], resources=[objects],
            conditions={"ArnNotEquals": {"aws:PrincipalArn": [archiver_role_arn, reader_role_arn]}},
        ))
        # A destroy must not strip the deny policy off the retained bucket.
        self.bucket.policy.apply_removal_policy(RemovalPolicy.RETAIN)

        # ─── Archiver role: explicit least-privilege statements ──────────────
        # Not bucket.grant_put (it adds retention, legal-hold and tagging actions).
        role = iam.Role(
            self, "ArchiverRole",
            role_name=ARCHIVER_ROLE_NAME,
            description="fsi-audit-archiver: stream records -> immutable S3 archive",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            # No AWSLambdaBasicExecutionRole (logs:* on "*"): logs go to the
            # function's own group only (cdk/lambda_logging.py).
        )
        grant_lambda_log_writes(role, ARCHIVER_FUNCTION_NAME)
        # GetObject backs HeadObject on the idempotent-retry (412) path.
        role.add_to_policy(iam.PolicyStatement(
            actions=["s3:PutObject", "s3:GetObject"], resources=[objects]))
        role.add_to_policy(iam.PolicyStatement(
            actions=["kms:GenerateDataKey", "kms:Decrypt"], resources=[self.key.key_arn]))
        # The archiver archives only what it re-reads from the source table:
        # GetItem by key on each of the five audit tables, table
        # ARN only (no index, no Query/Scan/BatchGetItem, no write action).
        for table in tables:
            role.add_to_policy(iam.PolicyStatement(
                actions=["dynamodb:GetItem"], resources=[table.table_arn]))

        # ESM failures go to this DLQ; its messages carry only the stream
        # batch info (stream ARN, shard, sequence range), never item content.
        self.dlq = sqs.Queue(
            self, "ArchiverDLQ",
            queue_name=ARCHIVER_DLQ_NAME,
            encryption=sqs.QueueEncryption.SQS_MANAGED,
            enforce_ssl=True,
            retention_period=Duration.days(14),
        )

        # No function-level dead_letter_queue: the function is only invoked
        # synchronously by the ESM, and an async DLQ would hold full items.
        # No resource-based policy (no add_permission): the ESM needs none, and
        # a same-account identity policy allowing lambda:InvokeFunction can't
        # be stopped by a resource policy that only adds Allows. Who may invoke
        # the archiver directly is limited by the SCP in
        # docs/SECURITY_OPERATIONAL_STEPS.md step 10; even a permitted direct
        # invoke can only archive items that exist in the audit tables.
        self.function = _lambda.Function(
            self, "Archiver",
            function_name=ARCHIVER_FUNCTION_NAME,
            runtime=_lambda.Runtime.PYTHON_3_13,
            handler="handler.handler",
            code=_lambda.Code.from_asset("../lambdas/audit_archiver"),
            role=role,
            log_group=lambda_log_group(self, "ArchiverLogGroup", ARCHIVER_FUNCTION_NAME),
            timeout=Duration.seconds(60),
            memory_size=256,
            environment={
                "ARCHIVE_BUCKET": self.bucket.bucket_name,
                "ARCHIVE_KMS_KEY_ARN": self.key.key_arn,
                "ARCHIVE_TABLES": ",".join(t.table_name for t in tables),
                # The five genuine stream ARNs; any other eventSourceARN is
                # refused. Not a trust boundary against a direct invoker (who
                # can forge it): the consistent GetItem re-read is.
                "EXPECTED_STREAM_ARNS": ",".join(t.table_stream_arn for t in tables),
            },
        )
        # One ESM per table. TRIM_HORIZON, no filter (INSERT, MODIFY and REMOVE
        # are all archived), bounded retries with bisect, max record age well
        # inside the 24 h stream retention so a DLQ entry stays replayable.
        for table in tables:
            self.function.add_event_source(lambda_event_sources.DynamoEventSource(
                table,
                starting_position=_lambda.StartingPosition.TRIM_HORIZON,
                batch_size=10,
                bisect_batch_on_error=True,
                retry_attempts=10,
                max_record_age=Duration.hours(6),
                report_batch_item_failures=True,
                on_failure=lambda_event_sources.SqsDlq(self.dlq),
            ))

        self._alarms(alarm_action)

    def _alarms(self, alarm_action) -> None:
        period = Duration.minutes(5)
        metrics = {
            "fsi-audit-archiver-dlq-not-empty": (
                self.dlq.metric_approximate_number_of_messages_visible(statistic="Maximum", period=period), 0),
            "fsi-audit-archiver-errors": (
                self.function.metric_errors(statistic="Sum", period=period), 0),
            "fsi-audit-archiver-iterator-age": (
                self.function.metric("IteratorAge", statistic="Maximum", period=period),
                ITERATOR_AGE_THRESHOLD_MS),
        }
        for alarm_name, metric_name in EMF_ALARMS.items():
            metrics[alarm_name] = (cloudwatch.Metric(
                namespace=METRIC_NAMESPACE, metric_name=metric_name, statistic="Sum", period=period), 0)
        for alarm_name in ALARM_NAMES:
            metric, threshold = metrics[alarm_name]
            alarm = cloudwatch.Alarm(
                self, "Alarm" + "".join(p.capitalize() for p in alarm_name.split("-")[1:]),
                alarm_name=alarm_name,
                metric=metric,
                threshold=threshold,
                evaluation_periods=1,
                comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
                treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
                alarm_description=f"Immutable audit archive: {alarm_name} (no silent gaps)",
            )
            # Notify on-call (fsi-governance-alarms); none of these ever
            # invokes the circuit breaker.
            if alarm_action is not None:
                alarm.add_alarm_action(alarm_action)

