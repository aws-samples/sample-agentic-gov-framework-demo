"""
Notification topic for the review-only governance and integrity alarms.

fsi-governance-alarms is encrypted with its own customer-managed KMS key
(CloudWatch can't publish to a topic encrypted with the AWS-managed SNS
key). Only CloudWatch alarms of this account and region may publish, and
only over TLS. The review-only alarms (hold changes, break-glass,
uncorroborated drift, archive DLQ/PAN/removed/conflict, publisher errors,
...) send their ALARM transition here. The four drift alarms that invoke the
automated circuit breaker are deliberately not wired to it, so containment
behavior is unchanged.

Optional CDK context alarm_email subscribes one address (the recipient must
confirm the subscription email). Without it the topic has no subscriber:
subscribing on-call is an ops step (docs/SECURITY_OPERATIONAL_STEPS.md).
"""
import re

from aws_cdk import (
    Stack,
    aws_cloudwatch_actions as cw_actions,
    aws_iam as iam,
    aws_kms as kms,
    aws_sns as sns,
    aws_sns_subscriptions as subscriptions,
)
from constructs import Construct

ALARM_TOPIC_NAME = "fsi-governance-alarms"
ALARM_TOPIC_KEY_ALIAS = "alias/fsi-governance-alarms"
ALARM_EMAIL_CONTEXT_KEY = "alarm_email"
# A plain address only (no display name, no list): local@domain.tld.
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,63}")


def context_alarm_email(value):
    """alarm_email: absent/empty -> None; otherwise one email address."""
    if value in (None, ""):
        return None
    if not isinstance(value, str) or len(value) > 254 or not _EMAIL_RE.fullmatch(value):
        raise ValueError(f"CDK context {ALARM_EMAIL_CONTEXT_KEY} must be one email address")
    return value


class GovernanceAlarmTopic(Construct):
    """KMS-encrypted SNS topic that only this account's CloudWatch alarms may publish to."""

    def __init__(self, scope: Construct, construct_id: str, *, key_admin_actions,
                 alarm_email: str = None) -> None:
        super().__init__(scope, construct_id)
        stack = Stack.of(self)
        account, region = stack.account, stack.region
        alarm_arns = f"arn:aws:cloudwatch:{region}:{account}:alarm:*"
        # Confused-deputy conditions documented for CloudWatch -> SNS.
        from_this_accounts_alarms = {
            "StringEquals": {"aws:SourceAccount": account},
            "ArnLike": {"aws:SourceArn": alarm_arns},
        }

        self.key = kms.Key(
            self, "AlarmTopicKey",
            alias=ALARM_TOPIC_KEY_ALIAS,
            description="fsi-governance-alarms SNS topic encryption key",
            enable_key_rotation=True,
            policy=iam.PolicyDocument(statements=[
                iam.PolicyStatement(
                    sid="KeyAdministration",
                    principals=[iam.AccountRootPrincipal()],
                    actions=list(key_admin_actions),
                    resources=["*"],
                ),
                iam.PolicyStatement(
                    sid="CloudWatchAlarmsPublishEncrypted",
                    principals=[iam.ServicePrincipal("cloudwatch.amazonaws.com")],
                    actions=["kms:GenerateDataKey*", "kms:Decrypt"],
                    resources=["*"],
                    conditions=from_this_accounts_alarms,
                ),
            ]),
        )

        self.topic = sns.Topic(
            self, "AlarmTopic",
            topic_name=ALARM_TOPIC_NAME,
            display_name="FSI governance alarms",
            master_key=self.key,
            enforce_ssl=True,  # Deny on aws:SecureTransport=false
        )
        self.topic.add_to_resource_policy(iam.PolicyStatement(
            sid="CloudWatchAlarmsPublish",
            principals=[iam.ServicePrincipal("cloudwatch.amazonaws.com")],
            actions=["sns:Publish"],
            resources=[self.topic.topic_arn],
            conditions=from_this_accounts_alarms,
        ))
        # Nobody else publishes, whatever their identity policy says: a
        # request whose source isn't one of this account's alarms is denied.
        self.topic.add_to_resource_policy(iam.PolicyStatement(
            sid="DenyPublishExceptThisAccountsAlarms",
            effect=iam.Effect.DENY,
            principals=[iam.AnyPrincipal()],
            actions=["sns:Publish"],
            resources=[self.topic.topic_arn],
            conditions={"ArnNotLike": {"aws:SourceArn": alarm_arns}},
        ))

        if alarm_email:
            self.topic.add_subscription(subscriptions.EmailSubscription(alarm_email))

        self.action = cw_actions.SnsAction(self.topic)
