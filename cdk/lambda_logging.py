"""
Scoped CloudWatch Logs for the stack's Lambda functions.

Each function writes to its own log group, created here with a fixed
retention, and its role may only CreateLogStream / PutLogEvents in that
group. This replaces AWSLambdaBasicExecutionRole (logs:* actions on
Resource "*"), so a function can't write into any other log group.

The groups are named /fsi/lambda/<function-name> (Lambda LoggingConfig),
not the implicit /aws/lambda/<function-name>: those implicit groups already
exist in accounts where the functions have run, and a CloudFormation-managed
group of the same name would fail the deploy with "already exists". The old
groups stop receiving logs; their retention/deletion is an ops step
(docs/SECURITY_OPERATIONAL_STEPS.md).
"""
from aws_cdk import RemovalPolicy, Stack, aws_iam as iam, aws_logs as logs
from constructs import Construct

LAMBDA_LOG_GROUP_PREFIX = "/fsi/lambda/"
# Demo value, set in one place. Raise it for production per your log
# retention policy (the audit evidence itself lives in the WORM archive).
LAMBDA_LOG_RETENTION = logs.RetentionDays.ONE_MONTH
LAMBDA_LOG_RETENTION_DAYS = 30


def lambda_log_group_name(function_name: str) -> str:
    return f"{LAMBDA_LOG_GROUP_PREFIX}{function_name}"


def lambda_log_group(scope: Construct, construct_id: str, function_name: str) -> logs.LogGroup:
    """The function's own log group. DESTROY (not RETAIN): a retained group
    would make the next deploy after a destroy fail on "already exists"."""
    return logs.LogGroup(
        scope, construct_id,
        log_group_name=lambda_log_group_name(function_name),
        retention=LAMBDA_LOG_RETENTION,
        removal_policy=RemovalPolicy.DESTROY,
    )


def grant_lambda_log_writes(role: iam.Role, *function_names: str) -> None:
    """CreateLogStream + PutLogEvents on exactly these functions' groups."""
    stack = Stack.of(role)
    role.add_to_policy(iam.PolicyStatement(
        actions=["logs:CreateLogStream", "logs:PutLogEvents"],
        resources=[
            f"arn:aws:logs:{stack.region}:{stack.account}:log-group:{lambda_log_group_name(name)}:*"
            for name in function_names
        ],
    ))
