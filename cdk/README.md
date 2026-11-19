# CDK Infrastructure (Optional)

This directory contains AWS CDK stack definitions for deploying the full infrastructure.

## Stacks

| Stack | Description | Status |
|-------|-------------|--------|
| `agents_stack.py` | Lambda functions for all three agents | Skeleton |
| `data_stack.py` | DynamoDB tables, S3 buckets, SQS queues | Skeleton |
| `guardrails_stack.py` | Bedrock Guardrail configuration | Skeleton |

## Important Notes

- **The CDK stacks are provided as reference architecture only.** They demonstrate the intended deployment topology but have not been validated in a live AWS account.
- **The demo scripts work without deploying any infrastructure** — use `--local` mode.
- **Before deploying**, review IAM policies carefully and adjust for your organization's security requirements.

## Prerequisites for Deployment

```bash
# Install CDK (pinned; matches aws-cdk-lib 2.265.0's cloud-assembly schema)
npm install -g aws-cdk@2.1146.0

# Install Python CDK dependencies (hash-locked)
pip install --require-hashes -r ../requirements-cdk.lock

# Bootstrap your account (first time only)
cdk bootstrap aws://ACCOUNT_ID/REGION

# Synthesize (validate without deploying)
cdk synth

# Deploy
cdk deploy --all
```

## Context Knobs

`pan_filter_reserved_concurrency` (default `10`) sets reserved concurrency on the `fsi-pan-filter` Lambda. It bounds how much of the account's Lambda concurrency the PAN filter can take and how fast anyone can query it as a yes/no oracle. Lambda refuses a reservation that would leave the account with less than 100 unreserved concurrent executions, so on accounts with a low concurrency quota the deploy fails. Lower the value, or pass `-c pan_filter_reserved_concurrency=0` to leave it unset, e.g. `cdk synth -c pan_filter_reserved_concurrency=5`.

`audit_archive_retention_days` (in `cdk.json`, default `90`) sets the default Object Lock COMPLIANCE retention of the immutable audit archive bucket. It must be an integer from 90 to 36500; anything else fails the synth, and `make gate` requires the template to hold at least the `cdk.json` value. Demo retention only. For production set retention per the applicable regulation (e.g. SEC 17a-4 / FINRA 4511: 6 years, BSA/FinCEN SAR records: 5 years, SOX audit records: 7 years) — confirm with your compliance team. COMPLIANCE mode means existing objects can never be shortened, so raise the value only deliberately.

Other optional context keys (all off by default): `allow_console_drift_injection=true` grants `fsi-console-operator` `cloudwatch:PutMetricData` on the `FSI/AgenticCompliance` namespace, for the live drift demo only; `console_host_role_arn=<role ARN>` creates `fsi-console-operator-hosted` and `fsi-console-audit-writer-hosted` (operator-audit PutItem only, for hosted principals without the operator role) and lets that host role assume them and `fsi-compliance-reader` for Cognito sessions; `ci_role_arn=<role ARN>` lets that CI role assume `fsi-deploy-gate-signer`. A malformed role ARN fails the synth.

`alarm_email=<address>` (optional) subscribes that address to the `fsi-governance-alarms` topic (the recipient must confirm the subscription email). It must be one plain email address, or the synth fails. Unset, the topic has no subscriber: subscribe on-call yourself (docs/SECURITY_OPERATIONAL_STEPS.md, step 11).

## Cost Considerations

Deploying these stacks will create billable AWS resources including:
- 5 DynamoDB tables (on-demand billing) and their streams
- Lambda functions (agents, circuit breaker, PAN filter, drift publisher, audit archiver)
- 2 S3 buckets (SAR filings; immutable audit archive with Object Lock)
- SQS queues (analyst review and DLQs)
- 1 SNS topic and its KMS key (on-call alarm notifications)
- 1 Bedrock Guardrail

Use `cdk destroy --all` to remove the stacks when done. The audit tables, the SAR bucket, and the audit archive bucket and its key are retained; archive objects can't be deleted until their COMPLIANCE retention expires.
