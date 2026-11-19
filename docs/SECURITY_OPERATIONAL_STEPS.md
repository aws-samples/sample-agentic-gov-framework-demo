# Security operational steps

The security hardening in this repository (16 numbered items plus follow-ups,
listed in the table below) fixes everything that can be fixed in code. The
steps below can't be done in code: they are account setup, IAM assignments, organization
policies and post-deploy checks. Work through them as a checklist before the
deployed stack handles anything other than the synthetic demo data.

Related docs: [governance-hold runbook](RUNBOOK_GOVERNANCE_HOLD.md),
[README](../README.md) (section "Security setup").

Placeholders: `<acct>` is the 12-digit account id, `<region>` the stack
region, `<sar-bucket>` the `SarBucketName` output of `FsiComplianceData`,
`<archive-bucket>` its `AuditArchiveBucketName` output.

## Status per item

| Item | Code status | Operational step |
|---|---|---|
| #1 console auth | FIXED: local scrypt sign-in, loopback only; `alb-cognito` verifier | Step 1 |
| #2 shim caller identity | Hand-off integrity FIXED | Step 4 |
| #3 breaker forgery/replay | FIXED | Step 2 |
| #5 unsigned governance inputs | Signing and verification FIXED | Step 3 |
| #6 shared identity | Console, breaker, gate and registry FIXED | Steps 2 and 4 |
| #7 PAN encodings/oracle | FIXED for the listed encodings | Steps 8 and 9 |
| #8 over-broad reads | IaC and logs FIXED | Step 5 |
| #9 DoS | Code FIXED | Steps 4 and 8 |
| #10 unpinned dependencies | Pins and hash locks FIXED | Step 7 |
| #11 drift signal forge/suppress | Code and IaC FIXED | Step 6 |
| #4, #12, #13, #14, #15, #16 | FIXED | none |
| Follow-up: console evidence / hosted roles | FIXED: incomplete-evidence banner, strict hosted purpose-to-role map | Step 1 (`audit_writer` mapping) |
| Follow-up: partial containment | FIXED: attach-only reconciling sweep (every 5 min and after each trip) | Step 3 (schedule statement), step 5 exception |
| Follow-up: containment Lambda changes | Ops only | Step 3 (containment function / schedule / floor statements) |
| Follow-up: signing alias / replay | FIXED: pinned key ARNs, signed `signed_at` freshness, `registry_version` floor | Step 3 (pins, cadence, `record-accepted`) |
| Immutable audit archive (WORM) | IaC, archiver and gate checks in code | Step 10 (production retention, SCPs, examiner procedure) |
| Follow-up: drift-metric forging/shaping | FIXED: single publisher, corroboration before deny-all, per-invocation metrics | Step 6 (and step 5 exception) |
| Integrity alarms paged no one | FIXED: KMS-encrypted `fsi-governance-alarms` topic on every review-only alarm | Step 11 (subscribe on-call) |
| Analyst queue accepted any sender | FIXED: queue policy denies `SendMessage` except `executor-agent-role` | Step 11 (analyst cross-check) |
| Lambda logs on `Resource: "*"` | FIXED: per-function log groups with retention, scoped log writes | Step 11 (old log groups) |
| PAN-shaped `request_ref` / local mode in a runtime | FIXED: refused at the shims and handlers, always scanned by the archiver; local mode has no override | none |

## About the SCPs below

- Service control policies apply to member accounts of an AWS Organization.
  They don't restrict the management account or service-linked roles. If the
  stack runs in a standalone account, apply the same statements as a
  permission boundary on every human and admin role instead.
- For a role session, `aws:PrincipalArn` is the role ARN including its path
  (for example `arn:aws:iam::<acct>:role/fsi-console/fsi-console-operator`),
  not the session ARN.
- An SCP only narrows. Each role's own IAM policy (created by the CDK stacks)
  still decides what it can do inside the SCP's ceiling.
- Attach each SCP to a test OU first and run the post-deploy checks before
  attaching it to the production OU.

## Checklist

### Step 1. Console hosting (#1)

The Makefile targets (`make ui`, `make ui-live`) bind `127.0.0.1` only, and
local console mode refuses to render on any other address. Hosting the
console for other people needs an ALB in front of it:

- [ ] ALB with an HTTPS listener (ACM certificate) and an
  `authenticate-cognito` action with `Scope: "openid aws.cognito.signin.user.admin"`.
- [ ] Cognito user pool and app client. The app client's allowed OAuth
  scopes include `aws.cognito.signin.user.admin`; Cognito `GetUser` rejects
  access tokens without it.
- [ ] Cognito groups `fsi-operator` and `fsi-auditor` for the people who may
  use the hosted console. `fsi-approver` grants nothing on the hosted
  console: approvals never go through the console host (approvers use
  `make release-approve`, see the [runbook](RUNBOOK_GOVERNANCE_HOLD.md)).
  Live audit reads and the model-registry view need `fsi-auditor`. A pool
  user in no `fsi-*` group signs in but gets no hosted AWS authority: the
  host never assumes a console role for them.
- [ ] Console instance in a **private subnet**, **no public IP**, security
  group ingress on port 8501 **from the ALB security group only**.
- [ ] Deploy `FsiComplianceAgents` with CDK context
  `console_host_role_arn=<console instance role ARN>`. That creates
  `fsi-console-operator-hosted` and `fsi-console-audit-writer-hosted`
  (PutItem on `operator-audit` only) and lets the host role mint sessions
  for them and for `fsi-compliance-reader`. Allow the console host role
  `sts:AssumeRole` and `sts:SetSourceIdentity` on all three.
- [ ] Launch command (the only non-loopback console launch anywhere in this
  project; no Makefile target does this):

  ```bash
  CONSOLE_AUTH_MODE=alb-cognito CONSOLE_COGNITO_ISSUER=… CONSOLE_COGNITO_CLIENT_ID=… CONSOLE_COGNITO_REGION=… \
  CONSOLE_ROLE_ARNS='{"operator": "…", "auditor": "…", "audit_writer": "…"}' MODE=live \
  .venv/bin/python -m streamlit run app/dashboard.py \
    --server.address <instance private IP> --server.port 8501 --server.enableXsrfProtection true
  ```

  `CONSOLE_COGNITO_ISSUER` is `https://cognito-idp.<region>.amazonaws.com/<user pool id>`.
  `CONSOLE_ROLE_ARNS` maps `operator` to the `fsi-console-operator-hosted`
  ARN, `auditor` to the `fsi-compliance-reader` ARN and `audit_writer` to the
  `fsi-console-audit-writer-hosted` ARN. An `approver` key is refused at
  startup. Purposes map strictly to roles: only `fsi-operator`
  (or `fsi-approver`) users get the operator-hosted role; an auditor-only
  user's own audit records (AUDIT_READ, sign-in) go through the audit-writer
  role, and without an `audit_writer` mapping they are refused.

  This bind is acceptable **only** because the instance is in a private
  subnet, its security group admits port 8501 from the ALB security group
  only, and it has no public IP. Never run it on a host with a public IP or
  with a security group rule from `0.0.0.0/0`, and never bind the console
  to all interfaces (the wildcard address).
- [ ] **Anonymous-denial check, before any real data:** fetch the ALB URL
  from a clean browser profile (or `curl -sI https://<alb host>/`) and
  confirm you get the ALB's redirect to the Cognito hosted UI (a `302` whose
  `Location` is the Cognito domain), which identifies the gate. A `200` or a
  bare `403` means stop and fix. Then confirm a direct request to
  `http://<instance private IP>:8501/` from a host outside the ALB security
  group times out.
- [ ] Console host hygiene:
  - Never start the console host with `WRITE_AUDIT=true`. The in-process
    pipeline is `NOT_CHECKED` and writes nothing only while `WRITE_AUDIT` is
    unset; with it set, the in-process compliance run would write audit
    records with the host's own credentials.
  - Page 5.1 "Run Compliance Gate" runs the gate in-process, and its
    read-only AWS checks use the console host's own credentials (the
    instance role). Give that role read-only access only.

### Step 2. Breaker and console roles (#3, #6)

- [ ] Create one **IAM user with MFA** per person. Allow `sts:AssumeRole` in
  each user's identity policy on the roles that person needs (note the
  paths):
  - `arn:aws:iam::<acct>:role/fsi-console/fsi-console-operator`
  - `arn:aws:iam::<acct>:role/fsi-breaker/fsi-breaker-operator`
  - `arn:aws:iam::<acct>:role/fsi-breaker/fsi-breaker-approver`
  - `arn:aws:iam::<acct>:role/fsi-compliance-reader`

  The roles trust IAM users of this account with MFA whose role session name
  equals their IAM user name (`sts:RoleSessionName == ${aws:username}`).
- [ ] Each person creates an MFA session profile and role profiles. Console
  profiles must not set `mfa_serial` (the console can't prompt) and must not
  be Identity Center profiles. Without `role_session_name`, botocore uses
  `botocore-session-<epoch>` and the role trust refuses it.

  ```ini
  [profile alice-mfa]            # written by `aws sts get-session-token --serial-number … --token-code …`
  aws_access_key_id = …
  aws_secret_access_key = …
  aws_session_token = …
  [profile fsi-operator]
  role_arn = arn:aws:iam::<acct>:role/fsi-console/fsi-console-operator
  source_profile = alice-mfa
  role_session_name = alice      # must equal your IAM user name
  [profile fsi-approver]
  role_arn = arn:aws:iam::<acct>:role/fsi-breaker/fsi-breaker-approver
  source_profile = alice-mfa
  role_session_name = alice
  [profile fsi-auditor]
  role_arn = arn:aws:iam::<acct>:role/fsi-compliance-reader
  source_profile = alice-mfa
  role_session_name = alice
  ```

- [ ] For the **CLI** breaker flow only (`make release-request` /
  `make release-approve`), Identity Center permission sets
  `FsiBreakerOperator` / `FsiBreakerApprover` are an alternative. Their inline
  policy allows only `lambda:InvokeFunction` on
  `arn:aws:lambda:<region>:<acct>:function:fsi-circuit-breaker-human`. The
  requester and the approver must then both use SSO: the breaker compares
  individuals only on the same channel.
- [ ] Leave `fsi-breaker-break-glass` **ungranted** outside incidents. Its
  trust is the account root with MFA and session-name conditions, so any IAM
  user whose policy allows `sts:AssumeRole` on it (including a `*` admin) can
  assume it. Grant that permission during an incident only; every assumption
  fires the `fsi-break-glass-assumed` alarm.
- [ ] Optional SCP limiting break-glass to named incident responders. Use the
  user-list form:

  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "DenyBreakGlassExceptIncidentResponders",
        "Effect": "Deny",
        "Action": "sts:AssumeRole",
        "Resource": "arn:aws:iam::<acct>:role/fsi-breaker/fsi-breaker-break-glass",
        "Condition": {
          "ArnNotLike": {
            "aws:PrincipalArn": [
              "arn:aws:iam::<acct>:user/<responder-1>",
              "arn:aws:iam::<acct>:user/<responder-2>"
            ]
          }
        }
      }
    ]
  }
  ```

  or the tag form (tag each responder's IAM user `fsi-incident-responder = true`,
  and restrict who can tag users):

  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "DenyBreakGlassExceptTaggedResponders",
        "Effect": "Deny",
        "Action": "sts:AssumeRole",
        "Resource": "arn:aws:iam::<acct>:role/fsi-breaker/fsi-breaker-break-glass",
        "Condition": {
          "StringNotEquals": {
            "aws:PrincipalTag/fsi-incident-responder": "true"
          }
        }
      }
    ]
  }
  ```

- [ ] Make sure a CloudTrail **management-event** trail exists. IAM is a
  global service and its API events reach EventBridge in `us-east-1`, so the
  hold-change rules (`/fsi/governance/hold-changes`, `fsi-out-of-band-hold-change`,
  `fsi-break-glass-assumed`) only see them when the stack is deployed in
  `us-east-1`.

### Step 3. Signing (#5)

Bootstrap order (once per account):

- [ ] **1. Bootstrap the stacks.** An admin runs, from `cdk/`:

  ```bash
  cdk deploy FsiComplianceData FsiComplianceAgents
  ```

  This creates the signing keys (`alias/fsi-model-registry-signing`,
  `alias/fsi-deploy-gate-signing`) and the signer roles
  (`fsi-model-risk-approver`, `fsi-deploy-gate-signer`). It uploads no agent
  bundle. Put CDK context (`console_host_role_arn`, `ci_role_arn`,
  `allow_console_drift_injection`) in the gitignored `cdk/cdk.context.json`
  or pass `-c key=value` on every `cdk deploy`, so the working tree stays
  clean for step 4.
- [ ] **1b. Pin the signing keys.** The deployer runs, with
  their own profile (read-only: `cloudformation:DescribeStacks`,
  `sts:GetCallerIdentity`):

  ```bash
  AWS_PROFILE=<deployer profile> .venv/bin/python scripts/pin_signing_keys.py
  ```

  It writes `data/signing_key_pins.json` with the account, region and the
  `RegistrySigningKeyArn` / `GateSigningKeyArn` stack outputs. Commit it.
  Signing and every verifier (registry, gate artifact, runtime attestation)
  use only these pinned ARNs and never resolve
  `alias/fsi-model-registry-signing` or `alias/fsi-deploy-gate-signing`, so
  re-pointing an alias has no effect. `make deploy` refuses when the pins
  don't match the deploy region, the deployer's account or the stack
  outputs; `pin_signing_keys.py --check` shows a drift. Optional:
  `max_signature_age_seconds` in the same file (registry default 120 days,
  cap 400; gate default 3600 s, cap 7 days).
- [ ] **2. Sign the registry.** The Model Risk approver (IAM user with MFA,
  role profile for `arn:aws:iam::<acct>:role/fsi-model-risk-approver` with
  `role_session_name = <their IAM user name>`; an SSO profile is refused)
  runs:

  ```bash
  AWS_PROFILE=<model risk profile> .venv/bin/python scripts/sign_registry.py --kms
  ```

  It writes `data/approved_models.json.kms.sig` (a v3 envelope that signs
  `signed_at`, the registry's `registry_version`, for example `2026-Q3`
  or `2026-Q3.1`, and `signed_by`, your STS caller ARN). Bump `registry_version` on every registry change: deploy
  refuses a registry older than the last accepted one.
- [ ] **3. Commit the signature.** Commit `data/approved_models.json.kms.sig`
  (a signature isn't secret). Leave the local-dev
  `data/approved_models.json.sig` as it is; the deploy chain refuses it.
- [ ] **4. Deploy from a clean tree.** Run `make deploy` from a fresh clone or a dedicated worktree; local tooling directories (agent scratch folders, `.worktrees/`) must be committed, removed, or added to `.git/info/exclude`. The gate's 'working tree not clean' FAIL lists the offending paths.

  ```bash
  make deploy GATE_SIGNER_PROFILE=<profile for fsi-deploy-gate-signer>
  ```

  `make deploy` runs `package` (bundles at HEAD), `gate-sign` (the gate
  under `fsi-deploy-gate-signer`, which alone may `kms:Sign` with the gate
  key), `verify-gate-artifact` (under your own profile), the CDK and
  AgentCore deploys, and finally `record-accepted`, which raises the SSM
  String parameter `/fsi/governance/accepted-registry` to the deployed
  registry (it never lowers it). `verify-gate-artifact` refuses a registry
  whose `registry_version` is lower than that floor, the same version with
  different bytes, a gate signature older than the floor's, and any
  signature past its maximum age. The parameter is not created by CDK (a
  stack update would reset it). If `record-accepted` fails after a deploy,
  re-run `make record-accepted`. It refuses a local-dev-signed registry, a missing
  `.kms.sig`, an untracked file anywhere in the tree, and any packaged source
  that differs from HEAD.
- [ ] **Every later registry change** repeats steps 2 to 4: edit
  `data/approved_models.json` (bump `registry_version`), re-sign with
  `--kms`, commit both files, deploy.
- [ ] **Re-sign cadence.** Re-sign the registry (`sign_registry.py --kms`)
  and redeploy at least every `max_signature_age_seconds.approved-models-registry`
  − 14 days (default 106 days). A deployed ComplianceAgent refuses all
  decisions once the registry signature is older than that max age.
  `verify_gate_artifact` warns when fewer than 14 days remain.
- [ ] **CI as the gate signer (optional).** Deploy `FsiComplianceAgents` with
  CDK context `ci_role_arn=<CI role ARN>`, so the signer role trusts the CI
  role without the MFA and session-name conditions. In CI,
  `GATE_SIGNER_PROFILE` names a profile like:

  ```ini
  [profile fsi-gate-signer-ci]
  role_arn = arn:aws:iam::<acct>:role/fsi-deploy-gate-signer
  credential_source = Environment
  role_session_name = ci-<run id>
  ```

- [ ] Restrict runtime creation and code upload to the CI deploy role, so a
  bundle can only reach a runtime through the gated chain:

  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "DenyRuntimeChangesExceptDeployRole",
        "Effect": "Deny",
        "Action": [
          "bedrock-agentcore:CreateAgentRuntime",
          "bedrock-agentcore:UpdateAgentRuntime"
        ],
        "Resource": "*",
        "Condition": {
          "ArnNotLike": {
            "aws:PrincipalArn": "arn:aws:iam::<acct>:role/<ci deploy role>"
          }
        }
      },
      {
        "Sid": "DenyCodeBucketWritesExceptDeployRole",
        "Effect": "Deny",
        "Action": "s3:PutObject",
        "Resource": "arn:aws:s3:::<agentcore code bucket>/*",
        "Condition": {
          "ArnNotLike": {
            "aws:PrincipalArn": "arn:aws:iam::<acct>:role/<ci deploy role>"
          }
        }
      },
      {
        "Sid": "DenyContainmentFunctionChangesExceptDeployRole",
        "Effect": "Deny",
        "Action": [
          "lambda:UpdateFunctionConfiguration",
          "lambda:UpdateFunctionCode",
          "lambda:UpdateAlias",
          "lambda:PublishVersion",
          "lambda:PutFunctionConcurrency",
          "lambda:DeleteFunctionConcurrency",
          "lambda:AddPermission",
          "lambda:RemovePermission",
          "lambda:PutFunctionEventInvokeConfig",
          "lambda:UpdateFunctionEventInvokeConfig",
          "lambda:DeleteFunction"
        ],
        "Resource": [
          "arn:aws:lambda:*:<acct>:function:fsi-circuit-breaker",
          "arn:aws:lambda:*:<acct>:function:fsi-circuit-breaker:*",
          "arn:aws:lambda:*:<acct>:function:fsi-circuit-breaker-human",
          "arn:aws:lambda:*:<acct>:function:fsi-circuit-breaker-human:*",
          "arn:aws:lambda:*:<acct>:function:fsi-pan-filter",
          "arn:aws:lambda:*:<acct>:function:fsi-pan-filter:*",
          "arn:aws:lambda:*:<acct>:function:fsi-governance-hold-sweep",
          "arn:aws:lambda:*:<acct>:function:fsi-governance-hold-sweep:*",
          "arn:aws:lambda:*:<acct>:function:fsi-drift-metric-publisher",
          "arn:aws:lambda:*:<acct>:function:fsi-drift-metric-publisher:*",
          "arn:aws:lambda:*:<acct>:function:fsi-audit-archiver",
          "arn:aws:lambda:*:<acct>:function:fsi-audit-archiver:*"
        ],
        "Condition": {
          "ArnNotLike": {
            "aws:PrincipalArn": [
              "arn:aws:iam::<acct>:role/<ci deploy role>",
              "arn:aws:iam::<acct>:role/cdk-hnb659fds-cfn-exec-role-<acct>-<region>"
            ]
          }
        }
      },
      {
        "Sid": "DenyContainmentScheduleChangesExceptDeployRole",
        "Effect": "Deny",
        "Action": [
          "events:DisableRule",
          "events:DeleteRule",
          "events:PutRule",
          "events:PutTargets",
          "events:RemoveTargets"
        ],
        "Resource": [
          "arn:aws:events:*:<acct>:rule/fsi-governance-hold-sweep",
          "arn:aws:events:*:<acct>:rule/fsi-breaker-alarm-recheck"
        ],
        "Condition": {
          "ArnNotLike": {
            "aws:PrincipalArn": [
              "arn:aws:iam::<acct>:role/<ci deploy role>",
              "arn:aws:iam::<acct>:role/cdk-hnb659fds-cfn-exec-role-<acct>-<region>"
            ]
          }
        }
      },
      {
        "Sid": "DenyAcceptedRegistryFloorChangesExceptDeployRole",
        "Effect": "Deny",
        "Action": [
          "ssm:PutParameter",
          "ssm:DeleteParameter",
          "ssm:DeleteParameters",
          "ssm:LabelParameterVersion"
        ],
        "Resource": "arn:aws:ssm:*:<acct>:parameter/fsi/governance/*",
        "Condition": {
          "ArnNotLike": {
            "aws:PrincipalArn": [
              "arn:aws:iam::<acct>:role/<ci deploy role>"
            ]
          }
        }
      },
      {
        "Sid": "DenyGovernanceStateWritesExceptBreaker",
        "Effect": "Deny",
        "Action": [
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem",
          "dynamodb:BatchWriteItem",
          "dynamodb:PartiQLInsert",
          "dynamodb:PartiQLUpdate",
          "dynamodb:PartiQLDelete",
          "dynamodb:DeleteTable",
          "dynamodb:RestoreTableToPointInTime"
        ],
        "Resource": "arn:aws:dynamodb:*:<acct>:table/governance-state",
        "Condition": {
          "ArnNotLike": {
            "aws:PrincipalArn": [
              "arn:aws:iam::<acct>:role/circuit-breaker-role",
              "arn:aws:iam::<acct>:role/fsi-breaker/fsi-breaker-break-glass",
              "arn:aws:iam::<acct>:role/<ci deploy role>",
              "arn:aws:iam::<acct>:role/cdk-hnb659fds-cfn-exec-role-<acct>-<region>"
            ]
          }
        }
      }
    ]
  }
  ```

  The containment statements keep anyone but the deploy path
  from changing the kill switch itself: `fsi-circuit-breaker`,
  `fsi-circuit-breaker-human`, `fsi-pan-filter`, `fsi-governance-hold-sweep`
  and `fsi-drift-metric-publisher` (configuration, code, aliases, versions,
  concurrency, resource policy, async/DLQ config, deletion), the two
  schedules (`fsi-governance-hold-sweep`, `fsi-breaker-alarm-recheck`) and
  the accepted-registry floor (`/fsi/governance/accepted-registry`). The
  actions go beyond the five core containment actions: `RemovePermission` would
  silently remove the alarms' invoke permission (kill switch inoperative),
  `DeleteFunctionConcurrency` pairs with `PutFunctionConcurrency`, and the
  async-config actions could drop the DLQ. The CloudFormation execution role
  is excepted because `cdk deploy` acts through it; the SSM floor is written
  only by `make record-accepted` under the CI deploy role. The
  `governance-state` item serializes trip and release and has no stream, so
  an out-of-band write would leave no write-once trace:
  `DenyGovernanceStateWritesExceptBreaker` leaves its writes to
  `circuit-breaker-role` (both breaker functions), the break-glass role and
  the deploy path.

### Step 4. Runtime invoke scoping and data events (#2, #6, #9)

The `/invocations` shims can't see the SigV4 caller, so who may invoke a
runtime is decided by IAM.

- [ ] Restrict `bedrock-agentcore:InvokeAgentRuntime` on the three runtimes
  to the console roles and the CI role:

  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "DenyRuntimeInvokeExceptNamedRoles",
        "Effect": "Deny",
        "Action": "bedrock-agentcore:InvokeAgentRuntime",
        "Resource": [
          "arn:aws:bedrock-agentcore:<region>:<acct>:runtime/DetectionAgent-*",
          "arn:aws:bedrock-agentcore:<region>:<acct>:runtime/ComplianceAgent-*",
          "arn:aws:bedrock-agentcore:<region>:<acct>:runtime/ExecutorAgent-*"
        ],
        "Condition": {
          "ArnNotLike": {
            "aws:PrincipalArn": [
              "arn:aws:iam::<acct>:role/fsi-console/fsi-console-operator",
              "arn:aws:iam::<acct>:role/fsi-console/fsi-console-operator-hosted",
              "arn:aws:iam::<acct>:role/<ci role>"
            ]
          }
        }
      }
    ]
  }
  ```

  With this in place, the `make demo-*-live` scripts must run under the
  `fsi-operator` profile (`AWS_PROFILE=fsi-operator make demo-live`).
- [ ] The console invokes only the runtime ARNs that
  `cdk/deploy_agentcore_runtimes.py` writes to the SSM String parameter
  `/fsi/governance/agentcore-runtime-arns` (never a runtime looked up by
  name). The console roles hold `ssm:GetParameter` on that one parameter;
  the step 3 SCP statement on `/fsi/governance/*` limits writes to the
  deploy role. With no valid parameter the console refuses every live run.
- [ ] Enable CloudTrail **data events** for the AgentCore runtimes, for
  `PutItem` on the `operator-audit` table, and for Lambda `Invoke` on
  `fsi-circuit-breaker-human` and `fsi-pan-filter`. DynamoDB and Lambda data
  events aren't recorded by default, and operator-audit records are
  authoritative only together with them. Example selectors for the
  DynamoDB and Lambda parts (`put-event-selectors` replaces the trail's
  existing selectors, so merge these with what the trail already has, and
  add the AgentCore runtime selector the same way):

  ```bash
  aws cloudtrail put-event-selectors --trail-name <trail> --advanced-event-selectors '[
    {"Name": "operator-audit PutItem", "FieldSelectors": [
      {"Field": "eventCategory", "Equals": ["Data"]},
      {"Field": "resources.type", "Equals": ["AWS::DynamoDB::Table"]},
      {"Field": "resources.ARN", "Equals": ["arn:aws:dynamodb:<region>:<acct>:table/operator-audit"]},
      {"Field": "eventName", "Equals": ["PutItem"]}]},
    {"Name": "breaker and PAN Lambda invokes", "FieldSelectors": [
      {"Field": "eventCategory", "Equals": ["Data"]},
      {"Field": "resources.type", "Equals": ["AWS::Lambda::Function"]},
      {"Field": "resources.ARN", "Equals": [
        "arn:aws:lambda:<region>:<acct>:function:fsi-circuit-breaker-human",
        "arn:aws:lambda:<region>:<acct>:function:fsi-pan-filter"]}]}
  ]'
  ```

- [ ] Put per-caller invoke quotas in front of AgentCore (for example an API
  layer with usage plans) so one caller can't exhaust runtime capacity.
- [ ] Optional: configure AgentCore inbound JWT authorization on the
  runtimes. This repo's runtime-creation path doesn't wire it.

### Step 5. Data-plane reads (#8)

The SAR bucket policy already denies filing reads to everyone except
`fsi-compliance-reader`. DynamoDB tables have no resource policy in this
IaC, so broad admin roles can still read them until this step is done.

- [ ] SCP (or permission boundary on admin roles) removing broad data reads
  on the audit tables and the SAR filings. The exceptions are exactly the
  roles the stacks grant reads to; their own IAM policies narrow each one
  further (for example the agents have `GetItem` only):

  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "DenyAuditTableReadsExceptGrantedRoles",
        "Effect": "Deny",
        "Action": [
          "dynamodb:GetItem",
          "dynamodb:BatchGetItem",
          "dynamodb:Query",
          "dynamodb:Scan",
          "dynamodb:PartiQLSelect",
          "dynamodb:ExportTableToPointInTime"
        ],
        "Resource": [
          "arn:aws:dynamodb:*:<acct>:table/detection-results",
          "arn:aws:dynamodb:*:<acct>:table/detection-results/*",
          "arn:aws:dynamodb:*:<acct>:table/compliance-decisions",
          "arn:aws:dynamodb:*:<acct>:table/compliance-decisions/*",
          "arn:aws:dynamodb:*:<acct>:table/executor-audit",
          "arn:aws:dynamodb:*:<acct>:table/executor-audit/*",
          "arn:aws:dynamodb:*:<acct>:table/governance-audit",
          "arn:aws:dynamodb:*:<acct>:table/governance-audit/*",
          "arn:aws:dynamodb:*:<acct>:table/operator-audit",
          "arn:aws:dynamodb:*:<acct>:table/operator-audit/*"
        ],
        "Condition": {
          "ArnNotLike": {
            "aws:PrincipalArn": [
              "arn:aws:iam::<acct>:role/compliance-agent-role",
              "arn:aws:iam::<acct>:role/executor-agent-role",
              "arn:aws:iam::<acct>:role/circuit-breaker-role",
              "arn:aws:iam::<acct>:role/fsi-drift-metric-publisher-role",
              "arn:aws:iam::<acct>:role/fsi-audit-archiver-role",
              "arn:aws:iam::<acct>:role/governance-hold-sweep-role",
              "arn:aws:iam::<acct>:role/fsi-compliance-reader",
              "arn:aws:iam::<acct>:role/fsi-console/fsi-console-operator",
              "arn:aws:iam::<acct>:role/fsi-console/fsi-console-operator-hosted"
            ]
          }
        }
      },
      {
        "Sid": "DenyAuditStreamReadsExceptConsumers",
        "Effect": "Deny",
        "Action": [
          "dynamodb:GetRecords",
          "dynamodb:GetShardIterator"
        ],
        "Resource": [
          "arn:aws:dynamodb:*:<acct>:table/detection-results/stream/*",
          "arn:aws:dynamodb:*:<acct>:table/compliance-decisions/stream/*",
          "arn:aws:dynamodb:*:<acct>:table/executor-audit/stream/*",
          "arn:aws:dynamodb:*:<acct>:table/governance-audit/stream/*",
          "arn:aws:dynamodb:*:<acct>:table/operator-audit/stream/*"
        ],
        "Condition": {
          "ArnNotLike": {
            "aws:PrincipalArn": [
              "arn:aws:iam::<acct>:role/fsi-drift-metric-publisher-role",
              "arn:aws:iam::<acct>:role/fsi-audit-archiver-role",
              "arn:aws:iam::<acct>:role/<ci deploy role>"
            ]
          }
        }
      },
      {
        "Sid": "DenySarFilingReadsExceptComplianceReader",
        "Effect": "Deny",
        "Action": [
          "s3:GetObject",
          "s3:GetObjectVersion"
        ],
        "Resource": "arn:aws:s3:::<sar-bucket>/filings/*",
        "Condition": {
          "ArnNotLike": {
            "aws:PrincipalArn": "arn:aws:iam::<acct>:role/fsi-compliance-reader"
          }
        }
      }
    ]
  }
  ```

  The console operator roles appear only for the `executor-audit`
  `by_day_ts` index Query that confirms a SOX rejection was audited. The
  drift metric publisher reads only the `compliance-decisions` stream and
  `GetItem` of four drift attributes (no narratives); the governance-hold
  sweep only queries `governance-audit/index/by_event_type`.
  `circuit-breaker-role` `GetItem`s `governance-audit` by key only for
  `release-request#*` and `completed-*`. `governance-state` is not an audit
  table and is not in this statement: `circuit-breaker-role` and
  `fsi-breaker-break-glass` hold `dynamodb:GetItem`/`dynamodb:UpdateItem`
  on it and `governance-hold-sweep-role` holds `dynamodb:GetItem` only, all
  limited to the key `breaker` (`dynamodb:LeadingKeys`); no role holds
  `PutItem` or `DeleteItem` on it.
  `fsi-audit-archiver-role` reads the five audit-table streams and
  `GetItem`s each of the five audit tables by key (step 10). Stream reads have
  their own statement: only the two stream consumers and the deploy role
  `<ci deploy role>` (for a DLQ replay, step 10) may read the streams, and
  the deploy role gets no table reads.
- [ ] Assign `fsi-compliance-reader` to named compliance staff (step 2
  profile shape).
- [ ] Restrict `bedrock-agentcore:Get*` / `bedrock-agentcore:List*` (the
  AgentCore control-plane reads, which expose runtime configuration and
  environment variables) to the deploy role, the gate signer and the console
  operator roles.

### Step 6. Drift signal (#11)

Only `fsi-drift-metric-publisher-role` publishes the drift metrics in
`FSI/AgenticCompliance`. The publisher Lambda derives every
datapoint from a stored VERIFIED decision record, read from the KEYS_ONLY
stream of `compliance-decisions`; no agent role publishes. Only the deploy
role defines alarms, and only the CDK execution role may change the
publisher's stream mapping or the table's stream. The console no longer calls
`SetAlarmState`, so the alarm part has no console exception.

In code, the breaker also corroborates every drift alarm against the stored
VERIFIED decisions before it attaches anything: an alarm with no matching
decisions is recorded as `ALARM_UNCORROBORATED` and alerts
(`fsi-uncorroborated-drift-alarm`) instead of holding. The SCP keeps forged
datapoints from reaching the alarms in the first place.

- [ ] **Standard variant** (stack deployed without
  `allow_console_drift_injection`):

  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "DenyDriftMetricPublishExceptPublisher",
        "Effect": "Deny",
        "Action": "cloudwatch:PutMetricData",
        "Resource": "*",
        "Condition": {
          "StringEquals": {
            "cloudwatch:namespace": "FSI/AgenticCompliance"
          },
          "ArnNotLike": {
            "aws:PrincipalArn": [
              "arn:aws:iam::<acct>:role/fsi-drift-metric-publisher-role"
            ]
          }
        }
      },
      {
        "Sid": "DenyDriftPublisherStreamChangesExceptDeployRole",
        "Effect": "Deny",
        "Action": [
          "lambda:CreateEventSourceMapping",
          "lambda:UpdateEventSourceMapping",
          "lambda:DeleteEventSourceMapping"
        ],
        "Resource": "*",
        "Condition": {
          "ArnLike": {
            "lambda:FunctionArn": "arn:aws:lambda:*:<acct>:function:fsi-drift-metric-publisher*"
          },
          "ArnNotLike": {
            "aws:PrincipalArn": [
              "arn:aws:iam::<acct>:role/cdk-hnb659fds-cfn-exec-role-<acct>-<region>"
            ]
          }
        }
      },
      {
        "Sid": "DenyComplianceStreamChangesExceptDeployRole",
        "Effect": "Deny",
        "Action": [
          "dynamodb:UpdateTable"
        ],
        "Resource": "arn:aws:dynamodb:*:<acct>:table/compliance-decisions",
        "Condition": {
          "ArnNotLike": {
            "aws:PrincipalArn": [
              "arn:aws:iam::<acct>:role/cdk-hnb659fds-cfn-exec-role-<acct>-<region>"
            ]
          }
        }
      },
      {
        "Sid": "DenyAlarmTamperingExceptDeployRole",
        "Effect": "Deny",
        "Action": [
          "cloudwatch:SetAlarmState",
          "cloudwatch:DisableAlarmActions",
          "cloudwatch:PutMetricAlarm",
          "cloudwatch:DeleteAlarms"
        ],
        "Resource": "arn:aws:cloudwatch:*:<acct>:alarm:fsi-*",
        "Condition": {
          "ArnNotLike": {
            "aws:PrincipalArn": [
              "arn:aws:iam::<acct>:role/cdk-hnb659fds-cfn-exec-role-<acct>-<region>"
            ]
          }
        }
      }
    ]
  }
  ```

  `cdk-hnb659fds-cfn-exec-role-…` is the CloudFormation execution role of a
  default `cdk bootstrap`. Use your own deploy role if you bootstrapped with
  a custom qualifier or execution role.
- [ ] **D4 live drift demo variant. Demo-only exception.** Use this **only
  if** the stack is deployed with CDK context
  `allow_console_drift_injection=true`. It's the standard variant with the
  console operator role added to the `PutMetricData` exception.
  `fsi-console-operator-hosted` is never excepted. An injected datapoint has
  no stored decision behind it, so the breaker records the resulting alarm as
  `ALARM_UNCORROBORATED` and never attaches the hold; use Manual trip to
  demonstrate containment. Switch back to the
  standard variant when the demo stack is redeployed without the context.

  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "DenyDriftMetricPublishExceptPublisherAndDemoConsole",
        "Effect": "Deny",
        "Action": "cloudwatch:PutMetricData",
        "Resource": "*",
        "Condition": {
          "StringEquals": {
            "cloudwatch:namespace": "FSI/AgenticCompliance"
          },
          "ArnNotLike": {
            "aws:PrincipalArn": [
              "arn:aws:iam::<acct>:role/fsi-drift-metric-publisher-role",
              "arn:aws:iam::<acct>:role/fsi-console/fsi-console-operator"
            ]
          }
        }
      },
      {
        "Sid": "DenyDriftPublisherStreamChangesExceptDeployRole",
        "Effect": "Deny",
        "Action": [
          "lambda:CreateEventSourceMapping",
          "lambda:UpdateEventSourceMapping",
          "lambda:DeleteEventSourceMapping"
        ],
        "Resource": "*",
        "Condition": {
          "ArnLike": {
            "lambda:FunctionArn": "arn:aws:lambda:*:<acct>:function:fsi-drift-metric-publisher*"
          },
          "ArnNotLike": {
            "aws:PrincipalArn": [
              "arn:aws:iam::<acct>:role/cdk-hnb659fds-cfn-exec-role-<acct>-<region>"
            ]
          }
        }
      },
      {
        "Sid": "DenyComplianceStreamChangesExceptDeployRole",
        "Effect": "Deny",
        "Action": [
          "dynamodb:UpdateTable"
        ],
        "Resource": "arn:aws:dynamodb:*:<acct>:table/compliance-decisions",
        "Condition": {
          "ArnNotLike": {
            "aws:PrincipalArn": [
              "arn:aws:iam::<acct>:role/cdk-hnb659fds-cfn-exec-role-<acct>-<region>"
            ]
          }
        }
      },
      {
        "Sid": "DenyAlarmTamperingExceptDeployRole",
        "Effect": "Deny",
        "Action": [
          "cloudwatch:SetAlarmState",
          "cloudwatch:DisableAlarmActions",
          "cloudwatch:PutMetricAlarm",
          "cloudwatch:DeleteAlarms"
        ],
        "Resource": "arn:aws:cloudwatch:*:<acct>:alarm:fsi-*",
        "Condition": {
          "ArnNotLike": {
            "aws:PrincipalArn": [
              "arn:aws:iam::<acct>:role/cdk-hnb659fds-cfn-exec-role-<acct>-<region>"
            ]
          }
        }
      }
    ]
  }
  ```

  The executor also emits its delivery and audit-failure counters into
  `FSI/AgenticCompliance` on a best-effort basis. `executor-agent-role` has
  no `PutMetricData` grant, so those counters show up only as executor ERROR
  logs. Don't add the executor (or `compliance-agent-role`) to the
  exception: it would let a compromised agent forge drift datapoints.

### Step 7. Dependencies (#10)

- [ ] Point installs at a controlled index (for example a CodeArtifact
  repository with a PyPI upstream) and keep `--require-hashes` with the
  committed lock files.
- [ ] Install only the pinned `@aws/agentcore@1.0.3` CLI; bump it deliberately.

### Step 8. PAN Lambda (#7, #9)

- [ ] Restrict `lambda:InvokeFunction` on `fsi-pan-filter` to the ingress
  caller. In the stacks only `fsi-console-operator` and
  `fsi-console-operator-hosted` hold that grant; an SCP like the step 4
  invoke SCP keeps admin roles from calling it directly.
- [ ] Confirm the account's unreserved Lambda concurrency allows the PAN
  filter's reserved concurrency (CDK context
  `pan_filter_reserved_concurrency`).

### Step 9. Account identifiers (#7)

- [ ] In production, tokenize real account numbers upstream. They often
  exceed the transaction schema's 12-digit account id cap, and the PAN
  filter isn't a substitute for tokenization.

### Step 10. Immutable audit archive

All five audit tables stream to `fsi-audit-archiver`, which writes one JSON
object per stream record to `<archive-bucket>` under
`<table>/YYYY/MM/DD/HH/<eventID>.json`. The bucket has S3 Object Lock in
COMPLIANCE mode, versioning, SSE-KMS with `alias/fsi-audit-archive`
(rotating, retained), Block Public Access and a TLS-only, deny-only bucket
policy. `make gate` fails if any of that is removed or weakened.

- [ ] **Set production retention.** Demo retention only. For production set
  retention per the applicable regulation (e.g. SEC 17a-4 / FINRA 4511: 6
  years, BSA/FinCEN SAR records: 5 years, SOX audit records: 7 years) —
  confirm with your compliance team. Set `audit_archive_retention_days` in
  `cdk/cdk.json` (days, 90 to 36500) and commit it; the gate checks the
  template against that value. Retention can only be raised: COMPLIANCE
  mode never lets an existing object version be shortened.
- [ ] **Understand COMPLIANCE mode before the first deploy.**
  - Nobody, including the account root, can delete a locked object version
    or shorten its retention until it expires. AWS Support can't either.
  - Storage is a cost commitment for the retention period.
  - The bucket, its policy and its key survive `make destroy` (RETAIN), and
    nothing empties the bucket. Clean up after retention expires.
  - The bucket policy denies object deletes, `PutObjectRetention`,
    `PutObjectLegalHold` and `BypassGovernanceRetention` to everyone.
    Legal holds, retention extensions and lifecycle rules therefore need a
    reviewed change to the bucket policy in `cdk/audit_archive.py`.
  - The archiver never sends Object Lock headers; retention comes only from
    the bucket default.
- [ ] **Coverage.** The archive covers records written after the streams
  are enabled (for `compliance-decisions`, which already had a stream, up
  to 24 hours before the archiver's first deploy). Earlier records remain
  in DynamoDB (point-in-time recovery, 35 days); archiving them needs a
  separate, reviewed backfill. An examiner establishes coverage per table
  from the earliest object's `LastModified`.
- [ ] **Source of truth.** The archiver never archives stream
  content. For every table it takes only the key from the record, reads the
  item with a consistent `GetItem` and archives that item (`item_sha256` is
  over it). On the four NEW_IMAGE tables (PutItem-only, no UpdateItem) the
  stream image must equal the item read (`image_source: get_item_verified`).
  It refuses, and writes nothing to S3, a record whose `eventSource` is not
  `aws:dynamodb` or whose `eventSourceARN` is not one of the five streams in
  `EXPECTED_STREAM_ARNS`, whose key is not that table's single string key,
  whose image differs from the table, whose item does not exist, or that
  claims a REMOVE of an item that still exists. Each refusal is logged and
  counted (`ArchiveSourceRefused`, alarm `fsi-audit-archive-source-refused`;
  also `ArchiveItemMissing` when the item is absent). A direct invoker can
  forge the event source and ARN, so those checks only reject foreign
  events: the re-read is the control, and a forged record can never put
  content in the archive that is not in the audit table. A REMOVE of an
  item that is gone still writes a keys-only tombstone (the key is shape
  checked and PAN scanned) and raises `fsi-audit-archive-record-removed`.
  A refused record is not retried or sent to the DLQ (the batch continues).
  Cost: one `GetItem` (on-demand read) per record.
- [ ] **Snapshot semantics.** `compliance-decisions` has a KEYS_ONLY stream
  (the drift publisher depends on it) and the executor updates its lease and
  completion attributes in place, so the archiver archives the item's version
  at read time with a consistent `GetItem`. Each MODIFY is archived as a read-time
  snapshot (`image_source: get_item_consistent`); intermediate states can
  collapse into a later snapshot, but the last event always captures the
  final state. If a retry re-reads an item that changed in between, the
  first snapshot is kept and `ArchiveSnapshotSuperseded` is counted (a
  metric, no alarm). The other four tables archive the item only when it
  equals the stream image.
- [ ] **Examiner procedure** (as `fsi-compliance-reader`, which can list,
  read and decrypt the archive and nothing else):
  1. List a partition: `aws s3api list-objects-v2 --bucket <archive-bucket>
     --prefix executor-audit/2026/11/04/13/`.
  2. Check the lock and the stored checksum: `aws s3api get-object-retention
     --bucket <archive-bucket> --key <key>` (mode `COMPLIANCE`, retain-until
     date) and `aws s3api get-object-attributes --bucket <archive-bucket>
     --key <key> --object-attributes Checksum`.
  3. Download the object and recompute SHA-256 over its bytes. It must
     match `ChecksumSHA256` (base64) and the `content-sha256` metadata (hex,
     `head-object`).
  4. Recompute `item_sha256` as SHA-256 over the canonical JSON of `item`
     (sorted keys, separators `,` and `:`, UTF-8, no ASCII escaping).
  5. Treat `image_source` values `remove_event` and
     `pan_refused` as incidents (each also raises an alarm). Recover the
     content from the table with point-in-time recovery.
  6. Objects under `_conflicts/<table>/<eventID>/` are a second, different
     body for an archived event; the original object is unchanged. Treat
     them as incidents (`fsi-audit-archive-conflict`).
- [ ] **Alarms.** `fsi-audit-archiver-dlq-not-empty`,
  `fsi-audit-archiver-errors`, `fsi-audit-archive-record-failures`,
  `fsi-audit-archiver-iterator-age`, `fsi-audit-archive-conflict`,
  `fsi-audit-archive-pan-refused`, `fsi-audit-archive-record-removed`,
  `fsi-audit-archive-item-missing` and `fsi-audit-archive-source-refused` notify the `fsi-governance-alarms` topic;
  subscribe on-call to it (step 11). The step 6 alarm-tampering statement
  already covers them (`fsi-*`).
- [ ] **DLQ recovery** (the only supported path). Stream records stay
  available for 24 hours; the archiver gives up on a record after 6 hours,
  so a DLQ message is replayable for about 18 hours. The replay role is the
  deploy role `<ci deploy role>` only; break-glass roles are not excepted.
  1. Read the message from `fsi-audit-archiver-dlq`. It holds only
     `DDBStreamBatchInfo` (stream ARN, shard id, first and last sequence
     numbers), never item content.
  2. `aws dynamodbstreams get-shard-iterator --shard-iterator-type
     AT_SEQUENCE_NUMBER` with the first sequence number, then
     `get-records` up to the last one.
  3. Invoke `fsi-audit-archiver` synchronously with
     `{"Records": [...]}`. `get-records` output has no `eventSourceARN`:
     add `"eventSourceARN": "<the stream ARN from the DLQ message>"` to each
     record (the archiver refuses any other ARN). Retries are idempotent
     (conditional writes).
  4. After 24 hours the records can't be read from the stream. Rely on the
     table and point-in-time recovery, and record the gap as an incident.
- [ ] **SCPs** (an extra layer; the bucket policy already denies
  `PutBucketPolicy` and `DeleteBucketPolicy` to everyone except the CDK
  CloudFormation execution role, in-account and without AWS Organizations.
  The account root can always change or delete a bucket policy; that is
  the recovery path if your bootstrap uses a different execution role.)
  Also add `fsi-audit-archiver` to the step 3 containment statement and
  the archiver role and deploy role to the step 5 statements (done above).

  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "DenyAuditArchiverDirectInvoke",
        "Effect": "Deny",
        "Action": [
          "lambda:InvokeFunction",
          "lambda:InvokeFunctionUrl",
          "lambda:InvokeAsync"
        ],
        "Resource": [
          "arn:aws:lambda:*:<acct>:function:fsi-audit-archiver",
          "arn:aws:lambda:*:<acct>:function:fsi-audit-archiver:*"
        ],
        "Condition": {
          "ArnNotLike": {
            "aws:PrincipalArn": [
              "arn:aws:iam::<acct>:role/<ci deploy role>"
            ]
          }
        }
      },
      {
        "Sid": "DenyAuditArchiverStreamChangesExceptDeployRole",
        "Effect": "Deny",
        "Action": [
          "lambda:CreateEventSourceMapping",
          "lambda:DeleteEventSourceMapping",
          "lambda:UpdateEventSourceMapping"
        ],
        "Resource": "*",
        "Condition": {
          "ArnLike": {
            "lambda:FunctionArn": "arn:aws:lambda:*:<acct>:function:fsi-audit-archiver*"
          },
          "ArnNotLike": {
            "aws:PrincipalArn": [
              "arn:aws:iam::<acct>:role/cdk-hnb659fds-cfn-exec-role-<acct>-<region>"
            ]
          }
        }
      },
      {
        "Sid": "DenyAuditTableStreamChangesExceptDeployRole",
        "Effect": "Deny",
        "Action": [
          "dynamodb:UpdateTable"
        ],
        "Resource": [
          "arn:aws:dynamodb:*:<acct>:table/detection-results",
          "arn:aws:dynamodb:*:<acct>:table/executor-audit",
          "arn:aws:dynamodb:*:<acct>:table/governance-audit",
          "arn:aws:dynamodb:*:<acct>:table/operator-audit"
        ],
        "Condition": {
          "ArnNotLike": {
            "aws:PrincipalArn": [
              "arn:aws:iam::<acct>:role/cdk-hnb659fds-cfn-exec-role-<acct>-<region>"
            ]
          }
        }
      },
      {
        "Sid": "DenyAuditArchiveBucketPolicyChangesExceptDeployRole",
        "Effect": "Deny",
        "Action": [
          "s3:PutBucketPolicy",
          "s3:DeleteBucketPolicy"
        ],
        "Resource": "arn:aws:s3:::<archive-bucket>",
        "Condition": {
          "ArnNotLike": {
            "aws:PrincipalArn": [
              "arn:aws:iam::<acct>:role/cdk-hnb659fds-cfn-exec-role-<acct>-<region>"
            ]
          }
        }
      }
    ]
  }
  ```

  `compliance-decisions` `UpdateTable` is already covered by the step 6
  stream statement. `governance-state` has no stream and is not archived;
  its writes are limited by `DenyGovernanceStateWritesExceptBreaker`
  (step 3). ESM polling isn't an invoke by an account principal, so
  the invoke deny doesn't affect the archiver's event source mappings.
- [ ] **Residual risks and production hardening.**
  - The PAN check skips id and hash fields whose value is exactly one of the
    system id formats (UUIDs, `prefix#<uuid>`, detection overflow chunk
    keys, SHA-256 digests, `sha256:<digest>`, `nonce#<digest>`). A PAN
    deliberately disguised as such a value in such a field isn't caught; the
    ingress PAN filter still applies upstream.
  - The archiver scans each value on its own; cross-field split-PAN
    detection runs at ingress only.
  - Recommended for production: S3 server access logging (or CloudTrail
    data events) on the archive bucket, and replication to a separate
    account with its own Object Lock.

### Step 11. On-call notifications, analyst queue, Lambda logs

- [ ] **Subscribe on-call to `fsi-governance-alarms`.** Every review-only
  alarm sends its ALARM transition to this topic (output
  `GovernanceAlarmTopicArn` of `FsiComplianceData`): the eight archive
  alarms, `fsi-out-of-band-hold-change`, `fsi-break-glass-assumed`,
  `fsi-uncorroborated-drift-alarm`, `fsi-corroboration-unavailable`,
  `fsi-drift-shaping-suspected`, the three `fsi-drift-metric-publisher-*`
  alarms, `fsi-hold-reconciled`, `fsi-hold-sweep-failed`,
  `fsi-hold-sweep-not-running`, `fsi-newer-hold-detected`, `fsi-hold-release-superseded`,
  `fsi-hold-state-write-failed`, `fsi-hold-state-read-failed`,
  `fsi-compliance-invocation-surge`, `fsi-challenger-output-rejected` and
  `fsi-circuit-breaker-dlq-not-empty`. The four drift alarms that trip the
  automated breaker keep the breaker as their only action. Either:
  - deploy with `-c alarm_email=<on-call address>` (one plain address; the
    recipient must confirm the subscription email), or
  - subscribe your paging tool or an address yourself, for example
    `aws sns subscribe --topic-arn <topic-arn> --protocol email
    --notification-endpoint <on-call address>`.
  Without either the topic has no subscriber and the alarms still page no
  one. The topic is encrypted with its own key (`alias/fsi-governance-alarms`);
  only CloudWatch alarms of this account and region may publish, and only
  over TLS, so a manual `sns publish` test is denied. Test with the deploy
  role (the step 6 statement denies `SetAlarmState` to everyone else):
  `aws cloudwatch set-alarm-state --alarm-name fsi-hold-reconciled
  --state-value ALARM --state-reason test`. That alarm never invokes the
  breaker; it returns to `OK` at its next evaluation.
- [ ] **Analyst queue.** `fsi-analyst-review` denies `sqs:SendMessage` to
  every principal except `executor-agent-role`, so an admin or CI session
  can't post a fake escalation. The executor role itself (or anyone who can
  change the queue policy) still can. Analysts cross-check each message's
  `action_id` against the `ESCALATED_TO_ANALYST` record in `executor-audit`
  before acting on it, and treat a message without one as an incident. The
  step 6 alarm-tampering SCP pattern applies: deny `sqs:SetQueueAttributes`
  on `fsi-analyst-review` except the CDK execution role.
- [ ] **Lambda log groups.** `fsi-audit-archiver`, `fsi-pan-filter`,
  `fsi-circuit-breaker`, `fsi-circuit-breaker-human`,
  `fsi-governance-hold-sweep` and `fsi-drift-metric-publisher` now log to
  `/fsi/lambda/<function-name>` (30-day retention, set in
  `cdk/lambda_logging.py`), and each role may only `CreateLogStream` /
  `PutLogEvents` there (no `AWSLambdaBasicExecutionRole`). The implicit
  `/aws/lambda/<function-name>` groups from earlier deploys stop receiving
  logs and keep "never expire" retention. After the upgrade, set a
  retention on them (`aws logs put-retention-policy --log-group-name
  /aws/lambda/<function-name> --retention-in-days 30`) or delete them once
  their history is no longer needed. CDK's own auto-delete helper for the
  agent code bucket still uses `AWSLambdaBasicExecutionRole`.

## Upgrading an existing deployment
- Signature envelopes are now v3 (`signed_by` is signed). Re-sign the
  registry (`sign_registry.py --kms`) before `make deploy`; the gate and
  `verify-gate-artifact` refuse a v2 `.kms.sig`.
- The AgentCore deploy now writes `/fsi/governance/agentcore-runtime-arns`;
  until it has run once, the console refuses live runs.
- PAN-filter log lines no longer name the rule that fired (index and counts
  only); the rule stays in the detection audit item.

- Each existing audit table gains exactly one global secondary index in this
  change, and the new `operator-audit` table is created. CloudFormation
  creates only one GSI per table per update, so don't combine this deploy
  with any other index change.
- Decision records written before this change have no `provenance_status`
  and can no longer be routed by the executor (`PROVENANCE_CHECK_FAILED`).
  Re-run detection and compliance for anything still open.
- The deployed executor now requires `SAR_KMS_KEY_ARN`. The deploy script
  sets it from the `SarFilingsKeyArn` output of `FsiComplianceData`.
- Immutable audit archive: the four audit tables without a stream gain a
  NEW_IMAGE stream (an in-place update, no replacement), and
  `compliance-decisions` keeps its KEYS_ONLY stream with the archiver as its
  second consumer. Before deploying, update the step 3 and step 5 SCPs and
  set the production retention (step 10). The new bucket and key are
  retained on `make destroy`.
- On-call topic, queue policy and log groups (step 11): new
  `fsi-governance-alarms` topic and key in `FsiComplianceData`; the queue
  policy of `fsi-analyst-review` gains the send deny; six new
  `/fsi/lambda/*` log groups (new names, so no clash with the existing
  `/aws/lambda/*` groups). Look for Lambda logs under `/fsi/lambda/` from
  then on. A pre-upgrade audit record whose `console_request_ref` happens to
  be PAN-shaped is archived as `pan_refused` (and alarms) if it is streamed
  again; the item stays intact in the table.
- Adds the `governance-state` table (no stream, no GSI). A hold active at
  upgrade time can't be released in-band until one manual trip claims the
  state item (release requests return `HOLD_EVENT_UNKNOWN`). Add
  `DenyGovernanceStateWritesExceptBreaker` to the step 3 SCP, and confirm
  `make validate-iam` reports no new findings. The breaker functions'
  timeout goes from 30 s to 45 s (an in-place update).
- `make re-enable` is gone. Releasing a hold takes two people
  ([runbook](RUNBOOK_GOVERNANCE_HOLD.md)), and `make destroy` aborts while a
  hold is active.

Drift-signal and governance-hold follow-ups:

- `compliance-decisions` gains a KEYS_ONLY stream (an in-place update) that
  drives the new `fsi-drift-metric-publisher`.
- Update the step 5 exceptions and the step 6 statements **before**
  deploying. Otherwise the publisher fails silently (its datapoints are
  denied) and the drift alarms see nothing.
- `fsi-uncorroborated-trip` is renamed `fsi-uncorroborated-drift-alarm`;
  repoint any subscriptions.
- New `fsi-governance-hold-sweep` (role `governance-hold-sweep-role`, rule
  `fsi-governance-hold-sweep`, every 5 minutes) and `fsi-breaker-alarm-recheck`
  (every 2 minutes). Add both to the step 3 schedule statement and the sweep
  role to the step 5 exceptions **before** deploying, or the sweep fails
  (`fsi-hold-sweep-failed`).
- A drift alarm that the stored VERIFIED decisions don't corroborate no
  longer holds; it writes `ALARM_UNCORROBORATED` and alerts.
- v1 and v2 signature envelopes are refused (v2 left `signed_by` outside
  the signed digest). Run `pin_signing_keys.py` and commit
  `data/signing_key_pins.json` first, then re-sign `.kms.sig`
  (`sign_registry.py --kms`) and re-run `make gate-sign`.
- **alb-cognito upgrade:** deploy with `-c console_host_role_arn=…` so
  `fsi-console-audit-writer-hosted` exists, add
  `"audit_writer": "<fsi-console-audit-writer-hosted ARN>"` to
  `CONSOLE_ROLE_ARNS`, allow the console host role `sts:AssumeRole` and
  `sts:SetSourceIdentity` on it, and only then upgrade the console. Until
  then auditor-only AUDIT_READ is refused (fail closed).
- The console audit and PAN pages show an `INCOMPLETE EVIDENCE` banner when a
  read returned partial or failed data; that view is not sign-off evidence.
- Run `make record-accepted` after the first deploy (`make deploy` does it
  from then on).
- Registry signatures now expire: re-sign and redeploy at least every
  `max_signature_age_seconds.approved-models-registry` − 14 days (default
  106 days), or the deployed ComplianceAgent refuses all decisions.

## Post-deploy checks

These need a real account and can't run in the test suite:

- [ ] ALB/Cognito end to end, including that `GetUser` accepts the
  ALB-forwarded access token with the `aws.cognito.signin.user.admin` scope,
  and the anonymous-denial check from step 1.
- [ ] Real KMS signatures: `scripts/sign_registry.py --kms`, `make gate-sign`
  and `make verify-gate-artifact` succeed, and each runtime's first
  `/invocations` passes its attestation check.
- [ ] `scripts/pin_signing_keys.py --check` exits 0, and
  `/fsi/governance/accepted-registry` holds the deployed `registry_version`.
- [ ] The registry `signed_at` + its max age is more than 14 days away.
- [ ] `fsi-deploy-gate-signer` can run `compliance_gate.py --sign` end to
  end (every gate read allowed, `kms:Sign` succeeds), and the deployer's
  profile can't `kms:Sign` with the gate key.
- [ ] Real STS presigned verification with the nonce header: a manual trip
  and a two-person release through `fsi-circuit-breaker-human` succeed, and
  replaying the same proof is refused.
- [ ] CloudTrail to EventBridge delivery (`us-east-1` for IAM events): the
  hold-changes rule delivers to `/fsi/governance/hold-changes` through the
  direct `AWS::Logs::ResourcePolicy` (no custom resource), and the
  `HoldChangeTotal - HoldChangeByBreaker` alarm (`fsi-out-of-band-hold-change`)
  fires for a detach made by an IAM user. `HoldChangeByBreaker` counts the
  breaker's attach/detach and the sweep's **attaches** only (the sweep's
  re-attaches alert through `fsi-hold-reconciled` instead); a detach by the
  sweep role would still count as out-of-band.
- [ ] With step 5 attached and no hold active, `fsi-governance-hold-sweep`
  logs `NO_HOLD`, `fsi-hold-sweep-failed` stays `OK`, and
  `fsi-hold-sweep-not-running` is `OK` (each completed sweep emits
  `HoldSweepHeartbeat`; three 5-minute periods without one, including missing
  data, alarm).
- [ ] `/fsi/governance/agentcore-runtime-arns` holds the three ARNs the
  deploy printed, and the live console pages run.
- [ ] `fsi-breaker-alarm-recheck` and `fsi-governance-hold-sweep` rules are
  ENABLED.
- [ ] IAM refuses a customer-created role under
  `/aws-reserved/sso.amazonaws.com/` (the SSO path binding relies on it; the
  RoleId binding holds either way).
- [ ] In an account whose Identity Center roles carry a regional path
  segment, the breaker accepts the SSO approver.
- [ ] An MFA session profile (`get-session-token` + `source_profile` +
  `role_session_name = <IAM user name>`) satisfies both
  `aws:MultiFactorAuthPresent` and `sts:RoleSessionName == ${aws:username}`
  on the console roles, and the same profile **without**
  `role_session_name` is denied.
- [ ] The console operator can invoke each runtime with
  `qualifier="DEFAULT"`.
- [ ] The AgentCore Python 3.13 runtime provides glibc 2.28 or later (the
  DetectionAgent bundle installs `manylinux_2_28` numpy/pandas wheels).
- [ ] With the step 5 and step 6 SCPs attached: an admin role can't `Scan`
  an audit table or `PutMetricData` into `FSI/AgenticCompliance`, and the
  console pipeline, audit page and SOX page still work.
- [ ] With step 5 attached, a VERIFIED compliance run produces
  `ClustersAssessed` and `ClustersPerInvocation` datapoints (published by
  `fsi-drift-metric-publisher`), and `fsi-drift-metric-publisher-errors` and
  `fsi-drift-metric-publisher-iterator-age` stay `OK`.
- [ ] A console-injected breach (demo stack only) yields an
  `ALARM_UNCORROBORATED` event and no hold.
- [ ] `cloudwatch:DescribeAlarms` scoped to the four trusted alarm ARNs works
  for `circuit-breaker-role` with `AlarmNames` (if it doesn't, the recheck
  fails safe: no trip, `fsi-corroboration-unavailable` fires).
- [ ] Audit archive: after a detection run, each written record has an
  object under `<table>/YYYY/MM/DD/HH/` with `get-object-retention` mode
  `COMPLIANCE`; a `DeleteObject` on a version is denied; an admin role's
  `PutObject` and `GetObject` are denied; `fsi-audit-archiver-iterator-age`
  and `fsi-audit-archiver-dlq-not-empty` stay `OK`.
- [ ] On-call receives the `set-alarm-state` test from step 11 through
  `fsi-governance-alarms`; `aws sns publish` to the topic from an admin
  session is denied.
- [ ] `aws sqs send-message` to `fsi-analyst-review` from an admin session is
  denied, and an executor escalation still arrives.
- [ ] After a run, each of the six Lambda functions has a log stream under
  `/fsi/lambda/<function-name>` and none writes to `/aws/lambda/`.
- [ ] The Lambda Python 3.13 runtime's boto3 supports `PutObject`
  `IfNoneMatch` (otherwise every record fails and
  `fsi-audit-archive-record-failures` fires), and S3 accepts conditional
  writes on the Object Lock bucket.
