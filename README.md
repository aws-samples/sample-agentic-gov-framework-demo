# FSI Agentic Compliance — GPU-Accelerated Fraud Detection with Governance Envelope

This sample demonstrates how to build a governed, multi-agent fraud detection and compliance pipeline for financial services using Amazon Bedrock, NVIDIA cuGraph (GPU-accelerated graph analytics), and AWS serverless infrastructure.

> **Important:** This is sample code for demonstration purposes only. It is not intended for production use. Review the [Security](#security) section before deploying.

## Disclaimers

- **Not advice.** This sample is not legal, compliance or regulatory advice.
  Confirm every control and retention setting with your own compliance and
  legal teams.
- **Synthetic data only.** Use only the synthetic data shipped with the
  sample. Never load real customer, account or cardholder data.
- **Human review required.** SAR narratives are drafted by a generative AI
  model and require review by a qualified person before any filing decision.
- **Nothing is filed.** The sample does not file anything with FinCEN or any
  other regulator. The executor only writes drafts to the SAR S3 bucket and
  review items to the analyst SQS queue.

This sample uses generative AI through Amazon Bedrock: Anthropic Claude
Sonnet 4.5 drafts the SAR narrative and Amazon Nova Pro independently
challenges it (model ids in `cdk/deploy_agentcore_runtimes.py`). Model output
can be wrong; the pipeline routes disputes and failures to human review.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    GOVERNANCE ENVELOPE                               │
│                                                                     │
│  ┌─── Amazon Bedrock AgentCore Runtime (microVM, HTTP/8080) ────┐  │
│  │                                                               │  │
│  │  ┌─────────────┐    ┌──────────────────┐   ┌─────────────┐  │  │
│  │  │  DETECTION   │    │   COMPLIANCE     │   │   EXECUTOR   │  │  │
│  │  │   AGENT      │───▶│    REASONER      │──▶│    AGENT     │  │  │
│  │  │             │    │                  │   │             │  │  │
│  │  │ • cuGraph   │    │ • SAR Generation │   │ • Route SAR │  │  │
│  │  │ • PAN filter│    │ • Challenger     │   │ • Escalate  │  │  │
│  │  │ • PageRank  │    │ • Guardrail      │   │ • SOX enforce│  │  │
│  │  └─────────────┘    └──────────────────┘   └─────────────┘  │  │
│  │   NHI #1              NHI #2                 NHI #3          │  │
│  └───────────────────────────────────────────────────────────────┘  │
│        │                     │                       │             │
│        ▼                     ▼                       ▼             │
│  ┌───────────────────────────────────────────────────────────┐     │
│  │              DynamoDB AUDIT TABLES (PutItem-only)          │     │
│  └───────────────────────────────────────────────────────────┘     │
│                                                                     │
│  ┌─── AWS Lambda (retained — event-driven) ──────────────────┐    │
│  │                                                            │    │
│  │  ┌─────────────────┐    ┌──────────────────────────────┐  │    │
│  │  │ CIRCUIT BREAKER  │    │       PAN INGRESS FILTER      │  │    │
│  │  │ (alarm-triggered │    │   (PCI-DSS boundary, zero-   │  │    │
│  │  │  deny-all attach)│    │    trust, no data perms)      │  │    │
│  │  └─────────────────┘    └──────────────────────────────┘  │    │
│  └────────────────────────────────────────────────────────────┘    │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────┐      │
│  │       COMPLIANCE GATE (CI/CD deploy blocker)              │      │
│  └──────────────────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────────────┘
```

The overview above is simplified. [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
has the full diagram (Mermaid), the data flow, the trust boundaries and which
role writes which table.

## Three Non-Human Identities (NHI)

Each agent runs in its own AgentCore runtime under its own least-privilege
IAM role, created by CDK (`cdk/agents_stack.py`). The Lambda functions (PAN
filter, circuit breaker, hold sweep, drift metric publisher, audit archiver)
each have their own roles too.

| Agent | IAM Role | Permissions | Denied |
|-------|----------|-------------|--------|
| Detection | `detection-agent-role` | Read its code bundle and bundled synthetic dataset, write detection results (DynamoDB PutItem) | Invoke Bedrock, write SAR drafts |
| Compliance | `compliance-agent-role` | Invoke Bedrock (two approved inference profiles, with the guardrail), read recorded detections, write compliance decisions (PutItem) | Write SAR drafts, modify detection results |
| Executor | `executor-agent-role` | Write SAR drafts (S3, `filings/` prefix), send to the analyst queue (SQS), write `executor-audit` (PutItem), update four lease/completion attributes on `compliance-decisions`, trip the circuit breaker | Read raw transactions, invoke Bedrock, change decision fields |

## Prerequisites

- Python 3.11 or later (pandas 3.x; the AgentCore runtimes use 3.13)
- An AWS account (for live mode; cached demos require no AWS access; Bedrock-backed local pages need an operator AWS profile (see [Security setup](#security-setup)))
- AWS CLI configured with appropriate credentials (for live mode)
- Amazon Bedrock access with Claude model enabled in your region (for live mode)
- Node.js (for `make gate` and `make synth`): the compliance gate synthesizes the CDK app to check the audit archive. `make setup` installs the hash-locked CDK libraries (`requirements-cdk.lock`). Run `make gate` once before a demo to warm its synth cache (cold run about 6 s, cached about 3 s on a laptop).
- (Optional) NVIDIA GPU with RAPIDS toolkit for GPU-accelerated detection

## Quick Start

The demos run in `--local` mode using pre-cached outputs. Cached demos require no AWS access (and no GPU); Bedrock-backed local pages need an operator AWS profile (see [Security setup](#security-setup)).

```bash
# Create virtual environment and install dependencies
make setup

# Run all demos locally (uses cached output, works anywhere)
make demo

# Create your console sign-in once (prompts for a password, 12+ characters)
make console-operator OPERATOR_ID=alice DISPLAY_NAME="Alice" ROLES=operator,approver,auditor

# Launch the Streamlit dashboard (127.0.0.1 only; sign in as the operator above)
make ui

# Run compliance gate (219 assertions; needs Node.js)
make gate

# Run test suite (3,000+ tests)
make test
```

## Demo Scripts

### Local Mode (default — cached demos)

Cached demos require no AWS access; Bedrock-backed local pages need an operator AWS profile (see [Security setup](#security-setup)).

| Command | What it demonstrates |
|---------|---------------------|
| `make demo` | Run ALL demos in sequence |
| `make demo-detect` | GPU fraud ring detection — timing + clusters found |
| `make demo-pan` | PAN ingress filter catches 6 evasion variants before GPU processing |
| `make demo-sar` | SAR narrative generation via Bedrock + Guardrail blocking PII in output |
| `make demo-challenge` | Independent challenger DISPUTEs detection → escalates to NEEDS_REVIEW |
| `make demo-gate-fail` | Weaken guardrail config → gate BLOCKS deploy → restore → gate PASSES |
| `make demo-model-assurance` | D5.2 — approved model PASSES; unapproved / wrong-version model BLOCKED |
| `make demo-circuit-breaker` | Circuit breaker fires on drift threshold breach → agents disabled |
| `make demo-drift` | Drift monitoring metrics dashboard |

### Live Mode (requires deployed AWS infrastructure + Bedrock access)

| Command | What it demonstrates |
|---------|---------------------|
| `make demo-live` | Run ALL demos against live AWS |
| `make demo-detect-live` | Detection agent — CPU mode, writes results to DynamoDB |
| `make demo-pan-live` | PAN rejection — invokes the deployed PAN filter |
| `make demo-sar-live` | SAR generation — calls Bedrock, writes audit trail |
| `make demo-challenge-live` | Challenger — calls Bedrock for independent assessment |
| `make demo-circuit-breaker-live` | Circuit breaker — invokes actual Lambda circuit breaker |
| `make demo-drift-live` | Drift monitoring — reads live metrics from DynamoDB |

### Streamlit Dashboard

| Command | What it shows |
|---------|---------------|
| `make ui` | Dashboard reading cached local data (`127.0.0.1:8501`) |
| `make ui-live` | Dashboard reading live data from DynamoDB (`127.0.0.1:8502`, auto-refreshes every 30s) |
| `make console-operator` | Create or update a console sign-in (`OPERATOR_ID= DISPLAY_NAME= ROLES= [AWS_PROFILES=]`) |

Both dashboard targets set `CONSOLE_AUTH_MODE=local` and bind `127.0.0.1`
only; there is no shared password. Sign in with an operator created by
`make console-operator` (stored in `~/.fsi-console/operators.json`, mode
0600, outside the repo). See [Security setup](#security-setup).

## AWS Deployment

Deploy the full infrastructure using CDK:

```bash
# Prerequisites
npm install -g aws-cdk@2.1146.0  # CDK CLI (pinned; matches aws-cdk-lib 2.265.0's cloud-assembly schema)
make setup                       # Python deps, hash-locked (requirements.lock + requirements-dev.lock)

# Validate without deploying
make synth

# Deploy all stacks + agents: package -> gate-sign -> verify-gate-artifact -> deploy
# (first time: bootstrap and KMS-sign the registry, see below)
make deploy GATE_SIGNER_PROFILE=<profile for fsi-deploy-gate-signer>

# Run demos against live AWS
make demo-live

# Launch dashboard pointing at live data
make ui-live

# Tear down all AWS resources when done (aborts while a governance hold is active)
make destroy
```

### Deploy chain

`make deploy` runs `package → gate-sign → verify-gate-artifact` before any
CDK or AgentCore deploy:

- `package` builds `build/agentcore/<Agent>.zip` from sources at HEAD;
- `gate-sign` runs the compliance gate as `fsi-deploy-gate-signer`
  (`GATE_SIGNER_PROFILE` is required) and signs the gate artifact with KMS;
- `verify-gate-artifact` checks that signature and the bundle digests under
  your own profile, against the key ARNs pinned in
  `data/signing_key_pins.json` (never the key aliases), plus signature
  freshness and the accepted `registry_version` floor;
- after the runtime deploy, `record-accepted` raises that floor.

It refuses a local-dev-signed registry, a missing
`data/approved_models.json.kms.sig`, an untracked file anywhere in the tree,
and any packaged source that differs from HEAD. Run it from a fresh clone or
a dedicated worktree. The first deploy needs a one-time bootstrap (an admin
creates the keys and signer roles, the deployer pins them with
`scripts/pin_signing_keys.py` and commits the pins, the Model Risk approver
signs the registry with `scripts/sign_registry.py --kms` and commits the
`.kms.sig`); the exact
order is in [docs/SECURITY_OPERATIONAL_STEPS.md](docs/SECURITY_OPERATIONAL_STEPS.md)
step 3.

The ComplianceAgent assesses only recorded detections and refuses anything
else (HTTP 409). No console page needs an exception: the live pipeline,
Champion/Challenger and Poisoned transactions pages all record a fresh
detection first. Only if you deliberately send detection output with no
recorded detection, deploy with
`.venv/bin/python cdk/deploy_agentcore_runtimes.py --allow-unverified-evaluation`
(run it after `make deploy`; it redeploys the same prebuilt bundles and
re-verifies the signed gate artifact first). Those requests run as
UNVERIFIED evaluation: every decision is `NEEDS_REVIEW`, with no drift
metrics and no dispatch token.

### What Gets Deployed

| Resource | Purpose |
|----------|---------|
| 6 DynamoDB tables | Audit tables `detection-results`, `compliance-decisions`, `executor-audit`, `governance-audit`, `operator-audit`; plus `governance-state`, the single mutable item that serializes circuit-breaker trips and releases (not archived; its transitions are recorded in `governance-audit`) |
| 3 AgentCore runtimes | Detection, Compliance and Executor agents, deployed by `cdk/deploy_agentcore_runtimes.py` |
| 6 Lambda functions | `fsi-pan-filter`, `fsi-circuit-breaker` (alarms and automated trip), `fsi-circuit-breaker-human` (manual trip, two-person release), `fsi-governance-hold-sweep`, `fsi-drift-metric-publisher`, `fsi-audit-archiver` |
| 1 S3 bucket | SAR drafts (SSE-KMS, versioned) |
| 1 S3 bucket | Write-once audit archive (Object Lock COMPLIANCE, dedicated KMS key) fed by the audit tables' streams |
| 1 SQS queue | Analyst review queue (only the executor role may send) |
| 1 SNS topic | `fsi-governance-alarms` (KMS-encrypted): on-call notifications from the review-only integrity alarms |
| 1 Bedrock guardrail | `CfnGuardrail` plus a published version (content filters, denied phrases, PII and card-number filters) |
| IAM roles | One per agent runtime and per Lambda, the `governance-hold-deny-all` managed policy, and human roles (console operator, breaker operator/approver, break-glass, compliance reader, model-risk approver, gate signer) |

### Write-once audit archive

The audit tables are append-only by IAM policy: their writers hold
`dynamodb:PutItem` but not `UpdateItem` or `DeleteItem` (the one exception is
the executor's `UpdateItem` on `compliance-decisions`, limited to four lease
and completion attributes). IAM does not stop a writer from overwriting an
existing key with `PutItem`, so the tamper-evident copy is this archive.
`governance-state` is a mutable single item outside the archive; its
transitions are recorded in `governance-audit`.

Every record written to the five audit tables is also kept in a write-once
S3 archive for regulatory retention. Each table's DynamoDB stream feeds one
Lambda, `fsi-audit-archiver`, which writes one JSON object per stream record
to `<table>/YYYY/MM/DD/HH/<eventID>.json` in a dedicated bucket:

- S3 Object Lock in COMPLIANCE mode. Nobody, including the account root, can
  delete a locked object or shorten its retention until it expires.
- Default retention comes from `audit_archive_retention_days` in
  `cdk/cdk.json` (90 days for this demo; synth refuses less than 90). For
  production set it per the applicable regulation (for example SEC 17a-4 /
  FINRA 4511: 6 years, BSA/FinCEN SAR records: 5 years, SOX audit records:
  7 years) and confirm with your compliance team.
- SSE-KMS with its own rotating key, Block Public Access, TLS only, and a
  deny-only bucket policy: only the archiver can write, only the archiver
  and `fsi-compliance-reader` can read, and no one can delete objects or
  change retention.
- The agents still write only to DynamoDB, so the audit pipeline never waits
  on S3. Failed archive writes are retried, then sent to an encrypted DLQ,
  and alarmed; the archiver refuses content that holds a full PAN.
- `make gate` fails if the archive is removed or weakened.

The archive covers records written after the streams are enabled. Examiner
retrieval and validation, DLQ recovery and the production checklist are in
[docs/SECURITY_OPERATIONAL_STEPS.md](docs/SECURITY_OPERATIONAL_STEPS.md)
(step 10).

## Running in Live Mode

To run with real AWS services instead of cached outputs:

```bash
# Set required environment variables
export AWS_REGION=us-east-1
export BEDROCK_MODEL_ID=us.anthropic.claude-sonnet-4-5-20250929-v1:0
export GUARDRAIL_ID=your-guardrail-id
export GUARDRAIL_VERSION=1

# Run detection with CPU mode (no GPU required)
python lambdas/detection_agent/handler.py --mode cpu --file data/transactions_small.jsonl

# Run compliance agent with live Bedrock
python lambdas/compliance_agent/handler.py --detection-file cached_output/detection_result.json
```

The local demo targets (`make gate`, `make demo*`, `make model-swap-restore`,
`make dev-*`, `make ui*`) set `ALLOW_LOCAL_DEV_SIGNING=true` themselves, so
they accept the committed local-dev registry signature. When you run the
scripts directly with `python …` (as above), export it first:
`export ALLOW_LOCAL_DEV_SIGNING=true`. The PAN filter also needs
`ALLOW_LOCAL_DEV_TXN_REF_KEY=true` outside a deployed runtime (the
`make demo-pan*` targets set it). Neither flag is honoured inside a deployed
runtime, and the deploy chain never sets them.

Detection requests choose a dataset with `dataset_id` (`sample-small`, the
default); a caller-supplied `transaction_file` is refused. The `--file`
option above is the local CLI only.

### Dependencies (pinned and hash-locked)

Every requirements file pins exact versions, and installs use `--require-hashes`
against the lock files (full transitive closure with sha256 hashes):

```bash
pip install --require-hashes -r requirements.lock        # runtime + console
pip install --require-hashes -r requirements-dev.lock    # tests
pip install --require-hashes -r requirements-cdk.lock    # CDK app
```

Agent bundles install `agentcore/<agent>/requirements.lock` (linux aarch64 /
CPython 3.13, binary-only). After changing a pin, regenerate the matching lock
with `scripts/build_host_lock.py` (reads public PyPI metadata only).

### GPU mode (optional)

NVIDIA RAPIDS needs the CUDA toolkit and a supported GPU; it is not part of
the locks. Install the pinned versions separately on GPU instances:

```bash
pip install "cudf-cu12==26.10.2" "cugraph-cu12==26.10.0" --extra-index-url=https://pypi.nvidia.com
```

### AgentCore CLI

Only needed for `agentcore invoke` / `agentcore status`; the deploy itself uses
`cdk/deploy_agentcore_runtimes.py`. Install the pinned version globally with npm:

```bash
npm install -g @aws/agentcore@1.0.3  # AgentCore CLI (pinned; needs Node.js 20.12+)
```

### Supported Regions

This sample requires Amazon Bedrock access to Anthropic Claude Sonnet 4.5
(`us.anthropic.claude-sonnet-4-5-20250929-v1:0`) and Amazon Nova Pro
(`us.amazon.nova-pro-v1:0`) through their US cross-Region inference profiles. Check [Amazon Bedrock pricing](https://aws.amazon.com/bedrock/pricing/) for supported regions.

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AWS_REGION` | AWS region for Bedrock and DynamoDB | `us-east-1` |
| `BEDROCK_MODEL_ID` | Bedrock model identifier | `us.anthropic.claude-sonnet-4-5-20250929-v1:0` |
| `GUARDRAIL_ID` | Bedrock Guardrail identifier | (empty — guarded model calls are refused) |
| `GUARDRAIL_VERSION` | Published guardrail version | (empty — guarded model calls are refused) |
| `DETECTION_TABLE` | DynamoDB table for detection results | `detection-results` |
| `COMPLIANCE_TABLE` | DynamoDB table for compliance decisions | `compliance-decisions` |
| `WRITE_AUDIT` | Enable DynamoDB audit writes | `false` |

## Cost Warning

When running in live mode (not `--local`), this sample may incur AWS charges for:

- **Amazon Bedrock** — model invocation charges per token (two calls per cluster: SAR + Challenger)
- **Amazon DynamoDB** — write capacity for audit trail records
- **Amazon S3** — storage for SAR filings (if executor runs in live mode)
- **Amazon SQS** — messages for analyst queue

The `--local` mode uses pre-cached outputs and incurs **no AWS charges**.

## Key Design Decisions

1. **PAN filter runs BEFORE GPU** — the PAN filter rejects detected card numbers before graph processing; it is a data-hygiene control, not a guarantee
2. **Challenger is methodologically independent** — different model, different prompt, different reasoning approach
3. **Fail-safe to human review** — Bedrock failure, guardrail trigger, or challenger dispute → NEEDS_REVIEW
4. **Circuit breaker is asymmetric** — automated to trigger, manual to restore
5. **SOX separation of duties** — executor cannot modify decisions, only route them
6. **Compliance gate as CI/CD enforcement** — the gate blocks a deploy whose config fails its assertions
7. **Model assurance** — only org-approved, version-pinned models may be used (deploy + runtime)
8. **Write-once audit archive** — audit records stream to an S3 bucket with Object Lock COMPLIANCE, off the pipeline's critical path

## Project Structure

```
fsi-agentic-compliance/
├── app/
│   └── dashboard.py           # Streamlit demo dashboard (local + live modes)
├── agentcore/                 # AgentCore runtime entry points (one per agent) + bundle locks
├── lambdas/
│   ├── audit_archiver/        # Audit table streams -> Object Lock archive
│   ├── compliance_agent/      # SAR draft + independent challenger
│   ├── detection_agent/       # GPU fraud ring detection + PAN filter
│   ├── drift_metric_publisher/ # Decision stream -> drift metrics
│   ├── executor_agent/        # Decision routing + SOX enforcement
│   └── pan_filter/            # PAN ingress filter Lambda
├── governance_common/         # Shared helpers (PAN filter, payload limits, runtime checks)
├── cdk/
│   ├── app.py                 # CDK entry point
│   ├── data_stack.py          # DynamoDB, S3, SQS, SNS
│   ├── agents_stack.py        # Agent roles, Lambdas, guardrail, alarms
│   ├── audit_archive.py       # Object Lock archive + archiver
│   ├── deploy_agentcore_runtimes.py # AgentCore runtime deploy
│   └── cdk.json               # CDK CLI config
├── circuit_breaker/           # Governance hold: trip, two-person release, sweep
├── tests/                     # 100+ test modules, 3,000+ tests
├── demos/                     # 8 stage-ready demo scripts
├── cached_output/             # Pre-staged results for --local mode
├── data/                      # Synthetic transaction generator
├── scripts/                   # Utility scripts
├── docs/                      # Architecture (Mermaid), runbooks, regulatory mapping
├── compliance_gate.py         # CI/CD deploy blocker (219 assertions)
├── model_assurance.py         # D5.2 — approved-models registry validation
├── data/approved_models.json  # Org-approved model registry (version-pinned)
├── monitor_drift.py           # Drift monitoring
├── Makefile                   # All targets (demo, demo-live, deploy, ui, etc.)
├── requirements.txt           # Python dependencies
└── README.md
```

## Regulatory Mapping

| Regulation | Requirement | Implementation |
|-----------|-------------|----------------|
| PCI-DSS v4.0 §3.4 | Render PAN unreadable | PAN ingress filter (6 evasion variants) |
| BSA/AML | Suspicious activity reporting | SAR narrative generation via Bedrock |
| SR 11-7 | Model risk management | Independent challenger with different methodology; approved-models registry (D5.2 Model Assurance) |
| SOX §302/§404 | Internal controls, separation of duties | Append-only audit tables plus a write-once archive, IAM-enforced boundaries |
| FinCEN | SAR filing requirements | Drafts SAR narratives for human review, or escalates; nothing is filed |

## Security setup

### Console sign-in

`make ui` and `make ui-live` run the console with `CONSOLE_AUTH_MODE=local`
on `127.0.0.1` only (local mode refuses to render on any other address).
Each presenter gets their own sign-in:

```bash
make console-operator OPERATOR_ID=alice DISPLAY_NAME="Alice" ROLES=operator,auditor \
     AWS_PROFILES="operator=fsi-operator auditor=fsi-auditor"
```

- `ROLES` is any of `operator` (pipeline, PAN, injection, SOX, manual trip,
  release request, drift injection, gate), `approver` (approve a release,
  plus everything an operator can do) and `auditor` (SAR narratives on the
  audit page).
- `AWS_PROFILES` maps each purpose to the AWS profile the console uses for
  it. There is no ambient-credential fallback: a purpose without a profile
  shows "No AWS authority configured for this action".
- Hosting the console for other people (ALB + Cognito, `CONSOLE_AUTH_MODE=alb-cognito`)
  is an operational step: [docs/SECURITY_OPERATIONAL_STEPS.md](docs/SECURITY_OPERATIONAL_STEPS.md)
  step 1. No Makefile target binds anything but `127.0.0.1`.

### AWS profiles (MFA session + role profiles)

The console roles (`fsi-console-operator`, `fsi-breaker-approver`,
`fsi-compliance-reader`) trust IAM users of the account with MFA whose role
session name equals their IAM user name. Create an MFA session with
`make mfa-session CODE=<6-digit code>` (a 12 h session written to the MFA
source profile, by default the `source_profile` your `fsi-*` profiles already
name, `alice-mfa` below; override with `MFA_SERIAL`, `MFA_PROFILE`,
`MFA_SOURCE_PROFILE`), or by hand with
`aws sts get-session-token --serial-number … --token-code …`, write it to a
source profile, and point role profiles at it with `role_session_name`
(note the `/fsi-console/` and `/fsi-breaker/` path segments):

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

- Without `role_session_name`, the console shows "This AWS profile must set
  role_session_name to your IAM user name (see README)" and makes no AWS call.
- A console profile with `mfa_serial` is refused ("This AWS profile prompts
  for MFA; create an MFA session first (see README)"): the console can't
  prompt for a code.
- **Identity Center (SSO) profiles are not supported for any console
  purpose.** An SSO session can't satisfy the roles' session-name trust.
  SSO works only for the CLI breaker flow (`make release-request` /
  `make release-approve`), with both people on SSO.

### Governance hold release

Releasing a circuit-breaker hold takes two people: one requests, a
different person approves (same channel). See the
[governance-hold runbook](docs/RUNBOOK_GOVERNANCE_HOLD.md) for the in-band
steps, outcome codes and the out-of-band break-glass path.

To check every synthesized IAM policy with IAM Access Analyzer, run
`make validate-iam` (read-only; the profile needs
`access-analyzer:ValidatePolicy`; the report goes to
`build/iam-validation/report.json`).
### Operational steps

Some controls can't be set up in code (ALB/Cognito hosting, IAM user
assignments, SCPs, CloudTrail data events, KMS bootstrap). They are listed
as a checklist in
[docs/SECURITY_OPERATIONAL_STEPS.md](docs/SECURITY_OPERATIONAL_STEPS.md).

The review-only integrity alarms (hold changes, break-glass, uncorroborated
drift, archive DLQ/PAN/removed/conflict, publisher errors and others) notify
the `fsi-governance-alarms` topic. Subscribe on-call to it, or deploy with
`-c alarm_email=<address>` to create an email subscription (step 11 of the
operational steps); without a subscriber the alarms page no one.

## Demo behavior changes (security remediation)

What a presenter sees differently from earlier versions of this demo:

- **Sign-in.** `make ui` / `make ui-live` require `CONSOLE_AUTH_MODE=local`
  (set by the targets) and an operator created with `make console-operator`.
  There is no shared password.
- **Champion/Challenger page (live).** Each run records a fresh detection
  first, then runs the compliance agent on exactly that detection. Decisions
  are VERIFIED and can be `FILE_SAR` or `NEEDS_REVIEW` (a challenger dispute
  escalates). No `--allow-unverified-evaluation` deploy is needed.
- **Page 1.2 (live) is now "Poisoned transactions".** A red-team run plants
  injection payloads in transaction fields and sends them through the real
  pipeline: schema, detection, compliance (guardrail), strict output schema,
  decision by code. That is five stages. The executor is never called (no SAR
  filed, nothing escalated), and the guardrail may not block every call.
- **Console drift budget.** Live red-team runs count toward the drift alarms,
  so `app/drift_budget.py` keeps a local ledger: 90 s cooldown between
  red-team runs, and a red-team run is refused once the last ~65 minutes
  would reach 20 clusters. Pipeline and challenger live runs are refused
  (with a "Drift safety" message) only while red-team runs are in that window.
- **Challenger output that isn't strict JSON** shows `NEEDS_REVIEW` with an
  "output rejected" marker; it no longer counts as a dispute.
- **D4 (drift → breaker).** Live drift injection needs the stack deployed
  with CDK context `allow_console_drift_injection=true` **and** the console
  started with `CONSOLE_ALLOW_DRIFT_INJECTION=true`
  (`CONSOLE_ALLOW_DRIFT_INJECTION=true make ui-live`), in local console mode.
  This is the 4.1 Drift Control breach buttons, which publish metric
  datapoints; it is separate from page 1.2.
  The console no longer resets alarms: after a breach demo, **wait for the
  alarm to return to OK** (a few minutes) before re-running. In a deployed
  stack an injected breach has no stored VERIFIED decision behind it, so the
  breaker records it as `ALARM_UNCORROBORATED` and does **not** attach the
  hold; use Manual trip to demonstrate containment.
- **Release.** "Re-enable" (and `make re-enable`) is replaced by two-person
  release: request by one operator, approve by a different one. Local mode:
  sign out and sign in as the second operator. Live: `make release-approve
  REQUEST_ID=…` or the approver's own profile.
- **Lambda logs** are under `/fsi/lambda/<function-name>` (30-day
  retention), not `/aws/lambda/…`.
- **Local mode** (`mode=local` fixtures) is refused inside any deployed
  runtime, with no override. A `request_ref` that the PAN classifier flags is
  refused like a malformed one; the console regenerates its ids.
- **PAN page.** The page runs 13 evasion variants plus 7 safe inputs (the
  CLI `make demo-pan` runs 6 variants). Live results show BLOCKED/ALLOWED
  only; the firing rule appears only as a "local diagnostic" in local mode
  (in-process, no logs), and PAN-filter logs carry the rejected index and
  counts only.
- **Detection input.** Requests choose `dataset_id` (`sample-small`);
  `transaction_file` is refused.
- **Deploy.** `make deploy` runs `package → gate-sign → verify-gate-artifact`
  and refuses a local-dev-signed registry, a missing
  `data/approved_models.json.kms.sig`, an untracked file anywhere in the
  tree, and any packaged source that differs from HEAD.
- **Bedrock-backed local pages.** In `MODE=local`, pipeline step 3 and the
  local "Dispute Rate Breach" button call Bedrock in-process only with a
  deployed `fsi-console-operator` role and an operator AWS profile
  (`AWS_PROFILES="operator=…"`). Without them the pipeline shows cached
  compliance output (labelled "Bedrock not called") and still completes, and
  the dispute-breach button explains that it needs an operator profile. The
  cached demos (`make demo`, the challenger page, the default `make ui`
  walk-through) still need no AWS.
- **Local demo targets** set `ALLOW_LOCAL_DEV_SIGNING=true` themselves; export
  it when running the scripts directly with `python …`. D5
  (`make demo-model-swap`) still blocks on the unapproved model, not on the
  registry signature.
- **Audit page.** Live audit reads use the auditor profile and index queries
  (no table scans); SAR narratives are shown only to principals with the
  `auditor` role.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

### Important Security Considerations

- **This sample is not production-ready.** It demonstrates architectural patterns for governance of agentic AI systems in financial services.
- **IAM roles** — CDK creates every role (one per agent runtime and Lambda, plus the human roles) with least-privilege grants. In production also apply permission boundaries and the SCPs listed in [docs/SECURITY_OPERATIONAL_STEPS.md](docs/SECURITY_OPERATIONAL_STEPS.md), and review every policy for your account.
- **Encryption** — The SAR bucket and the audit archive use SSE-KMS with their own keys; the queues use KMS- or SQS-managed encryption; the DynamoDB tables use the default AWS owned key. The agent code bucket uses S3-managed keys. In production use customer managed KMS keys for the tables and queues. The buckets deny requests without TLS.
- **Network isolation** — Deploy Lambda functions in VPCs with no internet access where possible. Use VPC endpoints for DynamoDB, S3, SQS, and Bedrock.
- **Audit tables** — Point-in-Time Recovery and deletion protection are on for every table, and the tables are retained on stack deletion. The tables are append-only by IAM policy, not immutable; the write-once copy is the Object Lock archive.
- **PAN data** — While this sample demonstrates PAN detection at ingress, a production system should also implement tokenization, audit logging of access attempts, and integration with your PCI-DSS compliance tooling.
- **Bedrock Guardrails** — CDK creates the guardrail (content filters, denied phrases, PII and card-number filters) and a published version. Tune its policies for your data before production use.
- **No secrets in code** — This sample contains no credentials, keys, or secrets. All sensitive configuration is passed via environment variables.

## Testing

```bash
# Run full test suite
make test

# Run compliance gate (exits non-zero on failure)
make gate

# Run individual test files
python -m pytest tests/test_pan_ingress.py -v
python -m pytest tests/test_executor_sox.py -v
```

## Cleanup

If you deployed AWS resources:

```bash
make destroy
```

This removes the CDK-managed Lambda functions, queues, alarms and IAM roles. The audit tables and the SAR bucket are retained (RETAIN, deletion protection). The audit archive bucket and its KMS key are retained too: COMPLIANCE-mode objects cannot be deleted by anyone until retention expires, and `make destroy` never tries to empty the bucket. Storage for the archived objects is billed until they expire and you delete them.

The `--local` mode creates no AWS resources and requires no cleanup.

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md) for more information.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.
