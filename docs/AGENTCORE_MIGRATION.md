# AgentCore Runtime Migration — Full 3-Agent Deployment

## Overview

This document describes the migration of the FSI Agentic Compliance agents from AWS Lambda to Amazon Bedrock AgentCore Runtime. All three agents (Detection, Compliance, Executor) are now scaffolded for AgentCore deployment.

**Key principle:** The governance envelope (circuit breaker, compliance gate, NHI roles, SOX enforcement) and core agent logic remain unchanged. Only the compute hosting layer changes from Lambda to AgentCore Runtime.

**What stays on Lambda:**
- PAN Ingress Filter (lightweight, event-driven, no session needed)
- Circuit Breaker (CloudWatch alarm-triggered, IAM deny-policy operations)

## What Changed

| Component | Before (Lambda) | After (AgentCore) |
|-----------|----------------|-------------------|
| Entry point | `handler(event, context)` | HTTP server on `0.0.0.0:8080` |
| Invocation | Lambda invoke / API Gateway | `POST /invocations` |
| Health check | N/A | `GET /ping` |
| Compute | Stateless Lambda (15 min max) | Stateful microVM session (8 hr max) |
| Deployment | CDK → Lambda + layers | CDK (IAM/infra) + `deploy_agentcore_runtimes.py` |
| Config | CDK stack definitions | `agentcore/agentcore.json` + CDK |

## Project Structure

```
fsi-agentic-compliance/
├── agentcore/
│   ├── agentcore.json                  # AgentCore runtime config (all 3 agents)
│   ├── compliance_agent/
│   │   └── main.py                     # HTTP server → handler.py
│   ├── detection_agent/
│   │   └── main.py                     # HTTP server → handler.py
│   └── executor_agent/
│       └── main.py                     # HTTP server → handler.py
├── lambdas/                            # Core logic (UNCHANGED)
│   ├── compliance_agent/
│   │   ├── handler.py                  # SAR generation + challenger
│   │   └── sar_prompts.py             # Prompt templates
│   ├── detection_agent/
│   │   ├── handler.py                  # Graph detection orchestrator
│   │   ├── fraud_detection.py          # cuGraph/NetworkX detection
│   │   └── pan_filter.py              # PCI-DSS PAN filter
│   ├── executor_agent/
│   │   └── handler.py                  # Decision routing + SOX enforcement
│   └── pan_filter/                     # Standalone Lambda (retained)
├── circuit_breaker/                    # Standalone Lambda (retained)
├── cdk/
│   ├── app.py                          # CDK entry point
│   ├── data_stack.py                   # DynamoDB, S3, SQS (unchanged)
│   ├── agents_stack.py                 # IAM roles + AgentCore infra
│   └── deploy_agentcore_runtimes.py    # Post-CDK script: creates runtimes via boto3
└── docs/
    └── AGENTCORE_MIGRATION.md          # This file
```

## Running Locally

### Prerequisites

```bash
# Install Python dependencies (exact pins, hash-locked; the shims use stdlib http.server)
pip install --require-hashes -r requirements.lock

# AgentCore CLI (optional, for `agentcore invoke`; pinned, needs Node.js 20.12+)
npm install -g @aws/agentcore@1.0.3
```

### Start any agent locally

```bash
# Detection Agent (port 8080)
python agentcore/detection_agent/main.py

# Compliance Agent (port 8080)
python agentcore/compliance_agent/main.py

# Executor Agent (port 8080)
python agentcore/executor_agent/main.py
```

### Test health check

```bash
curl http://localhost:8080/ping
# Expected: {"status": "Healthy"}
```

### Test Detection Agent (cached mode)

```bash
curl -X POST http://localhost:8080/invocations \
  -H "Content-Type: application/json" \
  -d '{"mode": "local"}'
```

### Test Compliance Agent (cached mode)

```bash
curl -X POST http://localhost:8080/invocations \
  -H "Content-Type: application/json" \
  -d '{"mode": "local"}'
```

### Test Executor Agent (cached mode)

```bash
curl -X POST http://localhost:8080/invocations \
  -H "Content-Type: application/json" \
  -d '{"mode": "local"}'
```

### Test Executor Agent — SOX violation (should return 403)

```bash
curl -X POST http://localhost:8080/invocations \
  -H "Content-Type: application/json" \
  -d '{"mode": "local", "compliance_output": {}, "override_decision": true}'
# Expected: 403 with SOX_VIOLATION error
```

### Test Compliance Agent with live Bedrock

```bash
export AWS_REGION=us-east-1
export BEDROCK_MODEL_ID=us.anthropic.claude-sonnet-4-5-20250929-v1:0
export GUARDRAIL_ID=your-guardrail-id
export GUARDRAIL_VERSION=1

curl -X POST http://localhost:8080/invocations \
  -H "Content-Type: application/json" \
  -d '{
    "mode": "live",
    "detection_output": {
      "detection_id": "test-123",
      "flagged_clusters": [{
        "cluster_id": "cluster-001",
        "accounts": ["A001", "A002", "A003"],
        "account_count": 3,
        "typology": "circular_structuring",
        "total_amount_usd": 145000.00,
        "time_span_seconds": 87,
        "merchant_categories": ["wire_transfer", "crypto_exchange"],
        "confidence_factors": {
          "avg_intra_amount": 48333.33,
          "circular_ratio": 0.67,
          "fan_out_max": 3,
          "fan_in_max": 2
        }
      }]
    }
  }'
```

## Deploying to AWS

### Step 1: Deploy infrastructure (CDK)

```bash
cd cdk
cdk deploy --all
```

This creates:
- IAM roles (trust `bedrock-agentcore.amazonaws.com`)
- S3 code bucket for deployment packages
- DynamoDB tables, SQS queue, SAR S3 bucket
- Bedrock Guardrail
- PAN Filter Lambda + Circuit Breaker Lambda
- CloudWatch drift alarms

### Step 2: Deploy agents to AgentCore Runtime

```bash
python cdk/deploy_agentcore_runtimes.py
```

This script:
1. Packages each agent (main.py + handler + modules) into a zip
2. Uploads to the S3 code bucket
3. Creates/updates AgentCore Runtimes via `bedrock-agentcore-control` API

### Alternative: AgentCore CLI

```bash
cd agentcore
agentcore deploy
```

### Step 3: Invoke deployed agents

```bash
# Via AgentCore CLI
agentcore invoke --name ComplianceAgent '{"mode": "live", "detection_output": {...}}'

# Via boto3
python -c "
import boto3, json
client = boto3.client('bedrock-agentcore', region_name='us-east-1')
response = client.invoke_agent_runtime(
    agentRuntimeArn='arn:aws:bedrock-agentcore:us-east-1:ACCOUNT:runtime/ComplianceAgent',
    payload=json.dumps({'mode': 'live', 'detection_output': {...}}).encode()
)
print(json.loads(response['body'].read()))
"
```

## IAM Roles — NHI Governance

All three agent roles trust `bedrock-agentcore.amazonaws.com`:

| Agent | Role | CAN | CANNOT |
|-------|------|-----|--------|
| Detection | `detection-agent-role` | Write detection results (DynamoDB), read code (S3) | Invoke Bedrock, write SAR |
| Compliance | `compliance-agent-role` | Invoke Bedrock + Guardrail, read detection results, write compliance decisions, publish CloudWatch metrics | Write SAR, modify detection results |
| Executor | `executor-agent-role` | Write SAR (S3), send to analyst queue (SQS), write audit trail | Invoke Bedrock, read raw transactions |

**Circuit breaker behavior is unchanged:** When triggered, the deny-all policy (`governance-hold-deny-all`) is attached to all three agent roles, which immediately blocks AgentCore from executing any actions on behalf of those roles.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                    GOVERNANCE ENVELOPE                               │
│                                                                     │
│  ┌─────────────┐    ┌──────────────────┐    ┌─────────────────┐   │
│  │  DETECTION   │    │   COMPLIANCE     │    │    EXECUTOR     │   │
│  │   AGENT      │───▶│    REASONER      │───▶│     AGENT       │   │
│  │             │    │                  │    │                 │   │
│  │ AgentCore   │    │ AgentCore        │    │ AgentCore       │   │
│  │ Runtime     │    │ Runtime          │    │ Runtime         │   │
│  │ (HTTP/8080) │    │ (HTTP/8080)      │    │ (HTTP/8080)     │   │
│  └─────────────┘    └──────────────────┘    └─────────────────┘   │
│        │                     │                       │             │
│        ▼                     ▼                       ▼             │
│  ┌───────────────────────────────────────────────────────────┐     │
│  │              DynamoDB AUDIT TRAIL (PITR, no-delete)        │     │
│  └───────────────────────────────────────────────────────────┘     │
│                                                                     │
│  ┌─────────────────┐    ┌──────────────────────────────────┐      │
│  │ CIRCUIT BREAKER  │    │       COMPLIANCE GATE             │      │
│  │  (Lambda, alarm  │    │   (CI/CD deploy blocker)          │      │
│  │   triggered)     │    │                                   │      │
│  └─────────────────┘    └──────────────────────────────────┘      │
│                                                                     │
│  ┌─────────────────┐                                               │
│  │   PAN FILTER     │  (Lambda — ingress boundary, zero trust)     │
│  └─────────────────┘                                               │
└─────────────────────────────────────────────────────────────────────┘
```

## Detection Agent — Deployment Considerations

The Detection Agent has two deployment paths depending on GPU needs:

| Mode | Deployment | Package Size | Notes |
|------|-----------|--------------|-------|
| CPU (NetworkX) | Direct code deploy (zip) | ~50 MB | pandas + networkx + numpy |
| GPU (cuGraph) | Container deploy (ECR) | ~1.5 GB | Requires ARM64 RAPIDS image |

For a demo, CPU mode is sufficient and much simpler to deploy.

## Cleanup

```bash
# Remove AgentCore runtimes
agentcore remove all
agentcore deploy  # Tears down CFN resources

# Remove CDK stacks
cd cdk && cdk destroy --all
```

## Backward Compatibility

The `lambdas/` directory and all `make demo` / `make demo-live` targets continue to work unchanged. The AgentCore deployment is additive — both paths can coexist during the transition period.

## Future Enhancements

1. **AgentCore Gateway** — Expose all three agents as MCP tools behind a single Gateway endpoint, enabling a supervisor agent to orchestrate the Detection → Compliance → Executor pipeline.

2. **AgentCore Memory** — Add session memory to the Compliance Agent for multi-cluster assessment context across invocations.

3. **AgentCore Policy Engine** — Use Cedar policies to enforce NHI boundaries declaratively (replace IAM deny policies with Cedar-based access control).

4. **AgentCore Observability** — Built-in tracing and metrics without custom CloudWatch instrumentation.
