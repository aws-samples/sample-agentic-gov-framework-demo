#!/usr/bin/env python3
"""
CDK Application entry point.

Deploys the FSI Agentic Compliance infrastructure:
- Data layer (DynamoDB, S3, SQS)
- Agent Lambda functions
- Bedrock Guardrail configuration
"""
import aws_cdk as cdk

from agents_stack import AgentsStack
from data_stack import DataStack

app = cdk.App()

# ═════════════════════════════════════════════════════════════════════════════
# BLUEPRINT 5 — DEPLOYMENT CONTROL (ordered, dependency-safe provisioning)
# ═════════════════════════════════════════════════════════════════════════════
# Infrastructure is deployed as a dependency chain: the data layer (audit
# stores, SAR bucket, queue) is provisioned first, then the agents stack
# consumes those resources to scope each agent's least-privilege IAM role to
# the exact tables/buckets it may touch. Passing `data_stack=data` makes CDK
# enforce the ordering, so the access-control boundaries are wired correctly
# at deploy time rather than assumed at runtime.
# ═════════════════════════════════════════════════════════════════════════════

# Data layer — DynamoDB tables, S3 bucket, SQS queue
data = DataStack(app, "FsiComplianceData")

# Agent functions — three Lambda handlers
AgentsStack(app, "FsiComplianceAgents", data_stack=data)

app.synth()
