# Non-Human Identity (NHI) Governance

## Overview

This architecture enforces strict identity separation between three autonomous agents.
Each agent operates with its own IAM role (Non-Human Identity) with least-privilege permissions.

## Identity Assignments

### NHI #1: detection-agent-role
- **Purpose:** GPU-accelerated fraud ring detection
- **Permissions:**
  - READ: S3 transaction source, Kinesis stream
  - WRITE: `detection-results` DynamoDB table
- **Denied:**
  - bedrock:InvokeModel (cannot call LLMs)
  - s3:PutObject on SAR filing bucket
  - dynamodb:PutItem on compliance-decisions table

### NHI #2: compliance-agent-role
- **Purpose:** SAR generation, independent challenger assessment
- **Permissions:**
  - READ: `detection-results` DynamoDB table
  - WRITE: `compliance-decisions` DynamoDB table
  - INVOKE: Bedrock Converse (with guardrail attached)
- **Denied:**
  - s3:PutObject on SAR filing bucket
  - dynamodb:UpdateItem/DeleteItem on detection-results
  - iam:PassRole / iam:AttachRolePolicy

### NHI #3: executor-agent-role
- **Purpose:** Route decisions to filing or analyst queue
- **Permissions:**
  - READ: `compliance-decisions` DynamoDB table
  - WRITE: SAR filing S3 bucket, analyst SQS queue, audit table
- **Denied:**
  - bedrock:InvokeModel (cannot call LLMs)
  - s3:GetObject on transaction source
  - dynamodb:PutItem/UpdateItem on detection or compliance tables

## Circuit Breaker Override

When the circuit breaker fires, an explicit DENY policy is attached to ALL three roles,
immediately revoking all permissions. This is an additive deny — cannot be overridden
by any allow statement.

## Compliance Gate Assertions

The gate validates:
1. Three distinct roles exist (not shared)
2. Each role's actual permissions match its CAN/CANNOT spec
3. No role has `iam:PassRole` to another agent's role
4. Circuit breaker has permission to attach/detach policies on all three roles
