"""
Shared governance helpers (stdlib + botocore only).

This package ships at the root of every AgentCore deployment zip
(cdk/deploy_agentcore_runtimes.py, AGENTS[...]["packages"]) and is importable
from the repo root for local runs and tests. Modules:

- signing             governance signature envelopes (KMS ECDSA or local-dev HMAC)
- payload_limits      structure/concurrency limits for the /invocations shims
- bundle_digest       deterministic digest of an agent deployment zip
- runtime_attestation gate-artifact self-check state machine for the shims
- head_binding        packaged sources == HEAD blobs (gate --sign, deploy verify)
- aws_profile_check   offline shape check of a named AWS CLI profile
- deployed_runtime    deployed-runtime detection (local mode refused there)
- pan_filter          byte-identical copy of lambdas/pan_filter/pan_filter.py
                      (payload_limits.request_ref_ok uses contains_full_pan)
"""
