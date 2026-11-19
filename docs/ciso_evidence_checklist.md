# CISO Evidence Checklist

## Demonstrable Controls for Executive / Auditor Review

Everything below can be produced from a clone with no AWS account (`make setup`,
the local demos, `make test`, `make gate`) unless it is marked *deployed stack*.
Steps that code can't do are listed under "Before production" at the end.

### Layer 1: Data Boundary (PCI-DSS)
- [ ] PAN ingress filter blocks every evasion variant: 6 in `make demo-pan`; 13 evasion variants plus 7 safe inputs on console page 1.1 (`make ui`)
- [ ] No cardholder data enters GPU graph processing (detection filters every batch before building the graph)
- [ ] PAN-shaped `request_ref` values are refused, and local mode is refused in a deployed runtime
- [ ] Guardrail `fsi-compliance-guardrail` blocks card numbers and SSNs in model input and output, plus prompt-attack and injection phrases
- [ ] Demo: `make demo-pan`

### Layer 2: Model Governance (SR 11-7)
- [ ] SAR generation captures model_id + latency + guardrail_action
- [ ] Challenger uses genuinely different methodology (prompt fingerprint verified) and a different model family
- [ ] Guardrail attached to ALL Bedrock calls (an unguarded call is refused)
- [ ] Divergence → automatic escalation to NEEDS_REVIEW (never auto-approve when uncertain)
- [ ] Approved-models registry maintained (version-pinned, approver + expiry, `registry_version`) — `data/approved_models.json`
- [ ] D5.2 Model Assurance: configured model validated against registry at deploy time and again before every Bedrock call
- [ ] D5.2 Model Assurance: every model_id observed in the audit trail is an approved model
- [ ] Unapproved or expired model blocks the deploy (exact version-pinned match)
- [ ] *Deployed stack:* the deploy needs a KMS-signed registry (`data/approved_models.json.kms.sig`) and refuses one older than `/fsi/governance/accepted-registry`
- [ ] Demo: `make demo-challenge`; `make demo-model-assurance`; `BEDROCK_MODEL_ID=<unlisted> make gate` (blocks)

### Layer 3: Separation of Duties (SOX)
- [ ] Three distinct IAM roles (`detection-agent-role`, `compliance-agent-role`, `executor-agent-role`; the gate resolves the deployed ARNs: *deployed stack*)
- [ ] Detection cannot invoke Bedrock
- [ ] Compliance cannot file SARs
- [ ] Executor cannot modify decisions (UpdateItem limited to its lease attributes; audit writes are PutItem only)
- [ ] Override attempts rejected and logged (`SOX_VIOLATION_REJECTED` in `executor-audit`)
- [ ] Human roles require MFA; each console operator signs in individually and actions land in `operator-audit`
- [ ] Analyst queue `fsi-analyst-review` accepts messages from `executor-agent-role` only
- [ ] Demo: `make demo-sar`

### Layer 4: Automated Enforcement
- [ ] Compliance gate blocks deploy on ANY assertion failure; `make deploy` runs only with a KMS-signed gate artifact over bundles built at HEAD (*deployed stack*)
- [ ] 219 assertions across 6 domains (Boundary, Model Governance, Audit, Access Control, Model Assurance, Supply chain); without AWS credentials the 3 deployed-state assertions fail closed
- [ ] Circuit breaker fires automatically on drift threshold breach, after corroborating the alarm against stored decisions (an uncorroborated alarm alerts instead of holding)
- [ ] Circuit breaker is asymmetric: auto-trigger, two-person release (`make release-request`, then `make release-approve` by a different, STS-verified person); break-glass per [runbook](RUNBOOK_GOVERNANCE_HOLD.md)
- [ ] Hash-locked dependencies (`make setup`); IAM policies checked by Access Analyzer (`make validate-iam`, needs AWS credentials)
- [ ] Demo: `make demo-gate-fail`, `make demo-circuit-breaker`

### Layer 5: Audit Trail
- [ ] Every decision is recorded with full provenance chain
- [ ] Five DynamoDB audit tables with PITR, deletion protection and RETAIN
- [ ] Immutable S3 archive (`AuditArchiveBucketName` output): Object Lock COMPLIANCE; the archiver re-reads each record from its table, refuses forged or missing ones and stores a SHA-256 digest; archive alarms notify `fsi-governance-alarms`
- [ ] Retention is a 90-day demo value (`audit_archive_retention_days` in `cdk/cdk.json`), not the 7-year SOX period: set it per regulation before production
- [ ] Detection → Compliance → Executor chain is verifiable

### Before production (see [SECURITY_OPERATIONAL_STEPS.md](SECURITY_OPERATIONAL_STEPS.md))
- [ ] Archive retention per the applicable regulation (step 10)
- [ ] SCPs or permission boundaries (steps 3, 5, 6, 10) and CloudTrail data events (step 4)
- [ ] Named IAM users with MFA, a second person as release approver, a Model Risk approver who signs the registry (steps 2, 3)
- [ ] CI as gate signer (optional), hosted console behind ALB + Cognito, on-call subscribed to `fsi-governance-alarms` (steps 1, 3, 11)

### Full Demo Sequence
```bash
make demo   # Runs all 8 local demos in sequence (no AWS needed)
make gate   # Runs compliance gate (219 assertions across 6 domains)
make test   # Runs full test suite
```
