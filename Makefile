# FSI-Agentic-Compliance v2 — Hybrid Build (cuGraph + Governance Envelope)

.PHONY: help setup test gate validate-iam package gate-sign verify-gate-artifact record-accepted verify-doc-links demo-model-swap model-swap-restore demo demo-live demo-detect demo-pan demo-sar demo-challenge demo-gate-fail demo-model-assurance demo-circuit-breaker demo-drift demo-detect-live demo-pan-live demo-sar-live demo-challenge-live demo-circuit-breaker-live demo-drift-live generate-data deploy release-request release-approve destroy synth ui ui-live console-operator mfa-session dev-detection dev-compliance dev-executor

VENV_DIR := .venv
PYTHON := $(VENV_DIR)/bin/python
PIP := $(VENV_DIR)/bin/pip

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ─── Setup ────────────────────────────────────────────────────────────────────

$(VENV_DIR)/bin/activate:
	python3 -m venv $(VENV_DIR)

setup: $(VENV_DIR)/bin/activate ## Install hash-locked dependencies (no GPU required for --local mode)
	$(PIP) install --quiet --require-hashes -r requirements.lock
	$(PIP) install --quiet --require-hashes -r requirements-dev.lock
	$(PIP) install --quiet --require-hashes -r requirements-cdk.lock
	@echo "Setup complete (hash-locked). GPU deps (cudf, cugraph) are optional; see README \"GPU mode (optional)\"."

# ─── Testing ──────────────────────────────────────────────────────────────────

test: ## Run full test suite
	$(PYTHON) -m pytest tests/ -q

gate: ## Run compliance gate (CI/CD deploy blocker)
	ALLOW_LOCAL_DEV_SIGNING=true $(PYTHON) compliance_gate.py

validate-iam: ## Synthesize all context variants and validate every IAM policy with Access Analyzer (read-only; AWS_PROFILE needs access-analyzer:ValidatePolicy)
	$(PYTHON) scripts/validate_iam_policies.py --report build/iam-validation/report.json
verify-doc-links: ## Verify jump-to-code links in docs still resolve (run before a demo)
	$(PYTHON) scripts/verify_doc_links.py

# ─── Demo: All ────────────────────────────────────────────────────────────────

demo: demo-detect demo-pan demo-sar demo-challenge demo-gate-fail demo-model-assurance demo-circuit-breaker demo-drift ## Run ALL demos locally (cached, no AWS needed)

demo-live: demo-detect-live demo-pan-live demo-sar-live demo-challenge-live demo-circuit-breaker-live demo-drift-live ## Run ALL demos against live AWS (requires Bedrock + deployed infra)

# ─── Demo: Local (default — cached outputs, no AWS/GPU required) ──────────────

demo-detect: ## Detection agent — local (cached output)
	ALLOW_LOCAL_DEV_SIGNING=true $(PYTHON) demos/demo_detect.py --local

demo-pan: ## PAN rejection at ingress (6 evasion variants)
	ALLOW_LOCAL_DEV_SIGNING=true ALLOW_LOCAL_DEV_TXN_REF_KEY=true $(PYTHON) demos/demo_pan_rejection.py --evasion

demo-sar: ## SAR narrative generation — local (cached)
	ALLOW_LOCAL_DEV_SIGNING=true $(PYTHON) demos/demo_sar.py --local

demo-challenge: ## Challenger divergence — local (cached)
	ALLOW_LOCAL_DEV_SIGNING=true $(PYTHON) demos/demo_challenge.py --local

demo-gate-fail: ## Compliance gate blocks weakened deploy (simulated guardrail config)
	ALLOW_LOCAL_DEV_SIGNING=true $(PYTHON) demos/demo_gate_fail.py

demo-model-swap: ## D5 finish — swap in an unapproved model, real gate BLOCKS (leaves handler edited)
	ALLOW_LOCAL_DEV_SIGNING=true $(PYTHON) demos/demo_model_swap.py --break

model-swap-restore: ## Restore handler.py after demo-model-swap (run off-stage)
	ALLOW_LOCAL_DEV_SIGNING=true $(PYTHON) demos/demo_model_swap.py --restore

demo-model-assurance: ## Model assurance (D5.2) — approved vs unapproved models
	ALLOW_LOCAL_DEV_SIGNING=true $(PYTHON) demos/demo_model_assurance.py --local

demo-circuit-breaker: ## Circuit breaker — local (simulated)
	ALLOW_LOCAL_DEV_SIGNING=true $(PYTHON) demos/demo_circuit_breaker.py --local

demo-drift: ## Drift monitoring — local (cached metrics)
	ALLOW_LOCAL_DEV_SIGNING=true $(PYTHON) demos/demo_drift.py --local

# ─── Demo: Live AWS (requires deployed infra + Bedrock access) ────────────────

demo-detect-live: ## Detection agent — live (CPU mode, writes to DynamoDB)
	ALLOW_LOCAL_DEV_SIGNING=true $(PYTHON) demos/demo_detect.py --no-local --mode cpu

demo-pan-live: ## PAN rejection — live (invokes deployed Lambda)
	ALLOW_LOCAL_DEV_SIGNING=true ALLOW_LOCAL_DEV_TXN_REF_KEY=true $(PYTHON) demos/demo_pan_rejection_live.py

demo-sar-live: ## SAR generation — live (calls Bedrock, writes audit)
	ALLOW_LOCAL_DEV_SIGNING=true $(PYTHON) demos/demo_sar.py --no-local

demo-challenge-live: ## Challenger — live (calls Bedrock)
	ALLOW_LOCAL_DEV_SIGNING=true $(PYTHON) demos/demo_challenge.py --no-local

demo-circuit-breaker-live: ## Circuit breaker — live (invokes actual circuit breaker)
	ALLOW_LOCAL_DEV_SIGNING=true $(PYTHON) demos/demo_circuit_breaker.py

demo-drift-live: ## Drift monitoring — live (reads from DynamoDB)
	ALLOW_LOCAL_DEV_SIGNING=true $(PYTHON) demos/demo_drift.py

# ─── Deploy ────────────────────────────────────────────────────────────────────

# Governed deploy chain: build the bundles once, have the gate
# signer role sign a gate artifact over exactly those bytes (clean tree, every
# packaged source at HEAD, KMS-signed registry), verify it with the
# deployer's own profile, then deploy the prebuilt bundles. None of these
# targets set ALLOW_LOCAL_DEV_SIGNING: they refuse local-dev signatures.
package: $(VENV_DIR)/bin/activate ## Build build/agentcore/<Agent>.zip (no AWS calls; needs data/approved_models.json.kms.sig)
	$(PIP) install --quiet --require-hashes -r requirements-cdk.lock
	$(PYTHON) cdk/deploy_agentcore_runtimes.py --package-only

gate-sign: ## Run the gate as fsi-deploy-gate-signer and sign build/gate/gate-artifact.json (GATE_SIGNER_PROFILE=<profile>)
	$(if $(GATE_SIGNER_PROFILE),,$(error GATE_SIGNER_PROFILE must name an AWS profile for fsi-deploy-gate-signer))
	AWS_PROFILE=$(GATE_SIGNER_PROFILE) $(PYTHON) compliance_gate.py --sign --bundles-dir build/agentcore

verify-gate-artifact: ## Verify the signed gate artifact against the bundles (deployer's own AWS_PROFILE)
	$(PYTHON) scripts/verify_gate_artifact.py

deploy: package gate-sign verify-gate-artifact ## Deploy infra (CDK) + agents (AgentCore Runtime) — only with a verified, KMS-signed gate artifact
	$(PIP) install --quiet --require-hashes -r requirements-cdk.lock
	@echo "Synthesizing CDK stacks..."
	cd cdk && cdk synth
	@echo "Deploying infrastructure to AWS (IAM roles, DynamoDB, S3, alarms)..."
	cd cdk && cdk deploy --all --require-approval broadening
	@echo ""
	@echo "Checking for governance hold (circuit breaker)..."
	@echo "NOTE: a hold is NOT released automatically. If one is active, deploy"
	@echo "stops here. Release takes two people: 'make release-request' (operator),"
	@echo "then 'make release-approve REQUEST_ID=...' (a different approver)."
	$(PYTHON) scripts/ensure_agents_enabled.py
	@echo ""
	@echo "Deploying agents to AgentCore Runtime..."
	$(PYTHON) cdk/deploy_agentcore_runtimes.py
	@echo ""
	@echo "Recording the accepted registry floor (/fsi/governance/accepted-registry)..."
	$(PYTHON) scripts/verify_gate_artifact.py --record-accepted
	@echo ""
	@echo "Deploy complete. Use 'agentcore invoke' or 'make demo-live' to test."

record-accepted: ## After a deploy: raise /fsi/governance/accepted-registry to the deployed registry (never lowers it)
	$(PYTHON) scripts/verify_gate_artifact.py --record-accepted

release-request: $(VENV_DIR)/bin/activate ## Two-person release, step 1: request a release of the active hold (your own AWS_PROFILE)
	$(PYTHON) scripts/ensure_agents_enabled.py --request-release

release-approve: $(VENV_DIR)/bin/activate ## Two-person release, step 2: a DIFFERENT person approves REQUEST_ID=... (own AWS_PROFILE)
	@test -n "$(REQUEST_ID)" || { echo "usage: make release-approve REQUEST_ID=<id printed by make release-request>"; exit 2; }
	$(PYTHON) scripts/ensure_agents_enabled.py --approve-release "$(REQUEST_ID)"

destroy: ## Destroy AgentCore runtimes + CDK stacks (CAUTION: deletes resources)
	@echo "⚠️  This will DELETE all deployed AWS resources (AgentCore + CDK)."
	@echo "    The regulatory audit tables and SAR bucket are RETAIN +"
	@echo "    deletion_protection=True — this command will NOT remove them."
	@echo "    Removing the audit trail itself requires a deliberate,"
	@echo "    separate out-of-band action."
	@echo "    The audit archive bucket and its KMS key are retained; COMPLIANCE-mode"
	@echo "    objects cannot be deleted by anyone until retention expires."
	@read -p "Are you sure? (y/N) " confirm && [ "$$confirm" = "y" ] || exit 1
	@echo "Removing AgentCore Runtimes (aborts if a governance hold is active)..."
	$(PYTHON) cdk/destroy_agentcore_runtimes.py
	@echo "Destroying CDK stacks..."
	cd cdk && cdk destroy --all --force
	@echo "Destroy complete."

synth: $(VENV_DIR)/bin/activate ## Synthesize CDK (validate without deploying)
	$(PIP) install --quiet --require-hashes -r requirements-cdk.lock
	cd cdk && cdk synth

# ─── AgentCore Local Dev ──────────────────────────────────────────────────────

dev-detection: $(VENV_DIR)/bin/activate ## Run Detection Agent locally (port 8080)
	ALLOW_LOCAL_DEV_SIGNING=true $(PYTHON) agentcore/detection_agent/main.py

dev-compliance: $(VENV_DIR)/bin/activate ## Run Compliance Agent locally (port 8080)
	ALLOW_LOCAL_DEV_SIGNING=true $(PYTHON) agentcore/compliance_agent/main.py

dev-executor: $(VENV_DIR)/bin/activate ## Run Executor Agent locally (port 8080)
	ALLOW_LOCAL_DEV_SIGNING=true $(PYTHON) agentcore/executor_agent/main.py

# ─── Streamlit Dashboard ──────────────────────────────────────────────────────

# Console sign-in: both targets run CONSOLE_AUTH_MODE=local —
# per-operator scrypt credentials from ~/.fsi-console/operators.json (create
# them with `make console-operator`) — and bind 127.0.0.1 ONLY. Local mode
# refuses to render on any non-loopback server.address. No target here ever
# binds beyond loopback or runs another console auth mode; hosting behind an
# ALB with Cognito is an operational step (docs, not this Makefile).
# Local uses 8501, live uses 8502 by default so both can run at once.
# Override with: make ui PORT=8600
UI_PORT ?= 8501
UI_LIVE_PORT ?= 8502

# The dashboard runs the compliance agent in-process for pipeline runs, and
# that agent fails closed (GuardrailNotConfiguredError) without a guardrail
# and approved model ids. Model ids default to the same approved values
# cdk/deploy_agentcore_runtimes.py deploys (data/approved_models.json);
# override via env or `make ui BEDROCK_MODEL_ID=...`.
BEDROCK_MODEL_ID ?= us.anthropic.claude-sonnet-4-5-20250929-v1:0
CHALLENGER_MODEL_ID ?= us.amazon.nova-pro-v1:0
# Fixed: the stack the guardrail outputs are read from is not overridable
# (neither from the environment nor the command line).
override GUARDRAIL_STACK := FsiComplianceAgents

# GUARDRAIL_ID / GUARDRAIL_VERSION: use the env/command-line value if set,
# otherwise read the stack's own GuardrailId / GuardrailVersion outputs
# (read-only describe-stacks). There is deliberately no hardcoded fallback:
# if the lookup fails they stay empty and the compliance agent fails closed.
define UI_GUARDRAIL_ENV
GID="$(GUARDRAIL_ID)"; GVER="$(GUARDRAIL_VERSION)"; \
REGION="$${AWS_REGION:-us-east-1}"; \
if [ -z "$$GID" ]; then GID=$$(aws cloudformation describe-stacks --stack-name $(GUARDRAIL_STACK) --region "$$REGION" --query "Stacks[0].Outputs[?OutputKey=='GuardrailId'].OutputValue" --output text 2>/dev/null); fi; \
if [ -z "$$GVER" ]; then GVER=$$(aws cloudformation describe-stacks --stack-name $(GUARDRAIL_STACK) --region "$$REGION" --query "Stacks[0].Outputs[?OutputKey=='GuardrailVersion'].OutputValue" --output text 2>/dev/null); fi; \
[ "$$GID" = "None" ] && GID=""; [ "$$GVER" = "None" ] && GVER=""; \
if [ -z "$$GID" ] || [ -z "$$GVER" ]; then \
  echo "WARNING: could not resolve GuardrailId/GuardrailVersion from the $(GUARDRAIL_STACK) stack ($$REGION)."; \
  echo "         Check your AWS credentials or set GUARDRAIL_ID and GUARDRAIL_VERSION."; \
  echo "         The dashboard will start, but the compliance agent will refuse to run (fails closed)."; \
else echo "Guardrail: $$GID (version $$GVER) | models: $(BEDROCK_MODEL_ID) / $(CHALLENGER_MODEL_ID)"; fi
endef

ui: $(VENV_DIR)/bin/activate ## Launch Streamlit dashboard (local cached data, port 8501, loopback only)
	$(PIP) install --quiet --require-hashes -r requirements.lock
	@$(UI_GUARDRAIL_ENV); \
	MODE=local CONSOLE_AUTH_MODE=local GUARDRAIL_ID="$$GID" GUARDRAIL_VERSION="$$GVER" \
	BEDROCK_MODEL_ID="$(BEDROCK_MODEL_ID)" CHALLENGER_MODEL_ID="$(CHALLENGER_MODEL_ID)" \
	ALLOW_LOCAL_DEV_SIGNING=true $(PYTHON) -m streamlit run app/dashboard.py --server.address 127.0.0.1 --server.port $(if $(PORT),$(PORT),$(UI_PORT))

ui-live: $(VENV_DIR)/bin/activate ## Launch Streamlit dashboard (live AWS data, port 8502, loopback only)
	$(PIP) install --quiet --require-hashes -r requirements.lock
	@$(UI_GUARDRAIL_ENV); \
	MODE=live CONSOLE_AUTH_MODE=local GUARDRAIL_ID="$$GID" GUARDRAIL_VERSION="$$GVER" \
	BEDROCK_MODEL_ID="$(BEDROCK_MODEL_ID)" CHALLENGER_MODEL_ID="$(CHALLENGER_MODEL_ID)" \
	ALLOW_LOCAL_DEV_SIGNING=true $(PYTHON) -m streamlit run app/dashboard.py --server.address 127.0.0.1 --server.port $(if $(PORT),$(PORT),$(UI_LIVE_PORT))

# Create or update a local console operator (password via getpass; written to
# ~/.fsi-console/operators.json, mode 0600, outside the repo). Example:
#   make console-operator OPERATOR_ID=alice DISPLAY_NAME="Alice" ROLES=operator,auditor \
#        AWS_PROFILES="operator=fsi-operator auditor=fsi-auditor"
console-operator: $(VENV_DIR)/bin/activate ## Create/update a console operator (OPERATOR_ID= DISPLAY_NAME= ROLES= [AWS_PROFILES=])
	@test -n "$(OPERATOR_ID)" && test -n "$(ROLES)" || { echo "usage: make console-operator OPERATOR_ID=<id> DISPLAY_NAME=<name> ROLES=<operator,approver,auditor> [AWS_PROFILES=\"operator=<profile> ...\"]"; exit 2; }
	$(PYTHON) scripts/console_add_operator.py --operator-id "$(OPERATOR_ID)" --display-name "$(if $(DISPLAY_NAME),$(DISPLAY_NAME),$(OPERATOR_ID))" --roles "$(ROLES)" $(foreach p,$(AWS_PROFILES),--aws-profile "$(p)")

# MFA session for the human roles (fsi-* profiles use source_profile = $(MFA_PROFILE)).
# MFA_PROFILE defaults to the source_profile already set on your fsi-* profiles in
# ~/.aws/config (read locally, no AWS call); set MFA_PROFILE=<name> to override.
# Uses your long-term IAM user credentials ($(MFA_SOURCE_PROFILE)); the MFA device is
# looked up automatically unless MFA_SERIAL is given. The code and the session keys are
# never echoed or logged; the keys are written only to ~/.aws/credentials via aws configure.
MFA_FSI_PROFILES   := fsi-operator fsi-approver fsi-auditor fsi-breaker-operator fsi-model-risk-approver fsi-deploy-gate-signer
MFA_PROFILE        ?= $(firstword $(foreach p,$(MFA_FSI_PROFILES),$(shell aws configure get source_profile --profile $(p) 2>/dev/null)))
MFA_SOURCE_PROFILE ?= default
MFA_DURATION       ?= 43200
mfa-session: ## Start a 12 h MFA session for the fsi-* profiles (CODE=<6-digit code> [MFA_SERIAL=] [MFA_PROFILE=] [MFA_SOURCE_PROFILE=])
	@printf '%s' "$(CODE)" | grep -Eq '^[0-9]{6}$$' || { echo "usage: make mfa-session CODE=<6-digit MFA code>"; exit 2; }
	@test -n "$(MFA_PROFILE)" || { echo "No fsi-* profile with a source_profile found in ~/.aws/config: set MFA_PROFILE=<profile your fsi-* profiles use as source_profile> (see README)"; exit 2; }
	@set -eu; unset AWS_PROFILE AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN; \
	SRC="$(MFA_SOURCE_PROFILE)"; DST="$(MFA_PROFILE)"; \
	SERIAL="$(MFA_SERIAL)"; \
	if [ -z "$$SERIAL" ]; then \
	  USER_NAME=$$(aws sts get-caller-identity --profile "$$SRC" --query Arn --output text | sed 's#.*:user/##'); \
	  SERIAL=$$(aws iam list-mfa-devices --profile "$$SRC" --user-name "$$USER_NAME" --query 'MFADevices[0].SerialNumber' --output text); \
	fi; \
	case "$$SERIAL" in arn:aws:iam::*:mfa/*) ;; *) echo "No MFA device found for profile $$SRC (set MFA_SERIAL=<arn>)"; exit 1;; esac; \
	CREDS=$$(aws sts get-session-token --profile "$$SRC" --serial-number "$$SERIAL" --token-code "$(CODE)" \
	  --duration-seconds "$(MFA_DURATION)" \
	  --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken,Expiration]' --output text) || exit 1; \
	set -- $$CREDS; \
	aws configure set aws_access_key_id     "$$1" --profile "$$DST"; \
	aws configure set aws_secret_access_key "$$2" --profile "$$DST"; \
	aws configure set aws_session_token     "$$3" --profile "$$DST"; \
	aws configure set region "$${AWS_REGION:-us-east-1}" --profile "$$DST"; \
	echo "MFA session written to profile $$DST using $$SERIAL (expires $$4)"

# ─── Utilities ────────────────────────────────────────────────────────────────

generate-data: ## Generate synthetic transaction dataset
	$(PYTHON) data/synthetic_data.py

generate-cache: ## Generate cached outputs (requires GPU or live Bedrock)
	ALLOW_LOCAL_DEV_SIGNING=true $(PYTHON) scripts/generate_cached_output.py
