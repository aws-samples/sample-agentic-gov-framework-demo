<style>
/* Readable links + inline-code chips for Markdown Preview (ignored by plain renderers). */
a { color: #2b6cb0 !important; text-decoration: none; }
a:hover { text-decoration: underline; }
/* Inline code (incl. linked code tokens): force a light chip with dark text so it is
   legible regardless of light/dark theme — this is the "dark highlight" fix. */
code { background: #eef2f6 !important; color: #1f2d3d !important;
       padding: 1px 4px; border-radius: 3px; }
a code { color: #2b6cb0 !important; background: #eef2f6 !important; }
</style>

> **Companion to [`FIVE_DS_WALKTHROUGH.md`](FIVE_DS_WALKTHROUGH.md)** — the walkthrough is your
> private script (dashboard narration + the talking points for each code snippet). *This* doc
> is the clean thing you put on the screen: click a link and jump straight to the code.
>
> **Open in Markdown Preview (`Cmd+Shift+V`)** so the links jump to the line. Only the short
> tokens (symbol names, `L###`) are links — the descriptions are plain text. Run
> `make verify-doc-links` before the talk to confirm every anchor resolves.

# The 5D approach — code map

| | | Answers |
|---|---|---|
| **D1** | **Data & Access Controls** | What reaches the model, and what the model can reach |
| **D2** | **Decision Explainability** | Why the system produced this answer, recorded before it acts |
| **D3** | **Deliberative Challenge** | Who checks the answer, independently of whoever wrote it |
| **D4** | **Drift Control** | Whether behaviour is still what was signed off |
| **D5** | **Deployment Controls** | Whether the four above are actually present in what shipped |

**D5 makes the other four durable** — everything else can be removed by a well-meaning
refactor, and only the gate notices.

## Jump to the code

| | Dashboard | Put this on the screen |
|---|---|---|
| **D1** | 1.1–1.3 | guardrail [`CfnGuardrail`](../cdk/agents_stack.py#L228) · PAN filter [`contains_full_pan`](../lambdas/detection_agent/pan_filter.py#L39) |
| **D2** | 2.1 | provenance chain [`provenance_chain`](../lambdas/executor_agent/handler.py#L148) |
| **D3** | 3.1 | different model [`CHALLENGER_MODEL_ID`](../lambdas/compliance_agent/handler.py#L45) · independence [`assert`](../lambdas/compliance_agent/handler.py#L198) · [`build_challenger_prompt`](../lambdas/compliance_agent/sar_prompts.py#L116) |
| **D4** | 4.1 | circuit breaker [`invoke_circuit_breaker`](../circuit_breaker/handler.py#L182) |
| **D5.1** | 5.1 | compliance gate [`run_all`](../compliance_gate.py#L65) |
| **D5.2** | 5.2 | model assurance [`validate_model`](../model_assurance.py#L94) |

---

## D1 — Data & Access Controls

- `pan_filter.py` — ingress data boundary (PCI-DSS §3.4): [`contains_full_pan`](../lambdas/detection_agent/pan_filter.py#L39)
  - NFKC normalize + zero-width strip → [L60](../lambdas/detection_agent/pan_filter.py#L60)
  - Luhn checksum → [L70](../lambdas/detection_agent/pan_filter.py#L70)
- `agents_stack.py` — model-I/O boundary (blocks PAN/SSN): [`CfnGuardrail`](../cdk/agents_stack.py#L228)
- Three least-privilege roles → [`DetectionAgentRole`](../cdk/agents_stack.py#L60) · [`ComplianceAgentRole`](../cdk/agents_stack.py#L92) · [`ExecutorAgentRole`](../cdk/agents_stack.py#L138)
- SOX forbidden signals → [`FORBIDDEN_SIGNALS`](../lambdas/executor_agent/handler.py#L58)

## D2 — Decision Explainability

- `executor_agent/handler.py` — the chain `detection_id -> compliance_id -> action_id`: [`provenance_chain`](../lambdas/executor_agent/handler.py#L148)
  - written as the action is taken → [`action_record`](../lambdas/executor_agent/handler.py#L140)
- `detection_agent/handler.py` — structured evidence computed before the decision: [`build_output`](../lambdas/detection_agent/handler.py#L157)

## D3 — Deliberative Challenge

- `compliance_agent/handler.py` — model-level independence (challenger on a different family): [`CHALLENGER_MODEL_ID`](../lambdas/compliance_agent/handler.py#L45)
- `compliance_agent/handler.py` — enforced-in-code prompt independence: [`assert`](../lambdas/compliance_agent/handler.py#L198)
  - challenger call uses the different model + guardrail → [L203](../lambdas/compliance_agent/handler.py#L203)
- `sar_prompts.py` — the genuinely different methodology: [`build_challenger_prompt`](../lambdas/compliance_agent/sar_prompts.py#L116)

## D4 — Drift Control

- `circuit_breaker/handler.py` — the trip: [`invoke_circuit_breaker`](../circuit_breaker/handler.py#L182)
  - revokes all three roles → [`attach_role_policy`](../circuit_breaker/handler.py#L213)
  - the trip is audited → [`write_governance_hold_event`](../circuit_breaker/handler.py#L222)
- thresholds (dispute > 51% / guardrail > 10% / volume > 3x) → [`check_thresholds`](../circuit_breaker/handler.py#L146)
- the alarm that fires it → [`DisputeRateAlarm`](../cdk/agents_stack.py#L340) · where the metrics come from → [`publish_drift_metrics`](../lambdas/compliance_agent/handler.py#L382)

## D5 — Deployment Controls

### D5.1

- `compliance_gate.py` — 71 assertions, 5 domains: [`run_all`](../compliance_gate.py#L65)
  - domains → [Boundary](../compliance_gate.py#L73) · [Model Governance](../compliance_gate.py#L141) · [Audit](../compliance_gate.py#L216) · [Access Control](../compliance_gate.py#L291) · [Model Assurance](../compliance_gate.py#L367)
  - exit 1 on any failure → [`report`](../compliance_gate.py#L427)

### D5.2

- `model_assurance.py` — exact, version-pinned match: [`validate_model`](../model_assurance.py#L94)
  - not on registry → blocked → [L118](../model_assurance.py#L118)
  - status + expiry gates → [L126](../model_assurance.py#L126)
- configured (deploy) + observed (runtime) → [`check_model_assurance`](../compliance_gate.py#L367)
- the registry → [`approved_models.json`](../data/approved_models.json)
- **finish (break-and-stop):** `make demo-model-swap` — swaps in an unapproved model, real gate blocks → [`demo_model_swap.py`](../demos/demo_model_swap.py) (off-stage reset: `make model-swap-restore`)

---

```bash
make ui-live            # live dashboard (or `make ui` for local/cached)
make gate               # 71/71 assertions, 5 domains
make verify-doc-links   # confirm every link above still resolves — run before the talk
```
