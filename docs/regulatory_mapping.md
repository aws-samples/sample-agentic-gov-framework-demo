# Regulatory Mapping

## How this architecture satisfies financial services regulatory requirements

### PCI-DSS v4.0

| Section | Requirement | Implementation |
|---------|-------------|----------------|
| 3.4 | Render PAN unreadable anywhere it is stored | PAN ingress filter blocks full PAN before processing |
| 3.5.1 | PAN masking requirements | 6 evasion variant detection (zero-width, unicode, separators) |
| 7.2 | Access control systems | Three distinct IAM roles with least privilege |
| 10.2 | Automated audit trails | DynamoDB audit with PITR, no-delete, 7-year retention |

### BSA/AML (Bank Secrecy Act)

| Requirement | Implementation |
|-------------|----------------|
| SAR filing obligation | Automated SAR narrative generation via Bedrock |
| Suspicious activity detection | cuGraph fraud ring detection (circular structuring, layering) |
| Timely filing | Automated pipeline: detect → assess → file or escalate |
| Record retention | DynamoDB with 7-year retention and PITR |

### SR 11-7 (Model Risk Management)

| Principle | Implementation |
|-----------|----------------|
| Effective challenge | Independent challenger model with different methodology |
| Model validation | Challenger DISPUTE → automatic escalation to human |
| Documentation | Full model metadata captured (model_id, latency, prompt hash) |
| Ongoing monitoring | Drift metrics with automated circuit breaker |

### SOX Sections 302/404

| Section | Requirement | Implementation |
|---------|-------------|----------------|
| 302 | CEO/CFO certification of controls | Compliance gate: 212 automated assertions |
| 404 | Internal control assessment | Separation of duties enforced by IAM boundaries |
| 404 | Control testing | 100+ test modules validate control effectiveness |

### FinCEN Guidelines

| Guideline | Implementation |
|-----------|----------------|
| SAR narrative quality | Formal BSA/FinCEN language via Bedrock with regulatory prompts |
| Typology identification | Automated classification: circular_structuring, layering_shell |
| Supporting evidence | Confidence factors, transaction details, time analysis |
| Filing decision | AGREE → auto-file, DISPUTE → escalate to human analyst |
