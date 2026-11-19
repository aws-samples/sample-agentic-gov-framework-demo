"""
Incomplete-evidence detection for the console.

Pure functions (no Streamlit). A page that shows audit records or PAN
results calls these and renders an "INCOMPLETE EVIDENCE" banner when a read
returned partial or failed data, so a partial view is never mistaken for
sign-off evidence. Reasons are fixed strings (table names and a category),
never exception text or record content.
"""

AUDIT_TABLES = ("detection-results", "compliance-decisions", "executor-audit", "governance-audit")
_ERROR_MARKERS = ("error", "error_ref", "error_code")
_PAN_VERDICTS = ("BLOCKED", "ALLOWED")


# Coarse classes from app/safe_errors.classify that are named in the banner;
# anything else (including "Error") stays a plain "read failed".
_NAMED_ERROR_CODES = ("AccessDenied", "Throttling", "NotFound", "Unavailable")


def _failed_read(records) -> bool:
    if not isinstance(records, list):
        return True
    return any(isinstance(r, dict) and any(k in r for k in _ERROR_MARKERS) for r in records)


def _failed_reason(table, records) -> str:
    codes = [r.get("error_code") for r in records if isinstance(r, dict)] if isinstance(records, list) else []
    code = next((c for c in codes if c in _NAMED_ERROR_CODES), None)
    return f"{table}: read failed ({code})" if code else f"{table}: read failed"


def _partial_reason(table, skipped) -> str:
    if isinstance(skipped, int) and not isinstance(skipped, bool) and skipped > 0:
        noun = "line" if skipped == 1 else "lines"
        return f"{table}: partial read ({skipped} undecodable {noun} skipped)"
    return f"{table}: partial read"


def audit_incomplete_reasons(audit_data) -> list:
    """Why an audit read is not complete evidence ([] when it is).

    The four table lists are the source of truth: a missing table, or a list
    holding an error entry, is a failed read. _evidence.tables[t] == "partial"
    marks a short read (BatchGetItem keys left unprocessed, or skipped
    undecodable local lines)."""
    if not isinstance(audit_data, dict):
        return [f"{t}: read failed" for t in AUDIT_TABLES]
    reasons = []
    evidence = audit_data.get("_evidence")
    partial = evidence.get("tables", {}) if isinstance(evidence, dict) else {}
    if not isinstance(partial, dict):
        partial = {}
    skipped = evidence.get("skipped", {}) if isinstance(evidence, dict) else {}
    if not isinstance(skipped, dict):
        skipped = {}
    for table in AUDIT_TABLES:
        if table not in audit_data or _failed_read(audit_data[table]):
            reasons.append(_failed_reason(table, audit_data.get(table)))
        elif partial.get(table) == "partial":
            reasons.append(_partial_reason(table, skipped.get(table)))
    return reasons


def pan_incomplete_reasons(results) -> list:
    """Why a PAN filter run is not complete evidence ([] when it is)."""
    if not isinstance(results, dict):
        return ["PAN results: missing"]
    reasons = []
    for key, label in (("evasion", "evasion variants"), ("safe", "safe inputs")):
        rows = results.get(key)
        if not isinstance(rows, list):
            reasons.append(f"{label}: missing")
            continue
        errors = sum(1 for r in rows if not isinstance(r, dict) or r.get("action") not in _PAN_VERDICTS)
        if errors:
            reasons.append(f"{label}: {errors} without a BLOCKED/ALLOWED verdict")
    batch = results.get("batch")
    if not isinstance(batch, dict) or batch.get("error"):
        reasons.append("batch ingress check: failed or missing")
    else:
        counts = [batch.get(k) for k in ("allowed_count", "rejected_count", "total_input")]
        if not all(isinstance(c, int) and not isinstance(c, bool) for c in counts) or \
                counts[0] + counts[1] != counts[2]:
            reasons.append("batch ingress check: counts do not add up")
    return reasons
