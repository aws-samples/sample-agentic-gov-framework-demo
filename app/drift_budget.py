"""
Console-side drift budget for red-team runs (1.2 Poisoned transactions).

Why: every live compliance run on a recorded detection is a VERIFIED
decision, and fsi-drift-metric-publisher counts it. The breaker's
fsi-challenger-dispute-rate-sustained alarm evaluates
IF(clusters >= 20, disputes / clusters, 0) > 0.51 over a 1-hour Sum, and the
breaker corroborates it from the same stored records. A red-team run records
~3 clusters, and a guardrail-blocked challenger counts as a dispute, so about
7 runs in an hour could put >= 20 mostly-disputed clusters in the window and
trip the fleet-wide hold. The per-minute alarms need >= 20 clusters in one
minute (out of reach for a person clicking a button).

What: a small ledger of the clusters this console submitted to live
compliance (pipeline, challenger and red-team runs), kept in a local file so
a console restart does not reset it. A red-team run is allowed only when
  - at least REDTEAM_COOLDOWN_SECONDS have passed since the last one, and
  - the console's clusters in the last LEDGER_WINDOW_SECONDS plus this run's
    clusters stay below ALARM_MIN_CLUSTERS (the alarm floor),
so red-team runs alone can never be what lifts the hour to the floor where a
dispute rate is evaluated. Red-team disputes could still be pushed over the
floor by ordinary runs (e.g. 6 red-team runs = 18 clusters / 12 disputes,
then one 2-cluster sample run = 20 clusters at ~0.65 > 0.51), so while any
red-team entry is in the window a pipeline or challenger run that would
bring the window to the floor is refused (reserve_other) and nothing is
recorded. With no red-team entry in the window they are never refused.

Limits: traffic that does not go through this console (CLI demos, another
console host, a deleted ledger file) is not seen. The ledger is advisory
bookkeeping, not an authorization control.
"""
import json
import os
import threading
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LEDGER_NAME = ".drift_ledger.json"

# Must equal MIN_CLUSTERS_FOR_ALARM_RATE (cdk/agents_stack.py),
# MIN_CLUSTERS_FOR_RATE (lambdas/drift_metric_publisher/handler.py) and
# MIN_CLUSTERS_FOR_CORROBORATION (circuit_breaker/handler.py); pinned by a test.
ALARM_MIN_CLUSTERS = 20
# 60-minute alarm window + the breaker's 3-minute corroboration slack + margin.
LEDGER_WINDOW_SECONDS = 65 * 60
REDTEAM_COOLDOWN_SECONDS = 90
# A red-team detection flagging more clusters than this is not sent to
# compliance at all (bounds what one run can add to the drift signal).
REDTEAM_MAX_CLUSTERS = 4

KIND_REDTEAM = "redteam"
KIND_OTHER = "other"

COOLDOWN_MESSAGE = ("Red-team cooldown: wait {seconds}s before the next run "
                    "(spaces out VERIFIED decisions for the drift alarms)")
BUDGET_MESSAGE = ("Red-team drift budget used up: this console recorded {used} cluster(s) "
                  "in the last hour; another run could bring the hour to the {floor}-cluster "
                  "floor where the dispute-rate alarm starts evaluating. Try again in ~{minutes} min.")
AFTER_REDTEAM_MESSAGE = ("Drift safety: red-team runs in the last hour left mostly-disputed decisions; "
                         "this console recorded {used} cluster(s) and this run's {n} would bring the "
                         "hour to the {floor}-cluster floor where the dispute-rate alarm evaluates them "
                         "(and could trip the breaker). Compliance was not run, so no decision was "
                         "recorded. Try again in ~{minutes} min, when the red-team runs age out.")
TOO_MANY_CLUSTERS_MESSAGE = ("The detection flagged {n} clusters (red-team limit {limit}); "
                             "compliance was not run, so no decision was recorded")

_LOCK = threading.Lock()


def _path() -> Path:
    return Path(os.environ.get("LOCAL_OUTPUT_DIR") or PROJECT_ROOT / "cached_output") / LEDGER_NAME


def _load(now: float) -> list:
    try:
        raw = json.loads(_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    entries = []
    for e in raw if isinstance(raw, list) else []:
        if (isinstance(e, dict) and isinstance(e.get("ts"), (int, float))
                and isinstance(e.get("clusters"), int) and e.get("kind") in (KIND_REDTEAM, KIND_OTHER)
                and now - LEDGER_WINDOW_SECONDS <= e["ts"] <= now + 60):
            entries.append(e)
    return entries


def _save(entries: list) -> None:
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(entries), encoding="utf-8")
    os.replace(tmp, path)


def summary(now: float | None = None) -> dict:
    """{"clusters": n in window, "redteam_runs": n, "cooldown_left": s}."""
    now = time.time() if now is None else now
    with _LOCK:
        entries = _load(now)
    red = [e["ts"] for e in entries if e["kind"] == KIND_REDTEAM]
    left = max(0, int(REDTEAM_COOLDOWN_SECONDS - (now - max(red)))) if red else 0
    return {"clusters": sum(e["clusters"] for e in entries), "redteam_runs": len(red),
            "cooldown_left": left, "floor": ALARM_MIN_CLUSTERS}


def _refusal(entries: list, clusters: int, now: float) -> str | None:
    red = [e["ts"] for e in entries if e["kind"] == KIND_REDTEAM]
    if red and now - max(red) < REDTEAM_COOLDOWN_SECONDS:
        return COOLDOWN_MESSAGE.format(seconds=int(REDTEAM_COOLDOWN_SECONDS - (now - max(red))) + 1)
    used = sum(e["clusters"] for e in entries)
    if used + clusters >= ALARM_MIN_CLUSTERS:
        oldest = min(e["ts"] for e in entries)
        minutes = max(1, int((oldest + LEDGER_WINDOW_SECONDS - now) / 60) + 1)
        return BUDGET_MESSAGE.format(used=used, floor=ALARM_MIN_CLUSTERS, minutes=minutes)
    return None


def check_redteam(clusters: int = REDTEAM_MAX_CLUSTERS, now: float | None = None) -> str | None:
    """Fixed refusal text, or None when a red-team run of `clusters` fits."""
    now = time.time() if now is None else now
    with _LOCK:
        return _refusal(_load(now), clusters, now)


def reserve_redteam(clusters: int, now: float | None = None) -> str | None:
    """Atomically check and record a red-team run of `clusters` (before
    compliance is called). Returns refusal text, or None once recorded."""
    now = time.time() if now is None else now
    with _LOCK:
        entries = _load(now)
        refusal = _refusal(entries, clusters, now)
        if refusal is None:
            entries.append({"ts": now, "clusters": int(clusters), "kind": KIND_REDTEAM})
            _save(entries)
        return refusal


def _other_refusal(entries: list, clusters: int, now: float) -> str | None:
    red = [e["ts"] for e in entries if e["kind"] == KIND_REDTEAM]
    if not red:
        return None
    used = sum(e["clusters"] for e in entries)
    if used + clusters >= ALARM_MIN_CLUSTERS:
        minutes = max(1, int((max(red) + LEDGER_WINDOW_SECONDS - now) / 60) + 1)
        return AFTER_REDTEAM_MESSAGE.format(used=used, n=int(clusters), floor=ALARM_MIN_CLUSTERS,
                                            minutes=minutes)
    return None


def check_other(clusters: int, now: float | None = None) -> str | None:
    """Fixed refusal text, or None when a pipeline/challenger run fits."""
    now = time.time() if now is None else now
    with _LOCK:
        return _other_refusal(_load(now), clusters, now)


def reserve_other(clusters: int, now: float | None = None) -> str | None:
    """Check and record a pipeline/challenger live compliance submission.
    Refused (nothing recorded) only while red-team entries are in the window
    and this run would bring the window to the alarm floor: the disputes the
    red-team runs left behind would then be evaluated. Without red-team
    entries it is never refused. Best effort: a ledger write failure never
    blocks an allowed run."""
    now = time.time() if now is None else now
    with _LOCK:
        entries = _load(now)
        refusal = _other_refusal(entries, clusters, now)
        if refusal is None:
            entries.append({"ts": now, "clusters": int(clusters), "kind": KIND_OTHER})
            try:
                _save(entries)
            except OSError:
                pass
        return refusal


def record(clusters: int, now: float | None = None) -> None:
    """Record a non-red-team live compliance submission (never refused).
    Best effort: a ledger write failure never blocks the run."""
    now = time.time() if now is None else now
    try:
        with _LOCK:
            entries = _load(now)
            entries.append({"ts": now, "clusters": int(clusters), "kind": KIND_OTHER})
            _save(entries)
    except OSError:
        pass
