# Runbook: governance hold (circuit breaker) release

A governance hold attaches `governance-hold-deny-all` to the three agent roles
(`detection-agent-role`, `compliance-agent-role`, `executor-agent-role`). It is
tripped automatically by the drift alarms or the executor's containment
decision, or manually by an operator. Releasing it always needs a human
decision, and normally two people.

Code: [circuit_breaker/handler.py](../circuit_breaker/handler.py),
[circuit_breaker/governance_state.py](../circuit_breaker/governance_state.py),
[circuit_breaker/hold_sweep.py](../circuit_breaker/hold_sweep.py),
[circuit_breaker/identity_proof.py](../circuit_breaker/identity_proof.py),
[circuit_breaker/authz.py](../circuit_breaker/authz.py),
[scripts/ensure_agents_enabled.py](../scripts/ensure_agents_enabled.py),
[scripts/break_glass_release.py](../scripts/break_glass_release.py).

## 1. Who can do what

| Role (IAM path) | Channel | Trip | Request release | Approve release |
|---|---|---|---|---|
| `fsi-breaker-operator` (`/fsi-breaker/`) | `iam-user` | yes | yes | no |
| `fsi-console-operator` (`/fsi-console/`) | `iam-user` | yes | yes | no |
| `fsi-console-operator-hosted` (`/fsi-console/`) | `console` | yes | no | no |
| `fsi-breaker-approver` (`/fsi-breaker/`) | `iam-user` | yes | yes | yes |
| Identity Center `FsiBreakerOperator` | `sso` | yes | yes | no |
| Identity Center `FsiBreakerApprover` | `sso` | yes | yes | yes |
| `fsi-breaker-break-glass` (`/fsi-breaker/`) | `break-glass` | no | no | out-of-band only (section 4) |

- The IAM roles trust IAM users of this account with MFA whose role session
  name is their own IAM user name. Configure each person's AWS profile with
  `role_session_name = <your IAM user name>` (full example in
  [SECURITY_OPERATIONAL_STEPS.md](SECURITY_OPERATIONAL_STEPS.md), step 2).
- The breaker identifies the individual by the role session name, and only
  compares individuals on the same channel. A request made on `iam-user` can
  only be approved on `iam-user`, by a different person.
- Every request and approval carries a presigned `sts:GetCallerIdentity`
  proof with a single-use nonce. The breaker verifies it with STS before it
  writes anything, and a replayed proof is refused.

## 2. Check the hold

```bash
make deploy        # stops at the hold check if a hold is active
python scripts/ensure_agents_enabled.py   # detect only; exit 1 while held
```

The current hold is the `governance-state` item. Every trip claims it with a
new `generation` (status `HELD`); a release or break-glass marks it
`RELEASED`. Read it with the account's read-only or admin role (the operator
roles are deliberately not granted it):

```bash
aws dynamodb get-item --table-name governance-state \
    --key '{"state_id":{"S":"breaker"}}' --consistent-read
```

Before releasing, find out why it tripped. The `GOVERNANCE_HOLD` record in
the `governance-audit` table (its `timestamp` is when it was written;
`trip_started_at` is when the trip started; `hold_generation` is the
generation it claimed, or `state_claimed: false` when it could not claim the
state) carries:

- `trigger_source`: `ALARM:<alarm name>`, `AUTO_TRIP:EXECUTOR_CONTAINMENT` or
  `MANUAL:<reason code>`;
- `triggered_by`: the verified ARN of a manual trip;
- `corroboration` (alarm trips): what the VERIFIED compliance records in the
  alarm window add up to. An alarm trip happens only with
  `corroborated: true`, or `corroborated: null` when the breaker couldn't
  read the records (`fsi-corroboration-unavailable` fires; the trip goes
  ahead, containment first). `trigger: recheck` means the scheduled
  `fsi-breaker-alarm-recheck` tripped it while the alarm stayed in `ALARM`.

**Uncorroborated drift alarms do not hold.** When the stored VERIFIED
decisions don't support a drift alarm (for example forged or console-injected
datapoints), the breaker attaches nothing. It writes an `ALARM_UNCORROBORATED`
event (with the same `corroboration` breakdown) and the
`fsi-uncorroborated-drift-alarm` alarm fires. Investigate who published the
datapoints (only `fsi-drift-metric-publisher-role` may, step 6 of the
[operational steps](SECURITY_OPERATIONAL_STEPS.md)), and trip manually if you
need containment. `shaping_suspected: true` (and `fsi-drift-shaping-suspected`)
means compliance invocations in the window ran at more than 3x the baseline
rate.

**The hold is reconciled.** While a hold is active,
`fsi-governance-hold-sweep` checks every 5 minutes (and the breaker right
after each trip) that all three agent roles carry `governance-hold-deny-all`
and re-attaches it to any role missing it. It never detaches. Each
re-attach writes a `GOVERNANCE_HOLD_RECONCILED` event and fires
`fsi-hold-reconciled`; find out who detached the policy (CloudTrail,
`fsi-out-of-band-hold-change`). If `fsi-hold-reconciled` fires right after a
release, the release raced the sweep: re-trip, then release (a new request
returns `HOLD_STATE_MISMATCH` until a trip claims the state).

Wait for the drift alarm to return to `OK` before releasing. While a trusted
alarm stays in `ALARM`, `fsi-breaker-alarm-recheck` re-corroborates it every
2 minutes, but it never re-trips an episode in which a hold or release was
already recorded, so releasing early can leave real drift uncontained.

## 3. In-band two-person release (normal path)

1. **Operator** (own AWS profile, operator or approver role):

   ```bash
   AWS_PROFILE=<your operator profile> make release-request
   ```

   It prints a request id. The request expires after 15 minutes and is bound
   to the current hold and its `generation` in the `governance-state` item.

2. **A different approver** (own AWS profile, approver role, same channel):

   ```bash
   AWS_PROFILE=<your approver profile> make release-approve REQUEST_ID=<id>
   ```

3. Check the outcome:
   - exit 0: all agent roles were detached;
   - `SECOND_APPROVER_REQUIRED`: the approver is the requester, or on a
     different channel; get a different person on the same channel;
   - `STALE_REQUEST` or `NO_ACTIVE_HOLD`: the hold changed since the request
     (a newer trip). Investigate the newer hold, then request again;
   - `REQUEST_EXPIRED`: request again;
   - `TRIP_IN_PROGRESS`: a trip is recorded that has not claimed the
     `governance-state` item yet. Wait a minute and request again; if it
     persists (`fsi-hold-state-write-failed` fired), re-trip once, then
     release;
   - `HOLD_ALREADY_RELEASED`: a release of this hold already completed (or
     crashed mid-way). Re-trip to start a new hold if one is needed;
   - `HOLD_STATE_MISMATCH` or `HOLD_EVENT_UNKNOWN`: the state item is not
     `HELD` (or does not exist yet). Re-trip, then release;
   - `RELEASE_SUPERSEDED` (exit 1): a newer trip claimed the state before the
     detach; nothing was detached. Review the newer hold, then request again;
   - `ALREADY_RELEASED`: this hold generation was already released;
   - `STATE_UNAVAILABLE`: the `governance-state` item could not be claimed or
     read; nothing was detached. Request again;
   - exit 3 without re-attach failures, "A newer hold superseded this
     release; the hold was restored.": a new trip landed while the release
     detached, and the breaker re-attached the deny-all automatically. Review
     the newer hold before any further release;
   - exit 3 with re-attach failures listed, "re-attach FAILED on <roles>;
     re-trip now": **re-trip immediately** (console "Manual Circuit
     Breaker", or invoke `fsi-circuit-breaker-human` with action `invoke`),
     then review. This step is mandatory; the sweep also re-attaches within
     5 minutes.
   - "completion audit record was not written": the release happened and its
     `GOVERNANCE_HOLD_RELEASED` pre-record exists; note it in the incident
     record.

The console's 4.1 page offers the same two steps ("Request release" and
"Approve release" with the request id).

## 4. Out-of-band release (breaker Lambda unavailable)

Use this only when `fsi-circuit-breaker-human` can't be invoked (deleted,
broken deploy, or itself denied). It is single-person by necessity and is
loud on purpose.

1. Open an incident ticket. You need its id, for example `INC-1234`.
2. Grant the incident responder `sts:AssumeRole` on
   `arn:aws:iam::<account>:role/fsi-breaker/fsi-breaker-break-glass` for the
   incident only. Assuming it requires MFA and a session name equal to the IAM
   user name, and every assumption fires `fsi-break-glass-assumed`.
3. Run, under the break-glass profile:

   ```bash
   AWS_PROFILE=<break-glass profile> python scripts/break_glass_release.py \
       --incident-id INC-1234 --i-understand-this-is-out-of-band
   ```

   - It refuses (exit 1) unless the caller is the break-glass role, bound by
     RoleId and IAM path.
   - It refuses (exit 2, nothing written) when the local clock is more than
     2 s off AWS time; sync the clock (NTP) and re-run.
   - It reads the `governance-state` item. Break-glass needs
     `dynamodb:GetItem`/`UpdateItem` on `governance-state` (key `breaker`).
     Exit 2 with "state read failed" means fix the role or table first.
   - It writes `BREAK_GLASS_RELEASE_STARTED` before touching any role, and
     stops (exit 2) if it can't.
   - It claims the state item for the generation it read (status
     `RELEASED`, `break_glass_*` fields). Break-glass also clears any trip
     whose state claim failed before it ran (the `fsi-hold-state-write-failed`
     alarm will already have fired for it). Exit 4: a newer hold claimed the
     state first; nothing was detached. Exit 2 after the STARTED record: the
     claim failed; nothing was detached.
   - It detaches the deny-all policy, re-reads each role and the state item,
     and writes `BREAK_GLASS_RELEASE_COMPLETED` with per-role results and an
     `outcome`. Exit 0 means all three roles are verified detached; exit 3
     means a partial release; exit 5 means a newer hold was claimed during
     the release: the sweep restores it, do NOT re-run, and open a second
     incident review. Exit 5 wins over exit 3.

   Exit codes: 0 detached, 1 not the break-glass role, 2 refused or failed
   with nothing detached, 3 partial, 4 superseded before the detach, 5
   superseded during the release.
4. Every detach it makes fires `fsi-out-of-band-hold-change`.
5. Remove the responder's `sts:AssumeRole` grant.
6. A second person reviews the incident within 24 hours: the two
   `BREAK_GLASS_RELEASE_*` records (the COMPLETED `outcome` is `DETACHED`,
   `PARTIAL`, `SUPERSEDED_AFTER`, `SUPERSEDED` for exit 4 with nothing
   detached, or `STATE_CLAIM_FAILED` for exit 2 after STARTED with nothing
   detached), the CloudTrail events in `/fsi/governance/hold-changes`, and
   the reason the in-band path was unavailable.

## 5. Residuals

- Trip and release are serialized on the `governance-state` item: a release
  detaches only the generation it was approved for, and a trip that claims
  the item during the detach is re-attached by the release itself
  (`fsi-newer-hold-detected`).
- A sweep that read `HELD` just before a release can re-attach over it
  (fail-safe; `fsi-hold-reconciled`). Re-trip, then release.
- A trip whose state claims both failed (`fsi-hold-state-write-failed`)
  keeps the hold enforced: the sweep, the alarm recheck and release requests
  treat it as the active hold, and release stays blocked
  (`TRIP_IN_PROGRESS`) until one manual re-trip claims the state. If a
  release detached it meanwhile, the next sweep re-attaches it (within 5
  minutes plus 60 s).
- A trip that started before, or within 5 s after, the current claim and
  whose own claims all failed is coalesced into the current hold (its
  `fsi-hold-state-write-failed` alarm has fired).
- A trip whose intent write and both state claims failed can be shadowed by
  an older hold record written after it; `fsi-hold-state-write-failed` has
  fired for it.
- A trip whose first claim failed and whose retry landed after a release's
  post-detach check is restored by the next sweep (within 5 minutes plus
  60 s, `fsi-hold-reconciled`).
- A hold that was active before the `governance-state` table existed needs
  one manual trip to adopt it before an in-band release (requests return
  `HOLD_EVENT_UNKNOWN` until then).
- When one laptop holds both the operator's and the approver's profiles, the
  two-person rule is only as strong as that laptop. Run the approval from the
  approver's own machine for anything beyond a demo.
- `make destroy` aborts while a hold is active; release first (section 3 or 4).
