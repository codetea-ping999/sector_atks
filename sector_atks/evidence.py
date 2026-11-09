"""Join emulation run records with SIEM/EDR exports to produce validation records.

Instead of typing "detected" by hand, each run is matched to the events that
the defensive tools actually recorded:

    runs.csv    run_id, technique_id, procedure_id, host, started_at, ended_at
                [, prevention_claimed, operator, tool]
    alerts.csv  event_id, rule_id, timestamp, host
                [, technique_ids, run_id, action, uri, source]
    logs.csv    event_id, timestamp, host [, run_id, uri, source]       (optional)

``action`` on an alert is ``alert`` (default) or a blocking result
(``blocked``, ``prevented``, ``quarantined``, ``denied``). Only blocking events
from the defensive tool confirm a prevention; the red team's own
``prevention_claimed`` is kept as a separate, unverified column.

Matching rules, strongest first:

1. An event carrying a ``run_id`` belongs to that run only.
2. Otherwise an event is a candidate for a run when it is on the same host,
   inside [start, end + grace], and, for alerts, carries an ATT&CK tag that
   matches the run's technique (sub-techniques compare by parent).
3. A candidate is *contested* when it fits more than one run, and *weak* when
   an alert has no ATT&CK tag. Neither confirms anything on its own: the run
   is marked ``ambiguous`` with the candidate ids for a person to resolve.

Runs outside the RoE scope or window are rejected rather than scored. With a
plan, every row carries the plan's engagement_id, plan_id and plan_version, so
that vdc.compute can keep this engagement apart from earlier ones.

Logs only show visibility (``logged``) and go to ``log_event_id``; they never
fill ``event_id``, which is reserved for alert or block events from the
defensive tool.
"""

from __future__ import annotations

import csv
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from .attack import parent_id
from .engagement import PlannedProcedure, Roe, parse_time, plan_identity

_TRUE = {"1", "true", "yes", "y"}
_FALSE = {"0", "false", "no", "n", ""}
BLOCK_ACTIONS = {"blocked", "prevented", "quarantined", "denied"}
ACTIONS = BLOCK_ACTIONS | {"alert"}


def parse_bool(value: str | None, where: str) -> bool:
    text = (value or "").strip().lower()
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    raise ValueError(f"{where}: expected true/false, got {value!r}")


@dataclass(frozen=True)
class Run:
    run_id: str
    technique_id: str
    procedure_id: str
    host: str
    started_at: datetime
    ended_at: datetime
    prevention_claimed: bool = False
    operator: str = ""


@dataclass(frozen=True)
class Event:
    event_id: str
    timestamp: datetime
    host: str
    rule_id: str = ""
    technique_ids: tuple[str, ...] = ()
    uri: str = ""
    run_id: str = ""
    action: str = "alert"

    @property
    def blocked(self) -> bool:
        return self.action in BLOCK_ACTIONS


@dataclass
class MatchResult:
    rows: list[dict]
    rejected: list[tuple[str, str]] = field(default_factory=list)  # (run_id, reason)
    ambiguous: list[str] = field(default_factory=list)  # run ids needing review
    contested_events: list[str] = field(default_factory=list)  # events fitting >1 run
    unmatched_alerts: list[str] = field(default_factory=list)

    @property
    def status(self) -> str:
        if self.rejected:
            return "rejected"
        return "needs_review" if self.ambiguous else "complete"


def _read(path: Path) -> list[dict]:
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def load_runs(path: Path) -> list[Run]:
    runs, seen = [], set()
    for i, r in enumerate(_read(path), start=2):
        if r["run_id"] in seen:
            raise ValueError(f"{path}:{i}: duplicate run_id {r['run_id']}")
        seen.add(r["run_id"])
        start, end = parse_time(r["started_at"]), parse_time(r["ended_at"])
        if end < start:
            raise ValueError(f"{path}:{i}: ended_at is before started_at")
        claimed = r.get("prevention_claimed", r.get("prevented"))
        runs.append(
            Run(r["run_id"], r["technique_id"].strip(), r["procedure_id"].strip(),
                r["host"].strip().lower(), start, end,
                parse_bool(claimed, f"{path}:{i}: prevention_claimed"),
                (r.get("operator") or "").strip())
        )
    return runs


def load_events(path: Path) -> list[Event]:
    events, seen = [], set()
    for i, r in enumerate(_read(path), start=2):
        eid = r["event_id"].strip()
        if eid in seen:
            raise ValueError(f"{path}:{i}: duplicate event_id {eid}")
        seen.add(eid)
        action = (r.get("action") or "alert").strip().lower()
        if action not in ACTIONS:
            raise ValueError(f"{path}:{i}: action must be one of {sorted(ACTIONS)}: {action!r}")
        tags = tuple(t.strip() for t in (r.get("technique_ids") or "").split(";") if t.strip())
        events.append(
            Event(eid, parse_time(r["timestamp"]), r["host"].strip().lower(),
                  (r.get("rule_id") or "").strip(), tags, (r.get("uri") or "").strip(),
                  (r.get("run_id") or "").strip(), action)
        )
    return events


def _in_window(e: Event, run: Run, grace: timedelta) -> bool:
    return e.host == run.host and run.started_at <= e.timestamp <= run.ended_at + grace


def _tag_matches(e: Event, run: Run) -> bool:
    return parent_id(run.technique_id) in {parent_id(t) for t in e.technique_ids}


def _candidates(events: list[Event], runs: list[Run], grace: timedelta, alerts: bool):
    """run_id -> (exact events, window candidates); event_id -> runs it fits by window."""
    run_ids = {r.run_id for r in runs}
    per_run = {r.run_id: ([], []) for r in runs}
    fits: dict[str, set[str]] = {}
    for e in events:
        if e.run_id:
            if e.run_id in run_ids:
                per_run[e.run_id][0].append(e)
            continue
        for run in runs:
            if _in_window(e, run, grace) and (not alerts or not e.technique_ids or _tag_matches(e, run)):
                per_run[run.run_id][1].append(e)
                fits.setdefault(e.event_id, set()).add(run.run_id)
    return per_run, fits


def match(
    runs: list[Run],
    alerts: list[Event],
    logs: list[Event] | None = None,
    roe: Roe | None = None,
    verifier: str = "",
    grace_seconds: int = 300,
    plan: list[PlannedProcedure] | None = None,
) -> MatchResult:
    if grace_seconds < 0:
        raise ValueError("grace_seconds must not be negative")
    engagement_id, plan_id, plan_version = roe.engagement_id if roe else "", "", ""
    planned: set[tuple[str, str]] = set()
    if plan is not None:
        plan_eng, plan_id, plan_version = plan_identity(plan)
        if roe and plan_eng != roe.engagement_id:
            raise ValueError(f"plan is for engagement {plan_eng}, RoE is {roe.engagement_id}")
        engagement_id = plan_eng
        planned = {(p.technique_id, p.procedure_id) for p in plan}
    grace = timedelta(seconds=grace_seconds)
    result = MatchResult(rows=[])

    accepted = []
    for run in sorted(runs, key=lambda r: (r.started_at, r.run_id)):
        if roe and not roe.in_scope(run.host):
            result.rejected.append((run.run_id, f"host {run.host} is outside the RoE scope"))
        elif roe and not (roe.in_window(run.started_at) and roe.in_window(run.ended_at)):
            result.rejected.append((run.run_id, "run is outside the RoE window"))
        else:
            accepted.append(run)

    alert_c, alert_fits = _candidates(alerts, accepted, grace, alerts=True)
    log_c, log_fits = _candidates(logs or [], accepted, grace, alerts=False)
    contested = {eid for eid, rs in {**alert_fits, **log_fits}.items() if len(rs) > 1}
    result.contested_events = sorted(contested)
    used: set[str] = set()

    for run in accepted:
        exact, window = alert_c[run.run_id]
        by_time = lambda es: sorted(es, key=lambda e: (e.timestamp, e.event_id))  # noqa: E731
        confirmed = by_time(exact + [e for e in window if e.event_id not in contested and e.technique_ids])
        doubtful = by_time([e for e in window if e.event_id in contested or not e.technique_ids])
        log_exact, log_window = log_c[run.run_id]
        seen = by_time(log_exact + [e for e in log_window if e.event_id not in contested])
        used.update(e.event_id for e in confirmed + doubtful)

        alert_events = [e for e in confirmed if not e.blocked]
        block_events = [e for e in confirmed if e.blocked]
        alerted, prevented = bool(alert_events), bool(block_events)
        logged = bool(alert_events or seen)
        status = "confirmed" if confirmed else "ambiguous" if doubtful else "none"
        if status == "ambiguous":
            result.ambiguous.append(run.run_id)
        outcome = ("detected" if alerted else "prevented" if prevented
                   else "logged" if logged else "none")
        notes = []
        if doubtful:
            notes.append(f"{len(doubtful)} contested or untagged event(s) need review")
        if run.prevention_claimed and not prevented:
            notes.append("prevention claimed by the red team but no blocking event found")
        if plan is not None and (run.technique_id, run.procedure_id) not in planned:
            notes.append("procedure is not in the plan")
        result.rows.append({
            "engagement_id": engagement_id,
            "plan_id": plan_id,
            "plan_version": plan_version,
            "technique_id": run.technique_id,
            "procedure_id": run.procedure_id,
            "tested_on": run.started_at.date().isoformat(),
            "tested_at": run.started_at.isoformat().replace("+00:00", "Z"),
            "outcome": outcome,
            "prevented": str(prevented).lower(),
            "alerted": str(alerted).lower(),
            "logged": str(logged).lower(),
            "prevention_claimed": str(run.prevention_claimed).lower(),
            "match_status": status,
            "run_id": run.run_id,
            "rule_id": ";".join(sorted({e.rule_id for e in confirmed if e.rule_id})),
            "event_id": ";".join(e.event_id for e in confirmed),
            "evidence_uri": ";".join(e.uri for e in confirmed if e.uri),
            "log_event_id": ";".join(e.event_id for e in seen),
            "candidate_event_id": ";".join(e.event_id for e in doubtful),
            "verifier": verifier if (confirmed or seen) else "",
            "notes": "; ".join(notes),
        })
    result.unmatched_alerts = sorted(a.event_id for a in alerts if a.event_id not in used)
    return result


COLUMNS = ["engagement_id", "plan_id", "plan_version", "technique_id", "procedure_id", "tested_on", "tested_at", "outcome",
           "prevented", "alerted", "logged", "prevention_claimed", "match_status", "run_id",
           "rule_id", "event_id", "evidence_uri", "log_event_id", "candidate_event_id",
           "verifier", "notes"]


def write_validations(rows: list[dict], path: Path) -> None:
    """Write atomically, so a reader never sees a half-written file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=COLUMNS)
            w.writeheader()
            w.writerows(rows)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise
