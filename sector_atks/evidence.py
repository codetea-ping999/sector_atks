"""Join emulation run records with SIEM/EDR exports to produce validation records.

Instead of typing "detected" by hand, each run is matched to the alerts and
log events that the defensive tools actually recorded:

    runs.csv    run_id, technique_id, procedure_id, host, started_at, ended_at
                [, prevented, operator, tool]
    alerts.csv  event_id, rule_id, timestamp, host [, technique_ids, uri, source]
    logs.csv    event_id, timestamp, host [, uri, source]          (optional)

An alert or log event belongs to a run when it is on the same host and its
timestamp falls between the run's start and its end plus a grace period. If an
alert carries ATT&CK technique tags, at least one must match the run's
technique (sub-techniques compare by parent). Runs outside the RoE scope or
window are rejected rather than scored.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from .attack import parent_id
from .engagement import Roe, parse_time

_TRUE = {"1", "true", "yes", "y"}


@dataclass(frozen=True)
class Run:
    run_id: str
    technique_id: str
    procedure_id: str
    host: str
    started_at: datetime
    ended_at: datetime
    prevented: bool = False
    operator: str = ""


@dataclass(frozen=True)
class Event:
    event_id: str
    timestamp: datetime
    host: str
    rule_id: str = ""
    technique_ids: tuple[str, ...] = ()
    uri: str = ""


@dataclass
class MatchResult:
    rows: list[dict]
    rejected: list[tuple[str, str]] = field(default_factory=list)  # (run_id, reason)
    unmatched_alerts: list[str] = field(default_factory=list)


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
        runs.append(
            Run(r["run_id"], r["technique_id"].strip(), r["procedure_id"].strip(),
                r["host"].strip().lower(), start, end,
                (r.get("prevented") or "").strip().lower() in _TRUE,
                (r.get("operator") or "").strip())
        )
    return runs


def load_events(path: Path) -> list[Event]:
    events = []
    for r in _read(path):
        tags = tuple(t.strip() for t in (r.get("technique_ids") or "").split(";") if t.strip())
        events.append(
            Event(r["event_id"].strip(), parse_time(r["timestamp"]), r["host"].strip().lower(),
                  (r.get("rule_id") or "").strip(), tags, (r.get("uri") or "").strip())
        )
    return events


def _belongs(e: Event, run: Run, grace: timedelta, check_tags: bool) -> bool:
    if e.host != run.host or not run.started_at <= e.timestamp <= run.ended_at + grace:
        return False
    if check_tags and e.technique_ids:
        return parent_id(run.technique_id) in {parent_id(t) for t in e.technique_ids}
    return True


def match(
    runs: list[Run],
    alerts: list[Event],
    logs: list[Event] | None = None,
    roe: Roe | None = None,
    verifier: str = "",
    grace_seconds: int = 300,
) -> MatchResult:
    if grace_seconds < 0:
        raise ValueError("grace_seconds must not be negative")
    grace = timedelta(seconds=grace_seconds)
    result = MatchResult(rows=[])
    used: set[str] = set()
    for run in sorted(runs, key=lambda r: r.started_at):
        if roe and not roe.in_scope(run.host):
            result.rejected.append((run.run_id, f"host {run.host} is outside the RoE scope"))
            continue
        if roe and not (roe.in_window(run.started_at) and roe.in_window(run.ended_at)):
            result.rejected.append((run.run_id, "run is outside the RoE window"))
            continue
        hits = [a for a in alerts if _belongs(a, run, grace, check_tags=True)]
        seen = [e for e in logs or [] if _belongs(e, run, grace, check_tags=False)]
        used.update(a.event_id for a in hits)
        alerted, logged = bool(hits), bool(hits or seen)
        outcome = ("detected" if alerted else "prevented" if run.prevented
                   else "logged" if logged else "none")
        evidence = hits or seen
        result.rows.append({
            "technique_id": run.technique_id,
            "procedure_id": run.procedure_id,
            "tested_on": run.started_at.date().isoformat(),
            "outcome": outcome,
            "prevented": str(run.prevented).lower(),
            "alerted": str(alerted).lower(),
            "logged": str(logged).lower(),
            "run_id": run.run_id,
            "rule_id": ";".join(sorted({a.rule_id for a in hits if a.rule_id})),
            "event_id": ";".join(e.event_id for e in evidence),
            "evidence_uri": ";".join(e.uri for e in evidence if e.uri),
            "verifier": verifier if evidence else "",
            "notes": f"matched {len(hits)} alert(s), {len(seen)} log event(s)",
        })
    result.unmatched_alerts = sorted(a.event_id for a in alerts if a.event_id not in used)
    return result


COLUMNS = ["technique_id", "procedure_id", "tested_on", "outcome", "prevented", "alerted",
           "logged", "run_id", "rule_id", "event_id", "evidence_uri", "verifier", "notes"]


def write_validations(rows: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)
