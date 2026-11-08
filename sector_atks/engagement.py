"""Rules of engagement (RoE) and test plans for authorised emulation.

sector_atks does not execute attacks. Emulation is run by an authorised team
with their own tools (for example CTID micro emulation plans, CALDERA or
Atomic Red Team) inside the scope and window written down here. This module
checks that the written authorisation is complete and reads the plan of
procedures to be tested, so that coverage can be measured against what was
planned rather than only against what happened to be run.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

ENVIRONMENTS = {"isolated-lab", "approved-production"}
REQUIRED = [
    "engagement_id",
    "objective",
    "authorized_by",
    "authorization_ref",
    "environment",
    "scope",
    "window",
    "stop_conditions",
    "emergency_contact",
    "log_retention_days",
]


def parse_time(text: str) -> datetime:
    """ISO 8601 with an explicit offset ("Z" allowed). Naive times are rejected
    because runs and alerts usually come from systems in different time zones."""
    text = text.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    t = datetime.fromisoformat(text)
    if t.tzinfo is None:
        raise ValueError(f"timestamp needs a UTC offset: {text}")
    return t.astimezone(timezone.utc)


@dataclass
class Roe:
    engagement_id: str
    environment: str
    hosts: set[str]
    start: datetime
    end: datetime
    raw: dict = field(repr=False, default_factory=dict)

    def in_scope(self, host: str) -> bool:
        return host in self.hosts

    def in_window(self, t: datetime) -> bool:
        return self.start <= t <= self.end


def check_roe(data: dict) -> list[str]:
    """Return the problems that make the RoE incomplete (empty list = OK)."""
    problems = [f"missing: {k}" for k in REQUIRED if data.get(k) in (None, "", [], {})]
    env = data.get("environment")
    if env and env not in ENVIRONMENTS:
        problems.append(f"environment must be one of {sorted(ENVIRONMENTS)}: {env}")
    if env == "approved-production" and not data.get("production_approval_ref"):
        problems.append("approved-production needs production_approval_ref")
    scope = data.get("scope") or {}
    if isinstance(scope, dict) and not scope.get("hosts"):
        problems.append("scope.hosts must list the hosts that may be tested")
    window = data.get("window") or {}
    try:
        start, end = parse_time(window["start"]), parse_time(window["end"])
        if end <= start:
            problems.append("window.end must be after window.start")
    except (KeyError, TypeError, ValueError) as e:
        if window:
            problems.append(f"window.start/end must be ISO 8601 with offset: {e}")
    stops = data.get("stop_conditions")
    if stops is not None and (not isinstance(stops, list) or not all(isinstance(s, str) and s for s in stops)):
        problems.append("stop_conditions must be a non-empty list of strings")
    days = data.get("log_retention_days")
    if days not in (None, "") and (not isinstance(days, int) or days < 1):
        problems.append("log_retention_days must be a positive integer")
    return problems


def load_roe(path: Path) -> Roe:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    problems = check_roe(data)
    if problems:
        raise ValueError(f"{path}: incomplete rules of engagement: " + "; ".join(problems))
    return Roe(
        engagement_id=data["engagement_id"],
        environment=data["environment"],
        hosts=set(data["scope"]["hosts"]),
        start=parse_time(data["window"]["start"]),
        end=parse_time(data["window"]["end"]),
        raw=data,
    )


@dataclass(frozen=True)
class PlannedProcedure:
    scenario_id: str
    step: int
    technique_id: str
    procedure_id: str
    reference: str  # e.g. ctid-micro:ad_enum, atomic:<guid>, internal:<id>


def load_plan(path: Path) -> list[PlannedProcedure]:
    """Read scenario_id, step, technique_id, procedure_id, reference.
    A (technique_id, procedure_id) pair may appear only once."""
    out, seen = [], set()
    with open(path, encoding="utf-8", newline="") as f:
        for i, r in enumerate(csv.DictReader(f), start=2):
            key = (r["technique_id"].strip(), r["procedure_id"].strip())
            if not all(key):
                raise ValueError(f"{path}:{i}: technique_id and procedure_id are required")
            if key in seen:
                raise ValueError(f"{path}:{i}: duplicate procedure {key[0]}/{key[1]}")
            seen.add(key)
            out.append(
                PlannedProcedure(
                    r.get("scenario_id", "").strip(),
                    int(r.get("step") or 0),
                    key[0],
                    key[1],
                    (r.get("reference") or "").strip(),
                )
            )
    return out
