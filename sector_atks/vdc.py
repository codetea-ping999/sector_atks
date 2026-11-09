"""Verified Detection Coverage (VDC).

    VDC = sum over t in T of  w_t * V_t                 (sum of w_t = 1)
    V_t = (1 / n_t) * sum over procedures p of t of  d_p * f_p

w_t  weight of technique t (see weights.py)
d_p  1 if the latest test of procedure p raised an alert, else 0
f_p  freshness of that test (step window or exponential decay)
n_t  number of procedures tested for t

Freshness is applied per procedure, so an old success cannot be propped up by
a recent failure of another procedure. When every procedure of t was tested
on the same day, V_t equals D_t * F_t from the research notes.

Validation records are defensive test results only: which technique and
procedure variant was exercised, when, and how the defence responded.
Prevention, alerting and logging are recorded as separate flags, because a
blocked action may leave neither an alert nor a log. The ``outcome`` column
gives defaults for those flags using the four classes from the purple-team
notes: prevented (防御された), detected (検知された), logged (ログのみ),
none (ログなし).

An alert or prevention only counts when it is backed by evidence: an event id
or evidence URI from the defensive tool, plus the person who checked it
(``verifier``). evidence.py fills these fields by matching run records with
SIEM/EDR exports. Records the matcher marked ``ambiguous`` never count.

Records are ordered by ``tested_at`` (ISO 8601 with a UTC offset). Two records
of the same procedure on the same day must both carry distinct ``tested_at``
values; otherwise the "latest" result would depend on the row order and the
input is rejected.

When a test plan is given, only records of the plan's engagement count, and
n_t is the number of planned procedures (plus any extra procedures run in that
engagement), so a technique cannot reach 100% by running one easy procedure,
and earlier engagements cannot be counted as executing this plan.
"""

from __future__ import annotations

import csv
import json
import math
from dataclasses import asdict, dataclass, field
from datetime import date, datetime
from pathlib import Path

from .attack import parent_id
from .engagement import PlannedProcedure, parse_time, plan_identity

OUTCOMES = {
    "prevented": "防御された",
    "detected": "検知された",
    "logged": "ログのみ",
    "none": "ログなし",
}

# Flags implied by each outcome when the record does not state them.
# "prevented" implies nothing about alerts or logs: claiming them needs evidence.
_DEFAULT_FLAGS = {
    "prevented": (True, False, False),
    "detected": (False, True, True),
    "logged": (False, False, True),
    "none": (False, False, False),
}
_TRUE = {"1", "true", "yes", "y"}
_FALSE = {"0", "false", "no", "n"}


@dataclass(frozen=True)
class Validation:
    technique_id: str
    procedure_id: str
    tested_on: date
    outcome: str
    notes: str = ""
    prevented: bool | None = None
    alerted: bool | None = None
    logged: bool | None = None
    run_id: str = ""
    rule_id: str = ""
    event_id: str = ""
    evidence_uri: str = ""
    verifier: str = ""
    tested_at: datetime | None = None  # UTC; orders reruns of the same day
    engagement_id: str = ""
    plan_id: str = ""
    plan_version: str = ""
    match_status: str = ""  # confirmed / ambiguous / none, from match-evidence
    log_event_id: str = ""
    prevention_claimed: bool | None = None  # the red team's own claim, never evidence

    @property
    def ambiguous(self) -> bool:
        return self.match_status == "ambiguous"

    @property
    def order(self) -> tuple:
        return (self.tested_on, self.tested_at is not None, self.tested_at or datetime.min)

    def has_evidence(self) -> bool:
        """An alert or prevention is backed by a defensive-tool event and a reviewer."""
        return not self.ambiguous and bool(self.event_id or self.evidence_uri) and bool(self.verifier)

    def has_log_evidence(self) -> bool:
        return (not self.ambiguous and bool(self.log_event_id or self.event_id or self.evidence_uri)
                and bool(self.verifier))

    def flags(self) -> tuple[bool, bool, bool]:
        """(prevented, alerted, logged), explicit values overriding the outcome's defaults."""
        default = _DEFAULT_FLAGS[self.outcome]
        stated = (self.prevented, self.alerted, self.logged)
        return tuple(d if s is None else s for s, d in zip(stated, default))  # type: ignore[return-value]


@dataclass
class TechniqueResult:
    technique_id: str
    name: str
    weight: float
    procedures: int
    detected: int
    prevented: int
    logged: int
    last_validated: date | None
    detection_rate: float  # D_t: alerted share, ignoring freshness
    prevention_rate: float  # verified (block event + reviewer)
    log_rate: float  # visibility: share of procedures with a verified log
    freshness: float  # F_t: mean freshness of the procedures' latest tests
    verified_rate: float  # V_t: mean of alerted * freshness per procedure
    contribution: float  # w_t * V_t
    residual: float  # w_t * (1 - V_t): what is left to win on this technique
    planned: int | None = None  # None when no plan was given
    executed_planned: int = 0
    unplanned: int = 0  # procedures run that were not in the plan
    execution_rate: float | None = None
    stale_share: float = 0.0  # detections that exist but have expired
    unverified: int = 0  # alerts/preventions without evidence, not counted
    ambiguous: int = 0  # latest record still needs a person to resolve the match
    prevention_rate_claimed: float = 0.0  # flags as recorded, without evidence
    log_rate_claimed: float = 0.0
    has_rule: bool | None = None
    previous_detection_rate: float | None = None


@dataclass
class Report:
    as_of: date
    freshness: str
    counts_prevented: bool
    requires_evidence: bool
    vdc: float
    techniques: list[TechniqueResult]
    plan_used: bool = False
    execution_rate: float | None = None
    freshness_debt: float = 0.0
    unverified: int = 0
    ambiguous: int = 0
    engagement_id: str = ""
    plan_id: str = ""
    plan_version: str = ""
    excluded_records: int = 0  # records of other engagements/plans, ignored
    prevention_claims_unverified: int = 0  # red team claimed, no block event
    vdc_previous: float | None = None
    freshness_debt_previous: float | None = None
    claimed_coverage: float | None = None
    claimed_coverage_weighted: float | None = None
    claim_gap: float | None = None
    detection_rate: float = 0.0
    prevention_rate: float = 0.0
    log_rate: float = 0.0
    prevention_rate_claimed: float = 0.0
    log_rate_claimed: float = 0.0
    regression_rate: float | None = None
    regressed: list[str] = field(default_factory=list)
    mean_days_to_remediate: float | None = None
    remediations: int = 0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["as_of"] = self.as_of.isoformat()
        for t in d["techniques"]:
            if t["last_validated"]:
                t["last_validated"] = t["last_validated"].isoformat()
        return d


def check_weights(weights: dict[str, tuple[str, float]]) -> None:
    if not weights:
        raise ValueError("no weighted techniques")
    for tid, (_, w) in weights.items():
        if not math.isfinite(w) or w < 0:
            raise ValueError(f"weight for {tid} must be a finite, non-negative number: {w}")
    total = sum(w for _, w in weights.values())
    if not math.isclose(total, 1.0, abs_tol=1e-6):
        raise ValueError(f"weights must sum to 1 (got {total})")


def load_weights(path: Path) -> dict[str, tuple[str, float]]:
    """Read technique_id, name, weight. Rows with an empty weight are skipped
    (they are outside the priority set). Weights must be finite, non-negative
    and unique per technique; they are renormalised to sum to 1."""
    raw: dict[str, tuple[str, float]] = {}
    with open(path, encoding="utf-8", newline="") as f:
        for i, r in enumerate(csv.DictReader(f), start=2):
            text = (r.get("weight") or "").strip()
            if not text:
                continue
            tid = r["technique_id"].strip()
            try:
                w = float(text)
            except ValueError:
                raise ValueError(f"{path}:{i}: weight is not a number: {text!r}") from None
            if not math.isfinite(w) or w < 0:
                raise ValueError(f"{path}:{i}: weight must be finite and non-negative: {text}")
            if tid in raw:
                raise ValueError(f"{path}:{i}: duplicate technique_id {tid}")
            raw[tid] = (r.get("name", ""), w)
    if not raw:
        raise ValueError(f"no weighted techniques in {path}")
    total = sum(w for _, w in raw.values())
    if total <= 0:
        raise ValueError(f"{path}: weights must sum to a positive number")
    return {t: (name, w / total) for t, (name, w) in raw.items()}


def _flag(value: str | None, path: Path, line: int, column: str) -> bool | None:
    text = (value or "").strip().lower()
    if not text:
        return None
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    raise ValueError(f"{path}:{line}: {column} must be true/false: {value!r}")


MATCH_STATUSES = {"", "confirmed", "ambiguous", "none"}


def load_validations(path: Path) -> list[Validation]:
    """Read technique_id, procedure_id, tested_on and/or tested_at, outcome[, notes,
    prevented, alerted, logged, run_id, rule_id, event_id, evidence_uri, verifier,
    engagement_id, plan_id, plan_version, match_status, log_event_id, prevention_claimed].

    tested_at needs a UTC offset; when both are given, tested_on must be its UTC date."""
    out = []
    with open(path, encoding="utf-8", newline="") as f:
        for i, r in enumerate(csv.DictReader(f), start=2):
            outcome = r["outcome"].strip().lower()
            if outcome not in OUTCOMES:
                raise ValueError(f"{path}:{i}: outcome must be one of {sorted(OUTCOMES)}")
            at_text = (r.get("tested_at") or "").strip()
            on_text = (r.get("tested_on") or "").strip()
            try:
                tested_at = parse_time(at_text) if at_text else None
            except ValueError as e:
                raise ValueError(f"{path}:{i}: tested_at: {e}") from None
            if not on_text and tested_at is None:
                raise ValueError(f"{path}:{i}: tested_on or tested_at is required")
            tested_on = date.fromisoformat(on_text) if on_text else tested_at.date()
            if tested_at is not None and tested_at.date() != tested_on:
                raise ValueError(f"{path}:{i}: tested_on {tested_on} is not the UTC date of "
                                 f"tested_at {at_text}")
            status = (r.get("match_status") or "").strip().lower()
            if status not in MATCH_STATUSES:
                raise ValueError(f"{path}:{i}: match_status must be confirmed/ambiguous/none: {status!r}")
            out.append(
                Validation(
                    r["technique_id"].strip(),
                    r["procedure_id"].strip(),
                    tested_on,
                    outcome,
                    (r.get("notes") or "").strip(),
                    _flag(r.get("prevented"), path, i, "prevented"),
                    _flag(r.get("alerted"), path, i, "alerted"),
                    _flag(r.get("logged"), path, i, "logged"),
                    (r.get("run_id") or "").strip(),
                    (r.get("rule_id") or "").strip(),
                    (r.get("event_id") or "").strip(),
                    (r.get("evidence_uri") or "").strip(),
                    (r.get("verifier") or "").strip(),
                    tested_at,
                    (r.get("engagement_id") or "").strip(),
                    (r.get("plan_id") or "").strip(),
                    (r.get("plan_version") or "").strip(),
                    status,
                    (r.get("log_event_id") or "").strip(),
                    _flag(r.get("prevention_claimed"), path, i, "prevention_claimed"),
                )
            )
    return out


def check_order(validations: list[Validation]) -> None:
    """Reject records whose order cannot be decided without the row order:
    two tests of the same procedure on the same day where either lacks
    tested_at, or both carry the same tested_at."""
    by_day: dict[tuple, list[Validation]] = {}
    for v in validations:
        if v.tested_at is not None and v.tested_at.tzinfo is None:
            raise ValueError(f"{v.technique_id}/{v.procedure_id}: tested_at needs a UTC offset")
        by_day.setdefault((v.technique_id, v.procedure_id, v.tested_on), []).append(v)
    for (tid, pid, day), vs in by_day.items():
        if len(vs) < 2:
            continue
        times = [v.tested_at for v in vs]
        if None in times:
            raise ValueError(f"{tid}/{pid} was tested more than once on {day}: "
                             "add tested_at (with UTC offset) to every record of that day")
        if len(set(times)) != len(times):
            raise ValueError(f"{tid}/{pid} has two records with the same tested_at on {day}")


def load_claimed(path: Path) -> set[str]:
    """Read technique_id, has_rule (true/false/1/0/yes/no)."""
    with open(path, encoding="utf-8", newline="") as f:
        return {
            r["technique_id"].strip()
            for r in csv.DictReader(f)
            if r["has_rule"].strip().lower() in _TRUE
        }


def freshness(age_days: int, mode: str = "step", window: int = 90, half_life: int = 90) -> float:
    if age_days < 0:
        raise ValueError("validation date is after the as-of date")
    if window < 0:
        raise ValueError("window must not be negative")
    if half_life <= 0:
        raise ValueError("half_life must be positive")
    if mode == "step":
        return 1.0 if age_days <= window else 0.0
    if mode == "exp":
        return 0.5 ** (age_days / half_life)
    raise ValueError(f"unknown freshness mode: {mode}")


def _resolve(tid: str, weights: dict) -> str | None:
    """Map a validation to a weighted technique, rolling sub-techniques up."""
    if tid in weights:
        return tid
    if parent_id(tid) in weights:
        return parent_id(tid)
    return None


def _latest(validations: list[Validation], weights: dict, as_of: date) -> dict[str, dict]:
    """technique -> procedure key -> latest Validation on or before as_of."""
    latest: dict[str, dict] = {}
    for v in validations:
        t = _resolve(v.technique_id, weights)
        if t is None or v.tested_on > as_of:
            continue
        key = (v.technique_id, v.procedure_id)
        cur = latest.setdefault(t, {}).get(key)
        if cur is None or v.order > cur.order:
            latest[t][key] = v
    return latest


def _claimed(v: Validation, counts_prevented: bool) -> bool:
    prevented, alerted, _ = v.flags()
    return alerted or (counts_prevented and prevented)


def _hit(v: Validation, counts_prevented: bool, requires_evidence: bool = True) -> bool:
    return _claimed(v, counts_prevented) and (v.has_evidence() or not requires_evidence)


def _remediation_days(
    validations: list[Validation], weights: dict, as_of: date, counts_prevented: bool,
    requires_evidence: bool,
) -> list[int]:
    """Days from a failed test of a procedure to the first later detected test of it."""
    history: dict[tuple, list[Validation]] = {}
    for v in validations:
        if _resolve(v.technique_id, weights) and v.tested_on <= as_of:
            history.setdefault((v.technique_id, v.procedure_id), []).append(v)
    days = []
    for runs in history.values():
        runs.sort(key=lambda v: v.order)
        failed_since = None
        for v in runs:
            if _hit(v, counts_prevented, requires_evidence):
                if failed_since is not None:
                    days.append((v.tested_on - failed_since).days)
                    failed_since = None
            elif failed_since is None:
                failed_since = v.tested_on
    return days


def _technique_results(
    weights: dict, validations: list[Validation], as_of: date, mode: str, window: int,
    half_life: int, counts_prevented: bool, requires_evidence: bool,
    planned: dict[str, set] | None,
) -> list[TechniqueResult]:
    latest = _latest(validations, weights, as_of)
    results = []
    for t, (name, w) in weights.items():
        runs = latest.get(t, {})
        plan_keys = planned.get(t, set()) if planned is not None else set()
        n = len(set(runs) | plan_keys) if planned is not None else len(runs)
        procs = list(runs.values())
        fresh = [freshness((as_of - v.tested_on).days, mode, window, half_life) for v in procs]
        hits = [_hit(v, counts_prevented, requires_evidence) for v in procs]
        flags = [v.flags() for v in procs]
        prevented_ok = [f[0] and (v.has_evidence() or not requires_evidence) for v, f in zip(procs, flags)]
        logged_ok = [f[2] and (v.has_log_evidence() or not requires_evidence) for v, f in zip(procs, flags)]
        k = len(procs)
        detected = sum(hits)
        verified = sum(f for f, h in zip(fresh, hits) if h) / n if n else 0.0
        stale = sum(1 - f for f, h in zip(fresh, hits) if h) / n if n else 0.0
        results.append(
            TechniqueResult(
                technique_id=t,
                name=name,
                weight=w,
                procedures=len(procs),
                detected=detected,
                prevented=sum(prevented_ok),
                logged=sum(logged_ok),
                last_validated=max((v.tested_on for v in procs), default=None),
                detection_rate=detected / k if k else 0.0,
                prevention_rate=sum(prevented_ok) / k if k else 0.0,
                log_rate=sum(logged_ok) / k if k else 0.0,
                freshness=sum(fresh) / len(procs) if procs else 0.0,
                verified_rate=verified,
                contribution=w * verified,
                residual=w * (1 - verified),
                planned=len(plan_keys) if planned is not None else None,
                executed_planned=len(set(runs) & plan_keys),
                unplanned=len(set(runs) - plan_keys) if planned is not None else 0,
                execution_rate=(len(set(runs) & plan_keys) / len(plan_keys) if plan_keys else 0.0)
                if planned is not None else None,
                stale_share=stale,
                unverified=sum(_claimed(v, counts_prevented) and not h and not v.ambiguous
                               for v, h in zip(procs, hits)),
                ambiguous=sum(v.ambiguous for v in procs),
                prevention_rate_claimed=sum(f[0] for f in flags) / k if k else 0.0,
                log_rate_claimed=sum(f[2] for f in flags) / k if k else 0.0,
            )
        )
    return results


def compute(
    weights: dict[str, tuple[str, float]],
    validations: list[Validation],
    as_of: date,
    mode: str = "step",
    window: int = 90,
    half_life: int = 90,
    claimed: set[str] | None = None,
    previous_as_of: date | None = None,
    counts_prevented: bool = False,
    requires_evidence: bool = True,
    plan: list[PlannedProcedure] | None = None,
) -> Report:
    """Compute VDC.

    By default only alerts count as detection (counts_prevented=True adds
    prevention) and only when backed by evidence (requires_evidence=False
    accepts self-reported results). With a plan, only records of the plan's
    engagement (and plan, when the record names one) count, and untested
    planned procedures count as misses.
    """
    check_weights(weights)
    freshness(0, mode, window, half_life)  # validate parameters even with no records
    check_order(validations)
    planned: dict[str, set] | None = None
    ident = ("", "", "")
    excluded = 0
    if plan is not None:
        ident = plan_identity(plan)
        engagement_id, plan_id, plan_version = ident
        kept = [
            v for v in validations
            if v.engagement_id == engagement_id
            and (not v.plan_id or v.plan_id == plan_id)
            and (not v.plan_version or v.plan_version == plan_version)
        ]
        excluded = len(validations) - len(kept)
        validations = kept
        planned = {}
        for p in plan:
            t = _resolve(p.technique_id, weights)
            if t:
                planned.setdefault(t, set()).add((p.technique_id, p.procedure_id))

    opts = dict(mode=mode, window=window, half_life=half_life, counts_prevented=counts_prevented,
                requires_evidence=requires_evidence, planned=planned)
    results = _technique_results(weights, validations, as_of, **opts)
    previous = (
        {r.technique_id: r for r in _technique_results(weights, validations, previous_as_of, **opts)}
        if previous_as_of else {}
    )
    for r in results:
        if previous_as_of:
            r.previous_detection_rate = previous[r.technique_id].detection_rate
        r.has_rule = (r.technique_id in claimed) if claimed is not None else None

    vdc = sum(r.contribution for r in results)
    if not -1e-9 <= vdc <= 1 + 1e-9:
        raise ValueError(f"VDC out of range: {vdc}")
    report = Report(
        as_of=as_of,
        freshness=f"step({window}d)" if mode == "step" else f"exp(half-life {half_life}d)",
        counts_prevented=counts_prevented,
        requires_evidence=requires_evidence,
        vdc=min(max(vdc, 0.0), 1.0),
        techniques=sorted(results, key=lambda r: (-round(r.residual, 9), r.technique_id)),
        plan_used=plan is not None,
        freshness_debt=sum(r.weight * r.stale_share for r in results),
        unverified=sum(r.unverified for r in results),
        ambiguous=sum(r.ambiguous for r in results),
        engagement_id=ident[0],
        plan_id=ident[1],
        plan_version=ident[2],
        excluded_records=excluded,
    )
    latest = [v for procs in _latest(validations, weights, as_of).values() for v in procs.values()]
    report.prevention_claims_unverified = sum(
        bool(v.prevention_claimed) and not (v.flags()[0] and v.has_evidence()) for v in latest
    )
    tested = sum(r.procedures for r in results)
    if tested:
        report.detection_rate = sum(r.detected for r in results) / tested
        report.prevention_rate = sum(r.prevented for r in results) / tested
        report.log_rate = sum(r.logged for r in results) / tested
        report.prevention_rate_claimed = sum(r.prevention_rate_claimed * r.procedures
                                             for r in results) / tested
        report.log_rate_claimed = sum(r.log_rate_claimed * r.procedures for r in results) / tested
    if planned is not None:
        total = sum(r.planned or 0 for r in results)
        report.execution_rate = sum(r.executed_planned for r in results) / total if total else 0.0

    if claimed is not None:
        report.claimed_coverage = sum(r.has_rule for r in results) / len(results)
        report.claimed_coverage_weighted = sum(r.weight for r in results if r.has_rule)
        report.claim_gap = report.claimed_coverage_weighted - report.vdc

    if previous_as_of:
        prev = previous.values()
        report.vdc_previous = sum(r.contribution for r in prev)
        report.freshness_debt_previous = sum(r.weight * r.stale_share for r in prev)
        before = [r for r in results if (r.previous_detection_rate or 0) > 0]
        report.regressed = sorted(
            r.technique_id for r in before if r.detection_rate < r.previous_detection_rate
        )
        report.regression_rate = len(report.regressed) / len(before) if before else 0.0

    days = _remediation_days(validations, weights, as_of, counts_prevented, requires_evidence)
    report.remediations = len(days)
    report.mean_days_to_remediate = sum(days) / len(days) if days else None
    return report


def format_text(report: Report) -> str:
    def pct(x: float | None) -> str:
        return "-" if x is None else f"{x * 100:.1f}%"

    detection = "アラート＋防御" if report.counts_prevented else "アラートのみ"
    evidence = "証跡必須" if report.requires_evidence else "自己申告も可"
    lines = [
        f"基準日: {report.as_of}  鮮度: {report.freshness}（手順ごと）  検知: {detection}（{evidence}）",
        f"VDC（検証済み検知カバレッジ）: {pct(report.vdc)}"
        + (f"  （前回 {pct(report.vdc_previous)}）" if report.vdc_previous is not None else ""),
    ]
    if report.plan_used:
        lines.append(
            f"検証計画: {report.plan_id} 版 {report.plan_version}（演習 {report.engagement_id}）  "
            f"実施率: {pct(report.execution_rate)}（未実施の計画手順は未検知として数える）"
        )
        if report.excluded_records:
            lines.append(f"対象外の記録: {report.excluded_records} 件（別の演習・計画の記録。数えていない）")
    else:
        lines.append("検証計画: なし（分母は実施した手順の数。少数の手順で高い値になり得る）")
    if report.claimed_coverage is not None:
        lines.append(
            f"自己申告カバレッジ: {pct(report.claimed_coverage)}（件数） / "
            f"{pct(report.claimed_coverage_weighted)}（重みつき）  申告ギャップ: {pct(report.claim_gap)}"
        )
    lines.append(
        f"実施した手順の割合（証跡あり）  検知: {pct(report.detection_rate)}  "
        f"防御: {pct(report.prevention_rate)}  ログ（可視性）: {pct(report.log_rate)}"
    )
    lines.append(
        f"（記録上の値・証跡なしを含む）  防御: {pct(report.prevention_rate_claimed)}  "
        f"ログ: {pct(report.log_rate_claimed)}"
    )
    if report.unverified:
        lines.append(f"証跡のない検知・防御: {report.unverified} 件（VDC に数えていない）")
    if report.ambiguous:
        lines.append(f"照合が曖昧で人の確認待ちの記録: {report.ambiguous} 件（VDC に数えていない）")
    if report.prevention_claims_unverified:
        lines.append(f"レッドチームが防御を申告したがブロックの証跡がない: "
                     f"{report.prevention_claims_unverified} 件")
    lines.append(
        f"鮮度の負債（検知できたが失効した分）: {pct(report.freshness_debt)}"
        + (f"  （前回 {pct(report.freshness_debt_previous)}）"
           if report.freshness_debt_previous is not None else "")
    )
    if report.regression_rate is not None:
        lines.append(
            f"回帰率（検知能力の低下）: {pct(report.regression_rate)}  "
            f"劣化した技術: {', '.join(report.regressed) or 'なし'}"
        )
    if report.mean_days_to_remediate is not None:
        lines.append(
            f"改善速度: 平均 {report.mean_days_to_remediate:.1f} 日（{report.remediations} 件）"
        )
    lines += [
        "",
        "優先度順（残り = w × (1 − V) の大きい順。V = 手順ごとの 検知 × 鮮度 の平均）",
        "technique     weight  plan  run      D      P    log      F      V  stale  contrib  resid  last        name",
    ]
    for r in report.techniques:
        last = r.last_validated.isoformat() if r.last_validated else "never     "
        plan = "-" if r.planned is None else str(r.planned)
        lines.append(
            f"{r.technique_id:<11} {r.weight:>8.3f} {plan:>5} {r.procedures:>4} {r.detection_rate:>6.2f} "
            f"{r.prevention_rate:>6.2f} {r.log_rate:>6.2f} {r.freshness:>6.2f} {r.verified_rate:>6.2f} "
            f"{r.stale_share:>6.2f} {r.contribution:>8.3f} {r.residual:>6.3f}  {last}  {r.name}"
        )
    return "\n".join(lines)


def navigator_layer(report: Report, name: str, attack_version: str = "") -> dict:
    """ATT&CK Navigator layer: score = V_t (0-1), comment carries the details."""
    layer = {
        "name": name,
        "domain": "enterprise-attack",
        "description": f"Verified Detection Coverage as of {report.as_of}: {report.vdc:.3f}",
        "versions": {"layer": "4.5", "navigator": "5.1.0"},
        "gradient": {"colors": ["#ff6666", "#ffe766", "#8ec843"], "minValue": 0, "maxValue": 1},
        "techniques": [
            {
                "techniqueID": r.technique_id,
                "score": round(r.verified_rate, 3),
                "comment": (
                    f"w={r.weight:.3f} V={r.verified_rate:.2f} D={r.detection_rate:.2f} "
                    f"P={r.prevention_rate:.2f} log={r.log_rate:.2f} F={r.freshness:.2f} "
                    f"procedures={r.procedures} last={r.last_validated or 'never'}"
                ),
                "metadata": [{"name": "weight", "value": f"{r.weight:.4f}"}],
            }
            for r in report.techniques
        ],
    }
    if attack_version:
        layer["versions"]["attack"] = attack_version
    return layer


def write_json(obj: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
