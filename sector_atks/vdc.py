"""Verified Detection Coverage (VDC).

    VDC = sum over t in T of  w_t * D_t * F_t        (sum of w_t = 1)

w_t  weight of technique t (see weights.py)
D_t  share of tested procedures for t whose latest result was detected
F_t  freshness of the latest validation of t (step window or exponential decay)

Validation records are defensive test results only: which technique and
procedure variant was exercised, when, and how the defence responded. They
classify each result with the four outcomes used in the purple-team notes:
prevented (防御された), detected (検知された), logged (ログのみ), none (ログなし).
"""

from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass, field
from datetime import date
from pathlib import Path

from .attack import parent_id

OUTCOMES = {
    "prevented": "防御された",
    "detected": "検知された",
    "logged": "ログのみ",
    "none": "ログなし",
}


@dataclass(frozen=True)
class Validation:
    technique_id: str
    procedure_id: str
    tested_on: date
    outcome: str
    notes: str = ""


@dataclass
class TechniqueResult:
    technique_id: str
    name: str
    weight: float
    procedures: int
    detected: int
    visible: int
    last_validated: date | None
    detection_rate: float  # D_t
    visibility: float
    freshness: float  # F_t
    contribution: float  # w_t * D_t * F_t
    residual: float  # w_t * (1 - D_t * F_t): what is left to win on this technique
    has_rule: bool | None = None
    previous_detection_rate: float | None = None


@dataclass
class Report:
    as_of: date
    freshness: str
    vdc: float
    techniques: list[TechniqueResult]
    claimed_coverage: float | None = None
    claimed_coverage_weighted: float | None = None
    claim_gap: float | None = None
    visibility: float = 0.0
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


def load_weights(path: Path) -> dict[str, tuple[str, float]]:
    """Read technique_id, name, weight. Rows with an empty weight are skipped
    (they are outside the priority set). Weights are renormalised to sum to 1."""
    with open(path, encoding="utf-8", newline="") as f:
        rows = [r for r in csv.DictReader(f) if (r.get("weight") or "").strip()]
    if not rows:
        raise ValueError(f"no weighted techniques in {path}")
    total = sum(float(r["weight"]) for r in rows)
    if total <= 0:
        raise ValueError("weights must sum to a positive number")
    return {r["technique_id"]: (r.get("name", ""), float(r["weight"]) / total) for r in rows}


def load_validations(path: Path) -> list[Validation]:
    out = []
    with open(path, encoding="utf-8", newline="") as f:
        for i, r in enumerate(csv.DictReader(f), start=2):
            outcome = r["outcome"].strip().lower()
            if outcome not in OUTCOMES:
                raise ValueError(f"{path}:{i}: outcome must be one of {sorted(OUTCOMES)}")
            out.append(
                Validation(
                    r["technique_id"].strip(),
                    r["procedure_id"].strip(),
                    date.fromisoformat(r["tested_on"].strip()),
                    outcome,
                    (r.get("notes") or "").strip(),
                )
            )
    return out


def load_claimed(path: Path) -> set[str]:
    """Read technique_id, has_rule (true/false/1/0/yes/no)."""
    with open(path, encoding="utf-8", newline="") as f:
        return {
            r["technique_id"].strip()
            for r in csv.DictReader(f)
            if r["has_rule"].strip().lower() in ("1", "true", "yes", "y")
        }


def freshness(age_days: int, mode: str = "step", window: int = 90, half_life: int = 90) -> float:
    if age_days < 0:
        raise ValueError("validation date is after the as-of date")
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
        if cur is None or v.tested_on >= cur.tested_on:
            latest[t][key] = v
    return latest


def _detected_outcomes(prevented_counts: bool) -> set[str]:
    return {"detected", "prevented"} if prevented_counts else {"detected"}


def detection_rates(
    validations: list[Validation], weights: dict, as_of: date, prevented_counts: bool = True
) -> dict[str, float]:
    hit = _detected_outcomes(prevented_counts)
    return {
        t: sum(v.outcome in hit for v in procs.values()) / len(procs)
        for t, procs in _latest(validations, weights, as_of).items()
        if procs
    }


def _remediation_days(validations: list[Validation], weights: dict, as_of: date, hit: set[str]) -> list[int]:
    """Days from a failed test of a procedure to the first later detected test of it."""
    history: dict[tuple, list[Validation]] = {}
    for v in validations:
        if _resolve(v.technique_id, weights) and v.tested_on <= as_of:
            history.setdefault((v.technique_id, v.procedure_id), []).append(v)
    days = []
    for runs in history.values():
        runs.sort(key=lambda v: v.tested_on)
        failed_since = None
        for v in runs:
            if v.outcome in hit:
                if failed_since is not None:
                    days.append((v.tested_on - failed_since).days)
                    failed_since = None
            elif failed_since is None:
                failed_since = v.tested_on
    return days


def compute(
    weights: dict[str, tuple[str, float]],
    validations: list[Validation],
    as_of: date,
    mode: str = "step",
    window: int = 90,
    half_life: int = 90,
    claimed: set[str] | None = None,
    previous_as_of: date | None = None,
    prevented_counts: bool = True,
) -> Report:
    hit = _detected_outcomes(prevented_counts)
    latest = _latest(validations, weights, as_of)
    previous = (
        detection_rates(validations, weights, previous_as_of, prevented_counts)
        if previous_as_of
        else {}
    )

    results = []
    for t, (name, w) in weights.items():
        procs = list(latest.get(t, {}).values())
        n = len(procs)
        detected = sum(v.outcome in hit for v in procs)
        visible = sum(v.outcome != "none" for v in procs)
        last = max((v.tested_on for v in procs), default=None)
        d = detected / n if n else 0.0
        f = freshness((as_of - last).days, mode, window, half_life) if last else 0.0
        results.append(
            TechniqueResult(
                technique_id=t,
                name=name,
                weight=w,
                procedures=n,
                detected=detected,
                visible=visible,
                last_validated=last,
                detection_rate=d,
                visibility=visible / n if n else 0.0,
                freshness=f,
                contribution=w * d * f,
                residual=w * (1 - d * f),
                has_rule=(t in claimed) if claimed is not None else None,
                previous_detection_rate=previous.get(t) if previous_as_of else None,
            )
        )

    report = Report(
        as_of=as_of,
        freshness=f"step({window}d)" if mode == "step" else f"exp(half-life {half_life}d)",
        vdc=sum(r.contribution for r in results),
        techniques=sorted(results, key=lambda r: (-round(r.residual, 9), r.technique_id)),
    )
    tested = sum(r.procedures for r in results)
    report.visibility = sum(r.visible for r in results) / tested if tested else 0.0

    if claimed is not None:
        report.claimed_coverage = sum(r.has_rule for r in results) / len(results)
        report.claimed_coverage_weighted = sum(r.weight for r in results if r.has_rule)
        report.claim_gap = report.claimed_coverage_weighted - report.vdc

    if previous_as_of:
        before = [r for r in results if (r.previous_detection_rate or 0) > 0]
        report.regressed = sorted(
            r.technique_id
            for r in before
            if r.technique_id in latest and r.detection_rate < r.previous_detection_rate
        )
        report.regression_rate = len(report.regressed) / len(before) if before else 0.0

    days = _remediation_days(validations, weights, as_of, hit)
    report.remediations = len(days)
    report.mean_days_to_remediate = sum(days) / len(days) if days else None
    return report


def format_text(report: Report) -> str:
    def pct(x: float | None) -> str:
        return "-" if x is None else f"{x * 100:.1f}%"

    lines = [
        f"基準日: {report.as_of}  鮮度: {report.freshness}",
        f"VDC（検証済み検知カバレッジ）: {pct(report.vdc)}",
    ]
    if report.claimed_coverage is not None:
        lines.append(
            f"自己申告カバレッジ: {pct(report.claimed_coverage)}（件数） / "
            f"{pct(report.claimed_coverage_weighted)}（重みつき）  申告ギャップ: {pct(report.claim_gap)}"
        )
    lines.append(f"可視性（ログが残った手順の割合）: {pct(report.visibility)}")
    if report.regression_rate is not None:
        lines.append(
            f"回帰率: {pct(report.regression_rate)}  劣化した技術: {', '.join(report.regressed) or 'なし'}"
        )
    if report.mean_days_to_remediate is not None:
        lines.append(
            f"改善速度: 平均 {report.mean_days_to_remediate:.1f} 日（{report.remediations} 件）"
        )
    lines += [
        "",
        "優先度順（残り = w × (1 − D × F) の大きい順）",
        f"{'技術':<11} {'重み':>6} {'手順':>4} {'D':>6} {'可視性':>6} {'F':>5} "
        f"{'寄与':>6} {'残り':>6}  最終検証    名前",
    ]
    for r in report.techniques:
        last = r.last_validated.isoformat() if r.last_validated else "未検証    "
        lines.append(
            f"{r.technique_id:<11} {r.weight:>6.3f} {r.procedures:>4} {r.detection_rate:>6.2f} "
            f"{r.visibility:>6.2f} {r.freshness:>5.2f} {r.contribution:>6.3f} {r.residual:>6.3f}  "
            f"{last}  {r.name}"
        )
    return "\n".join(lines)


def navigator_layer(report: Report, name: str, attack_version: str = "") -> dict:
    """ATT&CK Navigator layer: score = D_t * F_t (0-1), comment carries the details."""
    layer = {
        "name": name,
        "domain": "enterprise-attack",
        "description": f"Verified Detection Coverage as of {report.as_of}: {report.vdc:.3f}",
        "versions": {"layer": "4.5", "navigator": "5.1.0"},
        "gradient": {"colors": ["#ff6666", "#ffe766", "#8ec843"], "minValue": 0, "maxValue": 1},
        "techniques": [
            {
                "techniqueID": r.technique_id,
                "score": round(r.detection_rate * r.freshness, 3),
                "comment": (
                    f"w={r.weight:.3f} D={r.detection_rate:.2f} F={r.freshness:.2f} "
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
