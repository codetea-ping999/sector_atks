"""Build per-sector technique weights (w_t in the VDC definition).

For a sector s with tagged groups G_s, the base signal for technique t is

    share_s(t) = |{g in G_s : g uses t}| / |G_s|

optionally blended with an external prevalence signal p(t) in [0, 1]
(e.g. CTID Top ATT&CK Techniques or Sightings):

    score_s(t) = (1 - beta) * share_s(t) + beta * p(t)

Techniques whose tactics are all pre-compromise (reconnaissance, resource
development) are left out by default: they happen outside the defender's
environment, so an in-house detection test cannot verify them.

The top-N techniques by score form the priority set T, and their scores are
normalised so that the weights sum to 1.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

from .attack import Attack, parent_id

PRE_COMPROMISE = frozenset({"reconnaissance", "resource-development"})


@dataclass
class WeightRow:
    rank: int
    technique_id: str
    name: str
    groups_using: int
    share: float  # share of the sector's groups that use the technique
    lift: float  # share in sector / share across all groups
    prevalence: float
    score: float
    weight: float | None  # None when outside the top-N priority set


def group_techniques(attack: Attack, subtechniques: bool) -> dict[str, set[str]]:
    if subtechniques:
        return {gid: set(g.techniques) for gid, g in attack.groups.items()}
    return {gid: {parent_id(t) for t in g.techniques} for gid, g in attack.groups.items()}


def _shares(group_ids: set[str], usage: dict[str, set[str]]) -> dict[str, tuple[int, float]]:
    counts: dict[str, int] = {}
    for gid in group_ids:
        for t in usage.get(gid, ()):
            counts[t] = counts.get(t, 0) + 1
    n = len(group_ids) or 1
    return {t: (c, c / n) for t, c in counts.items()}


def load_prevalence(path: Path) -> dict[str, float]:
    """Read ``technique_id,prevalence`` rows; values are rescaled to [0, 1]."""
    with open(path, encoding="utf-8", newline="") as f:
        raw = {r["technique_id"]: float(r["prevalence"]) for r in csv.DictReader(f)}
    top = max(raw.values(), default=0.0) or 1.0
    return {t: v / top for t, v in raw.items()}


def sector_weights(
    attack: Attack,
    sector_groups: set[str],
    top_n: int = 20,
    subtechniques: bool = False,
    prevalence: dict[str, float] | None = None,
    beta: float = 0.0,
    exclude_tactics: frozenset[str] = PRE_COMPROMISE,
) -> list[WeightRow]:
    if not 0.0 <= beta <= 1.0:
        raise ValueError("beta must be between 0 and 1")
    usage = group_techniques(attack, subtechniques)
    in_sector = _shares(sector_groups, usage)
    overall = _shares(set(attack.groups), usage)
    prevalence = prevalence or {}

    rows = []
    for t, (count, share) in in_sector.items():
        tech = attack.techniques.get(t)
        if tech and tech.tactics and set(tech.tactics) <= exclude_tactics:
            continue
        p = prevalence.get(t, 0.0)
        base = overall[t][1]
        rows.append(
            WeightRow(
                rank=0,
                technique_id=t,
                name=attack.technique_name(t),
                groups_using=count,
                share=share,
                lift=share / base if base else 0.0,
                prevalence=p,
                score=(1 - beta) * share + beta * p,
                weight=None,
            )
        )
    rows.sort(key=lambda r: (-r.score, -r.lift, r.technique_id))
    total = sum(r.score for r in rows[:top_n]) or 1.0
    for i, r in enumerate(rows, start=1):
        r.rank = i
        if i <= top_n:
            r.weight = r.score / total
    return rows


def write_weights(rows: list[WeightRow], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(
            ["rank", "technique_id", "name", "groups_using", "share", "lift",
             "prevalence", "score", "weight"]
        )
        for r in rows:
            w.writerow([
                r.rank, r.technique_id, r.name, r.groups_using, f"{r.share:.4f}",
                f"{r.lift:.3f}", f"{r.prevalence:.4f}", f"{r.score:.4f}",
                "" if r.weight is None else f"{r.weight:.4f}",
            ])
