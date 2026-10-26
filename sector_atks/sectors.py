"""Tag ATT&CK groups with the sectors they are reported to target.

ATT&CK does not carry a structured "targeted sector" field, so sectors are
inferred from each group's description with keyword patterns. Every tag keeps
the matched phrase so it can be reviewed, and a manual override file can add
or remove tags (see ``load_overrides``).
"""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from pathlib import Path

from .attack import Group

# A generic sector word only counts when it reads as a victim category, i.e.
# it is followed by a list separator or a noun such as "sector" or "companies".
_AS_VICTIM = r"(?=,| and\b| or\b|\.|;| sectors?\b| industr| organi[sz]ation| compan| entit| firm| institution| agenc| provider| target)"

# Sector id -> (Japanese label, regex). Patterns avoid phrases that describe
# motive or tradecraft rather than victims, e.g. "financially motivated",
# "mining cryptocurrency", "social media accounts" or "nuclear policy".
SECTORS: dict[str, tuple[str, str]] = {
    "finance": (
        "金融",
        r"\bbank(s|ing)?\b|\bfinanc(e|ial)\b" + _AS_VICTIM
        + r"|\bfintech\b|(?<!mining )cryptocurrenc(y|ies)\b(?! min)|\binsurance\b|\bSWIFT\b|\bATMs?\b",
    ),
    "government": (
        "政府・行政",
        r"(?<!non-)(?<!non )\bgovernment|\bministr(y|ies)\b|diplomat|\bembass(y|ies)\b|public sector"
        r"|\bpolitical (organi[sz]ation|part)",
    ),
    "defense": (
        "防衛・航空宇宙",
        r"\bdefen[cs]e\b" + _AS_VICTIM + r"|\bdefen[cs]e (industr|contractor)|\bmilitary\b|\baerospace\b",
    ),
    "energy": (
        "エネルギー",
        r"\benergy\b|\boil\b|natural gas|\belectric(ity|al)? (utilit|grid|sector|compan)"
        r"|\butilit(y|ies)\b" + _AS_VICTIM
        + r"|power (grid|plant|compan)|nuclear (facilit|plant|power|sector)|petro(leum|chemical)",
    ),
    "healthcare": (
        "医療・製薬",
        r"\bhealth ?care\b|\bhospitals?\b|\bmedical\b|pharmaceutical|biomedical|biotechnology",
    ),
    "telecommunications": (
        "通信",
        r"\btelecom|internet service provider|satellite communication",
    ),
    "technology": (
        "IT・テクノロジー",
        r"\btechnology\b" + _AS_VICTIM + r"|\bhigh[- ]tech\b|\bIT (sector|compan|service)"
        r"|managed (IT )?service provider|\bMSPs?\b|\bsoftware\b" + _AS_VICTIM
        + r"|\bsoftware (vendor|develop)|semiconductor|cloud service",
    ),
    "manufacturing": (
        "製造",
        r"\bmanufactur|\bindustrial\b|\bautomotive\b|\bautomobile\b|\bchemical\b" + _AS_VICTIM,
    ),
    "education": (
        "教育・研究",
        r"\beducation|\buniversit(y|ies)\b|\bacademi[ac]|think tank|research (institut|organi[sz]ation|center)",
    ),
    "transportation": (
        "運輸・物流",
        r"\btransportation\b|\baviation\b|\bairlines?\b|\bmaritime\b|\bshipping\b|\blogistics\b"
        r"|\btravel\b" + _AS_VICTIM,
    ),
    "retail_hospitality": (
        "小売・宿泊・飲食",
        r"\bretail|\bhospitality\b|\bhotels?\b|\brestaurants?\b|point[- ]of[- ]sale|\be-?commerce\b",
    ),
    "media": (
        "メディア",
        r"(?<!social )\bmedia\b" + _AS_VICTIM + r"|\bmedia outlet|\bjournalist|\bnews (organi[sz]ation|outlet|agenc)",
    ),
    "civil_society": (
        "NGO・市民社会",
        r"\bNGOs?\b|non-?governmental organi[sz]ation|\bdissident|\bactivist|human rights",
    ),
}

_COMPILED = {s: re.compile(p, re.IGNORECASE) for s, (_, p) in SECTORS.items()}
# Only text after a victimology cue is searched, so that attribution clauses
# ("attributed to the Ministry of State Security", "military unit 74455") are
# not mistaken for targets.
_CUE = re.compile(
    r"\btarget|\battack|\bagainst\b|\bvictim|\bcompromis|\bintrusion|\bfocus"
    r"|\bbreach|\bspanning\b|\bsectors?\b|\bindustries\b",
    re.IGNORECASE,
)
_SENTENCE = re.compile(r"(?<=[.!?])\s+")
_CITATION = re.compile(r"\(Citation:[^)]*\)")
_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")


@dataclass
class SectorTag:
    group_id: str
    group_name: str
    sector: str
    evidence: str  # matched phrase, or "manual" for an override


def _clean(text: str) -> str:
    return _LINK.sub(r"\1", _CITATION.sub("", text))


def victimology(description: str) -> list[str]:
    """The parts of each sentence that follow a targeting cue."""
    spans = []
    for sentence in _SENTENCE.split(_clean(description)):
        cue = _CUE.search(sentence)
        if cue:
            spans.append(sentence[cue.start():])
    return spans


def tag_group(group: Group) -> list[SectorTag]:
    spans = victimology(group.description)
    tags = []
    for sector, pattern in _COMPILED.items():
        for span in spans:
            m = pattern.search(span)
            if m:
                tags.append(SectorTag(group.id, group.name, sector, m.group(0)))
                break
    return tags


def load_overrides(path: Path) -> list[tuple[str, str, str]]:
    """Read ``group_id,sector,action`` rows where action is ``add`` or ``remove``."""
    with open(path, encoding="utf-8", newline="") as f:
        rows = [r for r in csv.DictReader(f) if not r["group_id"].startswith("#")]
    for r in rows:
        if r["sector"] not in SECTORS:
            raise ValueError(f"unknown sector in overrides: {r['sector']}")
        if r["action"] not in ("add", "remove"):
            raise ValueError(f"action must be add or remove: {r['action']}")
    return [(r["group_id"], r["sector"], r["action"]) for r in rows]


def tag_groups(
    groups: dict[str, Group], overrides: list[tuple[str, str, str]] | None = None
) -> list[SectorTag]:
    tags = {(t.group_id, t.sector): t for g in groups.values() for t in tag_group(g)}
    for gid, sector, action in overrides or []:
        if action == "remove":
            tags.pop((gid, sector), None)
        elif gid in groups:
            tags[(gid, sector)] = SectorTag(gid, groups[gid].name, sector, "manual")
    return sorted(tags.values(), key=lambda t: (t.sector, t.group_id))


def groups_by_sector(tags: list[SectorTag]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {s: set() for s in SECTORS}
    for t in tags:
        out[t.sector].add(t.group_id)
    return out
