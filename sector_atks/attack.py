"""Read the parts of an ATT&CK Enterprise STIX 2.1 bundle that this project needs.

Only public, descriptive data is used: techniques, groups (intrusion sets),
campaigns, the "uses" relationships between them, and the detection
strategies / analytics / data components introduced in ATT&CK v18.
"""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack{suffix}.json"
)


def download_stix(dest: Path, version: str | None = None) -> Path:
    """Download the Enterprise ATT&CK bundle (optionally a pinned version, e.g. "20.0")."""
    suffix = f"-{version}" if version else ""
    url = STIX_URL.format(suffix=suffix)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url) as resp, open(dest, "wb") as out:
        out.write(resp.read())
    return dest


def _external_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _active(obj: dict) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def parent_id(technique_id: str) -> str:
    """T1059.001 -> T1059."""
    return technique_id.split(".")[0]


@dataclass
class Technique:
    id: str
    name: str
    tactics: list[str]
    is_subtechnique: bool


@dataclass
class Group:
    id: str
    name: str
    aliases: list[str]
    description: str
    techniques: set[str] = field(default_factory=set)


@dataclass
class Attack:
    version: str
    modified: str
    techniques: dict[str, Technique]
    groups: dict[str, Group]
    # technique id -> sorted list of log source names from ATT&CK analytics
    log_sources: dict[str, list[str]]

    def technique_name(self, technique_id: str) -> str:
        t = self.techniques.get(technique_id)
        return t.name if t else ""


def load_attack(path: Path, include_campaigns: bool = True) -> Attack:
    """Parse a STIX bundle into techniques, groups and their observed techniques.

    A group's techniques are its direct "uses" relationships, plus (by default)
    those of campaigns attributed to it. Techniques reached only through
    software are not included, because software is often shared between groups.
    """
    with open(path, encoding="utf-8") as f:
        objects = json.load(f)["objects"]

    by_stix: dict[str, dict] = {o["id"]: o for o in objects}
    version, modified = "", ""
    techniques: dict[str, Technique] = {}
    groups: dict[str, Group] = {}
    stix_to_tid: dict[str, str] = {}
    stix_to_gid: dict[str, str] = {}

    for o in objects:
        if o["type"] == "x-mitre-collection":
            version, modified = o.get("x_mitre_version", ""), o.get("modified", "")
        if not _active(o):
            continue
        if o["type"] == "attack-pattern":
            tid = _external_id(o)
            if not tid:
                continue
            tactics = [p["phase_name"] for p in o.get("kill_chain_phases", [])]
            techniques[tid] = Technique(
                tid, o["name"], tactics, bool(o.get("x_mitre_is_subtechnique"))
            )
            stix_to_tid[o["id"]] = tid
        elif o["type"] == "intrusion-set":
            gid = _external_id(o)
            if not gid:
                continue
            groups[gid] = Group(
                gid, o["name"], o.get("aliases", []), o.get("description", "")
            )
            stix_to_gid[o["id"]] = gid

    rels = [o for o in objects if o["type"] == "relationship" and _active(o)]
    campaign_to_gids: dict[str, set[str]] = {}
    for r in rels:
        if r["relationship_type"] == "attributed-to" and r["target_ref"] in stix_to_gid:
            campaign_to_gids.setdefault(r["source_ref"], set()).add(
                stix_to_gid[r["target_ref"]]
            )

    detects: dict[str, set[str]] = {}  # detection strategy stix id -> technique ids
    for r in rels:
        src, tgt, kind = r["source_ref"], r["target_ref"], r["relationship_type"]
        if kind == "uses" and tgt in stix_to_tid:
            tid = stix_to_tid[tgt]
            if src in stix_to_gid:
                groups[stix_to_gid[src]].techniques.add(tid)
            elif include_campaigns and src in campaign_to_gids:
                for gid in campaign_to_gids[src]:
                    groups[gid].techniques.add(tid)
        elif kind == "detects" and tgt in stix_to_tid:
            detects.setdefault(src, set()).add(stix_to_tid[tgt])

    log_sources: dict[str, set[str]] = {}
    for strategy_id, tids in detects.items():
        strategy = by_stix.get(strategy_id, {})
        for analytic_id in strategy.get("x_mitre_analytic_refs", []):
            analytic = by_stix.get(analytic_id, {})
            for src in analytic.get("x_mitre_log_source_references", []):
                for tid in tids:
                    log_sources.setdefault(tid, set()).add(src["name"])

    return Attack(
        version=version,
        modified=modified,
        techniques=techniques,
        groups=groups,
        log_sources={k: sorted(v) for k, v in log_sources.items()},
    )
