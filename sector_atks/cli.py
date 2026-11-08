"""Command line interface: ``python -m sector_atks <command>``."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import date
from pathlib import Path

from . import attack as attack_mod
from . import engagement, evidence, sectors, vdc, weights


def cmd_fetch_attack(args: argparse.Namespace) -> None:
    path = attack_mod.download_stix(Path(args.output), args.version)
    print(f"saved {path}")


def cmd_ctid_prevalence(args: argparse.Namespace) -> None:
    """Extract technique prevalence from CTID Top ATT&CK Techniques' Techniques.json."""
    data = json.loads(Path(args.techniques_json).read_text(encoding="utf-8"))
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["technique_id", "name", "prevalence"])
        for t in sorted(data, key=lambda t: t["tid"]):
            w.writerow([t["tid"], t["name"], t["prevalence_score"]])
    print(f"wrote {len(data)} techniques to {out}")


def cmd_build_weights(args: argparse.Namespace) -> None:
    att = attack_mod.load_attack(Path(args.stix), include_campaigns=not args.no_campaigns)
    overrides = sectors.load_overrides(Path(args.overrides)) if args.overrides else None
    tags = sectors.tag_groups(att.groups, overrides)
    by_sector = sectors.groups_by_sector(tags)
    prevalence = weights.load_prevalence(Path(args.prevalence)) if args.prevalence else None
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    with open(out / "group_sectors.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["group_id", "group_name", "sector", "evidence", "sentence", "source"])
        for t in tags:
            w.writerow([t.group_id, t.group_name, t.sector, t.evidence, t.sentence, t.source])

    tagged = {t.group_id for t in tags}
    untagged = sorted(set(att.groups) - tagged)
    with open(out / "untagged_groups.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["group_id", "group_name", "techniques", "source"])
        for gid in untagged:
            g = att.groups[gid]
            w.writerow([gid, g.name, len(g.techniques), f"https://attack.mitre.org/groups/{gid}/"])

    opts = dict(
        top_n=args.top,
        subtechniques=args.subtechniques,
        prevalence=prevalence,
        beta=args.beta,
        exclude_tactics=frozenset() if args.include_pre_compromise else weights.PRE_COMPROMISE,
    )
    baseline = weights.sector_weights(att, set(att.groups), **opts)
    weights.write_weights(baseline, out / "weights" / "_all_groups.csv")
    base_top = weights.top_set(baseline)
    tagged_top = weights.top_set(weights.sector_weights(att, tagged, **opts))
    untagged_top = weights.top_set(weights.sector_weights(att, set(untagged), **opts))

    loose = sectors.groups_by_sector(sectors.tag_groups(att.groups, overrides, strict=False))
    summary = []
    for sector, gids in by_sector.items():
        rows = weights.sector_weights(att, gids, **opts)
        loose_top = weights.top_set(weights.sector_weights(att, loose[sector], **opts))
        weights.write_weights(rows, out / "weights" / f"{sector}.csv")
        top = ", ".join(r.technique_id for r in rows[:5])
        summary.append([
            sector, sectors.SECTORS[sector][0], len(gids),
            "yes" if len(gids) < weights.MIN_GROUPS else "no",
            f"{weights.jaccard(weights.top_set(rows), base_top):.2f}",
            f"{weights.bootstrap_stability(att, gids, **opts):.2f}",
            len(loose[sector]),
            f"{weights.jaccard(weights.top_set(rows), loose_top):.2f}",
            len(rows), top,
        ])

    with open(out / "sector_summary.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["sector", "label_ja", "groups", "low_n", "overlap_with_all_groups",
                    "bootstrap_stability", "groups_loose_rule", "overlap_with_loose_rule",
                    "techniques", "top5"])
        w.writerows(summary)

    with open(out / "log_sources.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["technique_id", "name", "log_sources"])
        for tid in sorted(att.log_sources):
            w.writerow([tid, att.technique_name(tid), "; ".join(att.log_sources[tid])])

    meta = {
        "attack_version": att.version,
        "attack_modified": att.modified,
        "groups": len(att.groups),
        "groups_tagged": len(tagged),
        "groups_untagged": len(untagged),
        "untagged_vs_tagged_top_overlap": round(weights.jaccard(tagged_top, untagged_top), 3),
        "min_groups_for_stable_sector": weights.MIN_GROUPS,
        "top_n": args.top,
        "subtechniques": args.subtechniques,
        "include_campaigns": not args.no_campaigns,
        "prevalence": args.prevalence,
        "beta": args.beta,
        "include_pre_compromise": args.include_pre_compromise,
    }
    vdc.write_json(meta, out / "build_info.json")
    for row in summary:
        print(f"{row[0]:<20} groups={row[2]:<3} low_n={row[3]:<3} overlap={row[4]} "
              f"stability={row[5]} loose={row[6]}/{row[7]} top5={row[9]}")
    print(f"ATT&CK v{att.version}: wrote {out}")


def cmd_vdc(args: argparse.Namespace) -> None:
    w = vdc.load_weights(Path(args.weights))
    report = vdc.compute(
        w,
        vdc.load_validations(Path(args.validations)),
        as_of=date.fromisoformat(args.as_of) if args.as_of else date.today(),
        mode=args.freshness,
        window=args.window,
        half_life=args.half_life,
        claimed=vdc.load_claimed(Path(args.claimed)) if args.claimed else None,
        previous_as_of=date.fromisoformat(args.previous_as_of) if args.previous_as_of else None,
        counts_prevented=args.count_prevented,
        requires_evidence=not args.allow_unverified,
        plan=engagement.load_plan(Path(args.plan)) if args.plan else None,
    )
    print(vdc.format_text(report))
    if args.json:
        vdc.write_json(report.to_dict(), Path(args.json))
    if args.layer:
        vdc.write_json(
            vdc.navigator_layer(report, args.layer_name, args.attack_version), Path(args.layer)
        )


def cmd_check_roe(args: argparse.Namespace) -> None:
    data = json.loads(Path(args.roe).read_text(encoding="utf-8"))
    problems = engagement.check_roe(data)
    if problems:
        raise ValueError("incomplete rules of engagement:\n  " + "\n  ".join(problems))
    print(f"OK: {data['engagement_id']} ({data['environment']}, "
          f"{len(data['scope']['hosts'])} hosts, {data['window']['start']} - {data['window']['end']})")


def cmd_match_evidence(args: argparse.Namespace) -> None:
    roe = engagement.load_roe(Path(args.roe))
    result = evidence.match(
        evidence.load_runs(Path(args.runs)),
        evidence.load_events(Path(args.alerts)),
        evidence.load_events(Path(args.logs)) if args.logs else None,
        roe=roe,
        verifier=args.verifier,
        grace_seconds=args.grace,
    )
    evidence.write_validations(result.rows, Path(args.output))
    print(f"{len(result.rows)} runs matched -> {args.output}")
    for run_id, reason in result.rejected:
        print(f"rejected {run_id}: {reason}", file=sys.stderr)
    if result.unmatched_alerts:
        print(f"{len(result.unmatched_alerts)} alerts did not match any run "
              f"(first: {', '.join(result.unmatched_alerts[:5])})")
    if result.rejected:
        raise ValueError(f"{len(result.rejected)} runs were outside the rules of engagement")


def _read_catalog(path: Path) -> list[dict]:
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(line for line in f if not line.startswith("#")))


def cmd_plan_candidates(args: argparse.Namespace) -> None:
    """List public emulation plans that cover each priority technique."""
    w = vdc.load_weights(Path(args.weights))
    catalog = _read_catalog(Path(args.catalog))
    sector_groups: set[str] = set()
    if args.group_sectors and args.sector:
        with open(args.group_sectors, encoding="utf-8", newline="") as f:
            sector_groups = {r["group_id"] for r in csv.DictReader(f) if r["sector"] == args.sector}

    def covers(plan: dict, tid: str) -> bool:
        return any(attack_mod.parent_id(t) == tid or t == tid for t in plan["techniques"].split(";"))

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8", newline="") as f:
        cw = csv.writer(f)
        cw.writerow(["technique_id", "name", "weight", "micro_plans", "sector_group_plans",
                     "other_full_plans"])
        for tid, (name, weight) in sorted(w.items(), key=lambda kv: -kv[1][1]):
            plans = [p for p in catalog if covers(p, tid)]
            micro = [p["plan"] for p in plans if p["kind"] == "micro"]
            full = [p for p in plans if p["kind"] == "full"]
            in_sector = [f"{p['plan']}({p['group_id']})" for p in full if p["group_id"] in sector_groups]
            other = [p["plan"] for p in full if p["group_id"] not in sector_groups]
            cw.writerow([tid, name, f"{weight:.4f}", ";".join(micro), ";".join(in_sector),
                         ";".join(other)])
    print(f"wrote {out}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sector_atks", description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)

    f = sub.add_parser("fetch-attack", help="download the Enterprise ATT&CK STIX bundle")
    f.add_argument("--version", help='pin a release, e.g. "20.0" (default: latest)')
    f.add_argument("-o", "--output", default="cache/enterprise-attack.json")
    f.set_defaults(func=cmd_fetch_attack)

    c = sub.add_parser("ctid-prevalence", help="extract prevalence from CTID Top ATT&CK Techniques")
    c.add_argument("techniques_json", help="src/data/Techniques.json from that repository")
    c.add_argument("-o", "--output", default="data/ctid/top_attack_prevalence.csv")
    c.set_defaults(func=cmd_ctid_prevalence)

    b = sub.add_parser("build-weights", help="tag groups by sector and build weight files")
    b.add_argument("--stix", required=True)
    b.add_argument("--out-dir", required=True)
    b.add_argument("--overrides", help="CSV of manual group_id,sector,action corrections")
    b.add_argument("--top", type=int, default=20, help="size of the priority set T")
    b.add_argument("--subtechniques", action="store_true", help="weight sub-techniques separately")
    b.add_argument("--include-pre-compromise", action="store_true",
                   help="keep reconnaissance / resource-development techniques")
    b.add_argument("--no-campaigns", action="store_true", help="ignore attributed campaigns")
    b.add_argument("--prevalence", help="CSV of technique_id,prevalence to blend in")
    b.add_argument("--beta", type=float, default=0.0, help="blend factor for --prevalence")
    b.set_defaults(func=cmd_build_weights)

    v = sub.add_parser("vdc", help="compute Verified Detection Coverage")
    v.add_argument("--weights", required=True)
    v.add_argument("--validations", required=True)
    v.add_argument("--as-of", help="YYYY-MM-DD (default: today)")
    v.add_argument("--claimed", help="CSV of technique_id,has_rule for the claim gap")
    v.add_argument("--previous-as-of", help="earlier date to measure regression against")
    v.add_argument("--freshness", choices=["step", "exp"], default="step")
    v.add_argument("--window", type=int, default=90, help="days for step freshness")
    v.add_argument("--half-life", type=int, default=90, help="days for exp freshness")
    v.add_argument("--plan", help="CSV test plan; untested planned procedures count as misses")
    v.add_argument("--allow-unverified", action="store_true",
                   help="count alerts without event_id/evidence_uri and verifier (not recommended)")
    v.add_argument("--count-prevented", action="store_true",
                   help="also count prevention without an alert as detected (default: alerts only)")
    v.add_argument("--json", help="write the full report as JSON")
    v.add_argument("--layer", help="write an ATT&CK Navigator layer")
    v.add_argument("--layer-name", default="Verified Detection Coverage")
    v.add_argument("--attack-version", default="", help="ATT&CK version for the layer")
    v.set_defaults(func=cmd_vdc)

    r = sub.add_parser("check-roe", help="check that rules of engagement are complete")
    r.add_argument("roe", help="RoE JSON file")
    r.set_defaults(func=cmd_check_roe)

    m = sub.add_parser("match-evidence", help="match run records with SIEM/EDR exports")
    m.add_argument("--roe", required=True, help="RoE JSON; runs outside it are rejected")
    m.add_argument("--runs", required=True)
    m.add_argument("--alerts", required=True)
    m.add_argument("--logs", help="optional telemetry export for visibility")
    m.add_argument("--verifier", required=True, help="who reviewed the matches")
    m.add_argument("--grace", type=int, default=300, help="seconds after a run to accept events")
    m.add_argument("-o", "--output", default="out/validations.csv")
    m.set_defaults(func=cmd_match_evidence)

    c2 = sub.add_parser("plan-candidates", help="public emulation plans per priority technique")
    c2.add_argument("--weights", required=True)
    c2.add_argument("--catalog", default="data/emulation/ctid_catalog.csv")
    c2.add_argument("--group-sectors", help="group_sectors.csv to find plans for the sector's groups")
    c2.add_argument("--sector", help="sector id matching the weights file")
    c2.add_argument("-o", "--output", default="out/plan_candidates.csv")
    c2.set_defaults(func=cmd_plan_candidates)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except (ValueError, FileNotFoundError, KeyError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0
