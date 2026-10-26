"""Command line interface: ``python -m sector_atks <command>``."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import date
from pathlib import Path

from . import attack as attack_mod
from . import sectors, vdc, weights


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
        w.writerow(["group_id", "group_name", "sector", "evidence"])
        for t in tags:
            w.writerow([t.group_id, t.group_name, t.sector, t.evidence])

    summary = []
    for sector, gids in by_sector.items():
        rows = weights.sector_weights(
            att, gids, args.top, args.subtechniques, prevalence, args.beta,
            frozenset() if args.include_pre_compromise else weights.PRE_COMPROMISE,
        )
        weights.write_weights(rows, out / "weights" / f"{sector}.csv")
        top = ", ".join(r.technique_id for r in rows[:5])
        summary.append([sector, sectors.SECTORS[sector][0], len(gids), len(rows), top])

    with open(out / "sector_summary.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["sector", "label_ja", "groups", "techniques", "top5"])
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
        "groups_tagged": len({t.group_id for t in tags}),
        "top_n": args.top,
        "subtechniques": args.subtechniques,
        "include_campaigns": not args.no_campaigns,
        "prevalence": args.prevalence,
        "beta": args.beta,
        "include_pre_compromise": args.include_pre_compromise,
    }
    vdc.write_json(meta, out / "build_info.json")
    for row in summary:
        print(f"{row[0]:<20} groups={row[2]:<3} techniques={row[3]:<4} top5={row[4]}")
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
        prevented_counts=not args.exclude_prevented,
    )
    print(vdc.format_text(report))
    if args.json:
        vdc.write_json(report.to_dict(), Path(args.json))
    if args.layer:
        vdc.write_json(
            vdc.navigator_layer(report, args.layer_name, args.attack_version), Path(args.layer)
        )


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
    v.add_argument("--exclude-prevented", action="store_true",
                   help="do not count prevented-without-alert as detected")
    v.add_argument("--json", help="write the full report as JSON")
    v.add_argument("--layer", help="write an ATT&CK Navigator layer")
    v.add_argument("--layer-name", default="Verified Detection Coverage")
    v.add_argument("--attack-version", default="", help="ATT&CK version for the layer")
    v.set_defaults(func=cmd_vdc)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except (ValueError, FileNotFoundError, KeyError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0
