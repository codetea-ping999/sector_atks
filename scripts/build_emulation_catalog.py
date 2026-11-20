"""Build data/emulation/ctid_catalog.csv from a local clone of
center-for-threat-informed-defense/adversary_emulation_library.

Only references are extracted: plan name, URL, emulated ATT&CK group and the
technique IDs that the plan documentation mentions. No plan content is copied.

    python3 scripts/build_emulation_catalog.py path/to/adversary_emulation_library
"""

import csv
import re
import subprocess
import sys
from pathlib import Path

BASE = "https://github.com/center-for-threat-informed-defense/adversary_emulation_library/tree/master/"
TECHNIQUE = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b")
GROUP = re.compile(r"attack\.mitre\.org/groups/(G\d{4})")
TEXT = {".md", ".yaml", ".yml", ".json", ".txt"}
FULL_PLANS = {"menu_pass": "G0045"}  # README does not link the group page


def techniques(root: Path) -> list[str]:
    found = set()
    for path in root.rglob("*"):
        if path.is_file() and path.suffix.lower() in TEXT:
            found.update(TECHNIQUE.findall(path.read_text(encoding="utf-8", errors="ignore")))
    return sorted(found)


def main(lib: Path, out: Path) -> None:
    rows = []
    for plan in sorted((lib / "micro_emulation_plans" / "src").iterdir()):
        if plan.is_dir():
            rows.append(["micro", plan.name, "", BASE + f"micro_emulation_plans/src/{plan.name}",
                         ";".join(techniques(plan))])
    for plan in sorted(lib.iterdir()):
        readme = plan / "README.md"
        if not plan.is_dir() or plan.name in {"micro_emulation_plans", "resources", "structure"} \
                or not readme.exists():
            continue
        groups = GROUP.findall(readme.read_text(encoding="utf-8", errors="ignore"))
        group = FULL_PLANS.get(plan.name) or (max(set(groups), key=groups.count) if groups else "")
        rows.append(["full", plan.name, group, BASE + plan.name,
                     ";".join(techniques(plan / "Emulation_Plan"))])
    commit = subprocess.run(["git", "-C", str(lib), "log", "-1", "--format=%H %cs"],
                            capture_output=True, text=True).stdout.strip()
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8", newline="") as f:
        f.write(f"# source: adversary_emulation_library {commit} (Apache-2.0)\n")
        w = csv.writer(f)
        w.writerow(["kind", "plan", "group_id", "url", "techniques"])
        w.writerows(rows)
    print(f"wrote {len(rows)} plans to {out}")


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2] if len(sys.argv) > 2 else "data/emulation/ctid_catalog.csv"))
