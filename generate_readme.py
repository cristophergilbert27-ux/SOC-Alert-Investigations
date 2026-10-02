#!/usr/bin/env python3
"""
Rebuilds the incident table in README.md from the metadata header of every
report.md in this repository.

Each incident lives in its own folder:

    SOC-Alert-Investigations/
    |-- README.md
    |-- generate_readme.py
    |-- phishing-mail-delivered/
    |   |-- report.md
    |   `-- screenshots/
    `-- suspicious-powershell/
        |-- report.md
        `-- screenshots/

The table is written between the two marker comments in README.md:

    <!-- INCIDENTS:START -->
    <!-- INCIDENTS:END -->

Usage:  python generate_readme.py
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
README = ROOT / "README.md"
REPORT_NAME = "report.md"
SKIP_DIRS = {"TEMPLATE", "assets", ".git", ".github"}

START_MARKER = "<!-- INCIDENTS:START -->"
END_MARKER = "<!-- INCIDENTS:END -->"

# Metadata keys pulled out of the report header, in column order.
FIELDS = ["Incident", "Platform", "Severity", "Category", "Date"]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def parse_metadata(report_path: Path) -> dict:
    """Read the **Key:** value lines from the top of a report."""
    meta = {}
    text = report_path.read_text(encoding="utf-8", errors="replace")

    # Only look at the header block, before the first horizontal rule.
    header = text.split("\n---", 1)[0]

    for line in header.splitlines():
        match = re.match(r"^\s*\*\*(.+?):\*\*\s*(.*)$", line.strip())
        if match:
            key, value = match.group(1).strip(), match.group(2).strip()
            meta[key] = value

    return meta


def severity_key(row: dict) -> tuple:
    sev = row.get("Severity", "").strip().lower()
    return (SEVERITY_ORDER.get(sev, 9), row.get("Incident", "").lower())


def collect_rows() -> list:
    rows = []
    for folder in sorted(p for p in ROOT.iterdir() if p.is_dir()):
        if folder.name in SKIP_DIRS or folder.name.startswith("."):
            continue

        report = folder / REPORT_NAME
        if not report.exists():
            print(f"  skipped {folder.name}/ (no {REPORT_NAME})")
            continue

        meta = parse_metadata(report)
        if not meta:
            print(f"  skipped {folder.name}/ (no metadata header found)")
            continue

        missing = [f for f in FIELDS if not meta.get(f)]
        if missing:
            print(f"  warning: {folder.name}/ missing {', '.join(missing)}")

        row = {f: meta.get(f, "-") or "-" for f in FIELDS}
        row["_folder"] = folder.name
        rows.append(row)
        print(f"  found   {folder.name}/")

    return rows


def build_table(rows: list) -> str:
    if not rows:
        return "_No incident reports yet._"

    rows = sorted(rows, key=severity_key)

    header = "| # | " + " | ".join(FIELDS) + " | Report |"
    divider = "| --- " * (len(FIELDS) + 2) + "|"
    lines = [header, divider]

    for i, row in enumerate(rows, start=1):
        link = f"[Read]({row['_folder']}/{REPORT_NAME})"
        cells = [str(i)] + [row[f] for f in FIELDS] + [link]
        lines.append("| " + " | ".join(cells) + " |")

    return "\n".join(lines)


def main() -> int:
    if not README.exists():
        print(f"error: {README.name} not found next to this script.")
        return 1

    print("Scanning incident folders...")
    rows = collect_rows()
    table = build_table(rows)

    content = README.read_text(encoding="utf-8")

    if START_MARKER not in content or END_MARKER not in content:
        print(f"error: markers {START_MARKER} / {END_MARKER} not found in README.md")
        return 1

    pattern = re.compile(
        re.escape(START_MARKER) + r".*?" + re.escape(END_MARKER),
        re.DOTALL,
    )
    replacement = f"{START_MARKER}\n\n{table}\n\n{END_MARKER}"
    updated = pattern.sub(replacement, content)

    if updated == content:
        print("README.md already up to date.")
    else:
        README.write_text(updated, encoding="utf-8", newline="\n")
        print(f"README.md updated with {len(rows)} incident(s).")

    return 0


if __name__ == "__main__":
    sys.exit(main())
