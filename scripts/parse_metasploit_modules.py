#!/usr/bin/env python3
"""Parse Metasploit module files and generate a CSV summary.

Traverses the modules/ directory tree, extracts metadata from each Ruby
module file, and writes the results to requirements/metasploit-modules.csv.

Columns: path, module_type, cve, rank, disclosure_date
"""

import csv
import os
import re
import sys


# Regex patterns for extracting metadata from module Ruby source files
CVE_PATTERN = re.compile(r"""['"]CVE['"],\s*['"](\d{4}-\d+)['"]""")
RANK_PATTERN = re.compile(r"""Rank\s*=\s*(\w+)Ranking""")
DISCLOSURE_DATE_PATTERN = re.compile(
    r"""['"]DisclosureDate['"].*?['"]([^'"]+)['"]"""
)

OUTPUT_CSV = os.path.join("requirements", "metasploit-modules.csv")
MODULES_DIR = "modules"

CSV_COLUMNS = ["path", "module_type", "cve", "rank", "disclosure_date"]


def infer_module_type(filepath):
    """Infer the module type from the file path.

    Metasploit organizes modules under directories like
    modules/exploits/, modules/auxiliary/, modules/post/, etc.
    """
    parts = os.path.normpath(filepath).split(os.sep)
    # The first component after 'modules' is typically the type
    try:
        idx = parts.index("modules")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    except ValueError:
        pass
    return "unknown"


def parse_module(filepath):
    """Extract CVE, rank, and disclosure_date from a module file."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError:
        return [], "", ""

    cves = CVE_PATTERN.findall(content)
    cve_str = "; ".join(f"CVE-{c}" for c in cves) if cves else ""

    rank_match = RANK_PATTERN.search(content)
    rank = rank_match.group(1) if rank_match else ""

    date_match = DISCLOSURE_DATE_PATTERN.search(content)
    disclosure_date = date_match.group(1) if date_match else ""

    return cve_str, rank, disclosure_date


def collect_modules(modules_dir):
    """Walk the modules directory and collect metadata for every .rb file."""
    rows = []
    for root, _dirs, files in os.walk(modules_dir):
        for fname in sorted(files):
            if not fname.endswith(".rb"):
                continue
            filepath = os.path.join(root, fname)
            module_type = infer_module_type(filepath)
            cve, rank, disclosure_date = parse_module(filepath)
            rows.append(
                {
                    "path": filepath,
                    "module_type": module_type,
                    "cve": cve,
                    "rank": rank,
                    "disclosure_date": disclosure_date,
                }
            )
    rows.sort(key=lambda r: r["path"])
    return rows


def write_csv(rows, output_path):
    """Write rows to a CSV file."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def main():
    modules_dir = sys.argv[1] if len(sys.argv) > 1 else MODULES_DIR
    output_path = sys.argv[2] if len(sys.argv) > 2 else OUTPUT_CSV

    if not os.path.isdir(modules_dir):
        print(f"Modules directory '{modules_dir}' not found – writing empty CSV.")
        write_csv([], output_path)
        return

    rows = collect_modules(modules_dir)
    write_csv(rows, output_path)
    print(f"Wrote {len(rows)} module(s) to {output_path}")


if __name__ == "__main__":
    main()
