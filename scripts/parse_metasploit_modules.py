#!/usr/bin/env python3
"""Parse Metasploit module files and generate a CSV summary.

Traverses the modules/ directory tree, extracts metadata from each Ruby
module file, and writes the results to requirements/metasploit-modules.csv.

Columns: path, module_type, cve, rank, disclosure_date, module_code,
         name, description, references, platform, privileged
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
NAME_PATTERN = re.compile(
    r"""['"']Name['"']\s*=>\s*['"']([^'"']+)['"']"""
)
DESCRIPTION_PATTERN = re.compile(
    r"""['"']Description['"']\s*=>\s*%q\{(.*?)\}""", re.DOTALL
)
DESCRIPTION_SIMPLE_PATTERN = re.compile(
    r"""['"']Description['"']\s*=>\s*['"']([^'"']+)['"']"""
)
# Matches individual reference entries: ['TYPE', 'value']
REFERENCE_ENTRY_PATTERN = re.compile(
    r"""\[\s*['"'](\w+)['"']\s*,\s*['"']([^'"']+)['"']\s*\]"""
)
PLATFORM_PATTERN = re.compile(
    r"""['"']Platform['"']\s*=>\s*(?:\[([^\]]+)\]|['"']([^'"']+)['"'])"""
)
PRIVILEGED_PATTERN = re.compile(
    r"""['"']Privileged['"']\s*=>\s*(true|false)"""
)
OUTPUT_CSV = os.path.join("requirements", "metasploit-modules.csv")
MODULES_DIR = "modules"

CSV_COLUMNS = [
    "path", "module_type", "cve", "rank", "disclosure_date",
    "name", "description", "references", "platform", "privileged",
    "module_code",
]


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
    """Extract metadata and full source from a module file."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError:
        return "", "", "", "", "", "", "", "", ""

    cves = CVE_PATTERN.findall(content)
    cve_str = "; ".join(f"CVE-{c}" for c in cves) if cves else ""

    rank_match = RANK_PATTERN.search(content)
    rank = rank_match.group(1) if rank_match else ""

    date_match = DISCLOSURE_DATE_PATTERN.search(content)
    disclosure_date = date_match.group(1) if date_match else ""

    name_match = NAME_PATTERN.search(content)
    name = name_match.group(1).strip() if name_match else ""

    desc_match = DESCRIPTION_PATTERN.search(content)
    if desc_match:
        description = " ".join(desc_match.group(1).split())
    else:
        desc_simple = DESCRIPTION_SIMPLE_PATTERN.search(content)
        description = desc_simple.group(1).strip() if desc_simple else ""

    ref_entries = REFERENCE_ENTRY_PATTERN.findall(content)
    references = "; ".join(f"{rtype}:{rval}" for rtype, rval in ref_entries) if ref_entries else ""

    plat_match = PLATFORM_PATTERN.search(content)
    if plat_match:
        raw_plat = plat_match.group(1) or plat_match.group(2) or ""
        # Strip quotes and whitespace from each entry in array form
        platform = "; ".join(
            p.strip().strip("'\"")
            for p in re.split(r"[,\s]+", raw_plat.strip())
            if p.strip().strip("'\"")
        )
    else:
        platform = ""

    priv_match = PRIVILEGED_PATTERN.search(content)
    privileged = priv_match.group(1) if priv_match else ""

    return cve_str, rank, disclosure_date, name, description, references, platform, privileged, content


def collect_modules(modules_dir):
    """Walk the modules directory and collect metadata for every .rb file."""
    rows = []
    for root, _dirs, files in os.walk(modules_dir):
        for fname in sorted(files):
            if not fname.endswith(".rb"):
                continue
            filepath = os.path.join(root, fname)
            module_type = infer_module_type(filepath)
            cve, rank, disclosure_date, name, description, references, platform, privileged, module_code = parse_module(filepath)
            rows.append(
                {
                    "path": filepath,
                    "module_type": module_type,
                    "cve": cve,
                    "rank": rank,
                    "disclosure_date": disclosure_date,
                    "name": name,
                    "description": description,
                    "references": references,
                    "platform": platform,
                    "privileged": privileged,
                    "module_code": module_code,
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
