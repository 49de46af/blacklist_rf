#!/usr/bin/env python3

import argparse
import sys
from pathlib import Path

from lib.whois_client import whois_query_name

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"

DEFAULT_LIMIT = 2500


def resolve_file(filepath: str | Path, limit: int) -> None:
    filepath = Path(filepath)
    if not filepath.exists():
        print(f"  Skipping {filepath} (not found)")
        return

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    count = 0
    for i in range(len(lines)):
        if "-no-description-" not in lines[i]:
            continue

        count += 1
        if count > limit:
            print(f"  Reached limit ({limit}), stopping.")
            break

        parts = lines[i].split()
        entry = parts[0]

        if entry.upper().startswith("AS"):
            response = whois_query_name(entry, "as-name", get_org=True)
        else:
            response = whois_query_name(entry, "netname", get_org=True)

        if response is None:
            name = "-no-description-"
        else:
            name = response.strip()

        lines[i] = f"{entry} {name}\n"

        if count % 100 == 0:
            print(f"  Resolved {count}/{limit}...")

    with open(filepath, "w", encoding="utf-8") as f:
        f.writelines(lines)

    print(f"  {filepath}: resolved {min(count, limit)} entries")


def main() -> int:
    parser = argparse.ArgumentParser(description="Resolve WHOIS descriptions for ASNs and networks.")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT,
                        help=f"Max WHOIS queries per file (default: {DEFAULT_LIMIT})")
    parser.add_argument("files", nargs="*",
                        help="Files to resolve (default: all data/all-ru-*.txt)")
    args = parser.parse_args()

    if args.files:
        targets = args.files
    else:
        targets = [
            DATA_DIR / "all-ru-asn.txt",
            DATA_DIR / "all-ru-ipv4.txt",
            DATA_DIR / "all-ru-ipv6.txt",
        ]

    print(f"Resolving descriptions (limit: {args.limit} per file)...")
    for filepath in targets:
        print(f"Processing {filepath}...")
        resolve_file(filepath, args.limit)

    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
