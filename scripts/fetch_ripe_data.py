#!/usr/bin/env python3

import sys
from pathlib import Path

from lib.ripe_api import get_country_resources

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"


def write_resource_file(items: list[str], filepath: str | Path, prefix: str = "") -> None:
    with open(filepath, "w", encoding="utf-8") as f:
        for item in items:
            entry = f"{prefix}{item.strip()}"
            f.write(f"{entry} -no-description-\n")
    print(f"  {filepath} ({len(items)} entries)")


def main() -> int:
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    print("Fetching RU resources from RIPE API...")
    resources = get_country_resources("RU")

    asn_path = DATA_DIR / "all-ru-asn.txt"
    ipv4_path = DATA_DIR / "all-ru-ipv4.txt"
    ipv6_path = DATA_DIR / "all-ru-ipv6.txt"

    write_resource_file(resources["asn"], asn_path, prefix="AS")
    write_resource_file(resources["ipv4"], ipv4_path)
    write_resource_file(resources["ipv6"], ipv6_path)

    all_path = DATA_DIR / "all-ru.txt"
    with open(all_path, "w", encoding="utf-8") as out:
        for path in [asn_path, ipv4_path, ipv6_path]:
            with open(path, encoding="utf-8") as f:
                out.write(f.read())
    print(f"  {all_path} (combined)")

    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
