#!/usr/bin/env python3

import sys
from pathlib import Path

from lib.exporters import export_all

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = PROJECT_ROOT / "output"


def main() -> int:
    v4_file = OUTPUT_DIR / "blacklist-v4.txt"
    v6_file = OUTPUT_DIR / "blacklist-v6.txt"

    if not v4_file.exists() and not v6_file.exists():
        print("Error: no blacklist files found in output/. Run generate_blacklist.py first.", file=sys.stderr)
        return 1

    vk_v4_file = OUTPUT_DIR / "blacklist-vk-v4.txt"
    vk_v6_file = OUTPUT_DIR / "blacklist-vk-v6.txt"
    vk_v4 = vk_v4_file if vk_v4_file.exists() else None
    vk_v6 = vk_v6_file if vk_v6_file.exists() else None

    print("Exporting blacklists to all formats...")
    export_all(v4_file, v6_file, OUTPUT_DIR, vk_v4, vk_v6)

    exported = [f for f in OUTPUT_DIR.iterdir() if not f.name.endswith(".txt") and not f.name.startswith(".")]
    print(f"Exported {len(exported)} files:")
    for f in sorted(exported):
        size = f.stat().st_size
        print(f"  {f.name} ({size} bytes)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
