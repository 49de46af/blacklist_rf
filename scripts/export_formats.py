#!/usr/bin/env python3

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from lib.exporters import export_all

PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "output")


def main():
    v4_file = os.path.join(OUTPUT_DIR, "blacklist-v4.txt")
    v6_file = os.path.join(OUTPUT_DIR, "blacklist-v6.txt")

    if not os.path.exists(v4_file) and not os.path.exists(v6_file):
        print("Error: no blacklist files found in output/. Run generate_blacklist.py first.", file=sys.stderr)
        return 1

    vk_v4_file = os.path.join(OUTPUT_DIR, "blacklist-vk-v4.txt")
    vk_v6_file = os.path.join(OUTPUT_DIR, "blacklist-vk-v6.txt")
    vk_v4 = vk_v4_file if os.path.exists(vk_v4_file) else None
    vk_v6 = vk_v6_file if os.path.exists(vk_v6_file) else None

    print("Exporting blacklists to all formats...")
    export_all(v4_file, v6_file, OUTPUT_DIR, vk_v4, vk_v6)

    exported = [f for f in os.listdir(OUTPUT_DIR) if not f.endswith(".txt") and not f.startswith(".")]
    print(f"Exported {len(exported)} files:")
    for f in sorted(exported):
        path = os.path.join(OUTPUT_DIR, f)
        size = os.path.getsize(path)
        print(f"  {f} ({size} bytes)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
