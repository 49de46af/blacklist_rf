#!/usr/bin/env python3

import subprocess
import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent

STEPS = [
    ("Fetching RIPE data", "fetch_ripe_data.py"),
    ("Generating blacklist", "generate_blacklist.py"),
    ("Exporting formats", "export_formats.py"),
]


def main() -> int:
    for label, script in STEPS:
        path = SCRIPTS_DIR / script
        print(f"\n{'='*60}")
        print(f"  {label}: {script}")
        print(f"{'='*60}\n")

        result = subprocess.run([sys.executable, str(path)])
        if result.returncode != 0:
            print(f"\nError: {script} exited with code {result.returncode}", file=sys.stderr)
            return result.returncode

    print(f"\n{'='*60}")
    print("  All steps completed successfully.")
    print(f"{'='*60}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
