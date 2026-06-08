#!/usr/bin/env python3

import argparse
import gzip
import json
import sys
import tempfile
from pathlib import Path

import requests

from lib.ip_utils import range_to_cidrs

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"

RIPE_DB_URL = "https://ftp.ripe.net/ripe/dbase/split/ripe.db.inetnum.gz"
COUNTRY = "RU"


def download_ripe_db(dest_path: str | Path) -> None:
    print(f"Downloading {RIPE_DB_URL}...")
    response = requests.get(RIPE_DB_URL, stream=True, timeout=300)
    response.raise_for_status()
    with open(dest_path, "wb") as f:
        for chunk in response.iter_content(chunk_size=8192):
            f.write(chunk)
    print(f"  Saved to {dest_path}")


def parse_inetnum_file(filepath: str | Path) -> list[dict]:
    records = []
    record = {}

    opener = gzip.open if str(filepath).endswith(".gz") else open

    with opener(filepath, "rt", encoding="latin-1") as f:
        for line in f:
            if line.startswith("inetnum:"):
                if record.get("country") == COUNTRY:
                    normalized = _normalize_record(record)
                    if normalized:
                        records.append(normalized)
                record = {
                    "inetnum": line.split(":", 1)[1].strip(),
                    "netname": "",
                    "descr": "",
                    "country": "",
                    "org": "",
                }
            elif line.startswith("netname:"):
                record["netname"] = line.split(":", 1)[1].strip()
            elif line.startswith("descr:"):
                record["descr"] = (record.get("descr", "") + " " + line.split(":", 1)[1].strip()).strip()
            elif line.startswith("mnt-by:"):
                record["netname"] = (record.get("netname", "") + " " + line.split(":", 1)[1].strip()).strip()
            elif line.startswith("country:"):
                record["country"] = line.split(":", 1)[1].strip()
            elif line.startswith("org:"):
                record["org"] = line.split(":", 1)[1].strip()

    if record.get("country") == COUNTRY:
        normalized = _normalize_record(record)
        if normalized:
            records.append(normalized)

    return records


def _normalize_record(record: dict) -> dict | None:
    if not record or not record.get("inetnum"):
        return None
    try:
        record["inetnum"] = range_to_cidrs(record["inetnum"])
    except (ValueError, IndexError):
        return None
    return record


def write_outputs(records: list[dict], text_path: str | Path, json_path: str | Path) -> None:
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=4, ensure_ascii=False)

    with open(text_path, "w", encoding="utf-8") as f:
        for item in records:
            for net in item["inetnum"]:
                f.write(f"{net} {item['netname']} ({item['org']}) [{item['descr']}]\n")

    print(f"  {text_path} ({len(records)} records)")
    print(f"  {json_path}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Parse RIPE DB for RU networks.")
    parser.add_argument("--input", help="Path to ripe.db.inetnum or .gz file (downloads if not provided)")
    args = parser.parse_args()

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    if args.input:
        db_path = args.input
    else:
        db_path = Path(tempfile.gettempdir()) / "ripe.db.inetnum.gz"
        download_ripe_db(db_path)

    print("Parsing RIPE database...")
    records = parse_inetnum_file(db_path)

    text_output = DATA_DIR / "ripe-ru-ipv4.txt"
    json_output = DATA_DIR / "ripe-ru-ipv4.json"
    write_outputs(records, text_output, json_output)

    if not args.input and Path(db_path).exists():
        Path(db_path).unlink()

    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
