#!/usr/bin/env python3

import argparse
import gzip
import json
import os
import sys
import tempfile
import urllib.request

sys.path.insert(0, os.path.dirname(__file__))
from lib.ip_utils import range_to_cidrs

PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")

RIPE_DB_URL = "https://ftp.ripe.net/ripe/dbase/split/ripe.db.inetnum.gz"
COUNTRY = "RU"


def download_ripe_db(dest_path):
    print(f"Downloading {RIPE_DB_URL}...")
    urllib.request.urlretrieve(RIPE_DB_URL, dest_path)
    print(f"  Saved to {dest_path}")


def parse_inetnum_file(filepath):
    records = []
    record = {}

    opener = gzip.open if filepath.endswith(".gz") else open

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


def _normalize_record(record):
    if not record or not record.get("inetnum"):
        return None
    try:
        record["inetnum"] = range_to_cidrs(record["inetnum"])
    except (ValueError, IndexError):
        return None
    return record


def write_outputs(records, text_path, json_path):
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=4, ensure_ascii=False)

    with open(text_path, "w", encoding="utf-8") as f:
        for item in records:
            for net in item["inetnum"]:
                f.write(f"{net} {item['netname']} ({item['org']}) [{item['descr']}]\n")

    print(f"  {text_path} ({len(records)} records)")
    print(f"  {json_path}")


def main():
    parser = argparse.ArgumentParser(description="Parse RIPE DB for RU networks.")
    parser.add_argument("--input", help="Path to ripe.db.inetnum or .gz file (downloads if not provided)")
    args = parser.parse_args()

    os.makedirs(DATA_DIR, exist_ok=True)

    if args.input:
        db_path = args.input
    else:
        db_path = os.path.join(tempfile.gettempdir(), "ripe.db.inetnum.gz")
        download_ripe_db(db_path)

    print("Parsing RIPE database...")
    records = parse_inetnum_file(db_path)

    text_output = os.path.join(DATA_DIR, "ripe-ru-ipv4.txt")
    json_output = os.path.join(DATA_DIR, "ripe-ru-ipv4.json")
    write_outputs(records, text_output, json_output)

    if not args.input and os.path.exists(db_path):
        os.remove(db_path)

    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
