#!/usr/bin/env python3

import argparse
import re
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from lib.io_utils import read_lines_from_source
from lib.ripe_api import get_announced_prefixes
from lib.whois_client import whois_query

ASN_RE = re.compile(r"\bAS\d+\b", re.IGNORECASE)


def normalize_asn(value):
    match = ASN_RE.search(value)
    if match:
        return match.group(0).upper()
    return None


def print_prefixes(asn, quiet=False):
    normalized = normalize_asn(asn)
    if normalized is None:
        return

    if not quiet:
        print(f"# Networks announced by {normalized}")
        response = whois_query(normalized, "as-name", get_org=True)
        if response is not None and isinstance(response, str):
            print(f"# AS-Name (ORG): {response.strip()}")

    prefixes = get_announced_prefixes(normalized)
    for prefix in prefixes:
        print(prefix)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Retrieve networks announced by an AS number."
    )
    parser.add_argument(
        "asn_or_source",
        help="AS number, file with ASNs, URL, or '-' for stdin",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true",
        help="Output only prefixes, no comments",
    )
    args = parser.parse_args(argv)

    source = args.asn_or_source

    if normalize_asn(source) and not source.startswith(("http://", "https://")):
        print_prefixes(source, quiet=args.quiet)
        return 0

    try:
        lines = read_lines_from_source(source)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    for line in lines:
        normalized = normalize_asn(line)
        if normalized:
            print_prefixes(normalized, quiet=args.quiet)

    return 0


if __name__ == "__main__":
    sys.exit(main())
