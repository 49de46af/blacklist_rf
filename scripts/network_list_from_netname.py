#!/usr/bin/env python3

import argparse
import sys

from lib.io_utils import read_lines_from_source, iter_netnames
from lib.ip_utils import range_to_cidrs
from lib.whois_client import whois_query_inetnums


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Retrieve networks by network name via WHOIS."
    )
    parser.add_argument(
        "source",
        help="File with netnames, URL, or '-' for stdin",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true",
        help="Output only prefixes, no comments",
    )
    args = parser.parse_args(argv)

    try:
        lines = read_lines_from_source(args.source)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    for netname in iter_netnames(lines):
        inetnums = whois_query_inetnums(netname)
        if not inetnums:
            continue

        if not args.quiet:
            print(f"# Network name: {netname}")

        for inetnum in inetnums:
            try:
                for cidr in range_to_cidrs(inetnum):
                    print(cidr)
            except (ValueError, IndexError):
                continue

    return 0


if __name__ == "__main__":
    sys.exit(main())
