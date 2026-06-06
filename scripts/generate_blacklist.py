#!/usr/bin/env python3

import os
import re
import sys

sys.path.insert(0, os.path.dirname(__file__))
from lib.io_utils import iter_netnames
from lib.ripe_api import get_announced_prefixes
from lib.whois_client import whois_query
from lib.ip_utils import range_to_cidrs, aggregate_prefixes

PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
CONFIG_DIR = os.path.join(PROJECT_ROOT, "config")
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "output")


def load_lines(filepath):
    if not os.path.exists(filepath):
        return []
    with open(filepath, encoding="utf-8") as f:
        lines = []
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                lines.append(line)
        return lines


def load_patterns(filepath):
    raw = load_lines(filepath)
    return [p for p in raw if p]


def load_asn_list(filepath):
    asns = set()
    for line in load_lines(filepath):
        match = re.search(r"\bAS\d+\b", line, re.IGNORECASE)
        if match:
            asns.add(match.group(0).upper())
    return asns


def load_data_file(filepath):
    entries = []
    if not os.path.exists(filepath):
        return entries
    with open(filepath, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            entry = parts[0]
            description = parts[1] if len(parts) > 1 else ""
            entries.append((entry, description))
    return entries


def filter_by_patterns(entries, patterns, exclude_patterns=None):
    if not patterns:
        return []
    combined = "|".join(patterns)
    regex = re.compile(combined, re.IGNORECASE)

    exclude_regex = None
    if exclude_patterns:
        exclude_combined = "|".join(exclude_patterns)
        exclude_regex = re.compile(exclude_combined, re.IGNORECASE)

    result = []
    for entry, desc in entries:
        if regex.search(desc):
            if exclude_regex and exclude_regex.search(desc):
                continue
            result.append(entry)
    return result


def filter_by_patterns_with_desc(entries, patterns, exclude_patterns=None):
    if not patterns:
        return []
    combined = "|".join(patterns)
    regex = re.compile(combined, re.IGNORECASE)

    exclude_regex = None
    if exclude_patterns:
        exclude_combined = "|".join(exclude_patterns)
        exclude_regex = re.compile(exclude_combined, re.IGNORECASE)

    result = []
    for entry, desc in entries:
        if regex.search(desc):
            if exclude_regex and exclude_regex.search(desc):
                continue
            result.append((entry, desc))
    return result


def resolve_netnames(netnames_file):
    results = []
    lines = load_lines(netnames_file)
    for netname in iter_netnames(lines):
        inetnums = whois_query(netname, "inetnum")
        if not inetnums or not isinstance(inetnums, list):
            continue
        for inetnum in inetnums:
            try:
                cidrs = range_to_cidrs(inetnum)
                for cidr in cidrs:
                    results.append((netname, cidr))
            except (ValueError, IndexError):
                continue
    return results


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    patterns = load_patterns(os.path.join(CONFIG_DIR, "patterns.txt"))
    whitelist_patterns = load_patterns(os.path.join(CONFIG_DIR, "whitelist_patterns.txt"))
    blacklist_asns = load_asn_list(os.path.join(CONFIG_DIR, "asn_blacklist.txt"))
    whitelist_asns = load_asn_list(os.path.join(CONFIG_DIR, "asn_whitelist.txt"))

    print("Loading data files...")
    asn_entries = load_data_file(os.path.join(DATA_DIR, "all-ru-asn.txt"))
    ipv4_entries = load_data_file(os.path.join(DATA_DIR, "all-ru-ipv4.txt"))
    ripe_entries = load_data_file(os.path.join(DATA_DIR, "ripe-ru-ipv4.txt"))

    print(f"Filtering ASNs by {len(patterns)} patterns (excluding {len(whitelist_patterns)} whitelist patterns)...")
    matched_asns = set(filter_by_patterns(asn_entries, patterns, whitelist_patterns))

    matched_asns |= blacklist_asns
    matched_asns -= whitelist_asns

    print(f"  {len(matched_asns)} ASNs matched")

    asn_desc_map = {e.upper(): d for e, d in asn_entries}
    all_prefixes = []
    commented_lines = []

    print("Resolving ASN prefixes via RIPE API...")
    for i, asn in enumerate(sorted(matched_asns)):
        prefixes = get_announced_prefixes(asn)
        all_prefixes.extend(prefixes)
        if prefixes:
            desc = asn_desc_map.get(asn, "")
            commented_lines.append(f"# AS-Name: {asn} {desc}")
            commented_lines.extend(prefixes)
        if (i + 1) % 10 == 0:
            print(f"  {i + 1}/{len(matched_asns)} ASNs resolved...")

    netnames_file = os.path.join(CONFIG_DIR, "netnames.txt")
    if os.path.exists(netnames_file):
        print("Resolving netnames via WHOIS...")
        netname_results = resolve_netnames(netnames_file)
        for netname, prefix in netname_results:
            all_prefixes.append(prefix)
        prev_netname = None
        for netname, prefix in netname_results:
            if netname != prev_netname:
                commented_lines.append(f"# Network name: {netname}")
                prev_netname = netname
            commented_lines.append(prefix)
        print(f"  {len(netname_results)} prefixes from netnames")

    print("Filtering IPv4/RIPE data by patterns...")
    matched_ipv4 = filter_by_patterns_with_desc(ipv4_entries, patterns, whitelist_patterns)
    matched_ripe = filter_by_patterns_with_desc(ripe_entries, patterns, whitelist_patterns)
    for entry, desc in matched_ipv4:
        all_prefixes.append(entry)
        commented_lines.append(f"# NET-Name: {entry} {desc}")
        commented_lines.append(entry)
    for entry, desc in matched_ripe:
        all_prefixes.append(entry)
        commented_lines.append(f"# NET-Name: {entry} {desc}")
        commented_lines.append(entry)

    commented_path = os.path.join(OUTPUT_DIR, "blacklist_with_comments.txt")
    with open(commented_path, "w", encoding="utf-8") as f:
        for line in commented_lines:
            f.write(line + "\n")
    print(f"  {commented_path} ({len(commented_lines)} lines)")

    print("Aggregating and deduplicating...")
    v4_list, v6_list = aggregate_prefixes(all_prefixes)

    blacklist_path = os.path.join(OUTPUT_DIR, "blacklist.txt")
    v4_path = os.path.join(OUTPUT_DIR, "blacklist-v4.txt")
    v6_path = os.path.join(OUTPUT_DIR, "blacklist-v6.txt")

    with open(blacklist_path, "w", encoding="utf-8") as f:
        for p in v4_list + v6_list:
            f.write(p + "\n")

    with open(v4_path, "w", encoding="utf-8") as f:
        for p in v4_list:
            f.write(p + "\n")

    with open(v6_path, "w", encoding="utf-8") as f:
        for p in v6_list:
            f.write(p + "\n")

    print(f"Generated:")
    print(f"  {blacklist_path} ({len(v4_list) + len(v6_list)} entries)")
    print(f"  {v4_path} ({len(v4_list)} IPv4)")
    print(f"  {v6_path} ({len(v6_list)} IPv6)")

    vk_patterns = load_patterns(os.path.join(CONFIG_DIR, "vk_patterns.txt"))
    vk_exclude = load_patterns(os.path.join(CONFIG_DIR, "vk_exclude_patterns.txt"))

    if vk_patterns:
        print("Building VK blacklists...")
        ipv6_entries = load_data_file(os.path.join(DATA_DIR, "all-ru-ipv6.txt"))
        vk_prefixes = []
        for source in [ipv4_entries, ipv6_entries, ripe_entries]:
            vk_prefixes.extend(filter_by_patterns(source, vk_patterns, vk_exclude))

        vk_v4, vk_v6 = aggregate_prefixes(vk_prefixes)

        vk_path = os.path.join(OUTPUT_DIR, "blacklist-vk.txt")
        vk_v4_path = os.path.join(OUTPUT_DIR, "blacklist-vk-v4.txt")
        vk_v6_path = os.path.join(OUTPUT_DIR, "blacklist-vk-v6.txt")

        with open(vk_path, "w", encoding="utf-8") as f:
            for p in vk_v4 + vk_v6:
                f.write(p + "\n")
        with open(vk_v4_path, "w", encoding="utf-8") as f:
            for p in vk_v4:
                f.write(p + "\n")
        with open(vk_v6_path, "w", encoding="utf-8") as f:
            for p in vk_v6:
                f.write(p + "\n")

        print(f"  {vk_path} ({len(vk_v4) + len(vk_v6)} entries)")
        print(f"  {vk_v4_path} ({len(vk_v4)} IPv4)")
        print(f"  {vk_v6_path} ({len(vk_v6)} IPv6)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
