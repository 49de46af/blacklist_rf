#!/usr/bin/env python3

import re
import sys
from pathlib import Path

from lib.io_utils import iter_netnames, read_prefixes
from lib.ripe_api import get_announced_prefixes
from lib.whois_client import whois_query_inetnums
from lib.ip_utils import range_to_cidrs, aggregate_prefixes

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = PROJECT_ROOT / "config"
DATA_DIR = PROJECT_ROOT / "data"
OUTPUT_DIR = PROJECT_ROOT / "output"


def load_asn_list(filepath: str | Path) -> set[str]:
    asns = set()
    for line in read_prefixes(filepath):
        match = re.search(r"\bAS\d+\b", line, re.IGNORECASE)
        if match:
            asns.add(match.group(0).upper())
    return asns


def load_data_file(filepath: str | Path) -> list[tuple[str, str]]:
    entries = []
    filepath = Path(filepath)
    if not filepath.exists():
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


def filter_by_patterns(entries: list[tuple[str, str]], patterns: list[str], exclude_patterns: list[str] | None = None) -> list[tuple[str, str]]:
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


def resolve_netnames(netnames_file: str | Path) -> list[tuple[str, str]]:
    results = []
    lines = read_prefixes(netnames_file)
    for netname in iter_netnames(lines):
        inetnums = whois_query_inetnums(netname)
        if not inetnums:
            continue
        for inetnum in inetnums:
            try:
                cidrs = range_to_cidrs(inetnum)
                for cidr in cidrs:
                    results.append((netname, cidr))
            except (ValueError, IndexError):
                continue
    return results


def _build_main_blacklist() -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    patterns = read_prefixes(CONFIG_DIR / "patterns.txt")
    whitelist_patterns = read_prefixes(CONFIG_DIR / "whitelist_patterns.txt")
    blacklist_asns = load_asn_list(CONFIG_DIR / "asn_blacklist.txt")
    whitelist_asns = load_asn_list(CONFIG_DIR / "asn_whitelist.txt")

    print("Loading data files...")
    asn_entries = load_data_file(DATA_DIR / "all-ru-asn.txt")
    ipv4_entries = load_data_file(DATA_DIR / "all-ru-ipv4.txt")
    ripe_entries = load_data_file(DATA_DIR / "ripe-ru-ipv4.txt")

    print(f"Filtering ASNs by {len(patterns)} patterns (excluding {len(whitelist_patterns)} whitelist patterns)...")
    matched_asns = set(e for e, _ in filter_by_patterns(asn_entries, patterns, whitelist_patterns))

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

    netnames_file = CONFIG_DIR / "netnames.txt"
    if netnames_file.exists():
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
    matched_ipv4 = filter_by_patterns(ipv4_entries, patterns, whitelist_patterns)
    matched_ripe = filter_by_patterns(ripe_entries, patterns, whitelist_patterns)
    for entry, desc in matched_ipv4:
        all_prefixes.append(entry)
        commented_lines.append(f"# NET-Name: {entry} {desc}")
        commented_lines.append(entry)
    for entry, desc in matched_ripe:
        all_prefixes.append(entry)
        commented_lines.append(f"# NET-Name: {entry} {desc}")
        commented_lines.append(entry)

    commented_path = OUTPUT_DIR / "blacklist_with_comments.txt"
    with open(commented_path, "w", encoding="utf-8") as f:
        for line in commented_lines:
            f.write(line + "\n")
    print(f"  {commented_path} ({len(commented_lines)} lines)")

    print("Aggregating and deduplicating...")
    v4_list, v6_list = aggregate_prefixes(all_prefixes)

    blacklist_path = OUTPUT_DIR / "blacklist.txt"
    v4_path = OUTPUT_DIR / "blacklist-v4.txt"
    v6_path = OUTPUT_DIR / "blacklist-v6.txt"

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

    return ipv4_entries, ripe_entries


def _build_rkn_collaborants() -> None:
    collaborants_asns = load_asn_list(CONFIG_DIR / "rkn_collaborants.txt")
    if not collaborants_asns:
        return

    print("Building RKN collaborants blacklists...")
    asn_entries = load_data_file(DATA_DIR / "all-ru-asn.txt")
    asn_desc_map = {e.upper(): d for e, d in asn_entries}

    all_prefixes = []
    commented_lines = []
    for i, asn in enumerate(sorted(collaborants_asns)):
        prefixes = get_announced_prefixes(asn)
        all_prefixes.extend(prefixes)
        if prefixes:
            desc = asn_desc_map.get(asn, "")
            commented_lines.append(f"# AS-Name: {asn} {desc}")
            commented_lines.extend(prefixes)
        if (i + 1) % 10 == 0:
            print(f"  {i + 1}/{len(collaborants_asns)} ASNs resolved...")

    commented_path = OUTPUT_DIR / "rkn-collaborants_with_comments.txt"
    with open(commented_path, "w", encoding="utf-8") as f:
        for line in commented_lines:
            f.write(line + "\n")

    v4_list, v6_list = aggregate_prefixes(all_prefixes)

    rkn_path = OUTPUT_DIR / "rkn-collaborants.txt"
    rkn_v4_path = OUTPUT_DIR / "rkn-collaborants-v4.txt"
    rkn_v6_path = OUTPUT_DIR / "rkn-collaborants-v6.txt"

    with open(rkn_path, "w", encoding="utf-8") as f:
        for p in v4_list + v6_list:
            f.write(p + "\n")
    with open(rkn_v4_path, "w", encoding="utf-8") as f:
        for p in v4_list:
            f.write(p + "\n")
    with open(rkn_v6_path, "w", encoding="utf-8") as f:
        for p in v6_list:
            f.write(p + "\n")

    print(f"  {rkn_path} ({len(v4_list) + len(v6_list)} entries)")
    print(f"  {rkn_v4_path} ({len(v4_list)} IPv4)")
    print(f"  {rkn_v6_path} ({len(v6_list)} IPv6)")


def _build_vk_blacklist(ipv4_entries: list[tuple[str, str]], ripe_entries: list[tuple[str, str]]) -> None:
    vk_patterns = read_prefixes(CONFIG_DIR / "vk_patterns.txt")
    vk_exclude = read_prefixes(CONFIG_DIR / "vk_exclude_patterns.txt")

    if not vk_patterns:
        return

    print("Building VK blacklists...")
    ipv6_entries = load_data_file(DATA_DIR / "all-ru-ipv6.txt")
    vk_prefixes = []
    for source in [ipv4_entries, ipv6_entries, ripe_entries]:
        vk_prefixes.extend(e for e, _ in filter_by_patterns(source, vk_patterns, vk_exclude))

    vk_v4, vk_v6 = aggregate_prefixes(vk_prefixes)

    vk_path = OUTPUT_DIR / "blacklist-vk.txt"
    vk_v4_path = OUTPUT_DIR / "blacklist-vk-v4.txt"
    vk_v6_path = OUTPUT_DIR / "blacklist-vk-v6.txt"

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


def main() -> int:
    ipv4_entries, ripe_entries = _build_main_blacklist()
    _build_rkn_collaborants()
    _build_vk_blacklist(ipv4_entries, ripe_entries)
    return 0


if __name__ == "__main__":
    sys.exit(main())
