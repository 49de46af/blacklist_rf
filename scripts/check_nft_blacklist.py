#!/usr/bin/env python3

import argparse
import re
import sys
from ipaddress import ip_address, ip_network, IPv4Network, IPv6Network


def parse_nft_config(filepath: str) -> tuple[list[IPv4Network], list[IPv6Network]]:
    if filepath == "-":
        content = sys.stdin.read()
    else:
        with open(filepath, encoding="utf-8") as f:
            content = f.read()

    v4_nets = []
    v6_nets = []

    in_elements = False
    for line in content.splitlines():
        stripped = line.strip()

        if "elements = {" in stripped:
            in_elements = True
            rest = stripped.split("elements = {", 1)[1]
            stripped = rest
        if in_elements:
            if "}" in stripped:
                stripped = stripped.split("}")[0]
                in_elements = False
            for token in re.split(r"[,\s]+", stripped):
                token = token.strip()
                if not token or token.startswith("#"):
                    continue
                try:
                    net = ip_network(token, strict=False)
                    if net.version == 4:
                        v4_nets.append(net)
                    else:
                        v6_nets.append(net)
                except ValueError:
                    continue

    return v4_nets, v6_nets


def check_ip_in_blacklist(ip_str: str, v4_nets: list[IPv4Network], v6_nets: list[IPv6Network]) -> bool:
    try:
        addr = ip_address(ip_str)
    except ValueError:
        return False

    nets = v4_nets if addr.version == 4 else v6_nets
    for net in nets:
        if addr in net:
            return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check if an IP address is in the nftables blacklist."
    )
    parser.add_argument("nft_file", help="Path to nftables config file")
    parser.add_argument("ip", help="IP address to check")
    args = parser.parse_args()

    v4_nets, v6_nets = parse_nft_config(args.nft_file)
    blocked = check_ip_in_blacklist(args.ip, v4_nets, v6_nets)

    if blocked:
        print(f"BLOCKED: {args.ip} is in the blacklist")
        return 1
    else:
        print(f"OK: {args.ip} is not in the blacklist")
        return 0


if __name__ == "__main__":
    sys.exit(main())
