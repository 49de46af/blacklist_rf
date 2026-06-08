import ipaddress


def range_to_cidrs(ip_range: str) -> list[str]:
    start_ip, end_ip = ip_range.split(" - ")
    start = ipaddress.ip_address(start_ip.strip())
    end = ipaddress.ip_address(end_ip.strip())
    return [str(cidr) for cidr in ipaddress.summarize_address_range(start, end)]


def is_ipv6(cidr: str) -> bool:
    return ":" in cidr


def deduplicate_prefixes(prefixes: list[str]) -> tuple[list[str], list[str]]:
    v4, v6 = set(), set()
    for p in prefixes:
        p = p.strip()
        if not p:
            continue
        if ":" in p:
            v6.add(p)
        else:
            v4.add(p)
    return sorted(v4), sorted(v6)


def aggregate_prefixes(prefixes: list[str]) -> tuple[list[str], list[str]]:
    v4, v6 = [], []
    for p in prefixes:
        try:
            net = ipaddress.ip_network(p, strict=False)
            if net.version == 4:
                v4.append(net)
            else:
                v6.append(net)
        except ValueError:
            continue
    agg_v4 = sorted(ipaddress.collapse_addresses(v4))
    agg_v6 = sorted(ipaddress.collapse_addresses(v6))
    return [str(n) for n in agg_v4], [str(n) for n in agg_v6]
