import ipaddress


def range_to_cidrs(ip_range):
    start_ip, end_ip = ip_range.split(" - ")
    start = ipaddress.IPv4Address(start_ip.strip())
    end = ipaddress.IPv4Address(end_ip.strip())
    return [str(cidr) for cidr in ipaddress.summarize_address_range(start, end)]


def is_ipv6(cidr):
    return ":" in cidr


def aggregate_prefixes(prefixes):
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
