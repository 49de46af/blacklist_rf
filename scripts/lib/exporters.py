import json
import os
from datetime import datetime, UTC
from ipaddress import ip_network, collapse_addresses


def _timestamp():
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def _read_prefixes(filepath):
    prefixes = []
    if not os.path.exists(filepath):
        return prefixes
    with open(filepath, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                prefixes.append(line)
    return prefixes


def _aggregate(prefixes):
    nets = []
    for p in prefixes:
        try:
            nets.append(ip_network(p, strict=False))
        except ValueError:
            continue
    return sorted(collapse_addresses(nets))


def export_nginx(v4_file, v6_file, output_dir):
    v4 = _read_prefixes(v4_file)
    v6 = _read_prefixes(v6_file)

    def _write_nginx(prefixes, path, label):
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# Nginx blacklist configuration {label}\n")
            f.write(f"# Last updated: {_timestamp()}\n")
            f.write("#\n# Usage: include /path/to/" + os.path.basename(path) + ";\n#\n\n")
            for p in prefixes:
                f.write(f"deny {p};\n")

    _write_nginx(v4 + v6, os.path.join(output_dir, "blacklist.conf"), "(mixed IPv4/IPv6)")
    _write_nginx(v4, os.path.join(output_dir, "blacklist-v4.conf"), "(IPv4 only)")
    _write_nginx(v6, os.path.join(output_dir, "blacklist-v6.conf"), "(IPv6 only)")


def export_ipset(v4_file, v6_file, output_dir, vk_v4_file=None, vk_v6_file=None):
    v4 = _read_prefixes(v4_file)
    v6 = _read_prefixes(v6_file)

    def _write_ipset(prefixes, path, set_name, family):
        count = len(prefixes)
        hashsize = max(count, 1024)
        maxelem = count * 2 if count else 2048
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# IPSet blacklist configuration\n")
            f.write(f"# Last updated: {_timestamp()}\n")
            f.write(f"#\n# Usage: ipset restore < {os.path.basename(path)}\n#\n\n")
            f.write(f"create {set_name} hash:net family {family} hashsize {hashsize} maxelem {maxelem}\n")
            for p in prefixes:
                f.write(f"add {set_name} {p}\n")

    _write_ipset(v4, os.path.join(output_dir, "blacklist-v4.ipset"), "blacklist-v4", "inet")
    _write_ipset(v6, os.path.join(output_dir, "blacklist-v6.ipset"), "blacklist-v6", "inet6")

    if vk_v4_file and os.path.exists(vk_v4_file):
        vk_v4 = _read_prefixes(vk_v4_file)
        _write_ipset(vk_v4, os.path.join(output_dir, "blacklist-vk-v4.ipset"), "blacklist-vk-v4", "inet")
    if vk_v6_file and os.path.exists(vk_v6_file):
        vk_v6 = _read_prefixes(vk_v6_file)
        _write_ipset(vk_v6, os.path.join(output_dir, "blacklist-vk-v6.ipset"), "blacklist-vk-v6", "inet6")


def _write_nft(v4_nets, v6_nets, path, set_v4_name, set_v6_name, usage_profile="vm_input"):
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# nftables blacklist\n")
        f.write(f"# Generated: {_timestamp()}\n")
        f.write(f"# IPv4: {len(v4_nets)}, IPv6: {len(v6_nets)}\n")
        f.write("#\n# Usage: sudo nft -f <this-file>\n")
        if usage_profile == "vk_forward":
            f.write("#   # VK egress blocking for VPN clients via NAT/FORWARD\n")
            f.write("#   sudo nft add chain inet filter forward '{ type filter hook forward priority 0; policy accept; }'\n")
            f.write(f'#   sudo nft add rule inet filter forward iifname "<VPN_IFACE>" ip daddr @{set_v4_name} counter reject\n')
            f.write(f'#   sudo nft add rule inet filter forward iifname "<VPN_IFACE>" ip6 daddr @{set_v6_name} counter reject\n')
        else:
            f.write("#   sudo nft add chain inet filter input '{ type filter hook input priority 0; policy accept; }'\n")
            f.write(f"#   sudo nft add rule inet filter input ip saddr @{set_v4_name} counter reject\n")
            f.write(f"#   sudo nft add rule inet filter input ip6 saddr @{set_v6_name} counter reject\n")
        f.write("#\n\n")
        f.write("table inet filter {\n\n")

        f.write(f"    set {set_v4_name} {{\n")
        f.write("        type ipv4_addr\n")
        f.write("        flags interval\n")
        if v4_nets:
            f.write("        elements = {\n")
            for i, net in enumerate(v4_nets):
                comma = "," if i < len(v4_nets) - 1 else ""
                f.write(f"            {net}{comma}\n")
            f.write("        }\n")
        f.write("    }\n\n")

        f.write(f"    set {set_v6_name} {{\n")
        f.write("        type ipv6_addr\n")
        f.write("        flags interval\n")
        if v6_nets:
            f.write("        elements = {\n")
            for i, net in enumerate(v6_nets):
                comma = "," if i < len(v6_nets) - 1 else ""
                f.write(f"            {net}{comma}\n")
            f.write("        }\n")
        f.write("    }\n\n")

        f.write("}\n")
    os.chmod(path, 0o644)


def export_nftables(v4_file, v6_file, output_dir, vk_v4_file=None, vk_v6_file=None):
    v4_raw = _read_prefixes(v4_file)
    v6_raw = _read_prefixes(v6_file)

    v4_agg = _aggregate(v4_raw)
    v6_agg = _aggregate(v6_raw)
    v4_strs = [str(n) for n in v4_agg]
    v6_strs = [str(n) for n in v6_agg]

    for name, v4, v6 in [
        ("blacklist.nft", v4_strs, v6_strs),
        ("blacklist-v4.nft", v4_strs, []),
        ("blacklist-v6.nft", [], v6_strs),
    ]:
        _write_nft(v4, v6, os.path.join(output_dir, name), "blacklist_v4", "blacklist_v6")

    if vk_v4_file and os.path.exists(vk_v4_file):
        vk_v4 = [str(n) for n in _aggregate(_read_prefixes(vk_v4_file))]
    else:
        vk_v4 = []
    if vk_v6_file and os.path.exists(vk_v6_file):
        vk_v6 = [str(n) for n in _aggregate(_read_prefixes(vk_v6_file))]
    else:
        vk_v6 = []

    if vk_v4 or vk_v6:
        for name, v4, v6 in [
            ("blacklist-vk.nft", vk_v4, vk_v6),
            ("blacklist-vk-v4.nft", vk_v4, []),
            ("blacklist-vk-v6.nft", [], vk_v6),
        ]:
            _write_nft(v4, v6, os.path.join(output_dir, name),
                        "blacklist_vk_v4", "blacklist_vk_v6", "vk_forward")


def export_routes(v4_file, v6_file, output_dir, vk_v4_file=None, vk_v6_file=None):
    def _write_routes(prefixes, path, ipv6=False):
        with open(path, "w", encoding="utf-8") as f:
            label = "IPv6" if ipv6 else "IPv4"
            f.write(f"# Linux routes blackhole ({label})\n")
            f.write(f"# Last updated: {_timestamp()}\n")
            f.write(f"#\n# Apply: sudo sh {os.path.basename(path)}\n#\n\n")
            for p in prefixes:
                if ipv6:
                    f.write(f"ip -6 route replace {p} via ::1 dev lo\n")
                else:
                    f.write(f"ip route replace {p} via 127.0.0.1 dev lo onlink\n")

    _write_routes(_read_prefixes(v4_file), os.path.join(output_dir, "blacklist-v4.routes"))
    _write_routes(_read_prefixes(v6_file), os.path.join(output_dir, "blacklist-v6.routes"), ipv6=True)

    if vk_v4_file and os.path.exists(vk_v4_file):
        _write_routes(_read_prefixes(vk_v4_file), os.path.join(output_dir, "blacklist-vk-v4.routes"))
    if vk_v6_file and os.path.exists(vk_v6_file):
        _write_routes(_read_prefixes(vk_v6_file), os.path.join(output_dir, "blacklist-vk-v6.routes"), ipv6=True)


def export_xray(v4_file, v6_file, output_dir):
    v4 = _read_prefixes(v4_file)
    v6 = _read_prefixes(v6_file)

    data = {
        "rules": [
            {
                "type": "field",
                "ip": v4 + v6,
                "outboundTag": "block",
            }
        ]
    }

    path = os.path.join(output_dir, "blacklist.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def export_mihomo(v4_file, v6_file, output_dir):
    v4 = _read_prefixes(v4_file)
    v6 = _read_prefixes(v6_file)

    path = os.path.join(output_dir, "blacklist.yaml")
    with open(path, "w", encoding="utf-8") as f:
        f.write("payload:\n")
        for p in v4:
            f.write(f"  - 'IP-CIDR,{p}'\n")
        for p in v6:
            f.write(f"  - 'IP-CIDR6,{p}'\n")


def export_all(v4_file, v6_file, output_dir, vk_v4_file=None, vk_v6_file=None):
    export_nginx(v4_file, v6_file, output_dir)
    export_ipset(v4_file, v6_file, output_dir, vk_v4_file, vk_v6_file)
    export_nftables(v4_file, v6_file, output_dir, vk_v4_file, vk_v6_file)
    export_routes(v4_file, v6_file, output_dir, vk_v4_file, vk_v6_file)
    export_xray(v4_file, v6_file, output_dir)
    export_mihomo(v4_file, v6_file, output_dir)
