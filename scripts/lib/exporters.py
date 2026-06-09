from datetime import datetime, UTC
from ipaddress import ip_network, collapse_addresses, IPv4Network, IPv6Network
from pathlib import Path

from lib.io_utils import read_prefixes


def _timestamp() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def _aggregate(prefixes: list[str]) -> list[IPv4Network | IPv6Network]:
    nets = []
    for p in prefixes:
        try:
            nets.append(ip_network(p, strict=False))
        except ValueError:
            continue
    return sorted(collapse_addresses(nets))


def export_nginx(v4_file: str | Path, v6_file: str | Path, output_dir: str | Path, rkn_v4_file: str | Path | None = None, rkn_v6_file: str | Path | None = None) -> None:
    v4 = read_prefixes(v4_file)
    v6 = read_prefixes(v6_file)

    def _write_nginx(prefixes, path, label):
        path = Path(path)
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# Nginx blacklist configuration {label}\n")
            f.write(f"# Last updated: {_timestamp()}\n")
            f.write(f"#\n# Usage: include /path/to/{path.name};\n#\n\n")
            for p in prefixes:
                f.write(f"deny {p};\n")

    output_dir = Path(output_dir)
    _write_nginx(v4 + v6, output_dir / "blacklist.conf", "(mixed IPv4/IPv6)")
    _write_nginx(v4, output_dir / "blacklist-v4.conf", "(IPv4 only)")
    _write_nginx(v6, output_dir / "blacklist-v6.conf", "(IPv6 only)")

    if rkn_v4_file and Path(rkn_v4_file).exists():
        rkn_v4 = read_prefixes(rkn_v4_file)
    else:
        rkn_v4 = []
    if rkn_v6_file and Path(rkn_v6_file).exists():
        rkn_v6 = read_prefixes(rkn_v6_file)
    else:
        rkn_v6 = []

    if rkn_v4 or rkn_v6:
        _write_nginx(rkn_v4 + rkn_v6, output_dir / "rkn-collaborants.conf", "RKN collaborants (mixed IPv4/IPv6)")
        _write_nginx(rkn_v4, output_dir / "rkn-collaborants-v4.conf", "RKN collaborants (IPv4 only)")
        _write_nginx(rkn_v6, output_dir / "rkn-collaborants-v6.conf", "RKN collaborants (IPv6 only)")


def export_ipset(v4_file: str | Path, v6_file: str | Path, output_dir: str | Path, vk_v4_file: str | Path | None = None, vk_v6_file: str | Path | None = None, rkn_v4_file: str | Path | None = None, rkn_v6_file: str | Path | None = None) -> None:
    v4 = read_prefixes(v4_file)
    v6 = read_prefixes(v6_file)

    def _write_ipset(prefixes, path, set_name, family):
        path = Path(path)
        count = len(prefixes)
        hashsize = max(count, 1024)
        maxelem = count * 2 if count else 2048
        iptcmd = "ip6tables" if family == "inet6" else "iptables"
        is_vk = "vk" in set_name

        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# IPSet blacklist configuration\n")
            f.write(f"# Last updated: {_timestamp()}\n")
            f.write("#\n")
            f.write(f"# Usage:\n")
            f.write(f"#   1. Load the ipset:\n")
            f.write(f"#      ipset restore < {path.name}\n")
            f.write("#\n")
            if is_vk:
                f.write(f"#   2. Use with {iptcmd}:\n")
                f.write(f"#      {iptcmd} -I OUTPUT -m set --match-set {set_name} dst -j REJECT\n")
                f.write(f"#      {iptcmd} -I FORWARD -m set --match-set {set_name} dst -j REJECT\n")
            else:
                f.write(f"#   2. Use with {iptcmd}:\n")
                f.write(f"#      {iptcmd} -I INPUT -m set --match-set {set_name} src -m conntrack --ctstate NEW -j DROP\n")
                f.write(f"#      {iptcmd} -I FORWARD -m set --match-set {set_name} src -m conntrack --ctstate NEW -j DROP\n")
            f.write("#\n")
            f.write(f"#   3. To flush/delete the set:\n")
            f.write(f"#      ipset flush {set_name}\n")
            f.write(f"#      ipset destroy {set_name}\n")
            f.write("#\n\n")
            f.write(f"create {set_name} hash:net family {family} hashsize {hashsize} maxelem {maxelem}\n")
            for p in prefixes:
                f.write(f"add {set_name} {p}\n")

    output_dir = Path(output_dir)
    _write_ipset(v4, output_dir / "blacklist-v4.ipset", "blacklist-v4", "inet")
    _write_ipset(v6, output_dir / "blacklist-v6.ipset", "blacklist-v6", "inet6")

    if vk_v4_file and Path(vk_v4_file).exists():
        vk_v4 = read_prefixes(vk_v4_file)
        _write_ipset(vk_v4, output_dir / "blacklist-vk-v4.ipset", "blacklist-vk-v4", "inet")
    if vk_v6_file and Path(vk_v6_file).exists():
        vk_v6 = read_prefixes(vk_v6_file)
        _write_ipset(vk_v6, output_dir / "blacklist-vk-v6.ipset", "blacklist-vk-v6", "inet6")

    if rkn_v4_file and Path(rkn_v4_file).exists():
        rkn_v4 = read_prefixes(rkn_v4_file)
        _write_ipset(rkn_v4, output_dir / "rkn-collaborants-v4.ipset", "rkn-collaborants-v4", "inet")
    if rkn_v6_file and Path(rkn_v6_file).exists():
        rkn_v6 = read_prefixes(rkn_v6_file)
        _write_ipset(rkn_v6, output_dir / "rkn-collaborants-v6.ipset", "rkn-collaborants-v6", "inet6")


def _write_nft(v4_nets: list[str], v6_nets: list[str], path: str | Path, set_v4_name: str, set_v6_name: str, usage_profile: str = "vm_input") -> None:
    path = Path(path)
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
    path.chmod(0o644)


def export_nftables(v4_file: str | Path, v6_file: str | Path, output_dir: str | Path, vk_v4_file: str | Path | None = None, vk_v6_file: str | Path | None = None, rkn_v4_file: str | Path | None = None, rkn_v6_file: str | Path | None = None) -> None:
    v4_raw = read_prefixes(v4_file)
    v6_raw = read_prefixes(v6_file)

    v4_agg = _aggregate(v4_raw)
    v6_agg = _aggregate(v6_raw)
    v4_strs = [str(n) for n in v4_agg]
    v6_strs = [str(n) for n in v6_agg]

    output_dir = Path(output_dir)
    for name, v4, v6 in [
        ("blacklist.nft", v4_strs, v6_strs),
        ("blacklist-v4.nft", v4_strs, []),
        ("blacklist-v6.nft", [], v6_strs),
    ]:
        _write_nft(v4, v6, output_dir / name, "blacklist_v4", "blacklist_v6")

    if vk_v4_file and Path(vk_v4_file).exists():
        vk_v4 = [str(n) for n in _aggregate(read_prefixes(vk_v4_file))]
    else:
        vk_v4 = []
    if vk_v6_file and Path(vk_v6_file).exists():
        vk_v6 = [str(n) for n in _aggregate(read_prefixes(vk_v6_file))]
    else:
        vk_v6 = []

    if vk_v4 or vk_v6:
        for name, v4, v6 in [
            ("blacklist-vk.nft", vk_v4, vk_v6),
            ("blacklist-vk-v4.nft", vk_v4, []),
            ("blacklist-vk-v6.nft", [], vk_v6),
        ]:
            _write_nft(v4, v6, output_dir / name,
                        "blacklist_vk_v4", "blacklist_vk_v6", "vk_forward")

    if rkn_v4_file and Path(rkn_v4_file).exists():
        rkn_v4 = [str(n) for n in _aggregate(read_prefixes(rkn_v4_file))]
    else:
        rkn_v4 = []
    if rkn_v6_file and Path(rkn_v6_file).exists():
        rkn_v6 = [str(n) for n in _aggregate(read_prefixes(rkn_v6_file))]
    else:
        rkn_v6 = []

    if rkn_v4 or rkn_v6:
        for name, v4, v6 in [
            ("rkn-collaborants.nft", rkn_v4, rkn_v6),
            ("rkn-collaborants-v4.nft", rkn_v4, []),
            ("rkn-collaborants-v6.nft", [], rkn_v6),
        ]:
            _write_nft(v4, v6, output_dir / name,
                        "rkn_collaborants_v4", "rkn_collaborants_v6")


def export_routes(v4_file: str | Path, v6_file: str | Path, output_dir: str | Path, vk_v4_file: str | Path | None = None, vk_v6_file: str | Path | None = None, rkn_v4_file: str | Path | None = None, rkn_v6_file: str | Path | None = None) -> None:
    def _write_routes(prefixes, path, ipv6=False):
        path = Path(path)
        with open(path, "w", encoding="utf-8") as f:
            label = "IPv6" if ipv6 else "IPv4"
            f.write(f"# Linux routes blackhole ({label})\n")
            f.write(f"# Last updated: {_timestamp()}\n")
            f.write(f"#\n# Apply: sudo sh {path.name}\n#\n\n")
            for p in prefixes:
                if ipv6:
                    f.write(f"ip -6 route replace {p} via ::1 dev lo\n")
                else:
                    f.write(f"ip route replace {p} via 127.0.0.1 dev lo onlink\n")

    output_dir = Path(output_dir)
    _write_routes(read_prefixes(v4_file), output_dir / "blacklist-v4.routes")
    _write_routes(read_prefixes(v6_file), output_dir / "blacklist-v6.routes", ipv6=True)

    if vk_v4_file and Path(vk_v4_file).exists():
        _write_routes(read_prefixes(vk_v4_file), output_dir / "blacklist-vk-v4.routes")
    if vk_v6_file and Path(vk_v6_file).exists():
        _write_routes(read_prefixes(vk_v6_file), output_dir / "blacklist-vk-v6.routes", ipv6=True)

    if rkn_v4_file and Path(rkn_v4_file).exists():
        _write_routes(read_prefixes(rkn_v4_file), output_dir / "rkn-collaborants-v4.routes")
    if rkn_v6_file and Path(rkn_v6_file).exists():
        _write_routes(read_prefixes(rkn_v6_file), output_dir / "rkn-collaborants-v6.routes", ipv6=True)


def export_mihomo(v4_file: str | Path, v6_file: str | Path, output_dir: str | Path, vk_v4_file: str | Path | None = None, vk_v6_file: str | Path | None = None, rkn_v4_file: str | Path | None = None, rkn_v6_file: str | Path | None = None) -> None:
    v4 = read_prefixes(v4_file)
    v6 = read_prefixes(v6_file)

    def _write_mihomo(prefixes, path):
        path = Path(path)
        with open(path, "w", encoding="utf-8") as f:
            f.write("payload:\n")
            for p in prefixes:
                f.write(f"  - '{p}'\n")

    output_dir = Path(output_dir)
    _write_mihomo(v4 + v6, output_dir / "blacklist.yaml")

    if vk_v4_file and Path(vk_v4_file).exists():
        vk_v4 = read_prefixes(vk_v4_file)
    else:
        vk_v4 = []
    if vk_v6_file and Path(vk_v6_file).exists():
        vk_v6 = read_prefixes(vk_v6_file)
    else:
        vk_v6 = []

    if vk_v4 or vk_v6:
        _write_mihomo(vk_v4 + vk_v6, output_dir / "blacklist-vk.yaml")

    if rkn_v4_file and Path(rkn_v4_file).exists():
        rkn_v4 = read_prefixes(rkn_v4_file)
    else:
        rkn_v4 = []
    if rkn_v6_file and Path(rkn_v6_file).exists():
        rkn_v6 = read_prefixes(rkn_v6_file)
    else:
        rkn_v6 = []

    if rkn_v4 or rkn_v6:
        _write_mihomo(rkn_v4 + rkn_v6, output_dir / "rkn-collaborants.yaml")


def export_all(v4_file: str | Path, v6_file: str | Path, output_dir: str | Path, vk_v4_file: str | Path | None = None, vk_v6_file: str | Path | None = None, rkn_v4_file: str | Path | None = None, rkn_v6_file: str | Path | None = None) -> None:
    export_nginx(v4_file, v6_file, output_dir, rkn_v4_file, rkn_v6_file)
    export_ipset(v4_file, v6_file, output_dir, vk_v4_file, vk_v6_file, rkn_v4_file, rkn_v6_file)
    export_nftables(v4_file, v6_file, output_dir, vk_v4_file, vk_v6_file, rkn_v4_file, rkn_v6_file)
    export_routes(v4_file, v6_file, output_dir, vk_v4_file, vk_v6_file, rkn_v4_file, rkn_v6_file)
    export_mihomo(v4_file, v6_file, output_dir, vk_v4_file, vk_v6_file, rkn_v4_file, rkn_v6_file)
