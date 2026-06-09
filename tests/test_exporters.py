import os
import tempfile

from lib.exporters import (
    export_nginx,
    export_ipset,
    export_nftables,
    export_routes,
    export_mihomo,
)


def _create_prefix_files(tmpdir):
    v4_path = os.path.join(tmpdir, "v4.txt")
    v6_path = os.path.join(tmpdir, "v6.txt")
    with open(v4_path, "w") as f:
        f.write("10.0.0.0/24\n192.168.1.0/24\n")
    with open(v6_path, "w") as f:
        f.write("2001:db8::/32\n")
    return v4_path, v6_path


def _create_rkn_files(tmpdir):
    rkn_v4 = os.path.join(tmpdir, "rkn-v4.txt")
    rkn_v6 = os.path.join(tmpdir, "rkn-v6.txt")
    with open(rkn_v4, "w") as f:
        f.write("172.16.0.0/16\n")
    with open(rkn_v6, "w") as f:
        f.write("2001:db8:1::/48\n")
    return rkn_v4, rkn_v6


def test_export_nginx():
    with tempfile.TemporaryDirectory() as tmpdir:
        v4, v6 = _create_prefix_files(tmpdir)
        export_nginx(v4, v6, tmpdir)

        with open(os.path.join(tmpdir, "blacklist.conf")) as f:
            content = f.read()
        assert "deny 10.0.0.0/24;" in content
        assert "deny 2001:db8::/32;" in content

        with open(os.path.join(tmpdir, "blacklist-v4.conf")) as f:
            content = f.read()
        assert "deny 10.0.0.0/24;" in content
        assert "2001:db8" not in content


def test_export_ipset():
    with tempfile.TemporaryDirectory() as tmpdir:
        v4, v6 = _create_prefix_files(tmpdir)
        export_ipset(v4, v6, tmpdir)

        with open(os.path.join(tmpdir, "blacklist-v4.ipset")) as f:
            content = f.read()
        assert "create blacklist-v4 hash:net family inet" in content
        assert "add blacklist-v4 10.0.0.0/24" in content
        assert "iptables -I INPUT -m set --match-set blacklist-v4 src" in content
        assert "ipset flush blacklist-v4" in content

        with open(os.path.join(tmpdir, "blacklist-v6.ipset")) as f:
            content = f.read()
        assert "create blacklist-v6 hash:net family inet6" in content
        assert "add blacklist-v6 2001:db8::/32" in content
        assert "ip6tables -I INPUT -m set --match-set blacklist-v6 src" in content


def test_export_nftables():
    with tempfile.TemporaryDirectory() as tmpdir:
        v4, v6 = _create_prefix_files(tmpdir)
        export_nftables(v4, v6, tmpdir)

        with open(os.path.join(tmpdir, "blacklist.nft")) as f:
            content = f.read()
        assert "table inet filter {" in content
        assert "set blacklist_v4 {" in content
        assert "set blacklist_v6 {" in content
        assert "10.0.0.0/24" in content
        assert "2001:db8::/32" in content


def test_export_routes():
    with tempfile.TemporaryDirectory() as tmpdir:
        v4, v6 = _create_prefix_files(tmpdir)
        export_routes(v4, v6, tmpdir)

        with open(os.path.join(tmpdir, "blacklist-v4.routes")) as f:
            content = f.read()
        assert "ip route replace 10.0.0.0/24 via 127.0.0.1 dev lo onlink" in content

        with open(os.path.join(tmpdir, "blacklist-v6.routes")) as f:
            content = f.read()
        assert "ip -6 route replace 2001:db8::/32 via ::1 dev lo" in content


def test_export_mihomo():
    with tempfile.TemporaryDirectory() as tmpdir:
        v4, v6 = _create_prefix_files(tmpdir)
        export_mihomo(v4, v6, tmpdir)

        with open(os.path.join(tmpdir, "blacklist.yaml")) as f:
            content = f.read()
        assert "payload:" in content
        assert "'10.0.0.0/24'" in content
        assert "'2001:db8::/32'" in content


def test_export_nginx_rkn():
    with tempfile.TemporaryDirectory() as tmpdir:
        v4, v6 = _create_prefix_files(tmpdir)
        rkn_v4, rkn_v6 = _create_rkn_files(tmpdir)
        export_nginx(v4, v6, tmpdir, rkn_v4, rkn_v6)

        with open(os.path.join(tmpdir, "rkn-collaborants.conf")) as f:
            content = f.read()
        assert "deny 172.16.0.0/16;" in content
        assert "deny 2001:db8:1::/48;" in content

        with open(os.path.join(tmpdir, "rkn-collaborants-v4.conf")) as f:
            content = f.read()
        assert "deny 172.16.0.0/16;" in content
        assert "2001:db8" not in content


def test_export_ipset_rkn():
    with tempfile.TemporaryDirectory() as tmpdir:
        v4, v6 = _create_prefix_files(tmpdir)
        rkn_v4, rkn_v6 = _create_rkn_files(tmpdir)
        export_ipset(v4, v6, tmpdir, rkn_v4_file=rkn_v4, rkn_v6_file=rkn_v6)

        with open(os.path.join(tmpdir, "rkn-collaborants-v4.ipset")) as f:
            content = f.read()
        assert "create rkn-collaborants-v4 hash:net family inet" in content
        assert "add rkn-collaborants-v4 172.16.0.0/16" in content

        with open(os.path.join(tmpdir, "rkn-collaborants-v6.ipset")) as f:
            content = f.read()
        assert "create rkn-collaborants-v6 hash:net family inet6" in content
        assert "add rkn-collaborants-v6 2001:db8:1::/48" in content


def test_export_nftables_rkn():
    with tempfile.TemporaryDirectory() as tmpdir:
        v4, v6 = _create_prefix_files(tmpdir)
        rkn_v4, rkn_v6 = _create_rkn_files(tmpdir)
        export_nftables(v4, v6, tmpdir, rkn_v4_file=rkn_v4, rkn_v6_file=rkn_v6)

        with open(os.path.join(tmpdir, "rkn-collaborants.nft")) as f:
            content = f.read()
        assert "set rkn_collaborants_v4 {" in content
        assert "set rkn_collaborants_v6 {" in content
        assert "172.16.0.0/16" in content
        assert "2001:db8:1::/48" in content


def test_export_routes_rkn():
    with tempfile.TemporaryDirectory() as tmpdir:
        v4, v6 = _create_prefix_files(tmpdir)
        rkn_v4, rkn_v6 = _create_rkn_files(tmpdir)
        export_routes(v4, v6, tmpdir, rkn_v4_file=rkn_v4, rkn_v6_file=rkn_v6)

        with open(os.path.join(tmpdir, "rkn-collaborants-v4.routes")) as f:
            content = f.read()
        assert "ip route replace 172.16.0.0/16 via 127.0.0.1 dev lo onlink" in content

        with open(os.path.join(tmpdir, "rkn-collaborants-v6.routes")) as f:
            content = f.read()
        assert "ip -6 route replace 2001:db8:1::/48 via ::1 dev lo" in content


def test_export_mihomo_vk():
    with tempfile.TemporaryDirectory() as tmpdir:
        v4, v6 = _create_prefix_files(tmpdir)
        vk_v4 = os.path.join(tmpdir, "vk-v4.txt")
        vk_v6 = os.path.join(tmpdir, "vk-v6.txt")
        with open(vk_v4, "w") as f:
            f.write("10.10.0.0/16\n")
        with open(vk_v6, "w") as f:
            f.write("2001:db8:2::/48\n")
        export_mihomo(v4, v6, tmpdir, vk_v4, vk_v6)

        with open(os.path.join(tmpdir, "blacklist-vk.yaml")) as f:
            content = f.read()
        assert "payload:" in content
        assert "'10.10.0.0/16'" in content
        assert "'2001:db8:2::/48'" in content


def test_export_mihomo_rkn():
    with tempfile.TemporaryDirectory() as tmpdir:
        v4, v6 = _create_prefix_files(tmpdir)
        rkn_v4, rkn_v6 = _create_rkn_files(tmpdir)
        export_mihomo(v4, v6, tmpdir, rkn_v4_file=rkn_v4, rkn_v6_file=rkn_v6)

        with open(os.path.join(tmpdir, "rkn-collaborants.yaml")) as f:
            content = f.read()
        assert "payload:" in content
        assert "'172.16.0.0/16'" in content
        assert "'2001:db8:1::/48'" in content
