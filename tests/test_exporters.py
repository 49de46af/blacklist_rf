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
