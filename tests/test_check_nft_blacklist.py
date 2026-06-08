import os
import tempfile

from check_nft_blacklist import parse_nft_config, check_ip_in_blacklist


SAMPLE_NFT_CONFIG = """\
# nftables blacklist
# Generated: 2024-01-01 00:00:00 UTC

table inet filter {

    set blacklist_v4 {
        type ipv4_addr
        flags interval
        elements = {
            10.0.0.0/24,
            192.168.1.0/24
        }
    }

    set blacklist_v6 {
        type ipv6_addr
        flags interval
        elements = {
            2001:db8::/32
        }
    }

}
"""


def _write_config(content):
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".nft", delete=False, encoding="utf-8")
    f.write(content)
    f.close()
    return f.name


def test_parse_nft_config():
    path = _write_config(SAMPLE_NFT_CONFIG)
    try:
        v4, v6 = parse_nft_config(path)
        assert len(v4) == 2
        assert len(v6) == 1
    finally:
        os.unlink(path)


def test_check_ip_blocked_v4():
    path = _write_config(SAMPLE_NFT_CONFIG)
    try:
        v4, v6 = parse_nft_config(path)
        assert check_ip_in_blacklist("10.0.0.1", v4, v6) is True
        assert check_ip_in_blacklist("192.168.1.100", v4, v6) is True
    finally:
        os.unlink(path)


def test_check_ip_not_blocked():
    path = _write_config(SAMPLE_NFT_CONFIG)
    try:
        v4, v6 = parse_nft_config(path)
        assert check_ip_in_blacklist("8.8.8.8", v4, v6) is False
        assert check_ip_in_blacklist("172.16.0.1", v4, v6) is False
    finally:
        os.unlink(path)


def test_check_ipv6_blocked():
    path = _write_config(SAMPLE_NFT_CONFIG)
    try:
        v4, v6 = parse_nft_config(path)
        assert check_ip_in_blacklist("2001:db8::1", v4, v6) is True
    finally:
        os.unlink(path)


def test_check_ipv6_not_blocked():
    path = _write_config(SAMPLE_NFT_CONFIG)
    try:
        v4, v6 = parse_nft_config(path)
        assert check_ip_in_blacklist("2001:db9::1", v4, v6) is False
    finally:
        os.unlink(path)


def test_empty_config():
    config = """\
table inet filter {
    set blacklist_v4 {
        type ipv4_addr
        flags interval
    }
    set blacklist_v6 {
        type ipv6_addr
        flags interval
    }
}
"""
    path = _write_config(config)
    try:
        v4, v6 = parse_nft_config(path)
        assert len(v4) == 0
        assert len(v6) == 0
        assert check_ip_in_blacklist("10.0.0.1", v4, v6) is False
    finally:
        os.unlink(path)
