from lib.ip_utils import range_to_cidrs, is_ipv6, aggregate_prefixes


def test_range_to_cidrs_single():
    result = range_to_cidrs("192.168.1.0 - 192.168.1.255")
    assert result == ["192.168.1.0/24"]


def test_range_to_cidrs_multiple():
    result = range_to_cidrs("10.0.0.0 - 10.0.1.255")
    assert result == ["10.0.0.0/23"]


def test_range_to_cidrs_non_aligned():
    result = range_to_cidrs("192.168.0.0 - 192.168.2.255")
    assert len(result) == 2
    assert "192.168.0.0/23" in result
    assert "192.168.2.0/24" in result


def test_is_ipv6_true():
    assert is_ipv6("2001:db8::/32") is True


def test_is_ipv6_false():
    assert is_ipv6("192.168.0.0/24") is False


def test_aggregate_prefixes_dedup():
    prefixes = ["192.168.0.0/24", "192.168.0.0/24", "192.168.1.0/24"]
    v4, v6 = aggregate_prefixes(prefixes)
    assert "192.168.0.0/23" in v4
    assert len(v6) == 0


def test_aggregate_prefixes_mixed():
    prefixes = ["10.0.0.0/24", "2001:db8::/32"]
    v4, v6 = aggregate_prefixes(prefixes)
    assert len(v4) == 1
    assert len(v6) == 1
    assert v4[0] == "10.0.0.0/24"
    assert v6[0] == "2001:db8::/32"


def test_aggregate_prefixes_invalid():
    prefixes = ["not-a-cidr", "192.168.0.0/24"]
    v4, v6 = aggregate_prefixes(prefixes)
    assert v4 == ["192.168.0.0/24"]
    assert v6 == []
