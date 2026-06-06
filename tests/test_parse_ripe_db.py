import json
import os
import tempfile

from parse_ripe_db import parse_inetnum_file, _normalize_record, write_outputs


SAMPLE_RIPE_DATA = """\
inetnum:        192.168.0.0 - 192.168.0.255
netname:        TEST-NET
descr:          Test network
country:        RU
org:            ORG-TEST1-RIPE
mnt-by:         MNT-TEST

inetnum:        10.0.0.0 - 10.0.0.255
netname:        OTHER-NET
descr:          Other network
country:        DE
org:            ORG-OTHER1-RIPE
mnt-by:         MNT-OTHER

inetnum:        172.16.0.0 - 172.16.1.255
netname:        RU-GOV-NET
descr:          Government network
country:        RU
org:            ORG-GOV1-RIPE
mnt-by:         MNT-GOV
"""


def test_parse_inetnum_file():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="latin-1") as f:
        f.write(SAMPLE_RIPE_DATA)
        f.flush()
        path = f.name

    try:
        records = parse_inetnum_file(path)
        assert len(records) == 2
        names = {r["netname"].split()[0] for r in records}
        assert "TEST-NET" in names
        assert "RU-GOV-NET" in names
        assert not any("OTHER-NET" in r["netname"] for r in records)
    finally:
        os.unlink(path)


def test_normalize_record_valid():
    record = {
        "inetnum": "192.168.0.0 - 192.168.0.255",
        "netname": "TEST",
        "descr": "test",
        "country": "RU",
        "org": "ORG",
    }
    result = _normalize_record(record)
    assert result is not None
    assert result["inetnum"] == ["192.168.0.0/24"]


def test_normalize_record_invalid_range():
    record = {
        "inetnum": "invalid",
        "netname": "TEST",
        "descr": "test",
        "country": "RU",
        "org": "ORG",
    }
    result = _normalize_record(record)
    assert result is None


def test_write_outputs():
    records = [
        {
            "inetnum": ["192.168.0.0/24"],
            "netname": "TEST-NET",
            "descr": "Test",
            "country": "RU",
            "org": "ORG-TEST",
        }
    ]
    with tempfile.TemporaryDirectory() as tmpdir:
        text_path = os.path.join(tmpdir, "test.txt")
        json_path = os.path.join(tmpdir, "test.json")
        write_outputs(records, text_path, json_path)

        with open(text_path) as f:
            content = f.read()
        assert "192.168.0.0/24" in content
        assert "TEST-NET" in content

        with open(json_path) as f:
            data = json.load(f)
        assert len(data) == 1
        assert data[0]["netname"] == "TEST-NET"
