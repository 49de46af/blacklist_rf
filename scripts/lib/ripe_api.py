import requests

RIPE_STAT_BASE = "https://stat.ripe.net/data"
TIMEOUT = 120


def get_country_resources(country="RU"):
    url = f"{RIPE_STAT_BASE}/country-resource-list/data.json"
    params = {"resource": country, "v4_format": "prefix"}
    response = requests.get(url, params=params, timeout=TIMEOUT)
    response.raise_for_status()
    data = response.json()
    resources = data["data"]["resources"]
    return {
        "asn": resources.get("asn", []),
        "ipv4": resources.get("ipv4", []),
        "ipv6": resources.get("ipv6", []),
    }


def get_announced_prefixes(asn):
    try:
        url = f"{RIPE_STAT_BASE}/announced-prefixes/data.json"
        params = {"resource": asn}
        response = requests.get(url, params=params, timeout=TIMEOUT)
        response.raise_for_status()
        data = response.json()
        return [p["prefix"] for p in data["data"]["prefixes"]]
    except (requests.exceptions.RequestException, KeyError):
        return []
