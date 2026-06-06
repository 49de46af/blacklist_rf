# blacklist-rf

Auto-generated IP blacklist of Russian government and corporate networks, built from RIPE data.

Based on [C24Be/AS_Network_List](https://github.com/C24Be/AS_Network_List), rewritten in Python.

## Data sources

- [C24Be/AS_Network_List](https://github.com/C24Be/AS_Network_List) — original project, used as a base
- [ASN spreadsheet](https://docs.google.com/spreadsheets/d/1YWS5aMEykkM9koxcZW1q_bZBi2j1UGmTbhFhOfnrd4k) — ASNs of major companies (Yandex, VK, Sber, T-Bank, Wildberries, etc.)
- [RIPE Stat API](https://stat.ripe.net/) — all ASNs and prefixes registered in RU
- [RIPE Database](https://ftp.ripe.net/ripe/dbase/split/) — inetnum records dump with `country: RU`
- RIPE WHOIS (`whois.ripe.net:43`) — ASN and netname description resolution

## Filtering

Four levels:

1. **Patterns** (`config/patterns.txt`) — regex matching against ASN/network descriptions
2. **Exclude patterns** (`config/whitelist_patterns.txt`) — exclude matched entries
3. **ASN blacklist** (`config/asn_blacklist.txt`) — force-include by ASN number
4. **ASN whitelist** (`config/asn_whitelist.txt`) — force-exclude by ASN number

Additionally, netnames from `config/netnames.txt` are resolved via WHOIS.

VK-specific blacklists are generated separately using `config/vk_patterns.txt` and `config/vk_exclude_patterns.txt`.

## Output formats

| File | Purpose |
|------|---------|
| `blacklist.txt` | Plain CIDR list |
| `blacklist.conf` | nginx (`deny`) |
| `blacklist-v4.ipset` | ipset (`hash:net`) |
| `blacklist.nft` | nftables (sets) |
| `blacklist-v4.routes` | Linux routes (blackhole) |
| `blacklist.json` | Xray (routing rules) |
| `blacklist.yaml` | Mihomo (rule-provider) |

All formats are in `output/`, split into v4/v6 where applicable. VK-specific variants (`blacklist-vk-*`) are also generated for nftables, ipset, and routes.

## Usage

```bash
uv run python scripts/fetch_ripe_data.py        # fetch data from RIPE API
uv run python scripts/resolve_descriptions.py   # resolve descriptions via WHOIS
uv run python scripts/parse_ripe_db.py           # parse RIPE DB dump
uv run python scripts/generate_blacklist.py      # generate blacklist
uv run python scripts/export_formats.py          # export to all formats
```

Check if an IP is in the blacklist:

```bash
uv run python scripts/check_nft_blacklist.py output/blacklist.nft 31.177.95.1
```

## GitHub Actions

| Workflow | Schedule | Action |
|----------|----------|--------|
| Fetch RIPE data | 1st of month, 00:00 UTC | Fetch RU ASNs/prefixes |
| Resolve descriptions | 1st of month, 02:00-07:00 UTC | Resolve descriptions via WHOIS |
| Parse RIPE DB | Sunday, 12:00 UTC | Parse RIPE DB dump |
| Update blacklists | daily, 06:00 UTC | Generate + export |
| Update nftables | daily, 02:30 UTC | Update nft configs |

## Tests

```bash
uv run --group dev pytest
```

---

This project was rewritten with the help of an LLM.
