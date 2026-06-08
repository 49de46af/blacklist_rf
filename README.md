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

### Separate lists

**RKN Collaborants** (`config/rkn_collaborants.txt`) — ASNs of companies cooperating with Russian censorship (Yandex, VK, Sberbank, T-Bank, Wildberries, Ozon, Avito, VTB, Alfa-Bank, 2GIS, Megamarket, RuTube, MIR/NSPK, Rostelecom). Generated independently from the main blacklist via RIPE API. Output: `rkn-collaborants*` files in all formats.

**VK** (`config/vk_patterns.txt`, `config/vk_exclude_patterns.txt`) — VK/Odnoklassniki networks filtered by description. Output: `blacklist-vk*` files.

## Output formats

| Format | Main blacklist | RKN Collaborants | VK |
|--------|---------------|-------------------|-----|
| Plain CIDR | `blacklist.txt` | `rkn-collaborants.txt` | `blacklist-vk.txt` |
| nginx | `blacklist.conf` | `rkn-collaborants.conf` | — |
| ipset | `blacklist-v4.ipset` | `rkn-collaborants-v4.ipset` | `blacklist-vk-v4.ipset` |
| nftables | `blacklist.nft` | `rkn-collaborants.nft` | `blacklist-vk.nft` |
| routes | `blacklist-v4.routes` | `rkn-collaborants-v4.routes` | `blacklist-vk-v4.routes` |
| Mihomo | `blacklist.yaml` | — | — |

All formats are in `output/`, split into v4/v6 where applicable. Lists are independent — combine as needed (e.g. `nft -f blacklist.nft && nft -f rkn-collaborants.nft`).

## Usage

```bash
uv run scripts/fetch_ripe_data.py        # fetch data from RIPE API
uv run scripts/resolve_descriptions.py   # resolve descriptions via WHOIS
uv run scripts/parse_ripe_db.py           # parse RIPE DB dump
uv run scripts/generate_blacklist.py      # generate blacklist
uv run scripts/export_formats.py          # export to all formats
```

Check if an IP is in the blacklist:

```bash
uv run scripts/check_nft_blacklist.py output/blacklist.nft 31.177.95.1
cat output/blacklist.nft | uv run scripts/check_nft_blacklist.py - 31.177.95.1
```

## CLI tools

Standalone utilities for querying networks by ASN or netname.

### network_list_from_as.py

Retrieve networks announced by an AS number:

```bash
uv run scripts/network_list_from_as.py AS47764
uv run scripts/network_list_from_as.py -q config/rkn_collaborants.txt
uv run scripts/network_list_from_as.py https://example.com/asns.txt
echo "AS13238" | uv run scripts/network_list_from_as.py -q -
```

### network_list_from_netname.py

Retrieve networks by network name via WHOIS:

```bash
uv run scripts/network_list_from_netname.py config/netnames.txt
uv run scripts/network_list_from_netname.py -q https://example.com/netnames.txt
```

Both tools support file paths, URLs (GitHub URLs are auto-converted to raw), and stdin (`-`).

## GitHub Actions

| Workflow | Schedule | Action |
|----------|----------|--------|
| Fetch RIPE data | 1st of month, 00:00 UTC | Fetch RU ASNs/prefixes |
| Resolve descriptions | 1st of month, 02:00-07:00 UTC | Resolve descriptions via WHOIS |
| Parse RIPE DB | Sunday, 12:00 UTC | Parse RIPE DB dump |
| Update blacklists | daily, 06:00 UTC | Generate + export all formats |

## Tests

```bash
uv run --group dev pytest
```

---

This project was rewritten with the help of an LLM.
