import re
import sys
import urllib.request


def convert_github_url(url):
    return url.replace("https://github.com/", "https://raw.githubusercontent.com/").replace("/blob", "")


def read_lines_from_source(source):
    if source == "-":
        return [ln.rstrip("\n") for ln in sys.stdin]

    if source.startswith("http://") or source.startswith("https://"):
        if "github.com" in source:
            source = convert_github_url(source)
        with urllib.request.urlopen(source, timeout=30) as resp:
            return resp.read().decode("utf-8").splitlines()

    with open(source, "r", encoding="utf-8") as f:
        return f.readlines()


def iter_netnames(lines):
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if re.match(r"^netname:", stripped, re.IGNORECASE):
            yield stripped.split(":", 1)[1].strip()
        else:
            yield stripped
