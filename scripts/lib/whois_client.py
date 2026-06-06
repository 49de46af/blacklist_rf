import socket

WHOIS_SERVER = "whois.ripe.net"
WHOIS_PORT = 43


def whois_query(query, get_field="netname", get_org=False):
    try:
        return _do_query(query, get_field, get_org)
    except (socket.error, socket.timeout, OSError):
        return [] if get_field == "inetnum" else None


def _do_query(query, get_field, get_org):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(30)
    try:
        s.connect((WHOIS_SERVER, WHOIS_PORT))
        s.send(f"{query}\r\n".encode())

        response = ""
        while True:
            data = s.recv(4096)
            if not data:
                break
            try:
                response += data.decode("utf-8")
            except UnicodeDecodeError:
                response += data.decode("latin-1")
    finally:
        s.close()

    org_name = None
    inetnums = []
    name = None

    for line in response.split("\n"):
        if line.startswith("org-name:"):
            org_name = line.split(":", 1)[1].strip()
        if line.startswith(f"{get_field}:"):
            value = line.split(":", 1)[1].strip()
            if get_field == "inetnum":
                inetnums.append(value)
            else:
                name = value

    if org_name is None:
        org_name = "No org name found"

    if get_field == "inetnum":
        return inetnums

    if name is None:
        name = "-no-description-"

    if get_org:
        return f"{name} ({org_name})"
    return name
