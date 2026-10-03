#!/usr/bin/env python3

import re
import sys


ACTIONS = r"(alert|drop|pass|reject|sdrop|log)"


def get_sid(rule):
    match = re.search(r"\bsid\s*:\s*(\d+)\s*;", rule)
    return match.group(1) if match else None


def get_protocol(rule):
    match = re.match(
        rf"^{ACTIONS}\s+(\S+)",
        rule.strip(),
        re.IGNORECASE
    )

    return match.group(2).lower() if match else None


def load_adapted_sids(filename):
    sids = set()

    with open(filename, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            stripped = line.strip()

            if not stripped or stripped.startswith("#"):
                continue

            sid = get_sid(stripped)

            if sid:
                sids.add(sid)

    return sids


NETWORK_PROTOCOLS = {"ip", "ipv6", "icmp", "icmpv6", "pkthdr"}
TRANSPORT_PROTOCOLS = {"tcp", "udp", "tcp-pkt", "tcp-stream", "sctp"}
APPLICATION_PROTOCOLS = {
    "http", "http1", "http2", "dns", "tls", "ssl", "smtp", "ftp", "ftp-data",
    "ssh", "smb", "dcerpc", "krb5", "mqtt", "modbus", "pgsql", "rdp", "snmp",
    "sip", "rfb", "nfs", "ike", "quic", "ntp", "dhcp", "telnet",
}


def classify_rule(rule):
    """Classify the original header, before application-to-TCP adaptation."""
    protocol = get_protocol(rule)
    if protocol in NETWORK_PROTOCOLS:
        return "ip"
    if protocol in TRANSPORT_PROTOCOLS:
        return "transport"
    if protocol in APPLICATION_PROTOCOLS:
        return "application"
    raise ValueError(f"protocol without a group: {protocol!r}")


def matches_mode(rule, mode):
    mode = {"ipv4ipv6": "ip", "tcpudp": "transport"}.get(mode, mode)
    return classify_rule(rule) == mode


def is_application_rule(rule):
    return get_protocol(rule) in APPLICATION_PROTOCOLS


def main():
    if len(sys.argv) != 5:
        print(
            "usage:\n"
            f"  {sys.argv[0]} <ip|transport|application> "
            "<original.rules> <adapted.rules> <output.rules>\n\n"
            "modes:\n"
            "  ip           original headers ip, ipv6, icmp, icmpv6 or pkthdr\n"
            "  transport    original headers tcp, udp, tcp-pkt, tcp-stream or sctp\n"
            "  application  original rules related to application layer"
        )
        return 1

    mode = sys.argv[1].lower()
    original_file = sys.argv[2]
    adapted_file = sys.argv[3]
    output_file = sys.argv[4]

    if mode not in ("ip", "transport", "application"):
        print(
            "invalid mode. use 'ip', 'transport' or 'application'."
        )
        return 1

    adapted_sids = load_adapted_sids(adapted_file)

    found = 0

    with open(
        original_file,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as source, open(
        output_file,
        "w",
        encoding="utf-8"
    ) as output:

        for line in source:
            stripped = line.strip()

            if not stripped or stripped.startswith("#"):
                continue

            sid = get_sid(stripped)

            if not sid or sid not in adapted_sids:
                continue

            if matches_mode(stripped, mode):
                output.write(line)
                found += 1

    print(f"regras extraidas: {found}")
    print(f"arquivo gerado: {output_file}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
