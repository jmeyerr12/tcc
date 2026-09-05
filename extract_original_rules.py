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


def matches_mode(rule, mode):
    if mode in ("ip", "ipv4ipv6"):
        return "IPv4" in rule or "IPv6" in rule

    if mode in ("transport", "tcpudp"):
        protocol = get_protocol(rule)
        return protocol in ("tcp", "udp")
    
    if mode == "application":
        return is_application_rule(rule)

    return False

def is_application_rule(rule):
    protocol = get_protocol(rule)
    lower = rule.lower()

    application_protocols = {
        "http",
        "http1",
        "http2",
        "dns",
        "tls",
        "ssl",
        "smtp",
        "ftp",
        "ftp-data",
        "ssh",
        "smb",
        "dcerpc",
        "krb5",
        "mqtt",
        "modbus",
        "pgsql",
        "rdp",
        "snmp",
        "sip",
        "rfb",
        "nfs",
        "ike",
        "quic",
        "ntp",
        "dhcp",
        "telnet"
    }

    if protocol in application_protocols:
        return True

    application_keywords = (
        "http.",
        "dns.",
        "tls.",
        "ssl.",
        "smtp.",
        "ftp.",
        "ssh.",
        "smb.",
        "dcerpc.",
        "krb5.",
        "mqtt.",
        "modbus.",
        "pgsql.",
        "rdp.",
        "snmp.",
        "sip.",
        "rfb.",
        "nfs.",
        "ike.",
        "quic.",
        "file.data",
        "file_data",
        "base64_data",
        "js_data",
        "vba_data"
    )

    return any(
        keyword in lower
        for keyword in application_keywords
    )


def main():
    if len(sys.argv) != 5:
        print(
            "usage:\n"
            f"  {sys.argv[0]} <ip|transport|application> "
            "<original.rules> <adapted.rules> <output.rules>\n\n"
            "modes:\n"
            "  ip           original rules related to ipv4, ipv6 or icmp\n"
            "  transport    original rules related to tcp or udp\n"
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
