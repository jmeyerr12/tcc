#!/usr/bin/env bash
set -euo pipefail

TX_IF="${TX_IF:-tcc-tx}"
IDS_IF="${IDS_IF:-tcc-ids}"

if [[ "${EUID}" -ne 0 ]]; then
    echo "execute como root: sudo $0 ${1:-up}" >&2
    exit 1
fi

case "${1:-up}" in
    up)
        if ip link show dev "${TX_IF}" >/dev/null 2>&1; then
            ip link delete dev "${TX_IF}"
        elif ip link show dev "${IDS_IF}" >/dev/null 2>&1; then
            ip link delete dev "${IDS_IF}"
        fi

        ip link add "${TX_IF}" type veth peer name "${IDS_IF}"
        # O PCAP usado nos ensaios foi normalizado para quadros de ate 1514
        # bytes. MTU 1500 tambem e necessario para XDP nativo sobre veth.
        ip link set dev "${TX_IF}" mtu 1500 txqueuelen 10000 up
        ip link set dev "${IDS_IF}" mtu 1500 txqueuelen 10000 up

        # O baseline deve começar sem o cortador em nenhuma ponta da veth.
        ip link set dev "${TX_IF}" xdp off
        ip link set dev "${IDS_IF}" xdp off

        ethtool -K "${TX_IF}" gro off gso off tso off
        ethtool -K "${IDS_IF}" gro off gso off tso off

        echo "veth pronta para o baseline (sem XDP):"
        ip -brief link show dev "${TX_IF}"
        ip -brief link show dev "${IDS_IF}"
        ip -details link show dev "${IDS_IF}"
        ;;
    status)
        ip -brief link show dev "${TX_IF}"
        ip -brief link show dev "${IDS_IF}"
        ip -details link show dev "${IDS_IF}"
        ;;
    down)
        if ip link show dev "${TX_IF}" >/dev/null 2>&1; then
            ip link delete dev "${TX_IF}"
        elif ip link show dev "${IDS_IF}" >/dev/null 2>&1; then
            ip link delete dev "${IDS_IF}"
        fi
        ;;
    *)
        echo "uso: sudo $0 {up|status|down}" >&2
        exit 2
        ;;
esac
