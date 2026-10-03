#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "execute como root: sudo $0" >&2
    exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
INPUT="${PCAP:-${SCRIPT_DIR}/pcaps/CICIDS2017-Monday-mtu1500.pcap}"
SUPPORTED="${SCRIPT_DIR}/pcaps/CICIDS2017-Monday-supported.pcap"
WASH="${PROJECT_DIR}/build/wash_pcap"
STATS="${PROJECT_DIR}/build/pcap_stats"
BPF_OBJECT="${PROJECT_DIR}/build/af_xdp_kern.o"

for path in "${INPUT}" "${WASH}" "${STATS}" "${BPF_OBJECT}"; do
    if [[ ! -r "${path}" ]]; then
        echo "arquivo ausente: ${path}; execute make precut-tools" >&2
        exit 1
    fi
done

temporary="${SUPPORTED}.tmp.$$"
trap 'rm -f "${temporary}"' EXIT INT TERM
tcpdump -nr "${INPUT}" -w "${temporary}" \
    'ip and (tcp or udp) and (ip[0] & 0x0f = 5) and (ip[6:2] & 0x3fff = 0)'
mv "${temporary}" "${SUPPORTED}"

echo "PCAP comum sem corte:"
"${STATS}" "${SUPPORTED}"

for ruleset in application transport ip; do
    case "${ruleset}" in
        application) summary="${PROJECT_DIR}/application-rules/summary.txt" ;;
        transport) summary="${PROJECT_DIR}/transport-rules/summary.txt" ;;
        ip) summary="${PROJECT_DIR}/ip-rules/summary.txt" ;;
    esac
    output="${SCRIPT_DIR}/pcaps/CICIDS2017-Monday-supported-${ruleset}-cut.pcap"
    echo
    echo "Gerando ${output}"
    "${WASH}" "${BPF_OBJECT}" "${summary}" "${SUPPORTED}" "${output}"
    "${STATS}" "${output}"
done

if [[ -n "${SUDO_UID:-}" && -n "${SUDO_GID:-}" ]]; then
    chown "${SUDO_UID}:${SUDO_GID}" "${SUPPORTED}" \
        "${SCRIPT_DIR}"/pcaps/CICIDS2017-Monday-supported-*-cut.pcap
fi

echo
echo "PCAPs preparados. O XDP deve permanecer desligado durante a comparacao."
