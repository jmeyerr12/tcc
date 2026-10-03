#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "execute como root: sudo $0 {on RULESET|off|status}" >&2
    exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
TX_IF="${TX_IF:-tcc-tx}"
IDS_IF="${IDS_IF:-tcc-ids}"
PROGRAM_PIN="/sys/fs/bpf/jmm23_xdp"
MAP_DIR="/sys/fs/bpf/jmm23_maps"

detach() {
    if ip link show dev "${IDS_IF}" >/dev/null 2>&1; then
        ip link set dev "${IDS_IF}" xdp off
    fi
}

case "${1:-status}" in
    on)
        RULESET="${2:-}"
        case "${RULESET}" in
            application|transport|ip) ;;
            *)
                echo "conjunto desconhecido: ${RULESET}; use application, transport ou ip" >&2
                exit 2
                ;;
        esac

        # Read regenerated group intervals; never reuse a pilot's constants.
        interval_text="$(python3 - "${PROJECT_DIR}" "${RULESET}" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from run_intervals import summary_intervals
path = Path(sys.argv[1]) / (sys.argv[2] + '-rules') / 'summary.txt'
for start, end in summary_intervals(path):
    print(f'{start}-{end}')
PY
        )"
        mapfile -t INTERVALS <<< "${interval_text}"

        if ! ip link show dev "${IDS_IF}" >/dev/null 2>&1; then
            echo "interface ausente: ${IDS_IF}; execute setup_veth.sh up" >&2
            exit 1
        fi
        if ! ip link show dev "${TX_IF}" >/dev/null 2>&1; then
            echo "interface ausente: ${TX_IF}; execute setup_veth.sh up" >&2
            exit 1
        fi
        if ! mountpoint -q /sys/fs/bpf; then
            echo "/sys/fs/bpf nao esta montado" >&2
            exit 1
        fi

        if [[ ! -r "${PROJECT_DIR}/build/af_xdp_kern.o" ]]; then
            echo "objeto XDP ausente; execute make na raiz do projeto" >&2
            exit 1
        fi

        detach
        # veth recusa XDP nativo quando o MTU do peer exige frames maiores que
        # o buffer XDP. O PCAP do experimento ja foi normalizado para MTU 1500.
        ip link set dev "${TX_IF}" mtu 1500
        ip link set dev "${IDS_IF}" mtu 1500
        rm -f "${PROGRAM_PIN}"
        rm -rf "${MAP_DIR}"
        mkdir -p "${MAP_DIR}"

        bpftool prog load \
            "${PROJECT_DIR}/build/af_xdp_kern.o" \
            "${PROGRAM_PIN}" \
            type xdp \
            pinmaps "${MAP_DIR}"
        python3 "${PROJECT_DIR}/run_intervals.py" --dump "${INTERVALS[@]}"
        ip link set dev "${IDS_IF}" xdpdrv pinned "${PROGRAM_PIN}"

        echo "cortador ativo em ${IDS_IF} para ${RULESET}: ${INTERVALS[*]}"
        ip -details link show dev "${IDS_IF}"
        ;;
    off)
        detach
        echo "cortador desligado em ${IDS_IF}"
        ip -details link show dev "${IDS_IF}"
        ;;
    status)
        ip -details link show dev "${IDS_IF}"
        if [[ -e "${PROGRAM_PIN}" ]]; then
            bpftool prog show pinned "${PROGRAM_PIN}"
        fi
        ;;
    *)
        echo "uso: sudo $0 {on application|on transport|on ip|off|status}" >&2
        exit 2
        ;;
esac
