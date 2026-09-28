#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "execute como root: sudo $0 {baseline|application|transport|ip} [DURACAO_S] [GERADORES]" >&2
    exit 1
fi

SCENARIO="${1:-baseline}"
DURATION_S="${2:-10}"
GENERATORS="${3:-1}"
TX_IF="${TX_IF:-tcc-tx}"
IDS_IF="${IDS_IF:-tcc-ids}"
REPLAY_CPUS="${REPLAY_CPUS:-auto}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PCAP="${PCAP:-${SCRIPT_DIR}/pcaps/CICIDS2017-Monday-mtu1500.pcap}"

case "${SCENARIO}" in
    baseline|application|transport|ip) ;;
    *)
        echo "cenario desconhecido: ${SCENARIO}" >&2
        exit 2
        ;;
esac
if [[ ! "${DURATION_S}" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    echo "duracao deve ser um numero positivo" >&2
    exit 2
fi
if [[ ! "${GENERATORS}" =~ ^[1-9][0-9]*$ ]]; then
    echo "geradores deve ser um inteiro positivo" >&2
    exit 2
fi

REPLAY_CPU_LIST=()
if [[ "${REPLAY_CPUS}" != auto ]]; then
    IFS=',' read -r -a REPLAY_CPU_LIST <<<"${REPLAY_CPUS}"
    if (( ${#REPLAY_CPU_LIST[@]} < GENERATORS )); then
        echo "REPLAY_CPUS precisa informar ao menos uma CPU por gerador" >&2
        exit 2
    fi
    for cpu in "${REPLAY_CPU_LIST[@]}"; do
        if [[ ! "${cpu}" =~ ^[0-9]+$ ]] ||
           ! taskset --cpu-list "${cpu}" true >/dev/null 2>&1; then
            echo "CPU do gerador invalida ou indisponivel: ${cpu}" >&2
            exit 2
        fi
    done
fi
if [[ ! -r "${PCAP}" ]]; then
    echo "PCAP ausente ou ilegivel: ${PCAP}" >&2
    exit 1
fi
for interface in "${TX_IF}" "${IDS_IF}"; do
    if ! ip link show dev "${interface}" >/dev/null 2>&1; then
        echo "interface ausente: ${interface}; execute setup_veth.sh up" >&2
        exit 1
    fi
done
if pgrep -x suricata >/dev/null; then
    echo "encerre o Suricata antes de medir somente o gerador" >&2
    exit 1
fi

if [[ "${SCENARIO}" == baseline ]]; then
    "${SCRIPT_DIR}/setup_cutter.sh" off >/dev/null
else
    "${SCRIPT_DIR}/setup_cutter.sh" on "${SCENARIO}" >/dev/null
fi

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RESULT_DIR="${SCRIPT_DIR}/results/capacity_${SCENARIO}_top_g${GENERATORS}_${TIMESTAMP}"
mkdir -p "${RESULT_DIR}"

read_counter() {
    cat "/sys/class/net/$1/statistics/$2"
}

TX_PACKETS_BEFORE="$(read_counter "${TX_IF}" tx_packets)"
TX_BYTES_BEFORE="$(read_counter "${TX_IF}" tx_bytes)"
TX_DROPPED_BEFORE="$(read_counter "${TX_IF}" tx_dropped)"

REPLAY_PIDS=()
cleanup() {
    local replay_pid
    for replay_pid in "${REPLAY_PIDS[@]}"; do
        if kill -0 "${replay_pid}" 2>/dev/null; then
            kill -TERM "${replay_pid}" 2>/dev/null || true
        fi
    done
}
trap cleanup EXIT INT TERM

for ((generator = 1; generator <= GENERATORS; ++generator)); do
    REPLAY_CMD=(tcpreplay \
        --intf1="${TX_IF}" \
        --preload-pcap \
        --loop=0 \
        --duration="${DURATION_S}" \
        --topspeed \
        "${PCAP}")
    if [[ "${REPLAY_CPUS}" != auto ]]; then
        REPLAY_CMD=(taskset --cpu-list "${REPLAY_CPU_LIST[generator - 1]}" "${REPLAY_CMD[@]}")
    fi
    "${REPLAY_CMD[@]}" \
        >"${RESULT_DIR}/tcpreplay-${generator}.log" 2>&1 &
    REPLAY_PIDS+=("$!")
done

REPLAY_FAILED=0
for replay_pid in "${REPLAY_PIDS[@]}"; do
    if ! wait "${replay_pid}"; then
        REPLAY_FAILED=1
    fi
done
REPLAY_PIDS=()
if [[ "${REPLAY_FAILED}" -ne 0 ]]; then
    echo "um ou mais processos tcpreplay falharam" >&2
    exit 1
fi

TX_PACKETS_AFTER="$(read_counter "${TX_IF}" tx_packets)"
TX_BYTES_AFTER="$(read_counter "${TX_IF}" tx_bytes)"
TX_DROPPED_AFTER="$(read_counter "${TX_IF}" tx_dropped)"

SENT_PACKETS="$(awk '/^Actual:/ { sum += $2 } END { print sum + 0 }' "${RESULT_DIR}"/tcpreplay-*.log)"
SENT_BYTES="$(awk '/^Actual:/ { value=$4; gsub(/[()]/, "", value); sum += value } END { printf "%.0f\n", sum }' "${RESULT_DIR}"/tcpreplay-*.log)"
ACTUAL_MBPS="$(awk '/^Rated:/ { for (i = 1; i <= NF; ++i) if ($i ~ /^Mbps/) sum += $(i-1) } END { printf "%.2f\n", sum }' "${RESULT_DIR}"/tcpreplay-*.log)"
ACTUAL_PPS="$(awk '/^Rated:/ && /pps/ { sum += $(NF-1) } END { printf "%.2f\n", sum }' "${RESULT_DIR}"/tcpreplay-*.log)"
ACTUAL_DURATION_S="$(awk '/^Actual:/ { if ($8 > maximum) maximum = $8 } END { printf "%.2f\n", maximum }' "${RESULT_DIR}"/tcpreplay-*.log)"
ENOBUFS_RETRIES="$(awk '/Retried packets \(ENOBUFS\):/ { sum += $NF } END { print sum + 0 }' "${RESULT_DIR}"/tcpreplay-*.log)"

{
    printf 'scenario\tduration_s\tgenerators\treplay_cpus\tactual_mbps\tactual_pps\tsent_packets\tsent_bytes\ttcpreplay_enobufs\tinterface_tx_packets\tinterface_tx_bytes\tinterface_tx_dropped\n'
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "${SCENARIO}" "${ACTUAL_DURATION_S}" "${GENERATORS}" "${REPLAY_CPUS}" \
        "${ACTUAL_MBPS}" "${ACTUAL_PPS}" "${SENT_PACKETS}" "${SENT_BYTES}" \
        "${ENOBUFS_RETRIES}" \
        "$((TX_PACKETS_AFTER - TX_PACKETS_BEFORE))" \
        "$((TX_BYTES_AFTER - TX_BYTES_BEFORE))" \
        "$((TX_DROPPED_AFTER - TX_DROPPED_BEFORE))"
} >"${RESULT_DIR}/summary.tsv"

echo "resultado: ${RESULT_DIR}"
cat "${RESULT_DIR}/summary.tsv"

if [[ -n "${SUDO_UID:-}" && -n "${SUDO_GID:-}" ]]; then
    chown -R "${SUDO_UID}:${SUDO_GID}" "${RESULT_DIR}"
fi
