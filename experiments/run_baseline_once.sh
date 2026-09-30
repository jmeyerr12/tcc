#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-transport}" == application ]]; then
    echo "conjunto application fora do escopo experimental atual; consulte application-rules/README.md" >&2
    exit 2
fi

if [[ "${EUID}" -ne 0 ]]; then
    echo "execute como root: sudo $0 {transport|ip} TAXA_MBPS [DURACAO_S] [GERADORES] [THREADS_IDS|auto]" >&2
    exit 1
fi

RULESET="${1:-transport}"
RATE_MBPS="${2:-500}"
DURATION_S="${3:-10}"
GENERATORS="${4:-1}"
IDS_THREADS="${5:-${IDS_THREADS:-auto}}"
IDS_CPUS="${IDS_CPUS:-auto}"
REPLAY_CPUS="${REPLAY_CPUS:-auto}"
MODE="${EXPERIMENT_MODE:-baseline}"
TX_IF="${TX_IF:-tcc-tx}"
IDS_IF="${IDS_IF:-tcc-ids}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
PCAP="${PCAP:-${SCRIPT_DIR}/pcaps/CICIDS2017-Monday-mtu1500.pcap}"

case "${MODE}:${RULESET}" in
    baseline:transport)
        RULES="${PROJECT_DIR}/transport-rules/original-tcp-udp.rules"
        ;;
    baseline:ip)
        RULES="${PROJECT_DIR}/ip-rules/original-ip.rules"
        ;;
    cutter:transport)
        RULES="${PROJECT_DIR}/transport-rules/original-tcp-udp-adapted.rules"
        ;;
    cutter:ip)
        RULES="${PROJECT_DIR}/ip-rules/original-ip-adapted.rules"
        ;;
    *)
        echo "modo ou conjunto desconhecido: ${MODE}:${RULESET}" >&2
        exit 2
        ;;
esac

for value in "${RATE_MBPS}" "${DURATION_S}"; do
    if [[ ! "${value}" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
        echo "taxa e duracao devem ser numeros positivos" >&2
        exit 2
    fi
done
if [[ ! "${GENERATORS}" =~ ^[1-9][0-9]*$ ]]; then
    echo "o numero de geradores deve ser um inteiro positivo" >&2
    exit 2
fi
if [[ "${IDS_THREADS}" != auto && ! "${IDS_THREADS}" =~ ^[1-9][0-9]*$ ]]; then
    echo "threads do IDS deve ser um inteiro positivo ou auto" >&2
    exit 2
fi

REPLAY_CPU_LIST=()
if [[ "${IDS_CPUS}" != auto ]]; then
    if ! taskset --cpu-list "${IDS_CPUS}" true >/dev/null 2>&1; then
        echo "lista de CPUs do IDS invalida ou indisponivel: ${IDS_CPUS}" >&2
        exit 2
    fi
fi
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

for path in "${PCAP}" "${RULES}" /etc/suricata/suricata.yaml; do
    if [[ ! -r "${path}" ]]; then
        echo "arquivo ausente ou ilegivel: ${path}" >&2
        exit 1
    fi
done

for interface in "${TX_IF}" "${IDS_IF}"; do
    if ! ip link show dev "${interface}" >/dev/null 2>&1; then
        echo "interface ausente: ${interface}; execute setup_veth.sh up" >&2
        exit 1
    fi
done

if pgrep -x suricata >/dev/null; then
    echo "ja existe um processo Suricata; encerre-o antes do experimento" >&2
    exit 1
fi

case "${MODE}" in
    baseline)
        # Garante explicitamente que este ensaio e o baseline sem cortador.
        ip link set dev "${TX_IF}" xdp off
        ip link set dev "${IDS_IF}" xdp off
        ;;
    cutter)
        if ! ip -details link show dev "${IDS_IF}" | grep -q 'prog/xdp'; then
            echo "o cortador nao esta anexado a ${IDS_IF}; execute setup_cutter.sh on ${RULESET}" >&2
            exit 1
        fi
        ;;
esac

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
THREAD_SUFFIX=""
if [[ "${IDS_THREADS}" != auto ]]; then
    THREAD_SUFFIX="_w${IDS_THREADS}"
fi
RESULT_DIR="${SCRIPT_DIR}/results/${MODE}_${RULESET}_${RATE_MBPS}mbps_g${GENERATORS}${THREAD_SUFFIX}_${TIMESTAMP}"
mkdir -p "${RESULT_DIR}"

read_counter() {
    local interface="$1"
    local counter="$2"
    cat "/sys/class/net/${interface}/statistics/${counter}"
}

TX_PACKETS_BEFORE="$(read_counter "${TX_IF}" tx_packets)"
TX_BYTES_BEFORE="$(read_counter "${TX_IF}" tx_bytes)"
TX_DROPPED_BEFORE="$(read_counter "${TX_IF}" tx_dropped)"
RX_PACKETS_BEFORE="$(read_counter "${IDS_IF}" rx_packets)"
RX_BYTES_BEFORE="$(read_counter "${IDS_IF}" rx_bytes)"
RX_DROPPED_BEFORE="$(read_counter "${IDS_IF}" rx_dropped)"

SURI_PID=""
REPLAY_PIDS=()
cleanup() {
    local replay_pid
    for replay_pid in "${REPLAY_PIDS[@]}"; do
        if kill -0 "${replay_pid}" 2>/dev/null; then
            kill -TERM "${replay_pid}" 2>/dev/null || true
        fi
    done
    if [[ -n "${SURI_PID}" ]] && kill -0 "${SURI_PID}" 2>/dev/null; then
        kill -INT "${SURI_PID}" 2>/dev/null || true
        wait "${SURI_PID}" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

SURI_CMD=(suricata \
    -c /etc/suricata/suricata.yaml \
    --af-packet="${IDS_IF}" \
    --runmode=workers \
    -k none \
    -S "${RULES}" \
    -l "${RESULT_DIR}" \
    --pidfile "${RESULT_DIR}/suricata.pid" \
    --set af-packet.1.threads="${IDS_THREADS}" \
    --set stats.interval=1 \
    --set outputs.0.fast.enabled=no \
    --set outputs.1.eve-log.enabled=no)
if [[ "${IDS_CPUS}" != auto ]]; then
    SURI_CMD=(taskset --cpu-list "${IDS_CPUS}" "${SURI_CMD[@]}")
fi
"${SURI_CMD[@]}" \
    >"${RESULT_DIR}/suricata-console.log" 2>&1 &
SURI_PID=$!

suricata_ready() {
    grep -qi 'engine started[.]' \
        "${RESULT_DIR}/suricata.log" \
        "${RESULT_DIR}/suricata-console.log" 2>/dev/null
}

for _ in {1..30}; do
    if ! kill -0 "${SURI_PID}" 2>/dev/null; then
        wait "${SURI_PID}" || true
        echo "Suricata encerrou durante a inicializacao:" >&2
        tail -n 40 "${RESULT_DIR}/suricata-console.log" >&2
        exit 1
    fi
    if suricata_ready; then
        break
    fi
    sleep 0.2
done

if ! suricata_ready; then
    echo "Suricata nao confirmou a inicializacao dentro do prazo" >&2
    tail -n 40 "${RESULT_DIR}/suricata-console.log" >&2
    exit 1
fi

if [[ "${IDS_THREADS}" != auto ]]; then
    STARTED_THREADS="$(sed -nE \
        -e 's/.*Threads created -> W: ([0-9]+).*/\1/p' \
        -e 's/.*all ([0-9]+) packet processing threads?.*/\1/p' \
        "${RESULT_DIR}/suricata-console.log" | tail -n 1)"
    if [[ "${STARTED_THREADS}" != "${IDS_THREADS}" ]]; then
        echo "Suricata iniciou com ${STARTED_THREADS:-numero desconhecido} threads; solicitado: ${IDS_THREADS}" >&2
        exit 1
    fi
fi

sleep 1
RATE_PER_GENERATOR="$(awk -v rate="${RATE_MBPS}" -v generators="${GENERATORS}" 'BEGIN { printf "%.6f", rate / generators }')"
for ((generator = 1; generator <= GENERATORS; ++generator)); do
    REPLAY_CMD=(tcpreplay \
        --intf1="${TX_IF}" \
        --preload-pcap \
        --loop=0 \
        --duration="${DURATION_S}" \
        --mbps="${RATE_PER_GENERATOR}" \
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

# Permite que o IDS esvazie os buffers de captura antes da leitura final.
sleep 2

kill -INT "${SURI_PID}"
for _ in {1..150}; do
    if ! kill -0 "${SURI_PID}" 2>/dev/null; then
        break
    fi
    sleep 0.2
done
if kill -0 "${SURI_PID}" 2>/dev/null; then
    kill -TERM "${SURI_PID}"
fi
wait "${SURI_PID}" || true
SURI_PID=""

TX_PACKETS_AFTER="$(read_counter "${TX_IF}" tx_packets)"
TX_BYTES_AFTER="$(read_counter "${TX_IF}" tx_bytes)"
TX_DROPPED_AFTER="$(read_counter "${TX_IF}" tx_dropped)"
RX_PACKETS_AFTER="$(read_counter "${IDS_IF}" rx_packets)"
RX_BYTES_AFTER="$(read_counter "${IDS_IF}" rx_bytes)"
RX_DROPPED_AFTER="$(read_counter "${IDS_IF}" rx_dropped)"

{
    printf 'mode\truleset\ttarget_mbps\tduration_s\tgenerators\tids_threads\tids_cpus\treplay_cpus\n'
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "${MODE}" "${RULESET}" "${RATE_MBPS}" "${DURATION_S}" \
        "${GENERATORS}" "${IDS_THREADS}" "${IDS_CPUS}" "${REPLAY_CPUS}"
    printf '\ninterface\tcounter\tbefore\tafter\tdelta\n'
    printf '%s\ttx_packets\t%s\t%s\t%s\n' "${TX_IF}" "${TX_PACKETS_BEFORE}" "${TX_PACKETS_AFTER}" "$((TX_PACKETS_AFTER - TX_PACKETS_BEFORE))"
    printf '%s\ttx_bytes\t%s\t%s\t%s\n' "${TX_IF}" "${TX_BYTES_BEFORE}" "${TX_BYTES_AFTER}" "$((TX_BYTES_AFTER - TX_BYTES_BEFORE))"
    printf '%s\ttx_dropped\t%s\t%s\t%s\n' "${TX_IF}" "${TX_DROPPED_BEFORE}" "${TX_DROPPED_AFTER}" "$((TX_DROPPED_AFTER - TX_DROPPED_BEFORE))"
    printf '%s\trx_packets\t%s\t%s\t%s\n' "${IDS_IF}" "${RX_PACKETS_BEFORE}" "${RX_PACKETS_AFTER}" "$((RX_PACKETS_AFTER - RX_PACKETS_BEFORE))"
    printf '%s\trx_bytes\t%s\t%s\t%s\n' "${IDS_IF}" "${RX_BYTES_BEFORE}" "${RX_BYTES_AFTER}" "$((RX_BYTES_AFTER - RX_BYTES_BEFORE))"
    printf '%s\trx_dropped\t%s\t%s\t%s\n' "${IDS_IF}" "${RX_DROPPED_BEFORE}" "${RX_DROPPED_AFTER}" "$((RX_DROPPED_AFTER - RX_DROPPED_BEFORE))"
} >"${RESULT_DIR}/interface-counters.tsv"

final_suricata_counter() {
    local counter="$1"
    awk -F '|' -v target="${counter}" '
        {
            key = $1
            value = $3
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            if (key == target) {
                result = value
            }
        }
        END { print result == "" ? 0 : result }
    ' "${RESULT_DIR}/stats.log"
}

SENT_PACKETS="$(awk '/^Actual:/ { sum += $2 } END { print sum + 0 }' "${RESULT_DIR}"/tcpreplay-*.log)"
SENT_BYTES="$(awk '/^Actual:/ { value=$4; gsub(/[()]/, "", value); sum += value } END { printf "%.0f\n", sum }' "${RESULT_DIR}"/tcpreplay-*.log)"
ACTUAL_MBPS="$(awk '/^Rated:/ { for (i = 1; i <= NF; ++i) if ($i ~ /^Mbps/) sum += $(i-1) } END { printf "%.2f\n", sum }' "${RESULT_DIR}"/tcpreplay-*.log)"
ACTUAL_PPS="$(awk '/^Rated:/ && /pps/ { sum += $(NF-1) } END { printf "%.2f\n", sum }' "${RESULT_DIR}"/tcpreplay-*.log)"
ACTUAL_DURATION_S="$(awk '/^Actual:/ { if ($8 > maximum) maximum = $8 } END { printf "%.2f\n", maximum }' "${RESULT_DIR}"/tcpreplay-*.log)"
TARGET_ACHIEVEMENT_PERCENT="$(awk -v actual="${ACTUAL_MBPS}" -v target="${RATE_MBPS}" 'BEGIN { printf "%.4f", target == 0 ? 0 : 100 * actual / target }')"
ENOBUFS_RETRIES="$(awk '/Retried packets \(ENOBUFS\):/ { sum += $NF } END { print sum + 0 }' "${RESULT_DIR}"/tcpreplay-*.log)"
TX_DROPPED_DELTA="$((TX_DROPPED_AFTER - TX_DROPPED_BEFORE))"
IDS_PACKETS="$(final_suricata_counter decoder.pkts)"
IDS_BYTES="$(final_suricata_counter decoder.bytes)"
KERNEL_PACKETS="$(final_suricata_counter capture.kernel_packets)"
KERNEL_DROPS="$(final_suricata_counter capture.kernel_drops)"
INVALID_CHECKSUMS="$(final_suricata_counter tcp.invalid_checksum)"
END_TO_END_LOSS_PERCENT="$(awk -v sent="${SENT_PACKETS}" -v ids="${IDS_PACKETS}" 'BEGIN { printf "%.6f", sent == 0 ? 0 : 100 * (sent - ids) / sent }')"
CAPTURE_LOSS_PERCENT="$(awk -v captured="${KERNEL_PACKETS}" -v dropped="${KERNEL_DROPS}" 'BEGIN { printf "%.6f", captured == 0 ? 0 : 100 * dropped / captured }')"
IDS_MBPS="$(awk -v offered="${ACTUAL_MBPS}" -v sent="${SENT_BYTES}" -v ids="${IDS_BYTES}" 'BEGIN { printf "%.2f", sent == 0 ? 0 : offered * ids / sent }')"
IDS_PPS="$(awk -v offered="${ACTUAL_PPS}" -v sent="${SENT_PACKETS}" -v ids="${IDS_PACKETS}" 'BEGIN { printf "%.2f", sent == 0 ? 0 : offered * ids / sent }')"
IDS_BYTE_REDUCTION_PERCENT="$(awk -v sent="${SENT_BYTES}" -v ids="${IDS_BYTES}" 'BEGIN { printf "%.6f", sent == 0 ? 0 : 100 * (sent - ids) / sent }')"

{
    printf 'mode\truleset\ttarget_mbps\tactual_mbps\ttarget_achievement_percent\tactual_pps\tids_mbps\tids_pps\tids_byte_reduction_percent\trequested_duration_s\tactual_duration_s\tgenerators\tids_threads\tids_cpus\treplay_cpus\ttcpreplay_enobufs\tinterface_tx_dropped\tsent_packets\tsent_bytes\tids_packets\tids_bytes\tkernel_packets\tkernel_drops\tinvalid_checksums\tcapture_loss_percent\tend_to_end_loss_percent\n'
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "${MODE}" "${RULESET}" "${RATE_MBPS}" "${ACTUAL_MBPS}" "${TARGET_ACHIEVEMENT_PERCENT}" \
        "${ACTUAL_PPS}" "${IDS_MBPS}" "${IDS_PPS}" \
        "${IDS_BYTE_REDUCTION_PERCENT}" "${DURATION_S}" "${ACTUAL_DURATION_S}" "${GENERATORS}" "${IDS_THREADS}" \
        "${IDS_CPUS}" "${REPLAY_CPUS}" \
        "${ENOBUFS_RETRIES}" "${TX_DROPPED_DELTA}" \
        "${SENT_PACKETS}" "${SENT_BYTES}" "${IDS_PACKETS}" "${IDS_BYTES}" \
        "${KERNEL_PACKETS}" "${KERNEL_DROPS}" "${INVALID_CHECKSUMS}" \
        "${CAPTURE_LOSS_PERCENT}" "${END_TO_END_LOSS_PERCENT}"
} >"${RESULT_DIR}/summary.tsv"

echo "resultado: ${RESULT_DIR}"
echo
for replay_log in "${RESULT_DIR}"/tcpreplay-*.log; do
    echo "-- $(basename "${replay_log}") --"
    cat "${replay_log}"
done
echo
cat "${RESULT_DIR}/interface-counters.tsv"
echo
echo "resumo:"
cat "${RESULT_DIR}/summary.tsv"

if [[ -n "${SUDO_UID:-}" && -n "${SUDO_GID:-}" ]]; then
    chown -R "${SUDO_UID}:${SUDO_GID}" "${RESULT_DIR}"
fi
