#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "execute como root: sudo $0 {application|transport|ip} [DURACAO_S] [CARGA_MBPS|all]" >&2
    exit 1
fi

RULESET="${1:-application}"
DURATION_S="${2:-10}"
RATE_SELECTION="${3:-all}"
case "${RULESET}" in
    application|transport|ip) ;;
    *) echo "conjunto desconhecido: ${RULESET}" >&2; exit 2 ;;
esac
if [[ ! "${DURATION_S}" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    echo "duracao deve ser um numero positivo" >&2
    exit 2
fi
case "${RATE_SELECTION}" in
    all) RATES=(500 1000 2000 5000 7500) ;;
    500|1000|2000|5000|7500) RATES=("${RATE_SELECTION}") ;;
    *) echo "carga deve ser uma de: 500, 1000, 2000, 5000, 7500 ou all" >&2; exit 2 ;;
esac

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ORIGINAL="${SCRIPT_DIR}/pcaps/CICIDS2017-Monday-supported.pcap"
CUT="${SCRIPT_DIR}/pcaps/CICIDS2017-Monday-supported-${RULESET}-cut.pcap"
STATS="${SCRIPT_DIR}/../build/pcap_stats"
source "${SCRIPT_DIR}/replay_rate.sh"
for path in "${ORIGINAL}" "${CUT}" "${STATS}"; do
    if [[ ! -r "${path}" ]]; then
        echo "arquivo ausente: ${path}; execute sudo ./experiments/prepare_pre_cut_pcaps.sh" >&2
        exit 1
    fi
done

original_bytes="$("${STATS}" "${ORIGINAL}" | awk -F= '$1=="bytes_capturados" {print $2}')"
original_packets="$("${STATS}" "${ORIGINAL}" | awk -F= '$1=="pacotes" {print $2}')"
cut_bytes="$("${STATS}" "${CUT}" | awk -F= '$1=="bytes_capturados" {print $2}')"
if [[ -z "${original_bytes}" || -z "${original_packets}" || -z "${cut_bytes}" || \
      "${original_bytes}" -eq 0 || "${original_packets}" -eq 0 ]]; then
    echo "nao foi possivel calcular os tamanhos dos PCAPs" >&2
    exit 1
fi
size_ratio="$(awk -v cut="${cut_bytes}" -v original="${original_bytes}" \
    'BEGIN { printf "%.9f", cut / original }')"
reduction="$(awk -v ratio="${size_ratio}" 'BEGIN { printf "%.2f", 100 * (1-ratio) }')"

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RESULT_DIR="${SCRIPT_DIR}/results/precut_comparison_${RULESET}_${TIMESTAMP}"
mkdir -p "${RESULT_DIR}"

cleanup() {
    "${SCRIPT_DIR}/setup_cutter.sh" off >/dev/null 2>&1 || true
    if [[ -n "${SUDO_UID:-}" && -n "${SUDO_GID:-}" ]]; then
        chown -R "${SUDO_UID}:${SUDO_GID}" "${RESULT_DIR}"
    fi
}
trap cleanup EXIT INT TERM

"${SCRIPT_DIR}/setup_veth.sh" up >/dev/null
"${SCRIPT_DIR}/setup_cutter.sh" off >/dev/null
printf 'Comparacao sem XDP: ruleset=%s, reducao do PCAP=%s%%\n' "${RULESET}" "${reduction}"

COMPARISON="${RESULT_DIR}/comparison.tsv"
printf 'offered_original_mbps\tsize_reduction_percent\ttarget_pps\toriginal_actual_mbps\tcut_actual_mbps\toriginal_actual_pps\tcut_actual_pps\toriginal_ids_pps\tcut_ids_pps\toriginal_capture_loss_percent\tcut_capture_loss_percent\toriginal_pps_target_percent\tcut_pps_target_percent\ttarget_valid\n' >"${COMPARISON}"

INVALID_TARGET=0
for rate in "${RATES[@]}"; do
    case "${rate}" in
        5000) generators=2 ;;
        7500) generators=3 ;;
        *) generators=1 ;;
    esac
    cut_rate="$(awk -v rate="${rate}" -v ratio="${size_ratio}" \
        'BEGIN { printf "%.6f", rate * ratio }')"
    target_pps=0
    pps_multi=1
    replay_environment=()
    if [[ "${rate}" -eq 7500 ]]; then
        target_pps="$(equivalent_target_pps "${rate}" "${original_bytes}" "${original_packets}")"
        pps_multi="$(replay_pps_multi "${rate}")"
        replay_environment+=("TARGET_PPS=${target_pps}" "PPS_MULTI=${pps_multi}")
    fi

    printf '\n== carga original equivalente: %s Mb/s ==\n' "${rate}"
    if [[ "${target_pps}" -gt 0 ]]; then
        printf 'alvo do gerador: %s pps; agrupamento: %s pacotes\n' "${target_pps}" "${pps_multi}"
    fi
    original_log="${RESULT_DIR}/${rate}mbps-original.log"
    env "${replay_environment[@]}" PCAP="${ORIGINAL}" EXPERIMENT_MODE=baseline \
        "${SCRIPT_DIR}/run_baseline_once.sh" \
        "${RULESET}" "${rate}" "${DURATION_S}" "${generators}" | tee "${original_log}"
    original_dir="$(awk '/^resultado: / { print $2 }' "${original_log}")"

    cut_log="${RESULT_DIR}/${rate}mbps-cut.log"
    env "${replay_environment[@]}" PCAP="${CUT}" EXPERIMENT_MODE=precut \
        "${SCRIPT_DIR}/run_baseline_once.sh" \
        "${RULESET}" "${cut_rate}" "${DURATION_S}" "${generators}" | tee "${cut_log}"
    cut_dir="$(awk '/^resultado: / { print $2 }' "${cut_log}")"

    if [[ ! -r "${original_dir}/summary.tsv" || ! -r "${cut_dir}/summary.tsv" ]]; then
        echo "resumo ausente para a carga ${rate}" >&2
        exit 1
    fi
    original_row="$(tail -n 1 "${original_dir}/summary.tsv")"
    cut_row="$(tail -n 1 "${cut_dir}/summary.tsv")"
    target_valid="n/a"
    if [[ "${target_pps}" -gt 0 ]]; then
        original_actual_pps="$(awk -F '\t' 'NR == 2 { print $6 }' "${original_dir}/summary.tsv")"
        cut_actual_pps="$(awk -F '\t' 'NR == 2 { print $6 }' "${cut_dir}/summary.tsv")"
        if [[ "$(target_pps_reached "${target_pps}" "${original_actual_pps}")" == yes && \
              "$(target_pps_reached "${target_pps}" "${cut_actual_pps}")" == yes ]]; then
            target_valid="PASS"
        else
            target_valid="FAIL"
            INVALID_TARGET=1
        fi
    fi
    awk -F '\t' -v offered="${rate}" -v reduction="${reduction}" \
        -v target_pps="${target_pps}" -v target_valid="${target_valid}" \
        -v original="${original_row}" -v cut="${cut_row}" '
        BEGIN {
            split(original, a, "\t"); split(cut, b, "\t")
            printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", \
                offered, reduction, target_pps, a[4], b[4], a[6], b[6], \
                a[8], b[8], a[24], b[24], a[27], b[27], target_valid
        }
    ' >>"${COMPARISON}"
done

echo
echo "comparacao: ${COMPARISON}"
cat "${COMPARISON}"
if [[ "${INVALID_TARGET}" -ne 0 ]]; then
    echo "FAIL: a carga de 7,5 Gb/s nao atingiu 99% do PPS alvo; a rodada nao e valida como 7,5 Gb/s" >&2
    exit 1
fi
