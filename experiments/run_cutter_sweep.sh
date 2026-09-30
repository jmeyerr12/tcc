#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-transport}" == application ]]; then
    echo "conjunto application fora do escopo experimental atual; consulte application-rules/README.md" >&2
    exit 2
fi

if [[ "${EUID}" -ne 0 ]]; then
    echo "execute como root: sudo $0 [transport|ip] [DURACAO_S]" >&2
    exit 1
fi

RULESET="${1:-transport}"
DURATION_S="${2:-10}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SWEEP_DIR="${SCRIPT_DIR}/results/sweep_cutter_${RULESET}_${TIMESTAMP}"
mkdir -p "${SWEEP_DIR}"

cleanup() {
    "${SCRIPT_DIR}/setup_cutter.sh" off >/dev/null 2>&1 || true
    if [[ -n "${SUDO_UID:-}" && -n "${SUDO_GID:-}" ]]; then
        chown -R "${SUDO_UID}:${SUDO_GID}" "${SWEEP_DIR}"
    fi
}
trap cleanup EXIT INT TERM

"${SCRIPT_DIR}/setup_cutter.sh" on "${RULESET}"
printf 'Varredura com cortador: ruleset=%s, duracao=%ss\n' "${RULESET}" "${DURATION_S}"

for rate in 500 1000 2000 5000 10000; do
    case "${rate}" in
        5000) generators=2 ;;
        10000) generators=4 ;;
        *) generators=1 ;;
    esac

    printf '\n== %s Mbit/s (%s gerador(es)) ==\n' "${rate}" "${generators}"
    RUN_LOG="${SWEEP_DIR}/${rate}mbps.log"
    "${SCRIPT_DIR}/run_cutter_once.sh" \
        "${RULESET}" "${rate}" "${DURATION_S}" "${generators}" | tee "${RUN_LOG}"
done

SUMMARY="${SWEEP_DIR}/summary.tsv"
FIRST=1
for rate in 500 1000 2000 5000 10000; do
    directory="$(awk '/^resultado: / { print $2 }' "${SWEEP_DIR}/${rate}mbps.log")"
    file="${directory}/summary.tsv"
    if [[ "${FIRST}" -eq 1 ]]; then
        head -n 1 "${file}" >"${SUMMARY}"
        FIRST=0
    fi
    tail -n 1 "${file}" >>"${SUMMARY}"
done

echo
echo "resumo da varredura: ${SUMMARY}"
cat "${SUMMARY}"
