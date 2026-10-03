#!/usr/bin/env bash

# Funcoes compartilhadas pelos scripts de experimento. Este arquivo deve ser
# carregado com "source"; ele nao executa experimentos por conta propria.

equivalent_target_pps() {
    local rate_mbps="$1"
    local captured_bytes="$2"
    local packets="$3"
    awk -v rate="${rate_mbps}" -v bytes="${captured_bytes}" -v packets="${packets}" '
        BEGIN {
            if (bytes <= 0 || packets <= 0) exit 1
            printf "%.0f\n", rate * 1000000 * packets / (8 * bytes)
        }
    '
}

split_target_pps() {
    local target_pps="$1"
    local generators="$2"
    local base=$((target_pps / generators))
    local remainder=$((target_pps % generators))
    local generator rate

    for ((generator = 1; generator <= generators; ++generator)); do
        rate="${base}"
        if ((generator <= remainder)); then
            rate=$((rate + 1))
        fi
        if ((generator > 1)); then
            printf ' '
        fi
        printf '%s' "${rate}"
    done
    printf '\n'
}

replay_pps_multi() {
    local equivalent_mbps="$1"
    if awk -v rate="${equivalent_mbps}" 'BEGIN { exit !(rate >= 7500) }'; then
        printf '32\n'
    else
        printf '1\n'
    fi
}

target_pps_reached() {
    local target_pps="$1"
    local actual_pps="$2"
    if awk -v target="${target_pps}" -v actual="${actual_pps}" '
        BEGIN { exit !(target > 0 && actual >= 0.99 * target) }
    '; then
        printf 'yes\n'
    else
        printf 'no\n'
    fi
}
