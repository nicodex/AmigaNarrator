#!/bin/sh

EXE="${EXE:-}"
OUTDIR="${OUTDIR:-./bin}"
# SoX_ng <https://codeberg.org/sox_ng/sox_ng> (aplay might not support S8)
PLAYSTDIN="${PLAYSTDIN:-play_ng -r 22200 -e signed -b 8 -t raw -q -}"

print_usage() {
    printf 'Usage: %s "<text>" [accent]\n' "${0}" >&2
    exit ${1}
}

case "${1:-}" in
    '-h' | '--help' | '/?') print_usage 0 ;;
    '') print_usage 1 ;;
esac

if [ -n "${2:-}" ]; then
    LIB_PATH="${LIB_PATH:-./Libs/v33_translator.library}"
    if [ ! -f "${LIB_PATH}" ]; then
        printf '%s missing\n' "${LIB_PATH}" >&2
        exit 2
    fi
    ACCENT_DIR="${ACCENT_DIR:-./Accents}"
    if [ ! -f "${ACCENT_DIR}/${2}.accent" ]; then
        printf '%s/%s.accent missing\n' "${ACCENT_DIR}" "${2}" >&2
        exit 3
    fi
    printf '%s text: "%s"\n' "${2}" "${1}"
    PHONETIC_STR="$(${OUTDIR}/translateas${EXE} \
        -d "${ACCENT_DIR}/" -l "${LIB_PATH}" -q -- "${2}" \
        "${1}")"
else
    LIB_PATH="${LIB_PATH:-./Libs/translator.library}"
    if [ ! -f "${LIB_PATH}" ]; then
        printf '%s missing\n' "${LIB_PATH}" >&2
        exit 2
    fi
    printf 'English text: "%s"\n' "${1}"
    PHONETIC_STR="$(${OUTDIR}/translator${EXE} \
        -l "${LIB_PATH}" \
        "${1}" 2>/dev/null)"
fi
if [ -n "${PHONETIC_STR:-}" ]; then
    printf 'phonetic str: "%s"\n' "${PHONETIC_STR}"
    DEV_PATH="${DEV_PATH:-./Devs/narrator.device}"
    if [ ! -f "${DEV_PATH}" ]; then
        printf '%s missing\n' "${DEV_PATH}" >&2
        exit 2
    fi
    ${OUTDIR}/narrator${EXE} "${PHONETIC_STR}" 2>/dev/null | ${PLAYSTDIN}
fi

