#!/bin/sh
set -eu

case "${SEKISHO_INSECURE_BIND:-}" in
    "")
        exec sekisho up
        ;;
    1)
        exec sekisho up --bind 0.0.0.0:7470 --insecure-bind
        ;;
    *)
        printf 'error: SEKISHO_INSECURE_BIND must be 1 when set\n' >&2
        exit 64
        ;;
esac
