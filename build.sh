#!/usr/bin/env bash
set -euo pipefail

# Simple build script for all WFBX tools.
# Outputs go to ./bin

CC=${CC:-gcc}
CFLAGS=${CFLAGS:-"-O2 -Wall -Isrc"}
LDFLAGS_COMMON=${LDFLAGS_COMMON:-""}

#mkdir -p bin

echo "[BUILD] wfbx_tx"
$CC $CFLAGS -o bin/wfbx_tx src/wfbx_tx.c src/wfbx_stats_core.c src/wfbx_stats_mx.c $LDFLAGS_COMMON -lpcap -lpthread -lm

echo "[BUILD] wfbx_rx"
$CC $CFLAGS -o bin/wfbx_rx src/wfbx_rx.c $LDFLAGS_COMMON -lpcap

echo "[BUILD] wfbx_mx"
$CC $CFLAGS -o bin/wfbx_mx src/wfbx_mx.c src/wfbx_stats_core.c src/wfbx_stats_mx.c $LDFLAGS_COMMON -lpcap -lm

echo "[BUILD] legacy wfb_tx"
$CC $CFLAGS -o bin/wfb_tx src/wfb_tx.c $LDFLAGS_COMMON -lpcap

echo "[BUILD] legacy wfb_rx"
$CC $CFLAGS -o bin/wfb_rx src/wfb_rx.c $LDFLAGS_COMMON -lpcap

echo "Done. Binaries in ./bin"
