#!/usr/bin/env bash
# ============================================================================
#  run.sh — ONE-COMMAND PoC runner (fresh Codespaces)
#
#  Usage:
#     ./run.sh               → quick validation run  (--watch 2)
#     ./run.sh 20            → final run untuk report (--watch 20)
#     ./run.sh 20 --crash    → final run + Variant A (crash loop)
#
#  Script ini melakukan SEMUANYA:
#    [1] install foundry        (jika belum ada — sekali saja)
#    [2] build image docker cdk (jika belum ada — sekali saja)
#    [3] reset devnet fresh     (docker compose down -v + make start)
#    [4] tunggu cdk-node warm
#    [5] forge build Poison.sol (poc.py auto-load bytecode)
#    [6] jalankan poc.py        (semua bukti → evidence/)
# ============================================================================
set -euo pipefail

# ---- paths: script ini tinggal di <cdk>/poc --------------------------------
POC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CDK_DIR="$(dirname "$POC_DIR")"
TEST_DIR="$CDK_DIR/test"
cd "$POC_DIR"

# ---- args -------------------------------------------------------------------
WATCH="2"; CRASH=""
for a in "$@"; do
  case "$a" in
    [0-9]*)   WATCH="$a" ;;
    --crash)  CRASH="--crash" ;;
  esac
done

log() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
die() { printf '\033[1;31mFATAL: %s\033[0m\n' "$*" >&2; exit 1; }

# ---- [1] foundry ------------------------------------------------------------
if ! command -v cast >/dev/null 2>&1; then
  log "installing foundry (~1 min, sekali saja)"
  curl -L https://foundry.paradigm.xyz | bash >/dev/null
  export PATH="$HOME/.foundry/bin:$PATH"
  foundryup >/dev/null || die "foundryup gagal"
  command -v cast >/dev/null || die "cast tidak ada — buka shell baru lalu jalankan ulang"
fi

# ---- [2] image cdk ----------------------------------------------------------
if ! docker image inspect cdk >/dev/null 2>&1; then
  log "building image 'cdk' (5–10 min, sekali saja — dijalankan SEBELUM evidence ada)"
  (cd "$CDK_DIR" && docker build -t cdk .) || die "build image gagal"
fi

# ---- [3] devnet fresh -------------------------------------------------------
log "reset devnet ke state fresh + start (~4 min)"
if [ -z "${DEVNET_TARGET:-}" ]; then
  for t in start run up all; do
    if (cd "$TEST_DIR" && make -n "$t" >/dev/null 2>&1); then DEVNET_TARGET="$t"; break; fi
  done
fi
[ -n "${DEVNET_TARGET:-}" ] || \
  die "target make devnet tidak terdeteksi — cek 'make help' di $TEST_DIR lalu: DEVNET_TARGET=<nama> ./run.sh"
echo "  devnet: make $DEVNET_TARGET"
(cd "$TEST_DIR" \
  && docker compose down -v >/dev/null 2>&1 || true \
  && make "$DEVNET_TARGET") || die "devnet gagal start"

# ---- [4] warm-up ------------------------------------------------------------
log "menunggu cdk-node + aggsender siap (max 10 min)"
ok=0
for i in $(seq 1 60); do
  docker ps --format '{{.Names}}' | grep -q '^cdk-node$' || { sleep 10; continue; }
  if docker logs cdk-node 2>&1 | grep -qE "building certificate|no bridges consumed|AggSender started"; then
    ok=1; break
  fi
  sleep 10
done
[ "$ok" = 1 ] || die "cdk-node tidak menunjukkan aktivitas aggsender — cek: docker logs cdk-node"

# ---- [5] forge build --------------------------------------------------------
log "forge build Poison.sol"
forge build || die "forge build gagal"
[ -f out/Poison.sol/Poison.json ] || die "out/Poison.sol/Poison.json tidak ada"

# ---- [6] jalankan PoC -------------------------------------------------------
mkdir -p evidence
{ echo "cdk commit: $(git -C "$CDK_DIR" rev-parse HEAD)"; cast --version; date -u; } \
  > evidence/environment.txt

log "RUN PoC  (watch=$WATCH menit ${CRASH:-})"
set +e
python3 -u poc.py --watch "$WATCH" $CRASH 2>&1 | tee evidence/poc_console.txt
RC=${PIPESTATUS[0]}
set -e

echo
echo "exit code: $RC"
echo "semua bukti di: $POC_DIR/evidence/ (receipts, trace, DB dump, node.log, summary)"
exit $RC
