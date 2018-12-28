pragma solidity 0.5.0;


contract Relay {

    function verifyBlockSig(
        bytes calldata blockHeader,             // from user
        bytes32 blockMerkleHash,                // from user
        bytes calldata pendingSchedule,         // from user 
        uint8 sigV,                             // from user
        bytes32 sigR,                           // from user
        bytes32 sigS,                           // from user
        bytes32[] calldata claimedSignerPubKey, // from user
        bytes32 storedCompressedPubKey          // from storage (we maintain current schedule keys)
    )
    external
    pure
    returns (bool) 
    {
        bytes32 pairHash = sha256(abi.encodePacked(sha256(blockHeader), blockMerkleHash));
        bytes32 pendingScheduleHash = sha256(pendingSchedule);
        bytes32 finalHash = sha256(abi.encodePacked(pairHash, pendingScheduleHash));
        address calcAddress = ecrecover(finalHash, sigV, sigR, sigS);
        address claimedSignerAddress = address(
            (uint)(keccak256(abi.encodePacked(claimedSignerPubKey[0], claimedSignerPubKey[1]))) & (2**(8*21)-1)
        );

        return (
            (claimedSignerPubKey[0] == storedCompressedPubKey) && // signer is part of current schedule
            (calcAddress == claimedSignerAddress)                 // signer signed the given block data 
        );
    }
}