pragma solidity 0.5.0;


contract Relay {

    function verifyBlockSig(
            bytes calldata blockHeader,
            bytes32 blockMerkeleHash,
            bytes calldata pendingSchedule,
            uint8 sigV,
            bytes32 sigR,
            bytes32 sigS,
            bytes calldata claimedSignerPubKey
        )
    external
    pure
    returns (bool) 
    {
        bytes32 pairHash = sha256(abi.encodePacked(sha256(blockHeader), blockMerkeleHash));
        bytes32 pendingScheduleHash = sha256(pendingSchedule);
        bytes32 finalHash = sha256(abi.encodePacked(pairHash, pendingScheduleHash));
        address calcAddress = ecrecover(finalHash, sigV, sigR, sigS);
        address claimedSignerAddress = address((uint)(keccak256(claimedSignerPubKey)) & (2**(8*21)-1));

        return (calcAddress == claimedSignerAddress);
        // in the future claimedSignerPubKey's first 32B will also be compared to signer pub key from block data
    }
}