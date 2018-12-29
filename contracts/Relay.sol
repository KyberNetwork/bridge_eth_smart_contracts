pragma solidity 0.5.0;


contract Relay {

    // chunk 0
    uint constant TIMESTAMP_BITS  = 32;
    uint constant TIMESTAMP_MASK = 2 ** TIMESTAMP_BITS - 1;
    uint constant TIMESTAMP_OFFSET = 256 - TIMESTAMP_BITS;

    uint constant PRODUCER_BITS  = 64;
    uint constant PRODUCER_MASK = 2 ** PRODUCER_BITS - 1;
    uint constant PRODUCER_OFFSET = TIMESTAMP_OFFSET - PRODUCER_BITS;

    uint constant CONFIRMED_BITS  = 16;
    uint constant CONFIRMED_MASK = 2 ** CONFIRMED_BITS - 1;
    uint constant CONFIRMED_OFFSET = PRODUCER_OFFSET - CONFIRMED_BITS;

    uint constant PREVIOUS_0_BITS  = CONFIRMED_OFFSET;
    uint constant PREVIOUS_0_MASK = 2 ** PREVIOUS_0_BITS - 1;
    uint constant PREVIOUS_0_OFFSET = CONFIRMED_OFFSET - PREVIOUS_0_BITS;

    // chunk 1
    uint constant PREVIOUS_1_BITS  = 256 - PREVIOUS_0_BITS;
    uint constant PREVIOUS_1_MASK = 2 ** PREVIOUS_1_BITS - 1;
    uint constant PREVIOUS_1_OFFSET = 256 - PREVIOUS_1_BITS;

    uint constant TX_MROOT_0_BITS  = 256 - PREVIOUS_1_BITS;
    uint constant TX_MROOT_0_MASK = 2 ** TX_MROOT_0_BITS - 1;
    uint constant TX_MROOT_0_OFFSET = PREVIOUS_1_OFFSET - TX_MROOT_0_BITS;

    // chunk 2
    uint constant TX_MROOT_1_BITS  = 256 - TX_MROOT_0_BITS;
    uint constant TX_MROOT_1_MASK = 2 ** TX_MROOT_1_BITS - 1;
    uint constant TX_MROOT_1_OFFSET = 256 - TX_MROOT_1_BITS;

    uint constant ACTION_MROOT_0_BITS  = 256 - TX_MROOT_1_BITS;
    uint constant ACTION_MROOT_0_MASK = 2 ** ACTION_MROOT_0_BITS - 1;
    uint constant ACTION_MROOT_0_OFFSET = TX_MROOT_1_OFFSET - ACTION_MROOT_0_BITS;  

    // chunk 3
    uint constant ACTION_MROOT_1_BITS  = 256 - ACTION_MROOT_0_BITS;
    uint constant ACTION_MROOT_1_MASK = 2 ** ACTION_MROOT_1_BITS - 1;
    uint constant ACTION_MROOT_1_OFFSET = 160 - ACTION_MROOT_1_BITS; // since reading it to a 20B buffer

    uint constant SCHEDULE_BITS  = 32;
    uint constant SCHEDULE_MASK = 2 ** SCHEDULE_BITS - 1;
    uint constant SCHEDULE_OFFSET = ACTION_MROOT_1_OFFSET - SCHEDULE_BITS;

    function sliceBytes32(bytes memory bs, uint start) internal pure returns (uint)
    {
        require(bs.length >= start + 32, "slicing out of range");
        uint x;
        assembly {
            x := mload(add(bs, add(0x20, start)))
        }
        return x;
    }

    function sliceBytes20(bytes memory bs, uint start) internal pure returns (uint)
    {
        require(bs.length >= start + 20, "slicing out of range");
        uint x;
        assembly {
            x := mload(add(bs, add(0x14, start)))
        }
            return x;
    }


    function parseHeader(bytes calldata blockHeader) external pure returns (uint32){
        /* expected sizes 4, 8, 2, 32, 32, 32, 4, 1, 1 */
        //https://ethereum.stackexchange.com/questions/42659/parse-arbitrary-bytes-input

        uint chunk;
        chunk = sliceBytes32(blockHeader, 0);
        uint32 timestamp = (uint32)((chunk >> TIMESTAMP_OFFSET) & TIMESTAMP_MASK);
        uint64 producer = (uint64)((chunk >> PRODUCER_OFFSET) & PRODUCER_MASK);
        uint16 confirmed = (uint16)((chunk >> CONFIRMED_OFFSET) & CONFIRMED_MASK);
        uint previous_0 = (uint)((chunk >> PREVIOUS_0_OFFSET) & PREVIOUS_0_MASK);

        chunk = sliceBytes32(blockHeader, 32);
        uint previous_1 = (uint)((chunk >> PREVIOUS_1_OFFSET) & PREVIOUS_1_MASK);
        uint tx_mroot_0 = (uint)((chunk >> TX_MROOT_0_OFFSET) & TX_MROOT_0_MASK);
        
        chunk = sliceBytes32(blockHeader, 64);
        uint tx_mroot_1 = (uint)((chunk >> TX_MROOT_1_OFFSET) & TX_MROOT_1_MASK);
        uint action_mroot_0 = (uint)((chunk >> ACTION_MROOT_0_OFFSET) & ACTION_MROOT_0_MASK);

        // read only 20B, since not sure if optional firalds are there
        uint chunk160 = sliceBytes20(blockHeader, 96);
        uint action_mroot_1 = (uint)((chunk160 >> ACTION_MROOT_1_OFFSET) & ACTION_MROOT_1_MASK);
        uint32 schedule = (uint32)((chunk160 >> SCHEDULE_OFFSET) & SCHEDULE_MASK);
        

        uint previous = (previous_0 << PREVIOUS_1_BITS) | previous_1; 
        uint tx_mroot = (tx_mroot_0 << TX_MROOT_1_BITS) | tx_mroot_1;
        uint action_mroot = (action_mroot_0 << ACTION_MROOT_1_BITS) | action_mroot_1;

        return schedule;
    }

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