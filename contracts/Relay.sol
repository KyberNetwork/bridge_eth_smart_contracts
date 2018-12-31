pragma solidity 0.5.0;


contract Relay {

    // chunk 0
    uint constant TIMESTAMP_BITS  = 32;
    uint constant TIMESTAMP_MASK = 2 ** TIMESTAMP_BITS - 1;
    uint constant TIMESTAMP_OFFSET = 256 - TIMESTAMP_BITS; // 224

    uint constant PRODUCER_BITS  = 64;
    uint constant PRODUCER_MASK = 2 ** PRODUCER_BITS - 1;
    uint constant PRODUCER_OFFSET = TIMESTAMP_OFFSET - PRODUCER_BITS; // 160

    uint constant CONFIRMED_BITS  = 16;
    uint constant CONFIRMED_MASK = 2 ** CONFIRMED_BITS - 1;
    uint constant CONFIRMED_OFFSET = PRODUCER_OFFSET - CONFIRMED_BITS; // 144

    uint constant PREVIOUS_0_BITS  = CONFIRMED_OFFSET; // 144
    uint constant PREVIOUS_0_MASK = 2 ** PREVIOUS_0_BITS - 1;
    uint constant PREVIOUS_0_OFFSET = 0;

    // chunk 1
    uint constant PREVIOUS_1_BITS  = 256 - PREVIOUS_0_BITS; // 112
    uint constant PREVIOUS_1_MASK = 2 ** PREVIOUS_1_BITS - 1;
    uint constant PREVIOUS_1_OFFSET = 256 - PREVIOUS_1_BITS; // 144

    uint constant TX_MROOT_0_BITS  = 256 - PREVIOUS_1_BITS; // 144
    uint constant TX_MROOT_0_MASK = 2 ** TX_MROOT_0_BITS - 1;
    uint constant TX_MROOT_0_OFFSET = 0;

    // chunk 2
    uint constant TX_MROOT_1_BITS  = 256 - TX_MROOT_0_BITS; // 112
    uint constant TX_MROOT_1_MASK = 2 ** TX_MROOT_1_BITS - 1;
    uint constant TX_MROOT_1_OFFSET = 256 - TX_MROOT_1_BITS; // 144

    uint constant ACTION_MROOT_0_BITS  = 256 - TX_MROOT_1_BITS; // 144
    uint constant ACTION_MROOT_0_MASK = 2 ** ACTION_MROOT_0_BITS - 1;
    uint constant ACTION_MROOT_0_OFFSET = 0; 

    // chunk 3
    uint constant ACTION_MROOT_1_BITS  = 256 - ACTION_MROOT_0_BITS; // 112
    uint constant ACTION_MROOT_1_MASK = 2 ** ACTION_MROOT_1_BITS - 1;
    uint constant ACTION_MROOT_1_OFFSET = 160 - ACTION_MROOT_1_BITS; // 48

    uint constant SCHEDULE_BITS  = 32;
    uint constant SCHEDULE_MASK = 2 ** SCHEDULE_BITS - 1;
    uint constant SCHEDULE_OFFSET = ACTION_MROOT_1_OFFSET - SCHEDULE_BITS; // 16

    uint constant HAVE_NEW_PRODUCERS_BITS  = 8;
    uint constant HAVE_NEW_PRODUCERS_MASK = 2 ** HAVE_NEW_PRODUCERS_BITS - 1;
    uint constant HAVE_NEW_PRODUCERS_OFFSET = SCHEDULE_OFFSET - HAVE_NEW_PRODUCERS_BITS; // 8

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

    function sliceBytes4(bytes memory bs, uint start) internal pure returns (uint32)
    {
        require(bs.length >= start + 4, "slicing out of range");
        uint32 x;
        assembly {
            x := mload(add(bs, add(0x4, start)))
        }
            return x;
    }

    function parseFixedFields0(bytes memory blockHeader)
        internal
        pure
        returns (uint32 timestamp, uint64 producer, uint16 confirmed, uint previous, uint tx_mroot)
    {

        uint chunk;

        chunk = sliceBytes32(blockHeader, 0);
        timestamp = (uint32)((chunk >> TIMESTAMP_OFFSET) & TIMESTAMP_MASK);
        producer = (uint64)((chunk >> PRODUCER_OFFSET) & PRODUCER_MASK);
        confirmed = (uint16)((chunk >> CONFIRMED_OFFSET) & CONFIRMED_MASK);
        uint previous_0 = (uint)((chunk >> PREVIOUS_0_OFFSET) & PREVIOUS_0_MASK);

        chunk = sliceBytes32(blockHeader, 32);
        uint previous_1 = (uint)((chunk >> PREVIOUS_1_OFFSET) & PREVIOUS_1_MASK);
        uint tx_mroot_0 = (uint)((chunk >> TX_MROOT_0_OFFSET) & TX_MROOT_0_MASK);

        chunk = sliceBytes32(blockHeader, 64);
        uint tx_mroot_1 = (uint)((chunk >> TX_MROOT_1_OFFSET) & TX_MROOT_1_MASK);

        previous = (previous_0 << PREVIOUS_1_BITS) | previous_1; 
        tx_mroot = (tx_mroot_0 << TX_MROOT_1_BITS) | tx_mroot_1;
    }

    function parseFixedFields1(bytes memory blockHeader)
        internal
        pure
        returns (uint32 schedule, uint action_mroot, uint8 have_new_producers)
    {
        // TODO: remove duplication

        uint chunk;
        chunk = sliceBytes32(blockHeader, 64);
        uint action_mroot_0 = (uint)((chunk >> ACTION_MROOT_0_OFFSET) & ACTION_MROOT_0_MASK);

        // read only 20B, since not sure if optional fields are there
        uint chunk160 = sliceBytes20(blockHeader, 96);
        uint action_mroot_1 = (uint)((chunk160 >> ACTION_MROOT_1_OFFSET) & ACTION_MROOT_1_MASK);
        schedule = (uint32)((chunk160 >> SCHEDULE_OFFSET) & SCHEDULE_MASK);
        have_new_producers = (uint8)((chunk160 >> HAVE_NEW_PRODUCERS_OFFSET) & HAVE_NEW_PRODUCERS_MASK);

        action_mroot = (action_mroot_0 << ACTION_MROOT_1_BITS) | action_mroot_1;
    }

    function parseNonFixedFields(bytes memory blockHeader)
        internal
        pure
        returns (uint32 version, uint8 amount, uint64[21] memory producerNames, bytes32[21] memory producerKeyHighChunk)
    {
        version = sliceBytes4(blockHeader, 96 + 19); // 4 bytes version
        amount = (uint8)(blockHeader[96+19+4]);// 1 byte amount

        uint offset = 120; 

        for (uint i = 0; i < amount; i++) {
            require(blockHeader.length >= offset + 8, "slicing out of range");
            uint64 x;
            assembly {x := mload(add(blockHeader, add(0x8, offset)))}
            producerNames[i] = x;
            offset = offset + 8;

            offset = offset + 1; // skip 1 zeroed bytes
            offset = offset + 1; // skip first byte of the key

            require(blockHeader.length >= offset + 32, "slicing out of range");
            bytes32 y;
            assembly {y := mload(add(blockHeader, add(32, offset)))}
            producerKeyHighChunk[i] = y; 
            offset = offset + 32;
        }
    } 

    function parseHeader(bytes calldata blockHeader)
        external
        pure
        returns (
            uint32 timestamp,
            uint64 producer,
            uint16 confirmed,
            uint previous,
            uint tx_mroot,
            uint32 schedule,
            uint action_mroot,
            uint32 version,
            uint8 amount,
            uint64[21] memory producerNames,
            bytes32[21] memory producerKeyHighChunk // TODO: this should be 33 bytes!!!
        )
    {
        /* expected sizes 4, 8, 2, 32, 32, 32, 4, 1, 1 */

        (timestamp, producer, confirmed, previous, tx_mroot) = parseFixedFields0(blockHeader);
        uint8 have_new_producers;
        (schedule, action_mroot, have_new_producers) = parseFixedFields1(blockHeader);

        if(have_new_producers != 0 ) {
            
            (version, amount, producerNames, producerKeyHighChunk) = parseNonFixedFields(blockHeader);
        }
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