pragma solidity 0.5.0;


contract HeaderParser {

    uint constant TIMESTAMP_BYTES               = 4;
    uint constant PRODUCER_BYTES                = 8;
    uint constant CONFIRMED_BYTES               = 2;
    uint constant PREVIOUS_BYTES                = 32;
    uint constant TX_MROOT_BYTES                = 32;
    uint constant ACTION_MROOT_BYTES            = 32;
    uint constant SCHEDULE_BYTES                = 4;
    uint constant HAVE_NEW_PRODUCERS_BYTES      = 1;
    uint constant PRODUCERS_VERSION_BYTES       = 4;
    uint constant PRODUCERS_NAME_BYTES          = 8;
    uint constant PRODUCERS_AMOUNT_BYTES        = 1;
    uint constant PRODUCERS_KEY_HIGH_BYTES      = 32;
    uint constant OR_MASK =   0x8000000000000000000000000000000000000000000000000000000000000000;
    uint constant AND_MASK =  0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;

    function sliceBytes(bytes memory bs, uint start, uint size) internal pure returns (uint)
    {
        require(bs.length >= start + size, "slicing out of range");
        uint x;
        assembly {
            x := mload(add(bs, add(size, start)))
        }
        return x;
    }

    function reverseBytes(uint32 input) internal pure returns (uint32 output)
    {
        output = input >> 24 & 0xff | input >> 8 & 0xff00 | input << 8 & 0xff0000 |  input << 24 & 0xff000000;
    }

    function parseFixedFields0(bytes memory blockHeader)
        internal
        pure
        returns (uint32 ts, uint64 producer, uint16 confirmed, uint previous, uint tx_mroot)
    {
        uint offset = 0;

        ts = reverseBytes((uint32)(sliceBytes(blockHeader, offset, TIMESTAMP_BYTES)));
        offset = offset + TIMESTAMP_BYTES;

        producer = (uint64)(sliceBytes(blockHeader, offset, PRODUCER_BYTES));
        offset = offset + PRODUCER_BYTES;

        confirmed = (uint16)(sliceBytes(blockHeader, offset, CONFIRMED_BYTES));
        offset = offset + CONFIRMED_BYTES;

        previous = (uint256)(sliceBytes(blockHeader, offset, PREVIOUS_BYTES));
        offset = offset + PREVIOUS_BYTES;

        tx_mroot = (uint256)(sliceBytes(blockHeader, offset, TX_MROOT_BYTES));
        offset = offset + TX_MROOT_BYTES;
    }

    function parseFixedFields1(bytes memory blockHeader)
        internal
        pure
        returns (uint32 schedule, uint action_mroot, uint8 have_new_producers)
    {
        uint offset = 78;

        schedule = reverseBytes((uint32)(sliceBytes(blockHeader, offset, SCHEDULE_BYTES)));
        offset = offset + SCHEDULE_BYTES;

        action_mroot = (uint256)(sliceBytes(blockHeader, offset, ACTION_MROOT_BYTES));
        offset = offset + ACTION_MROOT_BYTES;

        have_new_producers = (uint8)(sliceBytes(blockHeader, offset, HAVE_NEW_PRODUCERS_BYTES));
        offset = offset + HAVE_NEW_PRODUCERS_BYTES;
    }

    function parseNonFixedFields(bytes memory blockHeader)
        internal
        pure
        returns (uint32 version, uint8 amount, uint64[21] memory producerNames, bytes32[21] memory producerKeyHighChunk)
    {
        uint offset = 115;

        version = reverseBytes((uint32)(sliceBytes(blockHeader, offset, PRODUCERS_VERSION_BYTES)));
        offset = offset + PRODUCERS_VERSION_BYTES;

        amount = (uint8)(sliceBytes(blockHeader, offset, PRODUCERS_AMOUNT_BYTES));
        offset = offset + PRODUCERS_AMOUNT_BYTES;

        for (uint i = 0; i < amount; i++) {
            producerNames[i] = (uint64)(sliceBytes(blockHeader, offset, PRODUCERS_NAME_BYTES));
            offset = offset + PRODUCERS_NAME_BYTES;

            offset = offset + 1; // skip 1 zeroed bytes
            offset = offset + 1; // skip first byte of the key

            producerKeyHighChunk[i] = (bytes32)(sliceBytes(blockHeader, offset, PRODUCERS_KEY_HIGH_BYTES));
            offset = offset + PRODUCERS_KEY_HIGH_BYTES;
        }
    } 

    function parseHeader(bytes memory blockHeader)
        public
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
        (timestamp, producer, confirmed, previous, tx_mroot) = parseFixedFields0(blockHeader);
        uint8 have_new_producers;
        (schedule, action_mroot, have_new_producers) = parseFixedFields1(blockHeader);

        if(have_new_producers != 0 ) {
            (version, amount, producerNames, producerKeyHighChunk) = parseNonFixedFields(blockHeader);
        }
    }
}