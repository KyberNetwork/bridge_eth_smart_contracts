pragma solidity 0.5.0;

import "./HeaderParser.sol";


contract Relay is HeaderParser {

    struct HeadersData {
        bytes blockHeaders;
        uint[] blockHeaderSizes;
        bytes32[] blockMerkleHashs;
        bytes32[] blockMerklePaths;
        uint[] blockMerklePathSizes;
        bytes32[] pendingScheduleHashs;
        uint8[] sigVs;
        bytes32[] sigRs;
        bytes32[] sigSs;
        uint[] claimedKeyIndices;
    }

    bytes32[21] public pubKeysFirstParts;
    bytes32[21] public pubKeysSecondParts;
    uint numProducers;
    uint public scheduleVersion;

    function storeInitialSchedule(
        uint inputScheduleVersion,
        bytes32[] memory inputPubKeysFirstParts,
        bytes32[] memory inputPubKeysSecondParts,
        uint numKeys
    ) public {
        scheduleVersion = inputScheduleVersion;
        numProducers = numKeys;
        for( uint idx = 0; idx < numKeys; idx++) {
            pubKeysFirstParts[idx] = inputPubKeysFirstParts[idx];
            pubKeysSecondParts[idx] = inputPubKeysSecondParts[idx]; 
        }
    }

    /* verify blocks have been built on the new producers block and store new schedule */
    function changeSchedule(
        bytes memory blockHeaders,
        uint[] memory blockHeaderSizes,
        bytes32[] memory blockMerkleHashs,
        bytes32[] memory blockMerklePaths,
        uint[] memory blockMerklePathSizes,
        bytes32[] memory pendingScheduleHashs,
        uint8[] memory sigVs,
        bytes32[] memory sigRs,
        bytes32[] memory sigSs,
        uint[] memory claimedKeyIndices,
        bytes32[] memory completingKeyParts
        
    ) public {
       HeadersData memory headersData = HeadersData({
            blockHeaders:blockHeaders,
            blockHeaderSizes:blockHeaderSizes,
            blockMerkleHashs:blockMerkleHashs,
            blockMerklePaths:blockMerklePaths,
            blockMerklePathSizes:blockMerklePathSizes,
            pendingScheduleHashs:pendingScheduleHashs,
            sigVs:sigVs,
            sigRs:sigRs,
            sigSs:sigSs,
            claimedKeyIndices:claimedKeyIndices
        });

        require(doVerifyBlockBasedOnSchedule(headersData));
        require(storeNewSchedule(blockHeaders, completingKeyParts));
    }

    function verifyBlockBasedOnSchedule(
        bytes memory blockHeaders,
        uint[] memory blockHeaderSizes,
        bytes32[] memory blockMerkleHashs,
        bytes32[] memory blockMerklePaths,
        uint[] memory blockMerklePathSizes,
        bytes32[] memory pendingScheduleHashs,
        uint8[] memory sigVs,
        bytes32[] memory sigRs,
        bytes32[] memory sigSs,
        uint[] memory claimedKeyIndices
    )
        public
        view
        returns (bool)
    {
        HeadersData memory headersData = HeadersData({
            blockHeaders:blockHeaders,
            blockHeaderSizes:blockHeaderSizes,
            blockMerkleHashs:blockMerkleHashs,
            blockMerklePaths:blockMerklePaths,
            blockMerklePathSizes:blockMerklePathSizes,
            pendingScheduleHashs:pendingScheduleHashs,
            sigVs:sigVs,
            sigRs:sigRs,
            sigSs:sigSs,
            claimedKeyIndices:claimedKeyIndices
        });

        return doVerifyBlockBasedOnSchedule(headersData);
    }

    function storeNewSchedule(
        bytes memory blockHeaders,
        bytes32[] memory completingKeyParts
    )
        internal
        returns (bool)
    {
        uint32 version;
        uint8 amount;
        uint64[21] memory producerNames;
        bytes32[21] memory producerCompressedKeys;

        /* TODO: must get v part as well? */
        /* assuming first block is the new producers block, so no need to separate it */
        (version, amount, producerNames, producerCompressedKeys) = parseNonFixedFields(blockHeaders);

        require(amount == producerCompressedKeys.length);

        /* write new schedule to storage */ 
        scheduleVersion = version;
        for (uint idx = 0; idx < producerCompressedKeys.length; idx++) {
            pubKeysFirstParts[idx] = producerCompressedKeys[idx];
            pubKeysSecondParts[idx] = completingKeyParts[idx];
        }

        return true;
    }

    function doVerifyBlockBasedOnSchedule(HeadersData memory headersData) internal view returns (bool) {
        uint offset_in_headers = 0;
        uint pathOffset = 0;
        bytes32 currentId;
        bytes32 previousId = "";

        // TODO: make sure enough unique blocks were given.
        for (uint idx = 0; idx < headersData.blockHeaderSizes.length; idx++) {
            bytes memory header = getOneHeader(
                headersData.blockHeaders,
                offset_in_headers,
                headersData.blockHeaderSizes[idx]
            );
            offset_in_headers = offset_in_headers + headersData.blockHeaderSizes[idx];

            bool valid = verifyBlockSig(
                header,
                headersData,
                idx,
                pubKeysFirstParts[headersData.claimedKeyIndices[idx]],
                pubKeysSecondParts[headersData.claimedKeyIndices[idx]]
            );
            if (!valid) return false;

            currentId = getIdFromHeader(header);
            uint pathSize = headersData.blockMerklePathSizes[idx];
            if(previousId != "") {
                bytes32[] memory path = getOnePath(headersData.blockMerklePaths, pathOffset, pathSize);

                valid = proofIsValid(previousId, path, headersData.blockMerkleHashs[idx]);
                if (!valid) return false;
            }
            pathOffset = pathOffset + pathSize;

            previousId = currentId;
        }

        return true;
    }

    function verifyBlockSig(
        bytes memory blockHeader,
        HeadersData memory headersData,
        uint idx,
        bytes32 claimedSignerPubKeyFirst,
        bytes32 claimedSignerPubKeySecond
    )
        internal
        pure
        returns (bool) 
    {
        bytes32 pairHash = sha256(abi.encodePacked(sha256(blockHeader), headersData.blockMerkleHashs[idx]));
        bytes32 finalHash = sha256(abi.encodePacked(pairHash, headersData.pendingScheduleHashs[idx]));
        address calcAddress = ecrecover(finalHash, headersData.sigVs[idx], headersData.sigRs[idx], headersData.sigSs[idx]);
        address claimedSignerAddress = address(
            (uint)(keccak256(abi.encodePacked(claimedSignerPubKeyFirst, claimedSignerPubKeySecond))) & (2**(8*21)-1)
        );

        return ( calcAddress == claimedSignerAddress );
    }

    function getId(bytes memory header, uint blockNum) internal pure returns (bytes32) {
        bytes32 headerHash = sha256(header);
        uint blockNumShifted = blockNum << (256 - 32);
        uint mask = ((2**(256 - 32))-1);
        uint result = ((uint)(headerHash) & mask) | blockNumShifted;
        return (bytes32)(result);
    }

    function getBlockNumFromId(bytes32 id) internal pure returns (uint) {
        return ((uint)(id) >> (256 - 32));
    }

    function getIdFromHeader(bytes memory header) internal pure returns (bytes32) {
        uint offset = TIMESTAMP_BYTES + PRODUCER_BYTES + CONFIRMED_BYTES;
        uint previous = (uint256)(sliceBytes(header, offset, PREVIOUS_BYTES));
        uint blockNum = getBlockNumFromId((bytes32)(previous)) + 1;
        return getId(header, blockNum);
    }

    function getOneHeader(
        bytes memory blockHeaders,
        uint offset_in_headers,
        uint headerSize
    )
        internal
        pure
        returns (bytes memory)
    {
        bytes memory header = new bytes(headerSize);
        uint size = headerSize;
        uint offset_in_header = 0;
        uint current_size;
        uint x;

        while(size > 0) {
            if (size >= 32) {
                current_size = 32;
                assembly { x := mload(add(blockHeaders,
                                      add(current_size, add(offset_in_headers, offset_in_header)))) }
                assembly { mstore(add(header, add(32,offset_in_header)), x) }
            } else {
                current_size = size;
                for (uint i = 0; i < current_size; i++) {
                    header[offset_in_header + i] = blockHeaders[offset_in_headers + offset_in_header + i];
                }
           }
           offset_in_header = offset_in_header + current_size;
           size = size - current_size;
        }
        return header;
    }

    function getOnePath(
        bytes32[] memory blockMerklePaths,
        uint pathOffset,
        uint pathSize
    )
        internal
        pure
        returns (bytes32[] memory)
    {
        bytes32[] memory path = new bytes32[](pathSize);
        for( uint i = 0; i < pathSize; i++) {
            path[i] = blockMerklePaths[pathOffset + i];
        }
        return path;
    }

    function makeCanonicalLeft(bytes32 self) internal pure returns (bytes32) {
        return (bytes32)((uint)(self) & AND_MASK);
    }

    function makeCanonicalRight(bytes32 self) internal pure returns (bytes32) {
        return (bytes32)((uint)(self) | OR_MASK);
    }

    function isCanonicalRight(bytes32 self) internal pure returns (bool) {
        return (((uint)(self) >> 255) == 1);
    }

    function proofIsValid(bytes32 leaf, bytes32[] memory path, bytes32 expectedRoot) internal pure returns (bool) {
        bytes32 current = leaf;
        bytes32 left;
        bytes32 right;
        
        for (uint i = 0; i < path.length; i++) {
            if(isCanonicalRight(path[i])) {
                left = current;
                right = path[i];
            } else {
                left = path[i];
                right = current;
            }
            left = makeCanonicalLeft(left);
            right = makeCanonicalRight(right);

            current = sha256(abi.encodePacked(left, right));
        }

        return (current == expectedRoot);
    }
}