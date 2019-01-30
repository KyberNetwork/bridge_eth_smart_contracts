pragma solidity 0.5.0;


contract MerkleProof {

    uint constant OR_MASK =   0x8000000000000000000000000000000000000000000000000000000000000000;
    uint constant AND_MASK =  0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;

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
