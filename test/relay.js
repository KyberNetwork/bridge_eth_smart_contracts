const bs58 = require('bs58')
const ethUtil = require('ethereumjs-util')
const keyUtils = require('eosjs-ecc/lib/key_utils.js');
const fs = require("fs");

var _slicedToArray = function () { function sliceIterator(arr, i) { var _arr = []; var _n = true; var _d = false; var _e = undefined; try { for (var _i = arr[Symbol.iterator](), _s; !(_n = (_s = _i.next()).done); _n = true) { _arr.push(_s.value); if (i && _arr.length === i) break; } } catch (err) { _d = true; _e = err; } finally { try { if (!_n && _i["return"]) _i["return"](); } finally { if (_d) throw _e; } } return _arr; } return function (arr, i) { if (Array.isArray(arr)) { return arr; } else if (Symbol.iterator in Object(arr)) { return sliceIterator(arr, i); } else { throw new TypeError("Invalid attempt to destructure non-iterable instance"); } }; }();
var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

function toBuffer(input) {
    inputList = input.split(" ")
    inputList.splice(inputList.indexOf("["), 1)
    inputList.splice(inputList.indexOf("]"), 1)

    inputListHex = []
    inputList.forEach(function(entry) {
        inputListHex.push("0x"+entry);
    });
    inputBuffer = Buffer(inputListHex)
    return inputBuffer
}

function bs58SigToHex(signatureRaw) {
    match = signatureRaw.match(/^SIG_([A-Za-z0-9]+)_([A-Za-z0-9]+)$/);
    _match = _slicedToArray(match, 3), keyType = _match[1], keyString = _match[2];
    sigBuff = keyUtils.checkDecode(keyString, keyType);
    return sigBuff
}

function getSigParts(sigBuff) {
    let i = sigBuff.readUInt8(0)
    let v = (i - 4)
    r = "0x"+sigBuff.slice(1,33).toString("hex")
    s = "0x"+sigBuff.slice(33,65).toString("hex")
    return [v,r,s]
}

function bs58pubKeyToHex(expectedSigningKeyRaw) {
    expectedSigningKeyHex = bs58.decode(expectedSigningKeyRaw.slice(3)) // remove "EOS"
    expectedSigningKey = expectedSigningKeyHex.slice(1,33) // remove first byte and last 4 bytes of checksum
    return expectedSigningKey
}

function add0xToAllItems(arr) {
    var i, n = arr.length;
    for (i = 0; i < n; ++i) {
        arr[i] = "0x" + arr[i];
    }
    return arr;
};

const Relay = artifacts.require("Relay")

contract("Relay", async accounts => {

    it("parse header", async () => {
        // this includes new producers:
        headerRaw = "[ 95 18 79 47 00 00 00 00 00 ea 30 55 00 00 00 00 00 01 bc f2 f4 48 22 5d 09 96 85 f1 4d a7 68 03 02 89 26 af 04 d2 60 7e af cf 60 9c 26 5c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 74 7d 10 3e 24 c9 6d eb 1b ee bc 13 eb 31 f7 c2 18 81 26 94 6c 86 77 df d1 69 1a f9 f9 c0 3a b1 00 00 00 00 01 57 01 00 00 04 00 00 00 00 00 ea 30 55 00 02 c0 de d2 bc 1f 13 05 fb 0f aa c5 e6 c0 3e e3 a1 92 42 34 98 54 27 b6 16 7c a5 69 d1 3d f4 35 cf 00 00 00 00 00 73 a2 c9 00 02 c0 de d2 bc 1f 13 05 fb 0f aa c5 e6 c0 3e e3 a1 92 42 34 98 54 27 b6 16 7c a5 69 d1 3d f4 35 cf 00 00 00 00 80 49 af f1 00 02 c0 de d2 bc 1f 13 05 fb 0f aa c5 e6 c0 3e e3 a1 92 42 34 98 54 27 b6 16 7c a5 69 d1 3d f4 35 cf 00 00 00 00 80 69 a2 73 00 02 c0 de d2 bc 1f 13 05 fb 0f aa c5 e6 c0 3e e3 a1 92 42 34 98 54 27 b6 16 7c a5 69 d1 3d f4 35 cf 00 ]"
        header = "0x" + toBuffer(headerRaw).toString("hex")
        /* console.log("header", header) */

        const relay = await Relay.new()
        const result = await relay.parseHeader(header);
        /*
        console.log("timestamp: ", result[0]);
        console.log("producer: ", result[1]);
        console.log("confirmed: ", result[2]);
        console.log("previous: ", result[3]);
        console.log("tx_mroot: ", result[4]);
        console.log("schedule: ", result[5]);
        console.log("action_mroot: ", result[6]);
        console.log("version: ", result[7]);
        console.log("amount: ", result[8]);
        console.log("producerNames: \n", result[9]);
        console.log("producerKeysHigh: \n", result[10]);
        */
    });

    it("parse 15 blocks", async () => {

        let newProducersData = JSON.parse(fs.readFileSync("new_producers.json", 'utf8'));
        let version = newProducersData.version
        let publicKeysForPython = []
        let namesToIdx = {}

        // prepare inputs for python uncompressed_keys.json manufacture
        for (var j = 0; j < newProducersData.producers.length; j++) {
            thisData = newProducersData.producers[j]
            expectedSigningKey = thisData.block_signing_key
            publicKeysForPython.push((bs58.decode(expectedSigningKey.slice(3)).toString("hex")).slice(0,-8))
            namesToIdx[thisData.producer_name] = j
        }

        // using the publicKeysForPython and uncompress.py script uncompressed_keys.json have been created 
        // remove if need to create input for python - console.log("publicKeysForPython", publicKeysForPython)

        // store schedule temporarily
        let uncompressed_keys = JSON.parse(fs.readFileSync("uncompressed_keys.json", 'utf8'));

        const relay = await Relay.new()
        await relay.storeSchedule(version,
                                  uncompressed_keys["first_parts"],
                                  uncompressed_keys["second_parts"])

        let blockHeaders = "0x"
        let blockHeaderSizes = []
        let blockMerkleHashs = []
        let blockMerklePaths = []
        let blockMerklePathSizes = []
        let pendingScheduleHashes = []
        let sigVs = []
        let sigRs = []
        let sigSs = []
        let v,r,s
        let claimedKeyIndices = []

        producersData = JSON.parse(fs.readFileSync("producers_data.json", 'utf8'));
        for (var j = 0; j < producersData.length; j++) {
            thisData = producersData[j]
            blockHeaders = blockHeaders + thisData.raw_header
            blockHeaderSizes.push(thisData.raw_header.length / 2)
            blockMerkleHashs.push("0x" + thisData.block_mroot)
            blockMerklePaths = blockMerklePaths.concat(add0xToAllItems(thisData.proof_path))
            blockMerklePathSizes.push(thisData.proof_path.length)
            pendingScheduleHashes.push("0x" + thisData.pending_schedule_hash)
            let arr  = getSigParts(bs58SigToHex(thisData.producer_signature))
            sigVs.push(arr[0])
            sigRs.push(arr[1])
            sigSs.push(arr[2])
            claimedKeyIndices.push(namesToIdx[thisData.producer])
        }

         const valid = await relay.verifyBlockBasedOnSchedule(
                blockHeaders,
                blockHeaderSizes,
                blockMerkleHashs,
                blockMerklePaths,
                blockMerklePathSizes,
                pendingScheduleHashes,
                sigVs,
                sigRs,
                sigSs,
                claimedKeyIndices)
         assert(valid);

    });
})