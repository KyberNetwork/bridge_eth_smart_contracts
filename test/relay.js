const Helper = require("./helper.js")
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

    it("verify block signature", async () => {
        headerRaw   = "[ c6 fc 6e 47 00 00 00 00 00 ea 30 55 00 00 00 00 00 01 bc f2 f4 48 22 5d 09 96 85 f1 4d a7 68 03 02 89 26 af 04 d2 60 7e af cf 60 9c 26 5c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 74 7d 10 3e 24 c9 6d eb 1b ee bc 13 eb 31 f7 c2 18 81 26 94 6c 86 77 df d1 69 1a f9 f9 c0 3a b1 00 00 00 00 00 00 ]"
        bmRootRaw   = "[ 00 00 00 01 bc f2 f4 48 22 5d 09 96 85 f1 4d a7 68 03 02 89 26 af 04 d2 60 7e af cf 60 9c 26 5c ]"
        scheduleRaw = "[ 00 00 00 00 01 00 00 00 00 00 ea 30 55 00 02 c0 de d2 bc 1f 13 05 fb 0f aa c5 e6 c0 3e e3 a1 92 42 34 98 54 27 b6 16 7c a5 69 d1 3d f4 35 cf ]"  
        signatureRaw = "SIG_K1_JuKvk5XSetfux7yvVZGyYkLMPTFyKAmg1HwikbKKUvNBkvtNWWHtWwRYoxYvY7csbXcMMSyiyiy4kvmgxrmW9UkeyPEfWr"
        expectedSigningKeyRaw = "EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV"

        header   = "0x"+toBuffer(headerRaw).toString("hex")
        bmRoot   = "0x"+toBuffer(bmRootRaw).toString("hex")
        schedule = "0x"+toBuffer(scheduleRaw).toString("hex")

        let v,r,s
        [v,r,s] = getSigParts(bs58SigToHex(signatureRaw))
        expectedSigningKey = "0x"+bs58pubKeyToHex(expectedSigningKeyRaw).toString("hex")
        // TODO: uncompress the key, for now using python code for it

        // this is as calculated in uncompress.py and stripped of from leading 0x04
        claimedSignerPubKey = [ expectedSigningKey, // "0xc0ded2bc1f1305fb0faac5e6c03ee3a1924234985427b6167ca569d13df435cf",
                               "0xeeceff7130fd352c698d2279967e2397f045479940bb4e7fb178fd9212fca8c0"]
        storedCompressedPubKey = expectedSigningKey

        console.log("header", header)
        console.log("bmRoot", bmRoot)
        console.log("schedule", schedule)
        console.log("v", v)
        console.log("r", r)
        console.log("s", s)
        console.log("claimedSignerPubKey   ", claimedSignerPubKey)
        console.log("storedCompressedPubKey", expectedSigningKeyRaw)

        //04c0ded2bc1f1305fb0faac5e6c03ee3a1924234985427b6167ca569d13df435cfeeceff7130fd352c698d2279967e2397f045479940bb4e7fb178fd9212fca8c0

        const relay = await Relay.new()
        const verified = await relay.verifyBlockSig(
                header,
                bmRoot,
                schedule,
                v,
                r,
                s,
                claimedSignerPubKey,
                storedCompressedPubKey
        )
        console.log(verified)
        assert(verified, "block not verified correctly")
    })

    it("parse header", async () => {
        // this includes new producers:
        headerRaw = "[ 95 18 79 47 00 00 00 00 00 ea 30 55 00 00 00 00 00 01 bc f2 f4 48 22 5d 09 96 85 f1 4d a7 68 03 02 89 26 af 04 d2 60 7e af cf 60 9c 26 5c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 74 7d 10 3e 24 c9 6d eb 1b ee bc 13 eb 31 f7 c2 18 81 26 94 6c 86 77 df d1 69 1a f9 f9 c0 3a b1 00 00 00 00 01 57 01 00 00 04 00 00 00 00 00 ea 30 55 00 02 c0 de d2 bc 1f 13 05 fb 0f aa c5 e6 c0 3e e3 a1 92 42 34 98 54 27 b6 16 7c a5 69 d1 3d f4 35 cf 00 00 00 00 00 73 a2 c9 00 02 c0 de d2 bc 1f 13 05 fb 0f aa c5 e6 c0 3e e3 a1 92 42 34 98 54 27 b6 16 7c a5 69 d1 3d f4 35 cf 00 00 00 00 80 49 af f1 00 02 c0 de d2 bc 1f 13 05 fb 0f aa c5 e6 c0 3e e3 a1 92 42 34 98 54 27 b6 16 7c a5 69 d1 3d f4 35 cf 00 00 00 00 80 69 a2 73 00 02 c0 de d2 bc 1f 13 05 fb 0f aa c5 e6 c0 3e e3 a1 92 42 34 98 54 27 b6 16 7c a5 69 d1 3d f4 35 cf 00 ]"
        header = "0x" + toBuffer(headerRaw).toString("hex")
        console.log("header", header)

        const relay = await Relay.new()
        const result = await relay.parseHeader(header);
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
    });

    it("validate merkle proof", async () => {
        
        leaves = ["0x0ff38b06e8d91eb9e0e315baadf124dd6088d985830af83e5fe9d19a1aec94db",
                  "0x04ca2c2c485ebd1ff324b61ff351cf8810d40fb53cc54f1de4136461b4d15a91",
                  "0xf642ce52f6d266daeffda3798cde463b375515e2ff07f28169142cda4fae81da",
                  "0xa1c526efa754b4c7b86bea5096ced3da383fb95c2f06b5147843b818055e5926",
                  "0x3eaa2d991b2e6bed7b11cdd1ecc4f591fdf32102c4b17417b71c255edd2116df",
                  "0x1863f557d6c65a9bb14c681dac086acde422725f2e51490d212fd60f15c0e457",
                  "0x64f457ce04f13bbf1f1f3fd108ba43ccc6e77f6851029b438bcf436be412308a"]

         paths = [["0x84ca2c2c485ebd1ff324b61ff351cf8810d40fb53cc54f1de4136461b4d15a91",
                  "0x98a5352460276f18cb130dc10c2266f98b4f98844fb06a8cb8d156a23abb36de",
                  "0xbe99e8ffbfd7eaf2969c487ce05c61d106cf87f1b1db50a88c1ff0339ba29040"],
                 ["0x0ff38b06e8d91eb9e0e315baadf124dd6088d985830af83e5fe9d19a1aec94db",
                  "0x98a5352460276f18cb130dc10c2266f98b4f98844fb06a8cb8d156a23abb36de",
                  "0xbe99e8ffbfd7eaf2969c487ce05c61d106cf87f1b1db50a88c1ff0339ba29040"],
                 ["0xa1c526efa754b4c7b86bea5096ced3da383fb95c2f06b5147843b818055e5926",
                  "0x6b104f5d1fd3a7efc6ded56f337f4e0dc1b7b67a88da128613d43c221d0e6718",
                  "0xbe99e8ffbfd7eaf2969c487ce05c61d106cf87f1b1db50a88c1ff0339ba29040"],
                 ["0x7642ce52f6d266daeffda3798cde463b375515e2ff07f28169142cda4fae81da",
                  "0x6b104f5d1fd3a7efc6ded56f337f4e0dc1b7b67a88da128613d43c221d0e6718",
                  "0xbe99e8ffbfd7eaf2969c487ce05c61d106cf87f1b1db50a88c1ff0339ba29040"],
                 ["0x9863f557d6c65a9bb14c681dac086acde422725f2e51490d212fd60f15c0e457",
                  "0xcfdf4879f658aa25845a1058400194db668177c07367eda6239d0330559a62bc",
                  "0x503dca34c439c417f755cde8420379eafb9b2d7179b5acfc1b302e5fc869d975"],
                 ["0x3eaa2d991b2e6bed7b11cdd1ecc4f591fdf32102c4b17417b71c255edd2116df",
                  "0xcfdf4879f658aa25845a1058400194db668177c07367eda6239d0330559a62bc",
                  "0x503dca34c439c417f755cde8420379eafb9b2d7179b5acfc1b302e5fc869d975"],
                 ["0xe4f457ce04f13bbf1f1f3fd108ba43ccc6e77f6851029b438bcf436be412308a",
                  "0x099df29b96e436d09301bda47f9ebc055b5e91bc24a10a614c39bc4e2b213a86",
                  "0x503dca34c439c417f755cde8420379eafb9b2d7179b5acfc1b302e5fc869d975"]]

        root = "0xdeac5a4438f924f5c24fc7c65bf7d0e39817db67e958ce81772b05a072e2e1fd";

        const relay = await Relay.new()
        var i;
        for (i = 0; i < leaves.length; i++) {
            const valid = await relay.proofIsValid(leaves[i], paths[i], root);
            console.log(valid);
            assert(valid, "proof is not valid")
        }
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