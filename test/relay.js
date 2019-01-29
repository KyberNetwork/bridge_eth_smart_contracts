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

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function readScheduleFromFile(fileName) {
    let oldProducersData = JSON.parse(fs.readFileSync(fileName, 'utf8'));
    let version = oldProducersData.version
    let publicKeysForPython = []
    let namesToIdx = {}

    // TODO: move uncompressing code to separate function!!!!
    // start manufacturing uncompressed keys from compressed ones (dumped from c++ program)
    for (var j = 0; j < oldProducersData.producers.length; j++) {
        thisData = oldProducersData.producers[j]
        expectedSigningKey = thisData.block_signing_key
        publicKeysForPython.push((bs58.decode(expectedSigningKey.slice(3)).toString("hex")).slice(0,-8))
        namesToIdx[thisData.producer_name] = j
    }
    let publicKeysForPythonAsJson = JSON.stringify(publicKeysForPython);
    fs.writeFile('tmp_keys_for_python.json', publicKeysForPythonAsJson, 'utf8');
    
    await sleep(500)
    require("child_process").execSync('python uncompress.py')
    await sleep(500)
    fs.unlink("tmp_keys_for_python.json") // delete the tmp file we created earlier 

    let uncompressed_keys = JSON.parse(fs.readFileSync("uncompressed_keys.json", 'utf8'));
    fs.unlink("uncompressed_keys.json") // delete also the file that the python script created

    return [version, namesToIdx, uncompressed_keys]
}

async function getHeadersData(file, namesToIdx) {
    blockHeaders = "0x"
    blockHeaderSizes = [], blockMerkleHashs = [], blockMerklePaths = [], blockMerklePathSizes = [];
    pendingScheduleHashes = [],  sigVs = [], sigRs = [], sigSs = [], claimedKeyIndices = [];

    producersData = JSON.parse(fs.readFileSync(file, 'utf8'));
    for (var j = 0; j < producersData.length; j++) {
        thisData = producersData[j]
        blockHeaders = blockHeaders + thisData.raw_header
        blockHeaderSizes.push(thisData.raw_header.length / 2)
        blockMerkleHashs.push("0x" + thisData.block_mroot)
        blockMerklePaths = blockMerklePaths.concat(add0xToAllItems(thisData.proof_path))
        blockMerklePathSizes.push(thisData.proof_path.length)
        pendingScheduleHashes.push("0x" + thisData.pending_schedule_hash)
        let arr  = getSigParts(bs58SigToHex(thisData.producer_signature))
        sigVs.push(arr[0]), sigRs.push(arr[1]), sigSs.push(arr[2]);
        claimedKeyIndices.push(namesToIdx[thisData.producer])
    }
    
    return {
        blockHeaders:blockHeaders,
        blockHeaderSizes:blockHeaderSizes,
        blockMerkleHashs:blockMerkleHashs,
        blockMerklePaths:blockMerklePaths,
        blockMerklePathSizes:blockMerklePathSizes,
        pendingScheduleHashes:pendingScheduleHashes,
        sigVs:sigVs,
        sigRs:sigRs,
        sigSs:sigSs,
        claimedKeyIndices:claimedKeyIndices
    }
} 

const Relay = artifacts.require("Relay")

contract("Relay", async accounts => {

    it("parse header", async () => {
        // this includes new producers:
        headerRaw = "[ 95 18 79 47 00 00 00 00 00 ea 30 55 00 00 00 00 00 01 bc f2 f4 48 22 5d 09 96 85 f1 4d a7 68 03 02 89 26 af 04 d2 60 7e af cf 60 9c 26 5c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 74 7d 10 3e 24 c9 6d eb 1b ee bc 13 eb 31 f7 c2 18 81 26 94 6c 86 77 df d1 69 1a f9 f9 c0 3a b1 00 00 00 00 01 57 01 00 00 04 00 00 00 00 00 ea 30 55 00 02 c0 de d2 bc 1f 13 05 fb 0f aa c5 e6 c0 3e e3 a1 92 42 34 98 54 27 b6 16 7c a5 69 d1 3d f4 35 cf 00 00 00 00 00 73 a2 c9 00 02 c0 de d2 bc 1f 13 05 fb 0f aa c5 e6 c0 3e e3 a1 92 42 34 98 54 27 b6 16 7c a5 69 d1 3d f4 35 cf 00 00 00 00 80 49 af f1 00 02 c0 de d2 bc 1f 13 05 fb 0f aa c5 e6 c0 3e e3 a1 92 42 34 98 54 27 b6 16 7c a5 69 d1 3d f4 35 cf 00 00 00 00 80 69 a2 73 00 02 c0 de d2 bc 1f 13 05 fb 0f aa c5 e6 c0 3e e3 a1 92 42 34 98 54 27 b6 16 7c a5 69 d1 3d f4 35 cf 00 ]"
        header = "0x" + toBuffer(headerRaw).toString("hex")
        header = "0x24f11547c0684a91facba66ee40000002460d0b0d9a7dbf1a82779c657edc04abcd9b74e03111fd79a3acae3b2160000000000000000000000000000000000000000000000000000000000000000845df9d90c39c48ac3dd78f58c8a0235587435310ad6d29d7981ffcb37e0cdae0100000001020000001500af49aae5e9b2390002e65e41cb9ee12e23af44d32c337788253765eee9cd5c5b39900bf22e6d39dab150956a785eda983b00028d316c09c917eecbd8da03a695029a63dc3a4294c75c254af7d00078709b1107708d3ad7445a993b0002fc35aa95c03e0e75553f2dc670e476e7cbceb0bd9962dd637629e307e6366336e0159c545eb5554400027488fb8ad5080f9ff609501b1b392858061e9cc4d7a7e98f8c1dcfb076c613ab7055c6d2343fa75e00032aeec24bd317fffed0cd787efaf3cd8b7454fcf1dc3be8d4d6b0d6d337282eca7015a7d5c4e82e650003de2988ea5bf8c7d01283f127e9f7a9b3d40fb95a618e78975e210995fcfbff4980b53499565aab6b000383a91696b1538d01f80a7ffabc105aa4eb0a2e69798585c07112e37f2c982e76c0684a91facba66e00030865d02cc3433ac84a94f3834ca39e0cc54446ab3da13e29d3cfc2cc9341c8d58055cc5767055d740002f19818348f231392e0e77ee0d30424f16f213fa44d143efb0944a9e698e6d1c48019bd8b4d57a57e00037fbdb976fea057a5cbb6cb72229f02f36c02635e98ee4ccf555b4c34cc8fbf38a0229bfa4d37a98b000226dfc6402e9ffba01f798814c93ab2aac31e1794409f089525b09deded0eddc390dd39e6aa98b38b00029d65a2751be09a3dcd5df1ed634c13fb11c4a9e31f726a4435d74b9f75c63dd6701573f92ae672a300038b9c2183652437df1294edc1654a7fc3885e9ff849678be67ce79082a566b3647055c694dea4e9ad00027c30a8443026f4c518fb1659aa6e41f15a21b44c075cd98e88e0939ece61d906802f8d144ddab2af0003d09cdc55b989bf3c1b728dc39f049fffe1eb88376b5eeee7ab3ee9fbf382cb26a022338a4d770dc50002f19e790aaf9335cf1ab21a32aa986e4c30ec1360f8e69e2e39ea28af606813df701437935e955cc50002c004a5f66932f3bdc28029071b982c23ab78ed17018bbeec277b9cb8e2d50754a0a09918638c31c60003d322a86189958f2ac52029908b02b8c0ae2262eae21d44b3c1c29ad1e4cb018fa0a2695ce97854cb0002d5d8e44856678a456b05e0359b8925bc4cda9191fd71b95a3550764c51ed3bc81039cd53458755cb00039579e7254e9dc8f4be4e91f4faced3861e2cae56163bee1cdc0ab302ecc7c9daa0f0a5cdb71c8de200026be42a9296f30dd30f72c714591a7ced3b8307ac575f0353848b2643c599906100"

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


    it("store initial schedule, prove a schedule change (b9313) and relay a block (b9626)", async () => {
        const relay = await Relay.new()

        // store initial schedule, taken from new producers list in block 6713
        let [version, namesToIdxSchedule1, fullKeys] = await readScheduleFromFile("producers_6713.json")
        await relay.storeInitialSchedule(version, fullKeys["x"], fullKeys["y"], fullKeys["x"].length)

        // get new pending schedule from block 9313, which we want to change to
        let namesToIdxSchedule2
        [version, namesToIdxSchedule2, fullKeys] = await readScheduleFromFile("producers_9313.json")
        completingKeyParts = fullKeys["y"]

        // get headers building on top of block 9313 (from c++) and use them to prove schedule change
        headersData = await getHeadersData("headers_9313.json", namesToIdxSchedule1)

        await relay.changeSchedule(
            headersData.blockHeaders,
            headersData.blockHeaderSizes,
            headersData.blockMerkleHashs,
            headersData.blockMerklePaths,
            headersData.blockMerklePathSizes,
            headersData.pendingScheduleHashes,
            headersData.sigVs,
            headersData.sigRs,
            headersData.sigSs,
            headersData.claimedKeyIndices,
            completingKeyParts)

        // get headers building on top of block 9626 (from c++) and use them to validate that block
        headersData = await getHeadersData("headers_9626.json", namesToIdxSchedule2)

        await relay.verifyBlockBasedOnSchedule(
            headersData.blockHeaders,
            headersData.blockHeaderSizes,
            headersData.blockMerkleHashs,
            headersData.blockMerklePaths,
            headersData.blockMerklePathSizes,
            headersData.pendingScheduleHashes,
            headersData.sigVs,
            headersData.sigRs,
            headersData.sigSs,
            headersData.claimedKeyIndices)

        // get headers building on top of block 10800 (from c++) and use them to validate that block
        headersData = await getHeadersData("headers_10800.json", namesToIdxSchedule2)

        await relay.verifyBlockBasedOnSchedule(
            headersData.blockHeaders,
            headersData.blockHeaderSizes,
            headersData.blockMerkleHashs,
            headersData.blockMerklePaths,
            headersData.blockMerklePathSizes,
            headersData.pendingScheduleHashes,
            headersData.sigVs,
            headersData.sigRs,
            headersData.sigSs,
            headersData.claimedKeyIndices)

        lirb = await relay.lastIrreversibleBlock()
        await relay.verifyAction(
            lirb,
        bytes memory blockHeader,
        bytes32 blockMerkleHash,
        bytes32[] memory blockMerklePath,
        uint blockMerklePathSize,
        bytes32 pendingScheduleHash,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS,
        uint claimedKeyIndex,
        bytes32[] memory actionPath,
        bytes32 actionRecieptDigest

    });
})