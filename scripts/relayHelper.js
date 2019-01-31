const Web3 = require('web3')
const fs = require('fs')
const path = require('path')
const RLP = require('rlp')
const BigNumber = require('bignumber.js')
const bs58 = require('bs58')
const ethUtil = require('ethereumjs-util')
const keyUtils = require('eosjs-ecc/lib/key_utils.js');

var _slicedToArray = function () { function sliceIterator(arr, i) { var _arr = []; var _n = true; var _d = false; var _e = undefined; try { for (var _i = arr[Symbol.iterator](), _s; !(_n = (_s = _i.next()).done); _n = true) { _arr.push(_s.value); if (i && _arr.length === i) break; } } catch (err) { _d = true; _e = err; } finally { try { if (!_n && _i["return"]) _i["return"](); } finally { if (_d) throw _e; } } return _arr; } return function (arr, i) { if (Array.isArray(arr)) { return arr; } else if (Symbol.iterator in Object(arr)) { return sliceIterator(arr, i); } else { throw new TypeError("Invalid attempt to destructure non-iterable instance"); } }; }();
var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

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

module.exports.readScheduleFromFile = async function(fileName) {
    let oldProducersData = JSON.parse(fs.readFileSync(fileName, 'utf8'));
    let version = oldProducersData.version
    let publicKeysForPython = []
    let namesToIdx = {}

    // TODO: move uncompressing code to separate function.
    // start manufacturing uncompressed keys from compressed ones (dumped from c++ program)
    for (var j = 0; j < oldProducersData.producers.length; j++) {
        thisData = oldProducersData.producers[j]
        expectedSigningKey = thisData.block_signing_key
        publicKeysForPython.push((bs58.decode(expectedSigningKey.slice(3)).toString("hex")).slice(0,-8))
        namesToIdx[thisData.producer_name] = j
    }
    let publicKeysForPythonAsJson = JSON.stringify(publicKeysForPython);
    await fs.writeFile('tmp_keys_for_python.json', publicKeysForPythonAsJson, 'utf8', (err, data) => {
    if (err) {throw err;}});
    
    await sleep(500)
    require("child_process").execSync('python scripts/uncompress.py')
    await sleep(500)
    fs.unlink("tmp_keys_for_python.json", (err, data) => {if (err) {throw err;}});

    let uncompressed_keys = JSON.parse(fs.readFileSync("uncompressed_keys.json", 'utf8'));
    fs.unlink("uncompressed_keys.json", (err, data) => {if (err) {throw err;}});

    return [version, namesToIdx, uncompressed_keys]
}

module.exports.getHeadersData = async function(file, namesToIdx) {
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

module.exports.getActionData = async function(file, namesToIdx) {
    blockMerklePath = []
    producersData = JSON.parse(fs.readFileSync(file, 'utf8'));
    thisData = producersData
    blockHeader = "0x" + thisData.raw_header
    blockMerkleHash = "0x" + thisData.block_mroot
    blockMerklePath = add0xToAllItems(thisData.proof_path)
    pendingScheduleHash = "0x" + thisData.pending_schedule_hash
    let arr = getSigParts(bs58SigToHex(thisData.producer_signature))
    sigV = arr[0], sigR = arr[1], sigS = arr[2];
    claimedKeyIndex = namesToIdx[thisData.producer]
    actionPath = add0xToAllItems(thisData.action_proof_path)
    actionRecieptDigest = "0x" + thisData.action_receipt_digest;
    irreversibleBlockToReference = thisData.previous_block_num

    return {
        blockMerklePath:blockMerklePath,
        blockHeader:blockHeader,
        blockMerkleHash:blockMerkleHash,
        blockMerklePath:blockMerklePath,
        pendingScheduleHash:pendingScheduleHash,
        sigV:sigV,
        sigR:sigR,
        sigS:sigS,
        claimedKeyIndex:claimedKeyIndex,
        actionPath:actionPath,
        actionRecieptDigest:actionRecieptDigest,
        irreversibleBlockToReference:irreversibleBlockToReference
    }
}