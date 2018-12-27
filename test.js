//const Tx = require('ethereumjs-tx')
const ethUtil = require('ethereumjs-util')
const ecc = require('eosjs-ecc');
const Signature = require('eosjs-ecc/lib/signature.js')
const keyUtils = require('eosjs-ecc/lib/key_utils.js');
const assert = require('assert');
const bs58 = require('bs58')
const EthCrypto = require('eth-crypto');

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

function getHash(inputBuffer) {
    hashedBuffer = ethUtil.sha256(inputBuffer)
    return hashedBuffer
}

console.log("/////////////////////////////////////")
console.log("verify hash is the same as eos code")
header = toBuffer("[ c6 fc 6e 47 00 00 00 00 00 ea 30 55 00 00 00 00 00 01 bc f2 f4 48 22 5d 09 96 85 f1 4d a7 68 03 02 89 26 af 04 d2 60 7e af cf 60 9c 26 5c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 74 7d 10 3e 24 c9 6d eb 1b ee bc 13 eb 31 f7 c2 18 81 26 94 6c 86 77 df d1 69 1a f9 f9 c0 3a b1 00 00 00 00 00 00 ]")
headerHash = getHash(header)
bmRoot = toBuffer("[ 00 00 00 01 bc f2 f4 48 22 5d 09 96 85 f1 4d a7 68 03 02 89 26 af 04 d2 60 7e af cf 60 9c 26 5c ]")
pair = Buffer.concat([headerHash, bmRoot])
pairHash = getHash(pair)
console.log("pairHash", pairHash.toString("hex"))
schedule = toBuffer("[ 00 00 00 00 01 00 00 00 00 00 ea 30 55 00 02 c0 de d2 bc 1f 13 05 fb 0f aa c5 e6 c0 3e e3 a1 92 42 34 98 54 27 b6 16 7c a5 69 d1 3d f4 35 cf ]")
scheduleHash = getHash(schedule)
pair = Buffer.concat([pairHash, scheduleHash])
pairHash = getHash(pair)
console.log("final hash: ", pairHash)
console.log("/////////////////////////////////////")

console.log("/////////////////////////////////////")
console.log("now start comparing eos sig recovery with eth sig recovery")
hashedMsgBuffer = pairHash //toBuffer("[ 46 3d 74 ac 73 6c 08 a2 e5 c8 5d f1 17 82 53 39 12 cc d8 5f 01 a4 25 9b 65 8e ae 08 cd 4a cb 8a ]")
signature = "SIG_K1_JuKvk5XSetfux7yvVZGyYkLMPTFyKAmg1HwikbKKUvNBkvtNWWHtWwRYoxYvY7csbXcMMSyiyiy4kvmgxrmW9UkeyPEfWr"
expectedSigningKey = "EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV"

console.log("/////////////////////////////////////")
console.log("eos works")
console.log("PUBLIC KEY RECOVERY ( EOS Library ) :");
const e = ecc.recoverHash(signature, hashedMsgBuffer);
const prefix = keyUtils.checkDecode(e.slice(3)).toString('hex').slice(0,2);
const key = keyUtils.checkDecode(e.slice(3)).toString('hex').slice(2);
console.log(e + " ===> " + prefix + " + " + key );    
assert.equal(expectedSigningKey, e)
console.log("/////////////////////////////////////")

console.log("/////////////////////////////////////")
console.log("convert sig to bytestream as this is what eth expects(taken from eosjs-ecc's signature.js)")
assert.equal(typeof signature === 'undefined' ? 'undefined' : _typeof(signature), 'string', 'signature');
var match = signature.match(/^SIG_([A-Za-z0-9]+)_([A-Za-z0-9]+)$/);
assert(match != null && match.length === 3, 'Expecting signature like: SIG_K1_base58signature..');
var _match = _slicedToArray(match, 3), keyType = _match[1], keyString = _match[2];
assert.equal(keyType, 'K1', 'K1 signature expected');
sigBuff = keyUtils.checkDecode(keyString, keyType);
console.log("sigBuff: ", sigBuff.toString("hex"))
console.log("sigBuff.length: ", sigBuff.length)
console.log("/////////////////////////////////////")

console.log("/////////////////////////////////////")
console.log("input data:")
console.log("hashedMsgHex: ", hashedMsgBuffer.toString("hex"))
console.log("signature58: ", signature)
console.log("signatureHex: ", sigBuff.toString("hex"))
console.log("expectedSigningKey58: ", expectedSigningKey)
expectedSigningKeyHex = bs58.decode(expectedSigningKey.slice(3)) // remove "EOS"
console.log("expectedSigningKeyHex length before removing first byte (identifier?) and last 4 bytes (checksum?): ", expectedSigningKeyHex.length)
if(expectedSigningKeyHex.length < 64) {console.log("eos signing keys are compressed")}
expectedSigningKeyHex = expectedSigningKeyHex.slice(1,33) // remove first byte and last 4 bytes of checksum
console.log("expectedSigningKeyHex: ", expectedSigningKeyHex.toString("hex"))
console.log("expectedSigningKeyHex.length: ", expectedSigningKeyHex.length)
let i = sigBuff.readUInt8(0)
let v = i - 4
r = sigBuff.slice(1,33)
s = sigBuff.slice(33,65)
console.log(r.toString("hex"))
console.log(s.toString("hex"))

ethSignatureStr = "0x" + r.toString("hex") + s.toString("hex") + v.toString(16)
console.log("/////////////////////////////////////")

console.log("/////////////////////////////////////")
console.log("do a try on ethereum with some private key just to see public key size")
ethPublicFromPrivate = ethUtil.privateToPublic("0x6abc93840b115a3fc88bca4fd6b495aadb5d442454c53e6a8d499f0af42f373d")
console.log("ethPublicFromPrivate: ", ethPublicFromPrivate.toString("hex"))
console.log("ethPublicFromPrivate.length: ", ethPublicFromPrivate.length)
if(ethPublicFromPrivate.length == 64) { console.log("ethereum public keys are uncompressed")}
console.log("/////////////////////////////////////")

console.log("/////////////////////////////////////")
console.log("try to recover with ethUtil.ecrecover")
let maybePublicKey = ethUtil.ecrecover(hashedMsgBuffer, v, r, s)
console.log("maybePublicKey: ", maybePublicKey.toString("hex"))
console.log("maybePublicKey.length: ", maybePublicKey.length)
console.log("since ethUtil.ecrecover returns uncompressed public key, need to compress it")
maybePublicKeyCompressed = maybePublicKey.slice(0,32) // only x part
console.log("maybePublicKeyCompressed: ", maybePublicKeyCompressed.toString("hex"))
console.log("maybePublicKeyCompressed.length: ", maybePublicKeyCompressed.length)
assert.equal(maybePublicKeyCompressed.length,expectedSigningKeyHex.length)
assert.equal(maybePublicKeyCompressed.toString("hex"),expectedSigningKeyHex.toString("hex"))
console.log("/////////////////////////////////////")

console.log("/////////////////////////////////////")
console.log("try to recover with EthCrypto")
messageHash = "0x" + hashedMsgBuffer.toString("hex")
console.log("messageHash: ", messageHash)
console.log("ethSignatureStr: ", ethSignatureStr)
const eth_signer = EthCrypto.recoverPublicKey(ethSignatureStr, messageHash);
console.log("PUBLIC KEY RECOVERY ( ETH Library) :");
console.log(eth_signer.slice(0,64) + " + " + eth_signer.slice(64));
assert.equal(eth_signer.slice(0,64),expectedSigningKeyHex.toString("hex"))
console.log("/////////////////////////////////////")
