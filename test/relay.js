const Helper = require("./helper.js")
const bs58 = require('bs58')
const ethUtil = require('ethereumjs-util')
const keyUtils = require('eosjs-ecc/lib/key_utils.js');

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
        //expectedSigningKey = "0x"+bs58pubKeyToHex(expectedSigningKeyRaw).toString("hex")
        // TODO: uncompress the key, for now using python code for it

        // this is as calculated in uncompress.py abd stripped of from leading 0x04
        claimedSignerPubKey =  "0xc0ded2bc1f1305fb0faac5e6c03ee3a1924234985427b6167ca569d13df435cfeeceff7130fd352c698d2279967e2397f045479940bb4e7fb178fd9212fca8c0"
        
        console.log("header", header)
        console.log("bmRoot", bmRoot)
        console.log("schedule", schedule)
        console.log("v", v)
        console.log("r", r)
        console.log("s", s)
        console.log("claimedSignerPubKey", claimedSignerPubKey)

        //04c0ded2bc1f1305fb0faac5e6c03ee3a1924234985427b6167ca569d13df435cfeeceff7130fd352c698d2279967e2397f045479940bb4e7fb178fd9212fca8c0

        const relay = await Relay.new()
        const verified = await relay.verifyBlockSig(
                header,
                bmRoot,
                schedule,
                v,
                r,
                s,
                claimedSignerPubKey
        )
        console.log(verified)
        assert(verified, "block not verified correctly")
    })
})