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
        header = "0x"+toBuffer(headerRaw).toString("hex")
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
        const relay = await Relay.new()
        let blockHeaders =
            "0x" +
            "5df21547701573f92ae672a301000000259943aeb714e885c783bc79487cd025bb687b39d9de755d73a7fea000dd0000000000000000000000000000000000000000000000000000000000000000a5b4c6124952e5b4adc41074c44a8f9dab8ad5b98d4e3048a918c179bbf14bc9020000000000" +
            "68f215477055c694dea4e9ad0c00000025a4bf5e39f4b6e60bd22df5bf5beb735323a5840fb8effdf7fabbdfbea40000000000000000000000000000000000000000000000000000000000000000e5c9b570b709e031159461a7505057de6fc4f3d73dff5f7f06aaa2d08f28e529020000000000" +
            "74f21547802f8d144ddab2af1700000025b08a353158bef89501cc282dae7af60aa0efa618c1dab3821fa9994dc40000000000000000000000000000000000000000000000000000000000000000515eebb51d9f366cc5564d69490336cfa8691c2901d68ae47fd28c62d8c69d5c020000000000" +
            "80f21547a022338a4d770dc5fc00000025bc548f6c04628ae97cf03c882bd4ae76e6b4826ea1438747906a9bb73500000000000000000000000000000000000000000000000000000000000000001124c122f6a7c54e7d25aa657d011b89665d5b4c8e95dc95e3a8c786ed461aac020000000000" +
            "8cf21547701437935e955cc5fc00000025c834442beb6a34af34ed271bddf1971dfcbf7aa334a79f12c65b9a3045000000000000000000000000000000000000000000000000000000000000000082a838744389ecd9f89853ae7150a8080cedbae7177998d7b3981636ab55eef2020000000000" + 
            "98f21547a0a09918638c31c6fc00000025d48e178722795e802626ff1cc0d7119d52804fae8c9dba3383af917e100000000000000000000000000000000000000000000000000000000000000000a363ceed2fb8cdd2499edc8cd69b506c698259ae7aa0acefa0d5393b72904a3e020000000000" +
            "a4f21547a0a2695ce97854cbfc00000025e07826870d025ad7d4735583c5522de26a9df545e98befd7b744f8e91700000000000000000000000000000000000000000000000000000000000000002740887d636ecce6c161698227d6561f22188827a80e4985f7e11187fcbdf40e020000000000" +
            "b0f215471039cd53458755cbfc00000025ec55ffe89fe6b668f0b2087f7da02c2fc85bfd52fcd8b21998caa1ce730000000000000000000000000000000000000000000000000000000000000000a67c10b87af51cd9e1c85aa5bfe0148882b3c8a092161af4b687aa145681c674020000000000" +
            "bcf21547a0f0a5cdb71c8de2fc00000025f8138900efbed060b0b492d07469965116aa553c4ac344965f631886c100000000000000000000000000000000000000000000000000000000000000008614b86c2c4026bb76c2a6edae8374115fc4278b10f0c1739fab9e33481e663b020000000000" +
            "c8f2154700af49aae5e9b239fc0000002604c288ed7b7b6be62700a367a9f7f5162a130f0e8d4d86e2a2110da5ce000000000000000000000000000000000000000000000000000000000000000053c7364b04236d3863c8600a557fb5aafbf09e6cc6d2b62e3041588dbb3deded020000000000" +
            "d4f2154750956a785eda983bfc0000002610c83ed46a2137006e1921851b315308b243501ceb2791b8598d539fdc00000000000000000000000000000000000000000000000000000000000000004427d71a87cfffa94c8d36c33e7b32039ce2d324d9463fa755c63a9a543da5ea020000000000" +
            "e0f21547708d3ad7445a993bfc000000261c898056c022b865ab6aa1b31b64717675386da4300337d1545493a3360000000000000000000000000000000000000000000000000000000000000000961fa1296e23156080ba9e2e2874bc694540ebfce8a1b0048ab087022036710f020000000000" +
            "ecf21547e0159c545eb55544fc0000002628b9527d421ec85981142907cde073a8816a08462fb33e0c363d42019100000000000000000000000000000000000000000000000000000000000000008ac3bce7ccfd5e0ae9b619158b36173b8a30f95d4d89b4417bc248a2ae89f8b6020000000000" +
            "f8f215477055c6d2343fa75efc0000002634d39d25ddf37732c12e2ed6ac51f47e6f230e0324777cd9cbb896fd3500000000000000000000000000000000000000000000000000000000000000000fb2b821bcae1877e83a854b32115fa79309bcbc5ef3ba6f48988287d314b54f020000000000" +
            "04f315477015a7d5c4e82e65fc00000026409520530e20cd2d1d8744e4074ed6407cf0dcd6812adb35d9529434880000000000000000000000000000000000000000000000000000000000000000079426fe9c8f17af6f48c786cbcce3915ff770428a51732a30c380f3597921fc020000000000"

        let blockHeaderSizes = [116,116,116,116,116,116,116,116,116,116,116,116,116,116,116]
        const valid = await relay.verifyBlockBasedOnSchedule(
                blockHeaders,
                blockHeaderSizes //,
                //[], //bytes32[15] memory blockMerkleHash,
                //"", //bytes memory pendingSchedule, /* assuming same pending schedule for all blocks */
                //[], // uint8[15] memory sigV,
                //[], //bytes32[15] memory sigR,
                //[], //bytes32[15] memory sigS,
                //[] //bytes32[15] memory claimedSignerPubKey
        )
    });
    
    
})