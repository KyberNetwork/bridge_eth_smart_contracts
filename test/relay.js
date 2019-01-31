const relayHelper = require('../scripts/relayHelper.js');
const Relay = artifacts.require("Relay")

contract("Relay", async accounts => {

    it("store initial schedule, prove a schedule (b9313), relay blocks (b9626, b10800), prove action(b10776)", async () => {
        const relay = await Relay.new()

        // store initial schedule, taken from new producers list in block 6713
        let [version, namesToIdxSchedule1, fullKeys] = await relayHelper.readScheduleFromFile("test/producers_6713.json")
        await relay.storeInitialSchedule(version, fullKeys["x"], fullKeys["y"], fullKeys["x"].length)

        // get new pending schedule from block 9313, which we want to change to
        let namesToIdxSchedule2
        [version, namesToIdxSchedule2, fullKeys] = await relayHelper.readScheduleFromFile("test/producers_9313.json")
        completingKeyParts = fullKeys["y"]

        // get headers building on top of block 9313 (from c++) and use them to prove schedule change
        headersData = await relayHelper.getHeadersData("test/headers_9313.json", namesToIdxSchedule1)

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
        headersData = await relayHelper.getHeadersData("test/headers_9626.json", namesToIdxSchedule2)

        await relay.relayBlock(
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
        headersData = await relayHelper.getHeadersData("test/headers_10800.json", namesToIdxSchedule2)

        await relay.relayBlock(
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

        // get header with action in block 10776
        actionData = await relayHelper.getActionData("test/header_10776.json", namesToIdxSchedule2)
        const valid = await relay.verifyAction(
            actionData.irreversibleBlockToReference,
            actionData.blockHeader,
            actionData.blockMerkleHash,
            actionData.blockMerklePath,
            actionData.pendingScheduleHash,
            actionData.sigV,
            actionData.sigR,
            actionData.sigS,
            actionData.claimedKeyIndex,
            actionData.actionPath,
            actionData.actionRecieptDigest)
        assert(valid)
    });
})