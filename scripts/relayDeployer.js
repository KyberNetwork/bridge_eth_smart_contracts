#!/usr/bin/env node

const Web3 = require('web3')
const fs = require('fs')
const path = require('path')
const RLP = require('rlp')
const BigNumber = require('bignumber.js')
const relayHelper = require('../scripts/relayHelper.js');
const assert = require('assert');

process.on('unhandledRejection', console.error.bind(console))

// current run command: node scripts/relayDeployer.js --gas-price-gwei 10 --rpc-url https://kovan.infura.io 
const { gasPriceGwei, printPrivateKey, rpcUrl, signedTxOutput, dontSendTx, chainId: chainIdInput } = require('yargs').usage(
    'Usage: $0 --gas-price-gwei [gwei] --print-private-key [bool] --rpc-url [url] --signed-tx-output [path] --dont-send-tx [bool] --chain-id'
  )
  .demandOption(['gasPriceGwei', 'rpcUrl'])
  .boolean('printPrivateKey')
  .boolean('dontSendTx').argv
const web3 = new Web3(new Web3.providers.HttpProvider(rpcUrl))
const solc = require('solc')

const rand = web3.utils.randomHex(7)
const privateKey = web3.utils.sha3('in love we trust' + rand)
console.log('privateKey', privateKey)

if (printPrivateKey) {
  let path = 'privatekey_' + web3.utils.randomHex(7) + '.txt'
  fs.writeFileSync(path, privateKey, function(err) {
    if (err) {
      return console.log(err)
    }
  })
}

const account = web3.eth.accounts.privateKeyToAccount(privateKey)
const sender = account.address
const gasPrice = new BigNumber(10).pow(9).times(gasPriceGwei)
console.log(`gasPrice: ${gasPrice}`)
const signedTxs = []
let nonce
let chainId = chainIdInput

console.log('from', sender)

async function sendTx(txObject) {
  const txTo = txObject._parent.options.address

  let gasLimit
  try {
    gasLimit = await txObject.estimateGas()
  } catch (e) {
    console.log(`Note: estimateGas failed`)
    gasLimit = 5000 * 1000
  }

  if (txTo !== null) {
    console.log(`Note: setting gasLimit manually`)
    gasLimit = 5000 * 1000
  }

  gasLimit *= 1.2
  gasLimit -= gasLimit % 1
  console.log(`gasLimit: ${gasLimit}`)

  const txData = txObject.encodeABI()
  const txFrom = account.address
  const txKey = account.privateKey

  const tx = {
    from: txFrom,
    to: txTo,
    nonce: nonce,
    data: txData,
    gas: gasLimit,
    chainId,
    gasPrice
  }

  const signedTx = await web3.eth.accounts.signTransaction(tx, txKey)
  nonce++
  // don't wait for confirmation
  signedTxs.push(signedTx.rawTransaction)
  if (!dontSendTx) {
    web3.eth.sendSignedTransaction(signedTx.rawTransaction, {
      from: sender
    })
  }
}

async function deployContract(
  solcOutput,
  contractFile,
  contractName,
  ctorArgs
) {
  const bytecode =
    solcOutput.contracts[contractFile][contractName].evm.bytecode.object
  const abi = solcOutput.contracts[contractFile][contractName].abi
  const myContract = new web3.eth.Contract(abi)
  const deploy = myContract.deploy({
    data: '0x' + bytecode,
    arguments: ctorArgs
  })
  let address =
    '0x' +
    web3.utils
      .sha3(RLP.encode([sender, nonce]))
      .slice(12)
      .substring(14)
  address = web3.utils.toChecksumAddress(address)

  await sendTx(deploy)

  myContract.options.address = address

  return [address, myContract]
}

function sleep(ms) {
    return new Promise(resolve => {
      setTimeout(resolve, ms)
    })
}

async function waitForEth() {
    while (true) {
      const balance = await web3.eth.getBalance(sender)
      console.log('waiting for balance to account ' + sender)
      if (balance.toString() !== '0') {
        console.log('received ' + balance.toString() + ' wei')
        return
      } else await sleep(10000)
    }
}

const contractPath = path.join(__dirname, '../contracts/')

const sources = {
  'HeaderParser.sol': {content: fs.readFileSync(contractPath + 'HeaderParser.sol', 'utf8')},
  'MerkleProof.sol': {content: fs.readFileSync(contractPath + 'MerkleProof.sol', 'utf8')},
  'Relay.sol': {content: fs.readFileSync(contractPath + 'Relay.sol', 'utf8')}
}

async function relayBlocks(myContract) {
    // store initial schedule, taken from new producers list in block 6713
    let [version, namesToIdxSchedule1, fullKeys] = await relayHelper.readScheduleFromFile("test/producers_6713.json")
    await sendTx(myContract.methods.storeInitialSchedule(version, fullKeys["x"], fullKeys["y"], fullKeys["x"].length));

    // get new pending schedule from block 9313, which we want to change to
    let namesToIdxSchedule2
    [version, namesToIdxSchedule2, fullKeys] = await relayHelper.readScheduleFromFile("test/producers_9313.json")
    completingKeyParts = fullKeys["y"]

    // get headers building on top of block 9313 (from c++) and use them to prove schedule change
    headersData = await relayHelper.getHeadersData("test/headers_9313.json", namesToIdxSchedule1)
    await sendTx(myContract.methods.changeSchedule(
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
    )

    // get headers building on top of block 9626 (from c++) and use them to validate that block
    headersData = await relayHelper.getHeadersData("test/headers_9626.json", namesToIdxSchedule2)
    await sendTx(myContract.methods.relayBlock(
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
    )

    // get headers building on top of block 10800 (from c++) and use them to validate that block
    headersData = await relayHelper.getHeadersData("test/headers_10800.json", namesToIdxSchedule2)
    await sendTx(myContract.methods.relayBlock(
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
    )
}

async function proveAction(myContract) {
    let namesToIdxSchedule2
    [version, namesToIdxSchedule2, fullKeys] = await relayHelper.readScheduleFromFile("test/producers_9313.json")

    // get header with action in block 10776
    actionData = await relayHelper.getActionData("test/header_10776.json", namesToIdxSchedule2)
    const valid = await myContract.methods.verifyAction(
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
        actionData.actionRecieptDigest).call()
    assert(valid)
    console.log("action from block 10776 validity is:", valid)
}

async function main() {
  nonce = await web3.eth.getTransactionCount(sender)
  console.log('nonce', nonce)

  chainId = chainId || (await web3.eth.net.getId())
  console.log('chainId', chainId)

  console.log('starting compilation')

  const input = {
    language: 'Solidity',
    sources: sources,
    settings: {
      optimizer: { enabled: true },
      outputSelection: {
        '*': {
          '*': ['*']
        }
      }
    }
  }

  const output = JSON.parse(solc.compile(JSON.stringify(input)))

  if (output.errors) {
    output.errors.forEach(err => {
      console.log(err.formattedMessage)
    })
  }
  console.log('finished compilation')

  if (!dontSendTx) {
    await waitForEth()
  }

  deploy = false;
  relay = false;
  action = true;

  let deployedAddress;
  let deployedContract;
  if (deploy) {
      [deployedAddress, deployedContract] = await deployContract(output, 'Relay.sol', 'Relay', [])
      console.log('deployedAddress: ' + deployedAddress)
  } else {
      deployedContract = new web3.eth.Contract(output.contracts['Relay.sol']['Relay'].abi)
      deployedContract.options.address = "0x2b08EBa5972e21C5551f3723BA46Ee9514d18485"
  }

  if (relay) await relayBlocks(deployedContract);
  if (action) {
      assert(!relay && !deploy) // blocks were just relayed and their tx was not necesseraly mined
      await proveAction(deployedContract);
  }

  console.log('last nonce is', nonce)
}

main()