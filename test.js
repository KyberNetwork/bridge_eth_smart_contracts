//const Tx = require('ethereumjs-tx')
const ethUtil = require('ethereumjs-util')

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

header = toBuffer("[ 39 1b 6a 47 00 00 00 00 00 ea 30 55 00 00 00 00 00 01 bc f2 f4 48 22 5d 09 96 85 f1 4d a7 68 03 02 89 26 af 04 d2 60 7e af cf 60 9c 26 5c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 74 7d 10 3e 24 c9 6d eb 1b ee bc 13 eb 31 f7 c2 18 81 26 94 6c 86 77 df d1 69 1a f9 f9 c0 3a b1 00 00 00 00 00 00 ]")
headerHash = getHash(header)
bmRoot = toBuffer("[ 00 00 00 01 bc f2 f4 48 22 5d 09 96 85 f1 4d a7 68 03 02 89 26 af 04 d2 60 7e af cf 60 9c 26 5c ]")
pair = Buffer.concat([headerHash, bmRoot])
console.log(pair)
pairHash = getHash(pair)
console.log(pairHash)
/*
const txParams = {
    nonce: '0x00',
    gasPrice: '0x00', 
    gasLimit: '0x00',
    to: '0x0000000000000000000000000000000000000000', 
    value: '0x00', 
    data: encoded,
    // EIP 155 chainId - mainnet: 1, ropsten: 3
    chainId: 3

}


const eTx = new Tx(rawTx);
const msgHash = eTx.hash(false)



module.exports.signTransaction = function(rawTx, transaction, wallet, dispatch){
	if (wallet.profile === 'ledger') {
		const ledgerService = new LedgerService({
			web3Service: (getGlobalContext() || {}).web3Service
		});
		let signed = ledgerService.signTransaction({
			dataToSign: rawTx,
			address: `0x${wallet.publicKey}`
		});
		return signed.raw;
	}

	if (wallet.profile === 'trezor') {
		dispatch(
			actions.signTxWithTrezor({
				dataToSign: rawTx,
				accountIndex: transaction.trezorAccountIndex
			})
		);
		return null;
	}

	const eTx = new Tx(rawTx);
	eTx.sign(wallet);
	return `0x${eTx.serialize().toString('hex')}`;
};
*/