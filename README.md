# EOS-ETH Relay:
Prove EOS actions on the ethereum blockchain using a trustless block relay service.

### Tested POC sequence:
https://github.com/talbaneth/bridge_eth_smart_contracts/blob/master/test/relay.js#L6

### Kovan deployment:
https://kovan.etherscan.io/address/0x2b08EBa5972e21C5551f3723BA46Ee9514d18485

### Verifying an action on testnet:
https://github.com/talbaneth/bridge_eth_smart_contracts/blob/master/scripts/relayDeployer.js#L202

### Smart contract test data:
manufactued using https://github.com/talbaneth/eos/blob/relay_data/programs/relay-data/main.cpp
inputs for this c++ program:
* jungle_first_11k.json (manufactured from scripts/get_headers_from_blockchain.sh)
* action_receipts_digests_10776.json (manufactured by replaying altered node)
* action_to_prove_10776.json (manufactured by replaying altered node)

### Caveats:
* For complete finality of a block more than one round of 2/3+1 producers is needed (https://medium.com/eosio/dpos-bft-pipelined-byzantine-fault-tolerance-8a0634a270ba).
* The header's "confirmed" field is overlooked in the finality algorithm.
* There is not yet a check that 2/3+1 producers are distinct.
* There might be periods were blocks are not allowed to be relayed (perhaps during schedule changes). This might be ok since actions from these times can still be proved. Currently we overlook this.
* There is only support for relaying blocks based on most latest schedule version.
* Gas optimizations.
