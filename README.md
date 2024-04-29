# zkSync Era: Boojum verifier CLI

To run local test:


```shell
cargo test test_local_proof --  --nocapture
```

It tries the local proof with all the fixes, on 24 bit. 
Both proof and the vkey are in example_proofs/snark_wrapper

It also generates the test, that can be inserted in unittests for Verifier.sol.






[![Logo](eraLogo.png)](https://zksync.io/)
# 
This is an experimental command line tool to verify the proofs for zkSync Era's updated proof system, Boojum [https://github.com/matter-labs/era-boojum](https://github.com/matter-labs/era-boojum).

The CLI fetches Boojum proofs for a given batch, public inputs, and aux input all from L1 and verifies the proof off chain. For testnet and sepolia chains, there may not be proofs submitted on chian for batches.

Learn more about the Boojum proof system in our blog post: [https://zksync.mirror.xyz/HJ2Pj45EJkRdt5Pau-ZXwkV2ctPx8qFL19STM5jdYhc](https://zksync.mirror.xyz/HJ2Pj45EJkRdt5Pau-ZXwkV2ctPx8qFL19STM5jdYhc)

# Proof generation limitation

We are currently generating boojum proofs for all batches on sepolia, so at the moment this is the only chain supported. For mainnet and testnet, these will be updated once supported.

# Running the CLI

You can verify that committed proofs are valid by running:

```shell
cargo run -- --batch <batch_number> --network <network> --l1-rpc <your L1 rpc https endpoint>
```

Full example

```shell
cargo run -- --batch 109939 --network mainnet --l1-rpc https://rpc.ankr.com/eth
```

If you need to update the verification key to the latest, run with the corresponding flag.
```shell
cargo run -- --batch 109939 --network mainnet --l1-rpc https://rpc.ankr.com/eth --update-verification-key true
```

## CLI Options

```shell
--batch - The L1 batch number you want to verify the generated proof
--network - Along with batch number, defines if you want to verify a proof for Era testnet or mainnet. It defaults to mainnet. Accepts "mainnet" or "testnet"
--l1-rpc - The RPC url required to pull data from L1.
--json - Flag to specify if the output should be in json. Note that all the usual std out prints are silenced.
```

## Error Codes

Below is a list of the error codes that can be seen in the json output of the cli tool:
- 0 => `Success`
- 1 => `InvalidNetwork`
- 2 => `NoRPCProvided`
- 3 => `FailedToDeconstruct`
- 4 => `FailedToGetDataFromL1`
- 5 => `FailedToFindCommitTxn`
- 6 => `InvalidLog`
- 7 => `FailedToGetTransactionReceipt`
- 8 => `FailedToGetBatchCommitment`
- 9 => `ProofDoesntExist`
- 10 => `FailedToFindProveTxn`
- 11 => `InvalidTupleTypes`
- 12 => `FailedToCallRPC`
- 13 => `VerificationKeyHashMismatch`
- 14 => `FailedToDownloadVerificationKey`
- 15 => `FailedToWriteVerificationKeyToDisk`
- 16 => `ProofVerificationFailed`
- 17 => `FailedToLoadVerificationKey`,
- 18 => `BadCalldataLength`,
- 19 => `FailedToCallRPCJsonError`,
- 20 => `FailedToCallRPCResponseError`,

# Future plans

Currently this CLI verification keys are hardcoded or pulled from github, but the plan is to extend this tool to:
* support all the 13 different circuits (and not only the 3 that are currently hardcoded)
* add more debugging / explanations

## License

The Era Boojum Cli is distributed under the terms of either

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

## Official Links

- [Website](https://zksync.io/)
- [GitHub](https://github.com/matter-labs)
- [Twitter](https://twitter.com/zksync)
- [Twitter for Devs](https://twitter.com/zkSyncDevs)
- [Discord](https://join.zksync.dev)



## More details
The proving process consists of three steps:

* Pull data from L1 including: proof, public input, aux input, and verification key hash
* Validates the verification key being used is in line with the one on L1.
* Checking if the 'proof' is correct.

The example output looks like this:

```
Fetching and validating the proof itself
Fetching batch 26 information from zkSync Era on network sepolia
Fetching batch 27 information from zkSync Era on network sepolia
Will be verifying a proof for state transition from root 0xe61dfa88ffe6c44dd9469b81516d912b13f6f057ea132673813512e243b09d60 to root 0xda85816088b8b9efc62faff0f0e9f47f684f527d52a3624fc6427dbff2ce9101
Will be using bootloader code hash 0x010009657432df24acfe7950b2d1a0707520ca6b7acb699e58c0f378c0ed7a11 and default AA code hash 0x01000651c5ae96f2aab07d720439e42491bb44c6384015e3a08e32620a4d582d


Fetching batch 27 information from zkSync Era on network sepolia
Verifying SNARK wrapped FRI proof.
=== Aux inputs:
  L1 msg linear hash:                  0x7c89cb8c193258689329f3c909b7b17f0b2374c8a7f6d42f075af49f41f69ac1
  Rollup state diff for compression:   0x071407206e21e82a93e534d50189296825811b98c49d3d11811d24c5e4312959
  Bootloader heap initial content:     0x972c46d32b5ef1159ff7977162f9885db659f3e5454bc329bc2a9abac2d4bcde
  Events queue state:                  0xa7b918ffb6690c6b3929a7c40dcafa5c46d5e9fc0c7f11ab5707ab1f00eeb9be
=== Loading verification key.
=== Verification Key Hash Check:
  Verification Key Hash from L1:       0x750d8e21be7555a6841472a5cacd24c75a7ceb34261aea61e72bb7423a7d30fc
  Computed Verification Key Hash:      0x750d8e21be7555a6841472a5cacd24c75a7ceb34261aea61e72bb7423a7d30fc
Verifying the proof
Proof is VALID
Public input is: Fr(0x0000000052f5d9be73c67d37ecb295eb70924f700ed17d40ca0a48e7c89c5d83)
```


First, the CLI fetches the 'proof' from the calldata of `proveBatches` on L1. This proof is a `Proof` struct from the Boojum repository, which includes the configuration, public inputs, and additional data required for Fast Reed-Solomon Interactive Oracle (FRI), like oracle caps, values, and queries.



Other data we collect data from L1 includes:
* The hash of the previous block
* The hash of the current block
* The hash of the bootloader code
* The hash of the default account code
* BlockAuxilaryOutput:
    * The hash of the system logs
    * The hash of the state diffs
    * The hash of bootloader initial contents
    * The hash of the event queue
* And other metadata like queue hashes



Finally, we check that this proof is valid and matches a specific verification key, in this case, it's the `scheduler_key.json`. This key is like a fingerprint of the code of the circuit.

# Advanced options

## Snark proof verification

Currently we are planning to wrap the final FRI proof, into a SNARK (to lower the size of the proof and cost of verification in L1).

To verify that the wrapper is correct, you can use the ``verify-snark-wrapper`` command. 

WARNING: This verifier is still WIP, so command arguments will change.

```shell
cargo run  -- verify-snark-wrapper example_proofs/snark_wrapper/l1_batch_proof_1.bin example_proofs/snark_wrapper/snark_verification_scheduler_key.json
```

You can also generate the solidity test for Verifier.sol, by running:

```shell
cargo run -- generate-solidity-test example_proofs/snark_wrapper/l1_batch_proof_1.bin
```

There is also a larger test inside, that computes the public inputs hash:

```shell
cargo test test_local_proof --  --nocapture
```