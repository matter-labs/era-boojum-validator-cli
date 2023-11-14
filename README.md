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

The CLI fetches Boojum proofs for a given batch, and also L1 data from our current prover, so it can compare both and validate they are equivalent.

Learn more about the Boojum proof system in our blog post: [https://zksync.mirror.xyz/HJ2Pj45EJkRdt5Pau-ZXwkV2ctPx8qFL19STM5jdYhc](https://zksync.mirror.xyz/HJ2Pj45EJkRdt5Pau-ZXwkV2ctPx8qFL19STM5jdYhc)

# Proof generation limitation

We are currently generating shadow proofs for only a percentage of batches on testnet and mainnet, so you might run the command and not find proofs for a specific batch. You can find batches that have proofs generated by looking at https://storage.googleapis.com/zksync-era-mainnet-proofs and https://storage.googleapis.com/zksync-era-testnet-proofs.

# Running the CLI

You can verify that committed proofs are valid by running:

```shell
cargo run -- --batch <batch_number> --l1-rpc <your L1 rpc https endpoint>
```

Full example

```shell
cargo run -- --batch 109939 --network mainnet --l1-rpc https://rpc.ankr.com/eth
```

## CLI Options

```shell
--batch - The L1 batch number you want to verify the generated proof
--network - Along with batch number, defines if you want to verify a proof for Era testnet or mainnet. It defaults to mainnet. Accepts "mainnet" or "testnet"
--l1-rpc - The RPC url required if you want the CLI to also reconstruct the input using data from Ethereum for our current prover, and compare with the ones for the new prover (basically confirming that both proofs are equivalent).
--proof - Optionally you can pass the file path for a local proof to be verified. The CLI will use the batch option if both are passed.
--update_verification_key - Specifes if the verification key should be updated from [github](https://github.com/matter-labs/era-contracts/blob/main/tools/data/scheduler_key.json).
```
# Future plans

Currently this CLI verification keys hardcoded, but the plan is to extend this tool to:
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

* Checking if the 'proof' is correct.
* Verifying if it corresponds to the execution of a given circuit.
* Confirming if the inputs are consistent with the data obtained from the blockchain.


The example output looks like this:

```
Fetching and validating the proof itself
Downloading proof for batch 109939 on network mainnet
Proof type: Scheduler
Will be evaluating Boolean constraint gate over specialized columns
Evaluating general purpose gates
Proof is VALID


Fetching data from Ethereum L1 for state roots, bootloader and default Account Abstraction parameters
Fetching batch 109938 information from zkSync Era on network mainnet
Fetching batch 109939 information from zkSync Era on network mainnet
Will be verifying a proof for state transition from root 0x82a329b7d25ebed88bacb07acf2f2aa802d7ef455388056b5aaa2102397ba0b7 to root 0x3bda3d0b1224289b815b8762840b30ada8c78f4037e5d4deb77c528164a55dd7
Will be using bootloader code hash 0x010007794e73f682ad6d27e86b6f71bbee875fc26f5708d1713e7cfd476098d3 and default AA code hash 0x0100067d861e2f5717a12c3e869cfb657793b86bbb0caa05cc1421f16c5217bc


Fetching auxilary block data
Downloading aux data for batch 109939 on network mainnet


Comparing public input from Ethereum with input for boojum
Recomputed public input from current prover using L1 data is [0x00ef1fcedf42b25f, 0x0013303f11868b9a, 0x00f21282095d269b, 0x00237a23e94d0c66]
Boojum proof's public input is [0x00ef1fcedf42b25f, 0x0013303f11868b9a, 0x00f21282095d269b, 0x00237a23e94d0c66]
Boojum's proof is VALID
```


First, the CLI fetches the 'proof' from our storage, which is on Google Cloud Storage (GCS) (in the future, it will be directly on Ethereum). This proof is a `Proof` struct from the Boojum repository, which includes the configuration, public inputs, and additional data required for Fast Reed-Solomon Interactive Oracle (FRI), like oracle caps, values, and queries.



Next, we check that this proof is valid and matches a specific verification key, in this case, it's the `verification_scheduler_key.json`. This key is like a fingerprint of the code of the circuit.


This process ensures that we have a valid 'proof' of our code's execution for given inputs. Now we need to verify that these inputs match the network hashes on Ethereum.


Next, we collect data from L1 which includes:

* The hash of the previous block
* The hash of the current block
* The hash of the bootloader code
* The hash of the default account code
* And other metadata like queue hashes

For now, we also get some auxiliary data (BlockAuxilaryOutput) from GCS, but in the future, when the system is fully deployed, this data will also be fetched from L1.

Finally, we calculate a hash from all these inputs and compare it with the public input of the 'proof'. If they match, it means the computation has been successfully verified.

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