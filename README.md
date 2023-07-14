# zkSync Era: Boojum verifier CLI

[![Logo](eraLogo.png)](https://zksync.io/)
# 
This is an experimental command line tool to verify the proofs for zkSync Era's updated proof system, Boojum.

The CLI fetches Boojum proofs for a given batch, and also L1 data from our current prover, so it can compare both and validate they are equivalent.

Learn more about the Boojum proof system in our blog post: [https://blog.matter-labs.io/zksyncera-boojum-fb9b8bd31144](https://blog.matter-labs.io/zksyncera-boojum-fb9b8bd31144)

# Limitation

This repository temporarily relies on some dependencies that are not yet public. We will open these soon, but meanwhile you can run this CLI with the binary file available in the /bin folder.

# Running the CLI

You can verify that committed proofs are valid by running:

```shell
./bin/era-boojum-validator-cli --batch <batch_number> --l1_rpc <your L1 rpc https endpoint>
```

Full example

```shell
./bin/era-boojum-validator-cli --batch 98718 --network testnet --l1_rpc https://mycoolrpcproviderforgoerli.com/<my personal key>
```

## CLI Options

```shell
--batch - The L1 batch number you want to verify the generated proof
--network - Along with batch number, defines if you want to verify a proof for Era testnet or mainnet. It defaults to mainnet. Accepts "mainnet" or "testnet"
--l1_rpc - The RPC url required if you want the CLI to also reconstruct the input using data from Ethereum for our current prover, and compare with the ones for the new prover (basically confirming that both proofs are equivalent).
--proof - Optionally you can pass the file path for a local proof to be verified. The CLI will use the batch option if both are passed.
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

