# Boojum verify CLI

This is an experimental command line tool to verify the proofs for zkSync Era updated proof system, Boojum, which uses FRI based proofs.

Know more about the Boojum proof system in our blog post: xxxxxx

# Running the CLI

You can verify that committed proofs are valid by running:

```shell
cargo run -- --batch <batch_number>
```

Full example

```shell
cargo run -- --batch 98718 --network testnet
```

## CLI Options

```shell
--batch - The L1 batch number you want to verify the generated proof
--network - Along with batch number, defines if you want to verify a proof for Era testnet, or mainnet. It defaults to mainnet.
--proof - Optionally you can pass the file path for a local proof to be verified. The CLI will use the batch option if both are passed.
```

# Future plans

Currently this CLI verification keys hardcoded, but the plan is to extend this tool to:
* support all the 13 different circuits (and not only the 3 that are currently hardcoded)
* regenerate / compare the verification keys (currently they are submitted in the repo, but we should have the option to regenerate based on current circuits design)
* compare state roots before and after given batch with current prover and boojum
* add more debugging / explanations