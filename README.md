# Boojum verify CLI

This is an experimental command line tool to verify the new FRI based proofs.

You can verify that committed proofs are valid by running:

```shell
cargo run
```
## Future plans

Currently it has 3 proofs & verification keys hardcoded, but the plan is to extend this tool to:
* allow fetching the proofs from remote locations
* support all the 13 different circuits (and only the 3 that are currently hardcoded)
* regenerate / compare the verification keys (currently they are submitted in the repo, but we should have the option to regenerate based on current circuits design)
* add more debugging / explanations


