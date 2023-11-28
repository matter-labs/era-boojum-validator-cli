# Crypto

A collection of functions used to interpret and extract various components of the circuits. 

# Features
The main features of this crate at the moment are:
- Ability to serialize/deserialize a SNARK wrapped FRI proof (this is the type of proof used on L1 for boojum)
- Calculate the hash of a given verification key

While the deserializer/verification key hashing is new, the serialization code comes from the [solidity plonk verifier repo](https://github.com/matter-labs/solidity_plonk_verifier/blob/82f96b7156551087f1c9bfe4f0ea68845b6debfc/codegen/src/lib.rs#L81). It is restated here to avoid mismatches in type versions.

# Callouts
There are some fields that get ignored by the serialization process (inputs are separated from the proof itself, first 2 values in the `state_polys_openings_at_dilations` tuple, and first value in `gate_setup_openings_at_z` tuple). These values are thus hardcoded during deserializtion and, with the exception of inputs which come from other L1 state variables, the best guess is that they are either proven inherrently by other parts of the solidity verification and are double checked in some other way by the rust verifier or are hardcoded into the verification as well.
