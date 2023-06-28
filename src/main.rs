use colored::Colorize;
use std::fs::File;
use std::io::Read;

use boojum::{
    cs::implementations::{
        pow::NoPow, transcript::GoldilocksPoisedon2Transcript, verifier::VerificationKey,
    },
    field::goldilocks::{GoldilocksExt2, GoldilocksField},
};
use circuit_definitions::{
    circuit_definitions::{
        base_layer::{BaseProofsTreeHasher, ZkSyncBaseLayerProof, ZkSyncBaseLayerStorage},
        recursion_layer::{
            node_layer::ConcreteNodeLayerCircuitBuilder, ZkSyncRecursionLayerProof,
            ZkSyncRecursionLayerStorage,
        },
        verifier_builder::StorageApplicationVerifierBuilder,
    },
    ZkSyncDefaultRoundFunction,
};

fn main() {
    // '10' is the id of the 'Storage Application' circuit (which is the one for which we have the basic_proof.bin)
    let key_10: ZkSyncBaseLayerStorage<VerificationKey<GoldilocksField, BaseProofsTreeHasher>> =
        serde_json::from_slice(include_bytes!("keys/verification_basic_10_key.json")).unwrap();

    // '13' is the id of the Leaf for Events sorter.
    let leaf_13: ZkSyncRecursionLayerStorage<
        VerificationKey<GoldilocksField, BaseProofsTreeHasher>,
    > = serde_json::from_slice(include_bytes!("keys/verification_leaf_13_key.json")).unwrap();

    let node: ZkSyncRecursionLayerStorage<VerificationKey<GoldilocksField, BaseProofsTreeHasher>> =
        serde_json::from_slice(include_bytes!("keys/verification_node_key.json")).unwrap();

    {
        let mut file = File::open("example_proofs/basic_proof.bin").unwrap();
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).unwrap();

        let proof: ZkSyncBaseLayerProof = bincode::deserialize(buffer.as_slice()).unwrap();
        println!("Proof type: {}", proof.short_description().bold());

        let verifier_builder = StorageApplicationVerifierBuilder::<
            GoldilocksField,
            ZkSyncDefaultRoundFunction,
        >::dyn_verifier_builder::<GoldilocksExt2>();
        let verifier = verifier_builder.create_verifier();

        let result = verifier.verify::<BaseProofsTreeHasher, GoldilocksPoisedon2Transcript, NoPow>(
            (),
            &key_10.into_inner(),
            &proof.into_inner(),
        );

        println!(
            "Proof result: {}",
            if result { "PASS".green() } else { "FAIL".red() }
        );
        assert!(result, "Proof failed");
    }
    {
        let mut file = File::open("example_proofs/leaf_proof.bin").unwrap();
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).unwrap();

        let proof: ZkSyncRecursionLayerProof = bincode::deserialize(buffer.as_slice()).unwrap();
        println!("Proof type: {}", proof.short_description().bold());

        // or recursive one??
        let verifier_builder =
            ConcreteNodeLayerCircuitBuilder::dyn_verifier_builder::<GoldilocksExt2>();

        let verifier = verifier_builder.create_verifier();
        let result = verifier.verify::<BaseProofsTreeHasher, GoldilocksPoisedon2Transcript, NoPow>(
            (),
            &leaf_13.into_inner(),
            &proof.into_inner(),
        );

        println!(
            "Proof result: {}",
            if result { "PASS".green() } else { "FAIL".red() }
        );
        assert!(result, "Proof failed");
    }

    {
        let mut file = File::open("example_proofs/node_proof.bin").unwrap();
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).unwrap();

        let proof: ZkSyncRecursionLayerProof = bincode::deserialize(buffer.as_slice()).unwrap();
        println!("Proof type: {}", proof.short_description().bold());
        // or recursive one??
        let verifier_builder =
            ConcreteNodeLayerCircuitBuilder::dyn_verifier_builder::<GoldilocksExt2>();

        let verifier = verifier_builder.create_verifier();
        let result = verifier.verify::<BaseProofsTreeHasher, GoldilocksPoisedon2Transcript, NoPow>(
            (),
            &node.into_inner(),
            &proof.into_inner(),
        );

        println!(
            "Proof result: {}",
            if result { "PASS".green() } else { "FAIL".red() }
        );
        assert!(result, "Proof failed");
    }
}
