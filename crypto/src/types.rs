use circuit_definitions::snark_wrapper::franklin_crypto::bellman::bn256::Bn256;
use circuit_definitions::snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::proof::Proof;
use crate::flonk::FflonkProof;

use circuit_definitions::circuit_definitions::aux_layer::{
    ZkSyncSnarkWrapperCircuit, ZkSyncSnarkWrapperCircuitNoLookupCustomGate,
};

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub enum ProofType {
    Fflonk(FflonkProof<Bn256, ZkSyncSnarkWrapperCircuitNoLookupCustomGate>),
    Plonk(Proof<Bn256, ZkSyncSnarkWrapperCircuit>),
}
