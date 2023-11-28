use circuit_definitions::snark_wrapper::franklin_crypto::bellman::compact_bn256::{Fq, Fr};
use circuit_definitions::snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::cs::Circuit;
use circuit_definitions::snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::proof::Proof;
use circuit_definitions::snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey;
use circuit_definitions::snark_wrapper::franklin_crypto::bellman::PrimeFieldRepr;
use circuit_definitions::{
    ethereum_types::U256,
    snark_wrapper::franklin_crypto::bellman::{
        bn256::{self, Bn256},
        CurveAffine, Engine, PrimeField,
    },
};
use primitive_types::H256;

pub mod serialize;

/// Transform an element represented as a U256 into a prime field element.
fn hex_to_scalar<F: PrimeField>(el: &U256) -> F {
    F::from_str(&el.to_string()).unwrap()
}

/// Transform a point represented as a pair of U256 into its affine representation.
fn deserialize_g1(point: (U256, U256)) -> <bn256::Bn256 as Engine>::G1Affine {
    if point == (U256::zero(), U256::zero()) {
        return <<bn256::Bn256 as Engine>::G1Affine as CurveAffine>::zero();
    }

    let x_scalar = hex_to_scalar(&point.0);
    let y_scalar = hex_to_scalar(&point.1);

    <<bn256::Bn256 as Engine>::G1Affine as CurveAffine>::from_xy_unchecked(x_scalar, y_scalar)
}

/// Transform a field element into the field representation.
fn deserialize_fe(felt: U256) -> Fr {
    Fr::from_str(&felt.to_string()).unwrap()
}

/// Works as the inverse of serialize proof used to prepare a proof for submission to L1 (see serialize.rs or README). We process the proof in reverse setting all fields we can.
/// Note that some of the fields are hardcoded as they are lost in serialization.
pub fn deserialize_proof<T: Circuit<Bn256>>(mut proof: Vec<U256>) -> Proof<Bn256, T> {
    let y = proof.pop().unwrap();
    let x = proof.pop().unwrap();
    let opening_proof_at_z_omega = deserialize_g1((x, y));

    let y = proof.pop().unwrap();
    let x = proof.pop().unwrap();
    let opening_proof_at_z = deserialize_g1((x, y));

    let linearization_poly_opening_at_z = deserialize_fe(proof.pop().unwrap());
    let quotient_poly_opening_at_z = deserialize_fe(proof.pop().unwrap());
    let lookup_table_type_poly_opening_at_z = deserialize_fe(proof.pop().unwrap());
    let lookup_selector_poly_opening_at_z = deserialize_fe(proof.pop().unwrap());
    let lookup_t_poly_opening_at_z_omega = deserialize_fe(proof.pop().unwrap());
    let lookup_t_poly_opening_at_z = deserialize_fe(proof.pop().unwrap());
    let lookup_grand_product_opening_at_z_omega = deserialize_fe(proof.pop().unwrap());
    let lookup_s_poly_opening_at_z_omega = deserialize_fe(proof.pop().unwrap());
    let copy_permutation_grand_product_opening_at_z_omega = deserialize_fe(proof.pop().unwrap());

    let mut copy_permutation_polys_openings_at_z = vec![];
    for _ in 0..3 {
        copy_permutation_polys_openings_at_z.push(deserialize_fe(proof.pop().unwrap()));
    }
    copy_permutation_polys_openings_at_z.reverse();

    let gate_selectors_openings_at_z = vec![(0_usize, deserialize_fe(proof.pop().unwrap()))];

    // Hardcoding 1, 3 as the first to values in the dilations given thats what the other proofs show
    let state_polys_openings_at_dilations = vec![deserialize_fe(proof.pop().unwrap())];
    let state_polys_openings_at_dilations = state_polys_openings_at_dilations
        .iter()
        .map(|e| (1_usize, 3_usize, *e))
        .collect::<Vec<(usize, usize, Fr)>>();

    let mut state_polys_openings_at_z = vec![];
    for _ in 0..4 {
        state_polys_openings_at_z.push(deserialize_fe(proof.pop().unwrap()));
    }
    state_polys_openings_at_z.reverse();

    let mut quotient_poly_parts_commitments = vec![];
    for _ in 0..4 {
        let y = proof.pop().unwrap();
        let x = proof.pop().unwrap();
        quotient_poly_parts_commitments.push(deserialize_g1((x, y)));
    }
    quotient_poly_parts_commitments.reverse();

    let y = proof.pop().unwrap();
    let x = proof.pop().unwrap();
    let lookup_grand_product_commitment = deserialize_g1((x, y));

    let y = proof.pop().unwrap();
    let x = proof.pop().unwrap();
    let lookup_s_poly_commitment = deserialize_g1((x, y));

    let y = proof.pop().unwrap();
    let x = proof.pop().unwrap();
    let copy_permutation_grand_product_commitment = deserialize_g1((x, y));

    let mut state_polys_commitments = vec![];
    for _ in 0..4 {
        let y = proof.pop().unwrap();
        let x = proof.pop().unwrap();
        state_polys_commitments.push(deserialize_g1((x, y)));
    }
    state_polys_commitments.reverse();

    let mut proof: Proof<Bn256, T> = Proof::empty();

    proof.state_polys_commitments = state_polys_commitments;
    proof.copy_permutation_grand_product_commitment = copy_permutation_grand_product_commitment;
    proof.lookup_s_poly_commitment = Some(lookup_s_poly_commitment);
    proof.lookup_grand_product_commitment = Some(lookup_grand_product_commitment);
    proof.quotient_poly_parts_commitments = quotient_poly_parts_commitments;
    proof.state_polys_openings_at_z = state_polys_openings_at_z;
    proof.state_polys_openings_at_dilations = state_polys_openings_at_dilations;
    proof.gate_selectors_openings_at_z = gate_selectors_openings_at_z;
    proof.copy_permutation_polys_openings_at_z = copy_permutation_polys_openings_at_z;
    proof.copy_permutation_grand_product_opening_at_z_omega =
        copy_permutation_grand_product_opening_at_z_omega;
    proof.lookup_s_poly_opening_at_z_omega = Some(lookup_s_poly_opening_at_z_omega);
    proof.lookup_grand_product_opening_at_z_omega = Some(lookup_grand_product_opening_at_z_omega);
    proof.lookup_t_poly_opening_at_z = Some(lookup_t_poly_opening_at_z);
    proof.lookup_t_poly_opening_at_z_omega = Some(lookup_t_poly_opening_at_z_omega);
    proof.lookup_selector_poly_opening_at_z = Some(lookup_selector_poly_opening_at_z);
    proof.lookup_table_type_poly_opening_at_z = Some(lookup_table_type_poly_opening_at_z);
    proof.quotient_poly_opening_at_z = quotient_poly_opening_at_z;
    proof.linearization_poly_opening_at_z = linearization_poly_opening_at_z;
    proof.opening_proof_at_z = opening_proof_at_z;
    proof.opening_proof_at_z_omega = opening_proof_at_z_omega;

    proof
}

/// Calculates the hash of a verification key. This function corresponds 1:1 with the following solidity code: https://github.com/matter-labs/era-contracts/blob/3e2bee96e412bac7c0a58c4b919837b59e9af36e/ethereum/contracts/zksync/Verifier.sol#L260
pub fn calculate_verification_key_hash<E: Engine, C: Circuit<E>>(
    verification_key: VerificationKey<E, C>,
) -> H256 {
    use sha3::{Digest, Keccak256};

    let mut res = vec![];

    // gate setup commitments
    assert_eq!(8, verification_key.gate_setup_commitments.len());

    for gate_setup in verification_key.gate_setup_commitments {
        let (x, y) = gate_setup.as_xy();
        x.into_repr().write_be(&mut res).unwrap();
        y.into_repr().write_be(&mut res).unwrap();
    }

    // gate selectors commitments
    assert_eq!(2, verification_key.gate_selectors_commitments.len());

    for gate_selector in verification_key.gate_selectors_commitments {
        let (x, y) = gate_selector.as_xy();
        x.into_repr().write_be(&mut res).unwrap();
        y.into_repr().write_be(&mut res).unwrap();
    }

    // permutation commitments
    assert_eq!(4, verification_key.permutation_commitments.len());

    for permutation in verification_key.permutation_commitments {
        let (x, y) = permutation.as_xy();
        x.into_repr().write_be(&mut res).unwrap();
        y.into_repr().write_be(&mut res).unwrap();
    }

    // lookup selector commitment
    let lookup_selector = verification_key.lookup_selector_commitment.unwrap();
    let (x, y) = lookup_selector.as_xy();
    x.into_repr().write_be(&mut res).unwrap();
    y.into_repr().write_be(&mut res).unwrap();

    // lookup tables commitments
    assert_eq!(4, verification_key.lookup_tables_commitments.len());

    for table_commit in verification_key.lookup_tables_commitments {
        let (x, y) = table_commit.as_xy();
        x.into_repr().write_be(&mut res).unwrap();
        y.into_repr().write_be(&mut res).unwrap();
    }

    // table type commitment
    let lookup_table = verification_key.lookup_table_type_commitment.unwrap();
    let (x, y) = lookup_table.as_xy();
    x.into_repr().write_be(&mut res).unwrap();
    y.into_repr().write_be(&mut res).unwrap();

    // flag for using recursive part
    Fq::default().into_repr().write_be(&mut res).unwrap();

    let mut hasher = Keccak256::new();
    hasher.update(&res);
    let computed_vk_hash = hasher.finalize();

    H256::from_slice(&computed_vk_hash)
}

#[cfg(test)]
mod test {
    use std::{fs, str::FromStr};
    use circuit_definitions::snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey;
    use circuit_definitions::snark_wrapper::franklin_crypto::bellman::pairing::bn256::Bn256;
    use circuit_definitions::circuit_definitions::aux_layer::ZkSyncSnarkWrapperCircuit;
    use primitive_types::H256;
    use super::calculate_verification_key_hash;

    #[test]
    fn test_verification_key_hash() {
        let vk_inner: VerificationKey<Bn256, ZkSyncSnarkWrapperCircuit> =
            serde_json::from_str(&fs::read_to_string("keys/scheduler_key.json").unwrap())
                .unwrap();

        let verification_key_hash = calculate_verification_key_hash(vk_inner);

        let exprected_vk_hash = H256::from_str("0x750d8e21be7555a6841472a5cacd24c75a7ceb34261aea61e72bb7423a7d30fc").unwrap();

        assert_eq!(verification_key_hash, exprected_vk_hash)
    }
}
