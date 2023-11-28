use circuit_definitions::snark_wrapper::franklin_crypto::bellman::compact_bn256::Fr;
use circuit_definitions::snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::cs::Circuit;
use circuit_definitions::snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::proof::Proof;
use circuit_definitions::snark_wrapper::franklin_crypto::bellman::PrimeFieldRepr;
use circuit_definitions::{
    ethereum_types::U256,
    snark_wrapper::franklin_crypto::bellman::{
        bn256::{self, Bn256},
        CurveAffine, Engine, PrimeField,
    },
};

fn serialize_g1_for_ethereum(point: &<bn256::Bn256 as Engine>::G1Affine) -> (U256, U256) {
    if <<bn256::Bn256 as Engine>::G1Affine as CurveAffine>::is_zero(point) {
        return (U256::zero(), U256::zero());
    }
    let (x, y) = <<bn256::Bn256 as Engine>::G1Affine as CurveAffine>::into_xy_unchecked(*point);
    let _ = <<bn256::Bn256 as Engine>::G1Affine as CurveAffine>::from_xy_checked(x, y).unwrap();

    let mut buffer = [0u8; 32];
    x.into_repr().write_be(&mut buffer[..]).unwrap();
    let x = U256::from_big_endian(&buffer);

    let mut buffer = [0u8; 32];
    y.into_repr().write_be(&mut buffer[..]).unwrap();
    let y = U256::from_big_endian(&buffer);

    (x, y)
}

fn serialize_fe_for_ethereum(field_element: &Fr) -> U256 {
    let mut be_bytes = [0u8; 32];
    field_element
        .into_repr()
        .write_be(&mut be_bytes[..])
        .expect("get new root BE bytes");
    U256::from_big_endian(&be_bytes[..])
}

pub fn serialize_proof<T: Circuit<Bn256>>(proof: &Proof<Bn256, T>) -> (Vec<U256>, Vec<U256>) {
    let mut inputs = vec![];
    for input in proof.inputs.iter() {
        inputs.push(serialize_fe_for_ethereum(&input));
    }
    let mut serialized_proof = vec![];

    for c in proof.state_polys_commitments.iter() {
        let (x, y) = serialize_g1_for_ethereum(&c);
        serialized_proof.push(x);
        serialized_proof.push(y);
    }

    let (x, y) = serialize_g1_for_ethereum(&proof.copy_permutation_grand_product_commitment);
    serialized_proof.push(x);
    serialized_proof.push(y);

    let (x, y) = serialize_g1_for_ethereum(&proof.lookup_s_poly_commitment.unwrap());
    serialized_proof.push(x);
    serialized_proof.push(y);

    let (x, y) = serialize_g1_for_ethereum(&proof.lookup_grand_product_commitment.unwrap());
    serialized_proof.push(x);
    serialized_proof.push(y);

    for c in proof.quotient_poly_parts_commitments.iter() {
        let (x, y) = serialize_g1_for_ethereum(&c);
        serialized_proof.push(x);
        serialized_proof.push(y);
    }

    assert_eq!(proof.state_polys_openings_at_z.len(), 4);
    for c in proof.state_polys_openings_at_z.iter() {
        serialized_proof.push(serialize_fe_for_ethereum(&c));
    }

    assert_eq!(proof.state_polys_openings_at_dilations.len(), 1);
    for (_, _, c) in proof.state_polys_openings_at_dilations.iter() {
        serialized_proof.push(serialize_fe_for_ethereum(&c));
    }

    assert_eq!(proof.gate_setup_openings_at_z.len(), 0);
    for (_, _, c) in proof.gate_setup_openings_at_z.iter() {
        serialized_proof.push(serialize_fe_for_ethereum(&c));
    }

    assert_eq!(proof.gate_selectors_openings_at_z.len(), 1);
    for (_, c) in proof.gate_selectors_openings_at_z.iter() {
        serialized_proof.push(serialize_fe_for_ethereum(&c));
    }

    for c in proof.copy_permutation_polys_openings_at_z.iter() {
        serialized_proof.push(serialize_fe_for_ethereum(&c));
    }

    serialized_proof.push(serialize_fe_for_ethereum(
        &proof.copy_permutation_grand_product_opening_at_z_omega,
    ));
    serialized_proof.push(serialize_fe_for_ethereum(
        &proof.lookup_s_poly_opening_at_z_omega.unwrap(),
    ));
    serialized_proof.push(serialize_fe_for_ethereum(
        &proof.lookup_grand_product_opening_at_z_omega.unwrap(),
    ));
    serialized_proof.push(serialize_fe_for_ethereum(
        &proof.lookup_t_poly_opening_at_z.unwrap(),
    ));
    serialized_proof.push(serialize_fe_for_ethereum(
        &proof.lookup_t_poly_opening_at_z_omega.unwrap(),
    ));
    serialized_proof.push(serialize_fe_for_ethereum(
        &proof.lookup_selector_poly_opening_at_z.unwrap(),
    ));
    serialized_proof.push(serialize_fe_for_ethereum(
        &proof.lookup_table_type_poly_opening_at_z.unwrap(),
    ));
    serialized_proof.push(serialize_fe_for_ethereum(&proof.quotient_poly_opening_at_z));
    serialized_proof.push(serialize_fe_for_ethereum(
        &proof.linearization_poly_opening_at_z,
    ));

    let (x, y) = serialize_g1_for_ethereum(&proof.opening_proof_at_z);
    serialized_proof.push(x);
    serialized_proof.push(y);

    let (x, y) = serialize_g1_for_ethereum(&proof.opening_proof_at_z_omega);
    serialized_proof.push(x);
    serialized_proof.push(y);

    (inputs, serialized_proof)
}
