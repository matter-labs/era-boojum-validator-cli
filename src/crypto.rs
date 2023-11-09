use circuit_definitions::franklin_crypto::bellman::PrimeFieldRepr;
use circuit_definitions::franklin_crypto::bellman::compact_bn256::Fr;
use circuit_definitions::franklin_crypto::bellman::plonk::better_better_cs::proof::Proof;
use circuit_definitions::{
    circuit_definitions::aux_layer::ZkSyncSnarkWrapperCircuit,
    ethereum_types::U256,
    franklin_crypto::bellman::{
        bn256::{self, Bn256},
        CurveAffine, Engine, PrimeField,
    },
};

fn hex_to_scalar<F: PrimeField>(el: &U256) -> F {
    F::from_str(&el.to_string()).unwrap()
}

// fn _hex_to_g1_affine<E: Engine>(g1: [String; 2]) -> E::G1Affine {
//     if g1 == ["0x", "0x"] {
//         return <E::G1Affine as CurveAffine>::zero();
//     }

//     let x = hex_to_scalar(&g1[0]);
//     let y = hex_to_scalar(&g1[1]);

//     <E::G1Affine as CurveAffine>::from_xy_unchecked(x, y)
// }

// fn _hex_to_g2_affine(g2: [String; 4]) -> <bn256::Bn256 as Engine>::G2Affine {
//     if g2 == ["0x", "0x", "0x", "0x"] {
//         return <<bn256::Bn256 as Engine>::G2Affine as CurveAffine>::zero();
//     }

//     let x_c0 = hex_to_scalar(&g2[0]);
//     let x_c1 = hex_to_scalar(&g2[1]);
//     let y_c0 = hex_to_scalar(&g2[2]);
//     let y_c1 = hex_to_scalar(&g2[3]);

//     let x = Fq2 { c0: x_c0, c1: x_c1 };

//     let y = Fq2 { c0: y_c0, c1: y_c1 };

//     <bn256::Bn256 as Engine>::G2Affine::from_xy_unchecked(x, y)
// }

fn deserialize_g1(point: (U256, U256)) -> <bn256::Bn256 as Engine>::G1Affine {
    if point == (U256::zero(), U256::zero()) {
        return <<bn256::Bn256 as Engine>::G1Affine as CurveAffine>::zero();
    }

    let x_scalar = hex_to_scalar(&point.0);
    let y_scalar = hex_to_scalar(&point.1);

    <<bn256::Bn256 as Engine>::G1Affine as CurveAffine>::from_xy_unchecked(x_scalar, y_scalar)
}

fn deserialize_fe(felt: U256) -> Fr {
    Fr::from_str(&felt.to_string()).unwrap()
}

pub fn deserialize_proof(mut proof: Vec<U256>) -> Proof<Bn256, ZkSyncSnarkWrapperCircuit> {
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

    let gate_selectors_openings_at_z = vec![(0usize, deserialize_fe(proof.pop().unwrap()))];

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

    let mut proof: Proof<Bn256, ZkSyncSnarkWrapperCircuit> = Proof::empty();

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

fn serialize_g1_for_ethereum(
    point: &<bn256::Bn256 as Engine>::G1Affine
) -> (U256, U256) {
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

pub fn serialize_proof(proof: &Proof<Bn256, ZkSyncSnarkWrapperCircuit>) -> (Vec<U256>, Vec<U256>) {
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

    serialized_proof.push(serialize_fe_for_ethereum(&proof.copy_permutation_grand_product_opening_at_z_omega));
    serialized_proof.push(serialize_fe_for_ethereum(&proof.lookup_s_poly_opening_at_z_omega.unwrap()));
    serialized_proof.push(serialize_fe_for_ethereum(&proof.lookup_grand_product_opening_at_z_omega.unwrap()));
    serialized_proof.push(serialize_fe_for_ethereum(&proof.lookup_t_poly_opening_at_z.unwrap()));
    serialized_proof.push(serialize_fe_for_ethereum(&proof.lookup_t_poly_opening_at_z_omega.unwrap()));
    serialized_proof.push(serialize_fe_for_ethereum(&proof.lookup_selector_poly_opening_at_z.unwrap()));
    serialized_proof.push(serialize_fe_for_ethereum(&proof.lookup_table_type_poly_opening_at_z.unwrap()));
    serialized_proof.push(serialize_fe_for_ethereum(&proof.quotient_poly_opening_at_z));
    serialized_proof.push(serialize_fe_for_ethereum(&proof.linearization_poly_opening_at_z));


    let (x, y) = serialize_g1_for_ethereum(&proof.opening_proof_at_z);
    serialized_proof.push(x);
    serialized_proof.push(y);

    let (x, y) = serialize_g1_for_ethereum(&proof.opening_proof_at_z_omega);
    serialized_proof.push(x);
    serialized_proof.push(y);

    dbg!(&serialized_proof.len());

    (inputs, serialized_proof)
}

#[cfg(test)]
mod tests {

    #[test]
    fn it_works() {
        assert!(true);
    }
}
