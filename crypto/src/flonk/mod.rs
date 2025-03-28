pub use circuit_definitions::snark_wrapper::franklin_crypto;
pub use circuit_definitions::snark_wrapper::franklin_crypto::bellman;
use franklin_crypto::bellman::plonk::better_better_cs::gates::naive_main_gate::NaiveMainGate;

use bellman::{
    bn256::{Bn256, Fr},
    kate_commitment::{commit_using_monomials, Crs, CrsForMonomialForm},
    pairing::ff::{Field, PrimeField},
    pairing::{CurveAffine, CurveProjective},
    plonk::{
        better_better_cs::{
            cs::{
                ensure_in_map_or_create, get_from_map_unchecked, AssembledPolynomialStorage, AssembledPolynomialStorageForMonomialForms, Assembly, Circuit, Gate, GateInternal, MainGate,
                PlonkConstraintSystemParams, PolyIdentifier, PolynomialInConstraint, PolynomialProxy, Setup, SynthesisMode, SynthesisModeTesting,
            },
            gates::selector_optimized_with_d_next::SelectorOptimizedWidth4MainGateWithDNext,
            utils::BinopAddAssignScaled,
        },
        better_cs::generator::make_non_residues,
        commitments::transcript::Transcript,
        domains::Domain,
        fft::cooley_tukey_ntt::{BitReversedOmegas, CTPrecomputations, OmegasInvBitreversed},
        polynomials::{Coefficients, Polynomial, Values},
    },
    worker::Worker,
    Engine, ScalarEngine, SynthesisError,
};
pub use franklin_crypto::plonk::circuit::custom_rescue_gate::Rescue5CustomGate;

mod definitions;
pub use definitions::*;
pub mod prover;
pub mod utils;
pub use utils::*;
pub mod verifier;
pub use verifier::*;

#[cfg(test)]
mod test;

pub const L1_VERIFIER_DOMAIN_SIZE_LOG: usize = 23;
pub const MAX_COMBINED_DEGREE_FACTOR: usize = 9;
pub(crate) const SANITY_CHECK: bool = true;
