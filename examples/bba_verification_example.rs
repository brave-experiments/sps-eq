// This example contains the verification procedure of a BBA token as described
// technical spec of the RFC&C organised by Brave. The part of issuing, or
// updating the token falls out of the scope of this example. For more code on
// BBAs, please refer to https://github.com/brave-experiments/bb-accumulators.
// Still work in progress

use ark_ff::{One, Zero, Field, UniformRand};
use ark_bls12_381::{Fr, Bls12_381, G2Projective as G2, G1Projective as G1, G1Affine, G1Projective};
use ark_ec::{ProjectiveCurve, msm::VariableBaseMSM};
use rand::thread_rng;

use sps_eq::sign::*;
use sps_eq::verify::*;

fn main() {
    let number_attributes = 5usize;
    let number_counters = number_attributes - 2;
    // Secret keys of issuer
    let sk_issuer = vec![Fr::random(&mut thread_rng()); number_attributes];
    let pk_issuer = sk_issuer.iter().map(|x| G1Projective::prime_subgroup_generator());


    // User
    let token_identifier = Fr::random(&mut thread_rng());
    let user_randomness = Fr::random(&mut thread_rng());

    // for this example we consider that the state of the BBA is already
    // updated.
    let state = vec![Fr::random(&mut thread_rng()); number_counters];
    let mut token = VariableBaseMSM::multi_scalar_mul(&[Z], &[Fr::one().into()]);

}