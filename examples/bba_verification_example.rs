// This example contains the verification procedure of a BBA token as described
// technical spec of the RFC&C organised by Brave. The part of issuing or
// updating the token falls out of the scope of this example. For more code on
// BBAs, please refer to https://github.com/brave-experiments/bb-accumulators.
// Still work in progress

use ark_bls12_381::{Bls12_381, Fr, G1Projective as G1};
use ark_ec::ProjectiveCurve;
use ark_ff::{UniformRand, Zero};
use rand::thread_rng;

use sps_eq::sign::*;
use sps_eq::verify::*;

fn main() {
    let number_attributes = 5usize;
    let number_counters = number_attributes - 2;
    // Key pair of issuer for the state of the token
    let sk_issuer = vec![Fr::rand(&mut thread_rng()); number_attributes];
    let mut pk_issuer = vec![G1::prime_subgroup_generator(); number_attributes];
    for (base, sk) in pk_issuer.iter_mut().zip(sk_issuer.iter()) {
        *base *= *sk;
    }

    // Key pair of issuer for the SPS-EQ signature over the token
    let sk_sps = SigningKey::<Bls12_381>::new(2, &mut thread_rng());
    let pk_sps = PublicKey::from(&sk_sps);

    // User
    let token_identifier = Fr::rand(&mut thread_rng());
    let user_randomness = Fr::rand(&mut thread_rng());

    // policy vector used in the example
    let policy_vector = vec![Fr::rand(&mut thread_rng()); number_counters];

    // for this example we consider that the state of the BBA is already
    // updated.
    let state = vec![Fr::rand(&mut thread_rng()); number_counters];
    let mut token_opening = state.clone();
    token_opening.push(token_identifier.into());
    token_opening.push(user_randomness.into());

    let mut token_commitment = G1::zero();
    for (pk, opening) in pk_issuer.iter().zip(token_opening.iter()) {
        let mut temp = *pk;
        temp *= *opening;
        token_commitment += temp;
    }

    // the token itself is created by the equivalence class of [token_commitment, generator]
    let token = vec![token_commitment, G1::prime_subgroup_generator()];
    // this equivalence class will be signed by the issuer.
    let signature = sk_sps.sign(&token, &mut thread_rng());

    // For sake of simplicity we abstract the zero knowledge proof in this example. The
    // user, to prove ownership of the token will disclose all its openings. In reality
    // the user hides its randomness and the actual state of the counters. It directly
    // computes the zero knowledge proof, and simply proves correctness of the computation
    let mut reward = Fr::zero();
    for (state, policy) in token_opening.iter().zip(policy_vector.iter()) {
        reward += *state * *policy;
    }

    let proof = (token_opening, token, signature, reward);

    // The verification procedure will verify the proof, rather than computing the actual
    // inner product. Similarly, it will verify the proof of opening knowledge, rather than
    // receive the opening itself.
    let mut verif_token = G1::zero();
    for (opening, pk) in proof.0.iter().zip(pk_issuer.iter()) {
        let mut temp = *pk;
        temp *= *opening;
        verif_token += temp;
    }

    let mut verif_reward = Fr::zero();
    for (state, policy) in proof.0.iter().zip(policy_vector.iter()) {
        verif_reward += *state * *policy;
    }

    assert_eq!(verif_reward, proof.3);
    assert_eq!(verif_token, proof.1[0]);
    assert!(pk_sps.verify(&proof.1, &proof.2).is_ok());
}
