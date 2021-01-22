use sps_eq::sign::*;
use sps_eq::verify::*;

use ark_bls12_381::{Bls12_381, G1Projective as G1};
use ark_ff::UniformRand;
use rand::thread_rng;

#[test]
fn test_new_repr() {
    let sk = SigningKey::<Bls12_381>::new(2, &mut thread_rng());
    let pk = PublicKey::from(&sk);

    let message = vec![G1::rand(&mut thread_rng()); 2];
    let signature = sk.sign(&message, &mut thread_rng());

    assert!(pk.verify(&message, &signature).is_ok());

    let new_repr = signature.generate_new_repr(&message, &mut thread_rng());
    let new_repr_message = new_repr.1;
    let new_repr_signature = new_repr.0;

    assert!(pk.verify(&new_repr_message, &new_repr_signature).is_ok());
}
