use rand::thread_rng;

#[macro_use]
extern crate criterion;

use criterion::Criterion;

use sps_eq::sign::*;
use sps_eq::verify::*;

use ark_bls12_381::{Bls12_381, G1Projective as G1};

mod proof_of_credential_benches {
    use super::*;
    use ark_ff::UniformRand;

    fn signature(c: &mut Criterion) {
        let sk = SigningKey::<Bls12_381>::new(2, &mut thread_rng());

        let message = vec![G1::rand(&mut thread_rng()); 2];

        c.bench_function("Signature", |b| {
            b.iter(|| sk.clone().sign(&message, &mut thread_rng()));
        });
    }

    fn verification(c: &mut Criterion) {
        let sk = SigningKey::<Bls12_381>::new(2, &mut thread_rng());
        let pk = PublicKey::from(sk.clone());

        let message = vec![G1::rand(&mut thread_rng()); 2];
        let signature = sk.sign(&message, &mut thread_rng());

        c.bench_function("Signature", |b| {
            b.iter(|| pk.verify(&message, &signature));
        });
    }

    criterion_group! {
        name = signature_benches;
        config = Criterion::default();
        targets =
            signature,
            verification,
    }
}

criterion_main!(
    proof_of_credential_benches::signature_benches,
);