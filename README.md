# Structure Preserving Signatures over Equivalence Classes
Implementation of the Structure Preserving Signatures over Equivalence Classes presented by 
Georg Fuchsbauer, Christian Hanser and Daniel Slamanig, [2014/944](https://eprint.iacr.org/2014/944.pdf).

## Disclaimer
This library is work in progress.

## Usage
```rust
use sps_eq::sign::*;
use sps_eq::verify::*;

use ark_bls12_381::{Bls12_381, G1Projective as G1};
use ark_ff::UniformRand;
use rand::thread_rng;

// Issuer generates key pair, by selecting the number of elements within an equivalence class.
let sk = SigningKey::<Bls12_381>::new(2, &mut thread_rng());
let pk = PublicKey::from(&sk);

// Representation of the equivalence class over which to generate the signature is selected
let message = vec![G1::rand(&mut thread_rng()); 2];
let signature = sk.sign(&message, &mut thread_rng());

assert!(pk.verify(&message, &signature).is_ok());

// Representation of the equivalence class and its signature are randomised
let new_repr = signature.generate_new_repr(&message, &mut thread_rng());
let new_repr_message = new_repr.1;
let new_repr_signature = new_repr.0;

assert!(pk.verify(&new_repr_message, &new_repr_signature).is_ok());
```

