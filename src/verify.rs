//! Module describing the verifying procedures and structs
use ark_ec::{
    PairingEngine,
    ProjectiveCurve
};

use crate::sign::{SigningKey, SpsEqSignature};

/// SPS-EQ public key
pub struct PublicKey<E: PairingEngine> {
    /// Capacity supported by the signing key
    pub signature_capacity: usize,
    /// Public keys
    public_keys: Vec<E::G2Projective>,
}

impl<E: PairingEngine> PublicKey<E> {
    /// Verify a signature with the public key
    fn verify(&self, messages: &Vec<E::G1Projective>, signature: SpsEqSignature<E>) -> Result<(), ()>{
        Ok(())
    }
}

/// Generate public keys from a secret key
impl<E: PairingEngine> From<SigningKey<E>> for PublicKey<E> {
    fn from(signing_key: SigningKey<E>) -> PublicKey<E> {
        let signature_capacity = signing_key.signature_capacity;

        let mut public_keys = vec![E::G2Projective::prime_subgroup_generator(); signature_capacity.clone()];
        for (pkey, skey) in public_keys.iter_mut().zip(signing_key.into_iter()) {
            *pkey *= skey;
        }
        PublicKey {signature_capacity, public_keys}
    }
}




#[cfg(test)]
mod tests {
    use super::*;

    use ark_ff::{One};
    use ark_bls12_381::{Fr, Bls12_381, G2Projective as G2};
    use rand::thread_rng;

    #[test]
    fn test_from_sk() {
        let sk = SigningKey::<Bls12_381>::new(2, &mut thread_rng());
        let pk = PublicKey::from(sk);
    }
}