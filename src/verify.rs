//! Module describing the verifying procedures and structs
use ark_ec::{PairingEngine, ProjectiveCurve};

use crate::errors::*;
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
    pub fn verify(
        &self,
        messages: &Vec<E::G1Projective>,
        signature: &SpsEqSignature<E>,
    ) -> Result<(), SpsEqSignatureError> {
        if self.signature_capacity != messages.len() {
            return Err(SpsEqSignatureError::UnmatchedCapacity);
        }

        let mut check_1 = E::pairing(messages[0], self.public_keys[0]);
        for (message, key) in messages.iter().zip(self.public_keys) {
            check_1 *= &E::pairing(messages[i], self.public_keys[i]);
        }

        // todo: change the error handling
        let expected_check_1 = E::pairing(signature.Z, signature.Yp);

        if check_1 != expected_check_1 {
            return Err(SpsEqSignatureError::InvalidSignature);
        }

        let check_2 = E::pairing(signature.Y, E::G2Projective::prime_subgroup_generator());
        let expected_check_2 =
            E::pairing(E::G1Projective::prime_subgroup_generator(), signature.Yp);
        if check_2 != expected_check_2 {
            return Err(SpsEqSignatureError::InvalidSignature);
        }

        Ok(())
    }
}

/// Generate public keys from a secret key
// todo: maybe we want to do from a reference?
impl<'a, E: PairingEngine> From<&SigningKey<E>> for PublicKey<E> {
    fn from(signing_key: &SigningKey<E>) -> PublicKey<E> {
        let signature_capacity = signing_key.signature_capacity;

        let mut public_keys =
            vec![E::G2Projective::prime_subgroup_generator(); signature_capacity];
        for (pkey, skey) in public_keys.iter_mut().zip(signing_key) {
            *pkey *= skey;
        }
        PublicKey {
            signature_capacity,
            public_keys,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ark_bls12_381::{Bls12_381, G1Projective as G1};
    use ark_ff::UniformRand;
    use rand::thread_rng;

    #[test]
    fn test_signature() {
        let sk = SigningKey::<Bls12_381>::new(2, &mut thread_rng());
        let pk = PublicKey::from(&sk);

        let message = vec![G1::rand(&mut thread_rng()); 2];
        let signature = sk.sign(&message, &mut thread_rng());

        // signature should be valid
        assert!(pk.verify(&message, &signature).is_ok());

        let different_message = vec![G1::rand(&mut thread_rng()); 2];
        // signature over a random message should fail
        assert!(pk.verify(&different_message, &signature).is_err())
    }
}
