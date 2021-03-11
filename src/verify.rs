//! Module describing the verifying procedures and structs
use ark_ec::{PairingEngine, ProjectiveCurve};

use crate::errors::*;
use crate::sign::{SigningKey, SpsEqSignature};
use ark_ff::{FromBytes, ToBytes};
use std::convert::TryInto;

/// SPS-EQ public key
#[derive(Debug)]
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
        messages: &[E::G1Projective],
        signature: &SpsEqSignature<E>,
    ) -> Result<(), SpsEqSignatureError> {
        if self.signature_capacity != messages.len() {
            return Err(SpsEqSignatureError::UnmatchedCapacity);
        }

        let mut check_1 = E::pairing(messages[0], self.public_keys[0]);
        for (&message, key) in messages.iter().zip(self.public_keys.clone()).skip(1) {
            check_1 *= &E::pairing(message, key);
        }

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

    // todo: handle the to_bytes/from_bytes -> likely to get mismatches in different architectures
    /// Convert a `PublicKey` to an array of bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, SpsEqSignatureError> {
        let mut writer = self.signature_capacity.to_be_bytes().to_vec();
        for point in self {
            let write = point.write(&mut writer);
            match write {
                Ok(_) => (),
                Err(_) => return Err(SpsEqSignatureError::IoErrorWrite),
            }
        }
        Ok(writer.to_vec())
    }

    /// Create a `PublicKey` from an array of bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SpsEqSignatureError> {
        let signature_capacity = usize::from_be_bytes(bytes[..8].try_into().expect("Handle this"));
        let mut public_keys = Vec::new();
        // todo: these values should not be hardcoded - should come from PairingEngine
        for keys in bytes[8..].chunks(288) {
            public_keys.push(E::G2Projective::read(keys).expect("and this"));
        }

        if signature_capacity != public_keys.len() {
            return Err(SpsEqSignatureError::UnmatchedCapacity);
        }

        Ok(PublicKey {
            signature_capacity,
            public_keys,
        })
    }
}

/// Generate public keys from a secret key
impl<'a, E: PairingEngine> From<&SigningKey<E>> for PublicKey<E> {
    fn from(signing_key: &SigningKey<E>) -> PublicKey<E> {
        let signature_capacity = signing_key.signature_capacity;

        let mut public_keys = vec![E::G2Projective::prime_subgroup_generator(); signature_capacity];
        for (pkey, skey) in public_keys.iter_mut().zip(signing_key) {
            *pkey *= skey;
        }
        PublicKey {
            signature_capacity,
            public_keys,
        }
    }
}

impl<E: PairingEngine> PartialEq for PublicKey<E> {
    fn eq(&self, other: &Self) -> bool {
        self.public_keys == other.public_keys
    }
}

impl<'a, E: PairingEngine> IntoIterator for &'a PublicKey<E> {
    type Item = E::G2Projective;
    type IntoIter = PubKeyIntoIterator<'a, E>;

    fn into_iter(self) -> Self::IntoIter {
        PubKeyIntoIterator {
            public_key: self,
            index: 0,
        }
    }
}

/// Iterator for `PublicKey`, which implements `Iterator` itself
pub struct PubKeyIntoIterator<'a, E: PairingEngine> {
    public_key: &'a PublicKey<E>,
    index: usize,
}

impl<'a, E: PairingEngine> Iterator for PubKeyIntoIterator<'a, E> {
    type Item = E::G2Projective;

    fn next(&mut self) -> Option<E::G2Projective> {
        match self.public_key.public_keys.get(self.index) {
            Some(x) => {
                self.index += 1;
                Some(*x)
            }
            None => None,
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
    fn test_from_to_bytes() {
        let sk = SigningKey::<Bls12_381>::new(2, &mut thread_rng());
        let pk = PublicKey::from(&sk);

        let mut bytes_pk = pk.to_bytes().unwrap();

        let pk_from_bytes = PublicKey::from_bytes(&mut bytes_pk).unwrap();

        assert_eq!(pk, pk_from_bytes);
    }
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
