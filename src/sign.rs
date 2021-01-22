//! Module describing the signing procedures and structs

use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_ff::{UniformRand, Zero, Field};

use zeroize::Zeroize;
use rand::{Rng, CryptoRng};

/// SPS-EQ signature
pub struct SpsEqSignature<E: PairingEngine> {
    /// Z point
    pub Z: E::G1Projective,
    /// Y point
    pub Y: E::G1Projective,
    /// Yp point
    pub Yp: E::G2Projective,
}


/// SPS-EQ signing key
#[derive(Clone, Debug)]
pub struct SigningKey<E: PairingEngine> {
    /// Capacity supported by the signing key
    pub signature_capacity: usize,
    /// Secret keys
    secret_keys: Vec<E::Fr>,
}

impl<E: PairingEngine> SigningKey<E> {
    /// Generate a cryptographically random [`SigningKey`].
    pub fn new<R>(signature_capacity: usize, rng: &mut R) -> SigningKey<E>
    where
        R: Rng + CryptoRng
    {
        let secret_keys = vec![E::Fr::rand(rng); signature_capacity];
        SigningKey{signature_capacity, secret_keys}
    }

    /// Generate a [`SigningKey`] from a given input.
    pub fn new_input(sks: Vec<E::Fr>) -> SigningKey<E>
    {
        let signature_capacity = sks.len();

        SigningKey{signature_capacity, secret_keys: sks}
    }

    /// Sign a message, represented by a tuple of elements of G1Projective
    pub fn sign<R>(&self, messages: &Vec<E::G1Projective>, rng: &mut R) -> SpsEqSignature<E>
    where
        R: Rng + CryptoRng
    {
        // todo: We probably want to do something when this goes out of scope
        let mut randomness = E::Fr::rand(rng);
        while randomness.is_zero() {
            randomness = E::Fr::rand(rng);
        }

        let mut Z = E::G1Projective::zero();
        let mut Y = E::G1Projective::prime_subgroup_generator();
        let mut Yp = E::G2Projective::prime_subgroup_generator();

        // todo: in here we'll eventually use `VariableBaseMSM::multi_scalar_mul`. Not necessary
        // yet, as we expect to have only two commitments.
        let mut messages = messages.clone();
        for (value, key) in messages.iter_mut().zip(self) {
            *value *= key;
            Z += value;
        }

        Z *= randomness;
        Y *= randomness.inverse().expect("It will never be zero");
        Yp *= randomness.inverse().expect("It will never be zero");

        SpsEqSignature{Z, Y, Yp}
    }
}

/// Implements `Zeroize` for SigningKeys.
/// todo: probably not required, as E::FR already implements zeroize
impl<E: PairingEngine> Zeroize for SigningKey<E> {
    fn zeroize(&mut self) {
        for key in self.secret_keys.iter_mut() {
            key.zeroize();
        }
    }
}

impl<E: PairingEngine> PartialEq for SigningKey<E> {
    fn eq(&self, other: &Self) -> bool {
        self.secret_keys == other.secret_keys
    }
}

impl<'a, E: PairingEngine> IntoIterator for &'a SigningKey<E> {
    type Item = E::Fr;
    type IntoIter = KeyIntoIterator<'a, E>;

    fn into_iter(self) -> Self::IntoIter {
        KeyIntoIterator {
            signing_key: self,
            index: 0,
        }
    }
}

pub struct KeyIntoIterator<'a, E: PairingEngine> {
    signing_key: &'a SigningKey<E>,
    index: usize,
}

impl<'a, E:PairingEngine> Iterator for KeyIntoIterator<'a, E> {
    type Item = E::Fr;

    fn next(&mut self) -> Option<E::Fr> {
        match self.signing_key.secret_keys.get(self.index) {
            Some(x) => {
                self.index += 1;
                Some(*x)
            }
            None => None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{One, Zero, Field};
    use ark_bls12_381::{Fr, Bls12_381, G2Projective as G2, G1Projective as G1, G1Affine, G1Projective};
    use ark_ec::{ProjectiveCurve, msm::VariableBaseMSM};
    use rand::thread_rng;

    #[test]
    fn test_iterator() {
        let sk = SigningKey::<Bls12_381>::new_input(vec![Fr::one(); 3]);
        for item in &sk {
            assert_eq!(item, Fr::one())
        }
    }

    #[test]
    fn given_sk() {
        let sk = SigningKey::<Bls12_381>::new(3, &mut thread_rng());
        let values = sk.secret_keys.clone();

        let sk_from_value = SigningKey::<Bls12_381>::new_input(values);
        assert_eq!(sk, sk_from_value)
    }

    #[test]
    fn test_addition() {
        let mut init = G2::prime_subgroup_generator();
        init *= Fr::one();

        assert_eq!(init, G2::prime_subgroup_generator())
    }

    #[test]
    fn g1_generator() {
        let Z = G1Affine::zero();
        let _lalal = G1Projective::zero();
        let _Y = G1::prime_subgroup_generator();
        let _Yp = G2::prime_subgroup_generator();

        // todo: multi scalar mult is not of utter importance now. We only expect two mults. Change
        // eventually
        let a = VariableBaseMSM::multi_scalar_mul(&[Z], &[Fr::one().into()]);

        let b = Fr::rand(&mut thread_rng());
        let _c = b.inverse();


        assert_eq!(a, Z);
    }
}
