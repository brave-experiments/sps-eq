//! Module describing the signing procedures and structs

use ark_ec::{PairingEngine, ProjectiveCurve};

use ark_ff::{Field, UniformRand, Zero};
use zeroize::Zeroize;

use crate::errors::*;
use rand::{CryptoRng, Rng};

/// SPS-EQ signature
pub struct SpsEqSignature<E: PairingEngine> {
    /// Z point
    pub Z: E::G1Projective,
    /// Y point
    pub Y: E::G1Projective,
    /// Yp point
    pub Yp: E::G2Projective,
}

impl<E: PairingEngine> SpsEqSignature<E> {
    /// Mutably changes the representation of the signature and a message. The
    /// function does not make assumptions with regards to the relation between
    /// the message and the signature (ie. signature may not correspond to the
    /// message)
    pub fn change_repr<R>(
        &mut self,
        message: &[E::G1Projective],
        rng: &mut R,
    ) -> Vec<E::G1Projective>
    where
        R: Rng + CryptoRng,
    {
        let rnd_f = E::Fr::rand(rng);
        let rnd_u = E::Fr::rand(rng);

        let rnd_signature = SpsEqSignature::<E>::rnd_signature(&self, rnd_u, rnd_f);
        self.Z = rnd_signature.Z;
        self.Y = rnd_signature.Y;
        self.Yp = rnd_signature.Yp;

        SpsEqSignature::<E>::rnd_message(message, rnd_f)
    }

    /// Generates a new representation of the signature and message, and returns
    /// the new representation of the signature and the message; The function
    /// does not make assumptions with regards to relation between the message
    /// and the signature (ie. signature may not correspond to the message)
    pub fn generate_new_repr<R>(
        self,
        message: &[E::G1Projective],
        rng: &mut R,
    ) -> (SpsEqSignature<E>, Vec<E::G1Projective>)
    where
        R: Rng + CryptoRng,
    {
        let rnd_f = E::Fr::rand(rng);
        let rnd_u = E::Fr::rand(rng);

        let rnd_signature = SpsEqSignature::<E>::rnd_signature(&self, rnd_u, rnd_f);
        let rnd_message = SpsEqSignature::<E>::rnd_message(message, rnd_f);

        (rnd_signature, rnd_message)
    }

    fn rnd_message(message: &[E::G1Projective], rnd_f: E::Fr) -> Vec<E::G1Projective> {
        message
            .to_owned()
            .into_iter()
            .map(|mut g| {
                g *= rnd_f;
                g
            })
            .collect()
    }

    fn rnd_signature(
        signature: &SpsEqSignature<E>,
        rnd_u: E::Fr,
        rnd_f: E::Fr,
    ) -> SpsEqSignature<E> {
        let rnd_u_inverse = rnd_u.inverse().expect("It will never be zero");

        let mut rnd_signature = SpsEqSignature {
            Z: signature.Z,
            Y: signature.Y,
            Yp: signature.Yp,
        };

        rnd_signature.Z *= rnd_u;
        rnd_signature.Z *= rnd_f;

        rnd_signature.Y *= rnd_u_inverse;
        rnd_signature.Yp *= rnd_u_inverse;

        rnd_signature
    }
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
        R: Rng + CryptoRng,
    {
        let secret_keys = vec![E::Fr::rand(rng); signature_capacity];
        SigningKey {
            signature_capacity,
            secret_keys,
        }
    }

    /// Generate a [`SigningKey`] from a given input.
    pub fn from(sks: Vec<E::Fr>) -> Result<SigningKey<E>, SpsEqSignatureError> {
        let signature_capacity = sks.len();

        Ok(SigningKey {
            signature_capacity,
            secret_keys: sks,
        })
    }

    /// Sign a message, represented by a tuple of elements of G1Projective
    pub fn sign<R>(&self, messages: &[E::G1Projective], rng: &mut R) -> SpsEqSignature<E>
    where
        R: Rng + CryptoRng,
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
        let mut messages = messages.to_owned();
        for (value, key) in messages.iter_mut().zip(self) {
            *value *= key;
            Z += *value;
        }

        Z *= randomness;
        Y *= randomness.inverse().expect("It will never be zero");
        Yp *= randomness.inverse().expect("It will never be zero");

        SpsEqSignature { Z, Y, Yp }
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

/// Iterator for `SigningKey`, which implements `Iterator` itself
pub struct KeyIntoIterator<'a, E: PairingEngine> {
    signing_key: &'a SigningKey<E>,
    index: usize,
}

impl<'a, E: PairingEngine> Iterator for KeyIntoIterator<'a, E> {
    type Item = E::Fr;

    fn next(&mut self) -> Option<E::Fr> {
        match self.signing_key.secret_keys.get(self.index) {
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
    use ark_bls12_381::{
        Bls12_381, Fr, G1Affine, G1Projective as G1, G1Projective, G2Projective as G2,
    };
    use ark_ec::{msm::VariableBaseMSM, ProjectiveCurve};
    use ark_ff::{Field, One, Zero};
    use rand::thread_rng;

    #[test]
    fn test_new_keys() {
        let capacity = 2;
        let rnd = &mut thread_rng();

        let sk = SigningKey::<Bls12_381>::new(capacity, rnd);

        assert_eq!(sk.signature_capacity, capacity);
        assert_eq!(sk.signature_capacity, sk.secret_keys.len());

        let rnds = [&mut thread_rng(), &mut thread_rng(), &mut thread_rng()];
        let secret_keys = vec![Fr::rand(rnds[0]), Fr::rand(rnds[1]), Fr::rand(rnds[2])];
        let capacity = secret_keys.len();

        let sk = SigningKey::<Bls12_381>::from(secret_keys).unwrap();

        assert_eq!(sk.signature_capacity, capacity);
        assert_eq!(sk.secret_keys.len(), capacity);
    }

    #[test]
    fn test_iterator() {
        let sk = SigningKey::<Bls12_381>::from(vec![Fr::one(); 3]).unwrap();
        for item in &sk {
            assert_eq!(item, Fr::one())
        }
    }

    #[test]
    fn given_sk() {
        let sk = SigningKey::<Bls12_381>::new(3, &mut thread_rng());
        let values = sk.secret_keys.clone();

        let sk_from_value = SigningKey::<Bls12_381>::from(values).unwrap();
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
