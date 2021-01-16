//! Module describing the signing procedures and structs

use ark_ec::{PairingEngine, ProjectiveCurve};

use ark_ff::{Field, UniformRand, Zero};

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
        message: &Vec<E::G1Projective>,
        rng: &mut R,
    ) -> Vec<E::G1Projective>
    where
        R: Rng + CryptoRng,
    {
        let rnd_f = E::Fr::rand(rng);
        let rnd_u = E::Fr::rand(rng);

        let rnd_signature = SpsEqSignature::<E>::rnd_signature(&self, rnd_u);
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
        message: &Vec<E::G1Projective>,
        rng: &mut R,
    ) -> (SpsEqSignature<E>, Vec<E::G1Projective>)
    where
        R: Rng + CryptoRng,
    {
        let rnd_f = E::Fr::rand(rng);
        let rnd_u = E::Fr::rand(rng);

        let rnd_signature = SpsEqSignature::<E>::rnd_signature(&self, rnd_u);
        let rnd_message = SpsEqSignature::<E>::rnd_message(message, rnd_f);

        (rnd_signature, rnd_message)
    }

    fn rnd_message(message: &Vec<E::G1Projective>, rnd_f: E::Fr) -> Vec<E::G1Projective> {
        let mut rnd_msg: Vec<E::G1Projective> = vec![];
        for (i, g) in message.into_iter().enumerate() {
            *g *= rnd_f;
            rnd_msg[i] = *g;
        }

        rnd_msg
    }

    fn rnd_signature(signature: &SpsEqSignature<E>, rnd_u: E::Fr) -> SpsEqSignature<E> {
        let rnd_u_inverse = rnd_u.inverse().expect("It will never be zero");

        let mut rnd_signature = SpsEqSignature {
            Z: signature.Z,
            Y: signature.Y,
            Yp: signature.Yp,
        };

        rnd_signature.Z *= rnd_u;
        rnd_signature.Y *= rnd_u_inverse;
        rnd_signature.Yp *= rnd_u_inverse;

        rnd_signature
    }
}

/// SPS-EQ signing key
#[derive(Clone)]
pub struct SigningKey<E: PairingEngine> {
    /// Capacity supported by the signing key
    pub signature_capacity: usize,
    /// Secret keys
    pub(crate) secret_keys: Vec<E::Fr>,
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
    pub fn from(sks: Vec<E::Fr>) -> Result<SigningKey<E>, ()> {
        let signature_capacity = sks.len();

        Ok(SigningKey {
            signature_capacity,
            secret_keys: sks,
        })
    }

    /// Sign a message, represented by a tuple of elements of G1Projective
    pub fn sign<R>(&self, messages: &Vec<E::G1Projective>, rng: &mut R) -> SpsEqSignature<E>
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
        let mut messages = messages.clone();
        for (value, key) in messages.iter_mut().zip(self.secret_keys.iter()) {
            *value *= *key;
            Z += value;
        }

        Z *= randomness;
        Y *= randomness.inverse().expect("It will never be zero");
        Yp *= randomness.inverse().expect("It will never be zero");

        SpsEqSignature { Z, Y, Yp }
    }
}

impl<E: PairingEngine> IntoIterator for SigningKey<E> {
    type Item = E::Fr;
    type IntoIter = std::vec::IntoIter<Self::Item>;
    fn into_iter(self) -> Self::IntoIter {
        self.secret_keys.into_iter()
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
        for item in sk.into_iter() {
            assert_eq!(item, Fr::one())
        }
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
