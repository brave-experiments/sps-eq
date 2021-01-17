# Structure Preserving Signatures over Equivalence Classes
Implementation of the Structure Preserving Signatures over Equivalence Classes presented by 
Georg Fuchsbauer, Christian Hanser and Daniel Slamanig, [2014/944](https://eprint.iacr.org/2014/944.pdf).

## Disclaimer
This library is work in progress.

## Usage
```rust
use sps_eq::parameters::{SystemParameters, IssuerParameters};
use sps_eq::issuer::{Issuer};
use sps_eq::tools::{EquivalenceClass};

let equivalence_class_length = 2;
let system_parameters: SystemParameters = SystemParameters::gen(equivalence_class_length);

// Maybe we want to allow the caller of the lib to include their rng of preference.
let issuer: Issuer = Issuer::new(&system_parameters);
let issuer_parameters: IssuerParameters = issuer.parameters; 

// Now the user selects the equivalence class over which it requests the 
// signature. This step may be done by the issuer directly, of course. 
let equivalence_class: EquivalenceClass = EquivalenceClass::random();

// Issuer signs the equivalence class
let issuance = issuer.sign(&equivalence_class);

// The user now verifies that the signature is valid
let signature_eq: SpsEqSiganture = issuance.verify(&equivalence_class);

// The user can now change the representation of the signature
let changed_representation: SpsEqSignature = signature_eq.chg_rep();

// Or it can change it by providing randomness
let changed_representation: SpsEqSignature = signature_eq.chg_rep_with_rng(&mut rng_of_choice);
```

