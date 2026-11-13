//! Differential testing against an independent implementation: RustCrypto's
//! `ml-kem` crate (dev-dependency only, never linked into the library).
//!
//! For random seeds and messages, both implementations must produce
//! byte-identical keys, ciphertexts and shared secrets, and must agree on
//! decapsulating *random* (almost always invalid) ciphertexts, which
//! exercises implicit rejection.
//!
//! Number of cases per property: proptest's default (256), or set
//! PROPTEST_CASES for longer runs (see scripts/extended-proptest.ps1).

use ml_kem::array::Array;
#[allow(deprecated)]
use ml_kem::{Decapsulate, ExpandedKeyEncoding, KeyExport};
use proptest::prelude::*;

macro_rules! crosscheck {
    ($test:ident, $ours:ident, $theirs:ty) => {
        proptest! {
            #[test]
            fn $test(d: [u8; 32], z: [u8; 32], m: [u8; 32],
                     junk in prop::collection::vec(any::<u8>(), mlkem::$ours::CT_LEN)) {
                use mlkem::$ours as ours;

                // Key generation from the same seed (d, z).
                let mut seed = [0u8; 64];
                seed[..32].copy_from_slice(&d);
                seed[32..].copy_from_slice(&z);
                let dk_ref = ml_kem::DecapsulationKey::<$theirs>::from_seed(Array::from(seed));
                let ek_ref = dk_ref.encapsulation_key();
                let (ek, dk) = ours::generate_internal(&d, &z);
                prop_assert_eq!(&ek.as_bytes()[..], &ek_ref.to_bytes()[..], "ek");
                #[allow(deprecated)]
                let dk_ref_bytes = dk_ref.to_expanded_bytes();
                prop_assert_eq!(&dk.as_bytes()[..], &dk_ref_bytes[..], "dk");

                // Encapsulation with the same m.
                let (c, k) = ek.encapsulate_internal(&m);
                let (c_ref, k_ref) = ek_ref.encapsulate_deterministic(&Array::from(m));
                prop_assert_eq!(&c.as_bytes()[..], &c_ref[..], "ciphertext");
                prop_assert_eq!(&k.as_bytes()[..], &k_ref[..], "shared secret");

                // Decapsulation of the honest ciphertext ...
                let (k1, k1_ref) = (dk.decapsulate(&c), dk_ref.decapsulate(&c_ref));
                prop_assert_eq!(&k1.as_bytes()[..], &k1_ref[..]);

                // ... and of random bytes (implicit rejection path).
                let junk_ours = ours::Ciphertext::try_from(&junk[..]).unwrap();
                let junk_ref = ml_kem::Ciphertext::<$theirs>::try_from(&junk[..]).unwrap();
                let (k2, k2_ref) = (dk.decapsulate(&junk_ours), dk_ref.decapsulate(&junk_ref));
                prop_assert_eq!(&k2.as_bytes()[..], &k2_ref[..], "implicit rejection");
            }
        }
    };
}

crosscheck!(crosscheck_512, ml_kem_512, ml_kem::MlKem512);
crosscheck!(crosscheck_768, ml_kem_768, ml_kem::MlKem768);
crosscheck!(crosscheck_1024, ml_kem_1024, ml_kem::MlKem1024);
