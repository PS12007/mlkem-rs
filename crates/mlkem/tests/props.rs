//! Property tests of the KEM's defining behaviour, for all parameter sets:
//! - Decaps(dk, Encaps(ek)) recovers the same shared secret;
//! - any modified ciphertext triggers implicit rejection, and the result is
//!   exactly J(z ‖ c′) as FIPS 203 Alg 18 line 7 prescribes;
//! - the §7.2 / §7.3 input checks reject bad keys and wrong lengths;
//! - RNG failure is reported, not ignored (Alg 19/20).
//!
//! Cases per property: proptest's default (256) or PROPTEST_CASES.

mod common;

use common::ALL;
use mlkem::{Error, RandomSource, ml_kem_768};
use proptest::prelude::*;
use sha3::digest::{ExtendableOutput, Update, XofReader};

/// SHAKE256(z ‖ c, 256 bits) from the *reference* sha3 crate, so the
/// expected rejection key does not come from our own hash code.
fn reference_j(z: &[u8], c: &[u8]) -> [u8; 32] {
    let mut h = sha3::Shake256::default();
    h.update(z);
    h.update(c);
    let mut out = [0u8; 32];
    h.finalize_xof().read(&mut out);
    out
}

proptest! {
    #[test]
    fn decaps_recovers_shared_secret(d: [u8; 32], z: [u8; 32], m: [u8; 32], which in 0usize..3) {
        let kem = ALL[which];
        let (ek, dk) = kem.keygen_internal(&d, &z);
        let (c, k) = kem.encaps_internal(&ek, &m).unwrap();
        prop_assert_eq!(kem.decaps(&dk, &c).unwrap(), k);
    }

    /// Flip one bit anywhere in the ciphertext. Decaps must return the
    /// implicit-rejection key J(z ‖ c′), never the real K and never an error.
    #[test]
    fn modified_ciphertext_is_implicitly_rejected(d: [u8; 32], z: [u8; 32], m: [u8; 32],
                                                  which in 0usize..3,
                                                  pos in any::<prop::sample::Index>(), bit in 0u8..8) {
        let kem = ALL[which];
        let (ek, dk) = kem.keygen_internal(&d, &z);
        let (mut c, k) = kem.encaps_internal(&ek, &m).unwrap();
        let i = pos.index(c.len());
        c[i] ^= 1 << bit;
        let k_rejected = kem.decaps(&dk, &c).unwrap();
        prop_assert_ne!(k_rejected, k);
        prop_assert_eq!(k_rejected, reference_j(&z, &c));
    }

    /// A key with one 12-bit value ≥ q must fail the modulus check (§7.2).
    #[test]
    fn ek_with_out_of_range_coefficient_rejected(d: [u8; 32], z: [u8; 32], which in 0usize..3,
                                                 slot in any::<prop::sample::Index>(),
                                                 value in 3329u16..4096) {
        let kem = ALL[which];
        let (mut ek, _) = kem.keygen_internal(&d, &z);
        prop_assert!(kem.ek_check(&ek));
        // Coefficient j occupies bits 12j .. 12j+11 of the t̂ part.
        let j = slot.index((ek.len() - 32) * 8 / 12);
        for b in 0..12 {
            let bitpos = 12 * j + b;
            let byte = &mut ek[bitpos / 8];
            *byte = (*byte & !(1 << (bitpos % 8))) | ((((value >> b) & 1) as u8) << (bitpos % 8));
        }
        prop_assert!(!kem.ek_check(&ek));
    }

    /// Changing any byte of the stored ek or H(ek) inside dk must fail the
    /// hash check (§7.3).
    #[test]
    fn dk_with_inconsistent_hash_rejected(d: [u8; 32], z: [u8; 32], which in 0usize..3,
                                          pos in any::<prop::sample::Index>(), bit in 0u8..8) {
        let kem = ALL[which];
        let (_, mut dk) = kem.keygen_internal(&d, &z);
        prop_assert!(kem.dk_check(&dk));
        let start = kem.dk_len() - kem.ek_len() - 64; // = 384k: start of ek inside dk
        let i = start + pos.index(kem.ek_len() + 32); // inside ek ‖ H(ek)
        dk[i] ^= 1 << bit;
        prop_assert!(!kem.dk_check(&dk));
    }
}

#[test]
fn wrong_lengths_are_type_check_failures() {
    for kem in ALL {
        let (ek, dk) = kem.keygen_internal(&[1; 32], &[2; 32]);
        assert!(!kem.ek_check(&ek[1..]));
        assert!(!kem.dk_check(&dk[..dk.len() - 1]));
        assert!(kem.decaps(&dk, &vec![0u8; kem.ct_len() + 1]).is_none());
    }
    assert_eq!(
        ml_kem_768::Ciphertext::try_from(&[0u8; 5][..]).unwrap_err(),
        Error::InvalidLength
    );
}

struct FailingRng;
impl RandomSource for FailingRng {
    fn fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Error> {
        Err(Error::RandomnessFailure)
    }
}

#[test]
fn rng_failure_is_reported() {
    assert_eq!(
        ml_kem_768::generate(&mut FailingRng).unwrap_err(),
        Error::RandomnessFailure
    );
    let (ek, _) = ml_kem_768::generate_internal(&[0; 32], &[0; 32]);
    assert_eq!(
        ek.encapsulate(&mut FailingRng).unwrap_err(),
        Error::RandomnessFailure
    );
}

#[cfg(windows)]
#[test]
fn public_api_round_trip_with_os_rng() {
    use mlkem::{OsRng, ml_kem_512, ml_kem_1024};
    macro_rules! round_trip {
        ($m:ident) => {{
            let (ek, dk) = $m::generate(&mut OsRng).unwrap();
            let (c, k) = ek.encapsulate(&mut OsRng).unwrap();
            assert_eq!(dk.decapsulate(&c), k);
            assert_eq!(dk.encapsulation_key(), ek);
        }};
    }
    round_trip!(ml_kem_512);
    round_trip!(ml_kem_768);
    round_trip!(ml_kem_1024);
}
