//! Shared helpers for the integration tests: one object-safe trait over the
//! three parameter sets, so each test can loop over all of them.
#![allow(dead_code)] // each test binary uses a different subset

use mlkem::{ml_kem_512, ml_kem_768, ml_kem_1024};

/// Slice-in, Vec-out view of one parameter set's public API.
pub trait Kem: Sync {
    fn name(&self) -> &'static str;
    fn ek_len(&self) -> usize;
    fn dk_len(&self) -> usize;
    fn ct_len(&self) -> usize;
    /// Alg 16. Returns (ek, dk).
    fn keygen_internal(&self, d: &[u8; 32], z: &[u8; 32]) -> (Vec<u8>, Vec<u8>);
    /// §7.2 check, then Alg 17. Returns (c, K), or None if ek is rejected.
    fn encaps_internal(&self, ek: &[u8], m: &[u8; 32]) -> Option<(Vec<u8>, [u8; 32])>;
    /// §7.3 checks, then Alg 21. None if dk or c is rejected.
    fn decaps(&self, dk: &[u8], c: &[u8]) -> Option<[u8; 32]>;
    fn ek_check(&self, ek: &[u8]) -> bool;
    fn dk_check(&self, dk: &[u8]) -> bool;
}

macro_rules! impl_kem {
    ($ty:ident, $m:ident) => {
        pub struct $ty;
        impl Kem for $ty {
            fn name(&self) -> &'static str {
                $m::PARAMS.name
            }
            fn ek_len(&self) -> usize {
                $m::EK_LEN
            }
            fn dk_len(&self) -> usize {
                $m::DK_LEN
            }
            fn ct_len(&self) -> usize {
                $m::CT_LEN
            }
            fn keygen_internal(&self, d: &[u8; 32], z: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
                let (ek, dk) = $m::generate_internal(d, z);
                (ek.as_bytes().to_vec(), dk.as_bytes().to_vec())
            }
            fn encaps_internal(&self, ek: &[u8], m: &[u8; 32]) -> Option<(Vec<u8>, [u8; 32])> {
                let ek = $m::EncapsulationKey::try_from(ek).ok()?;
                let (c, k) = ek.encapsulate_internal(m);
                Some((c.as_bytes().to_vec(), *k.as_bytes()))
            }
            fn decaps(&self, dk: &[u8], c: &[u8]) -> Option<[u8; 32]> {
                let dk = $m::DecapsulationKey::try_from(dk).ok()?;
                let c = $m::Ciphertext::try_from(c).ok()?;
                Some(*dk.decapsulate(&c).as_bytes())
            }
            fn ek_check(&self, ek: &[u8]) -> bool {
                $m::EncapsulationKey::try_from(ek).is_ok()
            }
            fn dk_check(&self, dk: &[u8]) -> bool {
                $m::DecapsulationKey::try_from(dk).is_ok()
            }
        }
    };
}
impl_kem!(MlKem512, ml_kem_512);
impl_kem!(MlKem768, ml_kem_768);
impl_kem!(MlKem1024, ml_kem_1024);

pub const ALL: [&dyn Kem; 3] = [&MlKem512, &MlKem768, &MlKem1024];

pub fn by_name(name: &str) -> &'static dyn Kem {
    *ALL.iter()
        .find(|k| k.name() == name)
        .unwrap_or_else(|| panic!("unknown parameter set {name}"))
}

pub fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd-length hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("bad hex"))
        .collect()
}

pub fn hex32(s: &str) -> [u8; 32] {
    hex_decode(s).try_into().expect("expected 32 bytes")
}
