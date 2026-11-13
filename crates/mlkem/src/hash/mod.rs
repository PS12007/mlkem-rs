//! Hash functions and XOFs: SHA3-256, SHA3-512, SHAKE128, SHAKE256
//! (FIPS 202), and the wrappers H, J, G, PRF and XOF that FIPS 203 §4.1
//! defines on top of them.
//!
//! Inputs are given as a list of byte slices (`&[&[u8]]`) and absorbed one
//! after the other. That is the same as hashing their concatenation (e.g.
//! G(d ‖ k) or J(z ‖ c)), without needing a heap allocation (`no_std`).

mod keccak;
mod sponge;

use crate::sample::XofReader;
use sponge::{SHA3_SUFFIX, SHAKE_SUFFIX, Sponge, Squeezer};

const SHA3_256_RATE: usize = 136;
const SHA3_512_RATE: usize = 72;
const SHAKE128_RATE: usize = 168;
const SHAKE256_RATE: usize = 136;

fn absorb_all<const R: usize>(parts: &[&[u8]]) -> Sponge<R> {
    let mut s = Sponge::<R>::new();
    for p in parts {
        s.absorb(p);
    }
    s
}

/// SHA3-256(parts concatenated), FIPS 202 §6.1.
pub(crate) fn sha3_256(parts: &[&[u8]]) -> [u8; 32] {
    let mut out = [0u8; 32];
    absorb_all::<SHA3_256_RATE>(parts)
        .finalize(SHA3_SUFFIX)
        .squeeze(&mut out);
    out
}

/// SHA3-512(parts concatenated), FIPS 202 §6.1.
pub(crate) fn sha3_512(parts: &[&[u8]]) -> [u8; 64] {
    let mut out = [0u8; 64];
    absorb_all::<SHA3_512_RATE>(parts)
        .finalize(SHA3_SUFFIX)
        .squeeze(&mut out);
    out
}

/// SHAKE256(parts concatenated, 8·out.len()), FIPS 202 §6.2.
pub(crate) fn shake256(parts: &[&[u8]], out: &mut [u8]) {
    absorb_all::<SHAKE256_RATE>(parts)
        .finalize(SHAKE_SUFFIX)
        .squeeze(out);
}

/// Incremental SHAKE128 in the absorbing phase: the SP 800-185 style
/// Init / Absorb API that FIPS 203 §4.1 uses for its XOF.
pub(crate) struct Shake128(Sponge<SHAKE128_RATE>);

/// SHAKE128 in the squeezing phase.
pub(crate) struct Shake128Reader(Squeezer<SHAKE128_RATE>);

impl Shake128 {
    /// XOF.Init()
    pub(crate) fn new() -> Self {
        Shake128(Sponge::new())
    }
    /// XOF.Absorb(ctx, str)
    pub(crate) fn absorb(&mut self, data: &[u8]) {
        self.0.absorb(data);
    }
    /// Ends absorbing. Every XOF.Squeeze after this reads from the reader.
    pub(crate) fn finalize(self) -> Shake128Reader {
        Shake128Reader(self.0.finalize(SHAKE_SUFFIX))
    }
}

impl XofReader for Shake128Reader {
    /// XOF.Squeeze(ctx, 8·out.len())
    fn squeeze(&mut self, out: &mut [u8]) {
        self.0.squeeze(out);
    }
}

// ---- FIPS 203 §4.1 wrappers -------------------------------------------

/// H(s) := SHA3-256(s)  (eq. 4.4)
pub(crate) fn h(parts: &[&[u8]]) -> [u8; 32] {
    sha3_256(parts)
}

/// J(s) := SHAKE256(s, 8·32)  (eq. 4.4)
pub(crate) fn j(parts: &[&[u8]]) -> [u8; 32] {
    let mut out = [0u8; 32];
    shake256(parts, &mut out);
    out
}

/// (a, b) ← G(c), where G(c) := SHA3-512(c) = a ‖ b  (eq. 4.5)
pub(crate) fn g(parts: &[&[u8]]) -> ([u8; 32], [u8; 32]) {
    let ab = sha3_512(parts);
    let (a, b) = ab.split_at(32);
    (a.try_into().unwrap(), b.try_into().unwrap())
}

/// PRF_η(s, b) := SHAKE256(s ‖ b, 8·64·η)  (eqs. 4.2, 4.3).
/// `out` must be 64·η bytes. η only sets the length, it is not a domain
/// separator (FIPS 203 says so explicitly).
pub(crate) fn prf(eta: usize, s: &[u8; 32], b: u8, out: &mut [u8]) {
    assert!((eta == 2 || eta == 3) && out.len() == 64 * eta);
    shake256(&[s, &[b]], out);
}

/// XOF.Init then XOF.Absorb(input) for SampleNTT (Alg 7 lines 1–2).
/// Alg 13 / 14 call this with input ρ ‖ j ‖ i (34 bytes).
pub(crate) fn xof(parts: &[&[u8]]) -> Shake128Reader {
    let mut x = Shake128::new();
    for p in parts {
        x.absorb(p);
    }
    x.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use sha3::Digest;
    use sha3::digest::{ExtendableOutput, Update, XofReader as _};

    fn ref_sha3_256(m: &[u8]) -> [u8; 32] {
        <sha3::Sha3_256 as Digest>::digest(m).into()
    }
    fn ref_sha3_512(m: &[u8]) -> [u8; 64] {
        <sha3::Sha3_512 as Digest>::digest(m).into()
    }
    fn ref_shake128(m: &[u8], n: usize) -> Vec<u8> {
        let mut h = sha3::Shake128::default();
        Update::update(&mut h, m);
        let mut out = vec![0u8; n];
        h.finalize_xof().read(&mut out);
        out
    }
    fn ref_shake256(m: &[u8], n: usize) -> Vec<u8> {
        let mut h = sha3::Shake256::default();
        Update::update(&mut h, m);
        let mut out = vec![0u8; n];
        h.finalize_xof().read(&mut out);
        out
    }
    fn our_shake128(m: &[u8], n: usize) -> Vec<u8> {
        let mut out = vec![0u8; n];
        xof(&[m]).squeeze(&mut out);
        out
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Example values published by NIST for SHA-3 / SHAKE (csrc.nist.gov
    /// "Cryptographic Standards and Guidelines: Examples with
    /// Intermediate Values"). They are also confirmed against the sha3 crate
    /// below, so a typo here would show up as a disagreement.
    #[test]
    fn known_answers() {
        let empty_256 = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
        let abc_256 = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532";
        let empty_shake128 = "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26";
        assert_eq!(hex(&sha3_256(&[b""])), empty_256);
        assert_eq!(hex(&sha3_256(&[b"abc"])), abc_256);
        assert_eq!(hex(&our_shake128(b"", 32)), empty_shake128);
        assert_eq!(hex(&ref_sha3_256(b"")), empty_256);
        assert_eq!(hex(&ref_shake128(b"", 32)), empty_shake128);
    }

    /// Every message length from 0 to just over 3 SHAKE128 blocks, which
    /// covers the boundaries of every rate: 72, 136 and 168 and their
    /// multiples, including the case where the suffix and the final 0x80
    /// share a byte (length ≡ rate − 1).
    #[test]
    fn every_length_across_block_boundaries() {
        let msg: Vec<u8> = (0..=3 * 168 + 1).map(|i| (i * 7 + 3) as u8).collect();
        for len in 0..msg.len() {
            let m = &msg[..len];
            assert_eq!(sha3_256(&[m]), ref_sha3_256(m), "sha3-256 len {len}");
            assert_eq!(sha3_512(&[m]), ref_sha3_512(m), "sha3-512 len {len}");
            assert_eq!(
                our_shake128(m, 200),
                ref_shake128(m, 200),
                "shake128 len {len}"
            );
            let mut out = vec![0u8; 300];
            shake256(&[m], &mut out);
            assert_eq!(out, ref_shake256(m, 300), "shake256 len {len}");
        }
    }

    proptest! {
        /// Splitting the input into pieces must not change the hash.
        #[test]
        fn split_input_matches_reference(m in prop::collection::vec(any::<u8>(), 0..700),
                                         a in any::<prop::sample::Index>(),
                                         b in any::<prop::sample::Index>()) {
            let (mut i, mut k) = (a.index(m.len() + 1), b.index(m.len() + 1));
            if i > k { core::mem::swap(&mut i, &mut k); }
            let parts: [&[u8]; 3] = [&m[..i], &m[i..k], &m[k..]];
            prop_assert_eq!(sha3_256(&parts), ref_sha3_256(&m));
            prop_assert_eq!(sha3_512(&parts), ref_sha3_512(&m));
            let mut out = vec![0u8; 64];
            shake256(&parts, &mut out);
            prop_assert_eq!(out, ref_shake256(&m, 64));
        }

        /// Squeezing in random-sized chunks gives one continuous stream.
        #[test]
        fn chunked_squeeze_matches_reference(m in prop::collection::vec(any::<u8>(), 0..300),
                                             chunks in prop::collection::vec(0usize..400, 1..8)) {
            let total: usize = chunks.iter().sum();
            let mut reader = xof(&[&m]);
            let mut got = Vec::new();
            for c in chunks {
                let mut buf = vec![0u8; c];
                reader.squeeze(&mut buf);
                got.extend_from_slice(&buf);
            }
            prop_assert_eq!(got, ref_shake128(&m, total));
        }

        /// FIPS 203 §4.1 wrappers are what they claim to be.
        #[test]
        fn fips203_wrappers(s in any::<[u8; 32]>(), b: u8, m in prop::collection::vec(any::<u8>(), 0..100)) {
            prop_assert_eq!(h(&[&m]), ref_sha3_256(&m));
            prop_assert_eq!(j(&[&m]).to_vec(), ref_shake256(&m, 32));
            let (ga, gb) = g(&[&m]);
            let full = ref_sha3_512(&m);
            prop_assert_eq!(&ga[..], &full[..32]);
            prop_assert_eq!(&gb[..], &full[32..]);
            let mut s_b = s.to_vec();
            s_b.push(b);
            for eta in [2, 3] {
                let mut out = vec![0u8; 64 * eta];
                prf(eta, &s, b, &mut out);
                prop_assert_eq!(out, ref_shake256(&s_b, 64 * eta));
            }
        }

        /// End to end: SampleNTT fed by our SHAKE128 equals the literal
        /// Algorithm 7 fed by the reference crate's SHAKE128.
        #[test]
        fn sample_ntt_with_real_xof(rho in any::<[u8; 32]>(), i: u8, jj: u8) {
            let a = crate::sample::sample_ntt(&mut xof(&[&rho, &[jj, i]]));
            let mut input = rho.to_vec();
            input.extend_from_slice(&[jj, i]);
            let stream = ref_shake128(&input, 168 * 10);
            prop_assert_eq!(a.canonical().map(i64::from), crate::spec::sample_ntt(&stream));
        }
    }
}
