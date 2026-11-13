//! K-PKE, the component public-key encryption scheme (FIPS 203 §5):
//! Algorithm 13 KeyGen, Algorithm 14 Encrypt, Algorithm 15 Decrypt.
//!
//! K-PKE on its own is only secure against passive attackers (IND-CPA). It
//! must not be used alone (§5 says so). ML-KEM (kem.rs) wraps it with the
//! Fujisaki–Okamoto transform to make it secure against chosen ciphertexts.
//!
//! # Where the secrets are
//! - KeyGen: σ, s, e. Encrypt: m, r, y, e1, e2. Decrypt: s, w, m.
//! - The matrix A, t̂ and ρ are public (they are the encryption key).
//!
//! Every function here has a fixed loop structure that depends only on the
//! parameter set. The secret-dependent arithmetic is in the Phase 1
//! building blocks, which are constant time (see LEARNING.md §1.5).
//!
//! # Lengths and the matrix
//! Vectors are `[Poly; MAX_K]` with only the first k entries used, so no
//! heap allocation is needed. A is never stored. Each entry is re-derived
//! with SampleNTT exactly when it is used. Both KeyGen and Encrypt use every
//! entry exactly once, so this costs nothing extra and saves 8 KiB of stack.

use crate::encode::{poly_compress_encode, poly_decode_decompress, poly_decode12, poly_encode12};
use crate::hash;
use crate::ntt::{multiply_ntts, ntt, ntt_inverse};
use crate::params::{MAX_K, Params};
use crate::poly::Poly;
use crate::sample::{sample_ntt, sample_poly_cbd};

type PolyVec = [Poly; MAX_K];

/// Â[i, j] = SampleNTT(ρ ‖ j ‖ i) (Alg 13 line 5, Alg 14 line 6). Note the
/// order: the *column* index j comes first in the XOF input.
fn matrix_entry(rho: &[u8; 32], i: usize, j: usize) -> Poly {
    sample_ntt(&mut hash::xof(&[rho, &[j as u8, i as u8]]))
}

/// One CBD sample from PRF_η(seed, N), then N ← N + 1
/// (Alg 13 lines 9–10 and 13–14, Alg 14 lines 10–11, 14–15 and 17).
fn sample_noise(eta: usize, seed: &[u8; 32], counter: &mut u8) -> Poly {
    let mut buf = [0u8; 64 * 3];
    let buf = &mut buf[..64 * eta];
    hash::prf(eta, seed, *counter, buf);
    *counter += 1;
    sample_poly_cbd(eta, buf)
}

/// Σ_j a[j] ∘ b[j] in the NTT domain. Each product is below q in absolute
/// value and `add` Barrett-reduces after every step, so nothing overflows.
fn inner_product_ntt(p: &Params, a: impl Fn(usize) -> Poly, b: &PolyVec) -> Poly {
    let mut acc = Poly::ZERO;
    for j in 0..p.k {
        acc = acc.add(&multiply_ntts(&a(j), &b[j]));
    }
    acc
}

/// Algorithm 13 K-PKE.KeyGen(d).
/// Writes ek_PKE (384k + 32 bytes) and dk_PKE (384k bytes).
pub(crate) fn keygen(p: &Params, d: &[u8; 32], ek: &mut [u8], dk: &mut [u8]) {
    let k = p.k;
    assert!(ek.len() == p.ek_len() && dk.len() == p.dk_pke_len());

    // line 1: (ρ, σ) ← G(d ‖ k). The extra byte k separates parameter sets,
    // so one seed gives unrelated keys under different parameter sets.
    let (rho, sigma) = hash::g(&[d, &[k as u8]]);

    // lines 2–15: s and e from the CBD, with one shared counter N.
    let mut n = 0u8;
    let mut s_hat = [Poly::ZERO; MAX_K];
    let mut e_hat = [Poly::ZERO; MAX_K];
    for i in 0..k {
        s_hat[i] = sample_noise(p.eta1, &sigma, &mut n);
    }
    for i in 0..k {
        e_hat[i] = sample_noise(p.eta1, &sigma, &mut n);
    }

    // lines 16–17: move s and e to the NTT domain.
    for i in 0..k {
        ntt(&mut s_hat[i]);
        ntt(&mut e_hat[i]);
    }

    // line 18: t̂ = Â ∘ ŝ + ê, row by row: t̂[i] = Σ_j Â[i, j] ∘ ŝ[j] + ê[i].
    for i in 0..k {
        let t_hat_i = inner_product_ntt(p, |j| matrix_entry(&rho, i, j), &s_hat).add(&e_hat[i]);
        // line 19: ek_PKE ← ByteEncode_12(t̂) ‖ ρ
        poly_encode12(&t_hat_i, &mut ek[384 * i..384 * (i + 1)]);
    }
    ek[384 * k..].copy_from_slice(&rho);

    // line 20: dk_PKE ← ByteEncode_12(ŝ)
    for i in 0..k {
        poly_encode12(&s_hat[i], &mut dk[384 * i..384 * (i + 1)]);
    }
}

/// Algorithm 14 K-PKE.Encrypt(ek_PKE, m, r). Writes c (32(du·k + dv) bytes).
pub(crate) fn encrypt(p: &Params, ek: &[u8], m: &[u8; 32], r: &[u8; 32], c: &mut [u8]) {
    let k = p.k;
    assert!(ek.len() == p.ek_len() && c.len() == p.ct_len());

    // lines 2–3: decode t̂ and extract ρ.
    let mut t_hat = [Poly::ZERO; MAX_K];
    for i in 0..k {
        t_hat[i] = poly_decode12(&ek[384 * i..384 * (i + 1)]);
    }
    let rho: &[u8; 32] = ek[384 * k..].try_into().unwrap();

    // lines 9–17: y (η1), e1 (η2) and e2 (η2) from PRF(r, N).
    let mut n = 0u8;
    let mut y_hat = [Poly::ZERO; MAX_K];
    let mut e1 = [Poly::ZERO; MAX_K];
    for i in 0..k {
        y_hat[i] = sample_noise(p.eta1, r, &mut n);
    }
    for i in 0..k {
        e1[i] = sample_noise(p.eta2, r, &mut n);
    }
    let e2 = sample_noise(p.eta2, r, &mut n);

    // line 18
    for i in 0..k {
        ntt(&mut y_hat[i]);
    }

    // line 19: u = NTT⁻¹(Âᵀ ∘ ŷ) + e1. Row i of Âᵀ is column i of Â, so
    // u[i] = NTT⁻¹(Σ_j Â[j, i] ∘ ŷ[j]) + e1[i].
    // line 22: c1 ← ByteEncode_du(Compress_du(u)).
    let c1_len = 32 * p.du as usize;
    for i in 0..k {
        let mut u_i = inner_product_ntt(p, |j| matrix_entry(rho, j, i), &y_hat);
        ntt_inverse(&mut u_i);
        let u_i = u_i.add(&e1[i]);
        poly_compress_encode(&u_i, p.du, &mut c[c1_len * i..c1_len * (i + 1)]);
    }

    // line 20: μ ← Decompress_1(ByteDecode_1(m)). Each bit of m becomes
    // 0 or ⌈q/2⌋ = 1665.
    let mu = poly_decode_decompress(1, m);

    // line 21: v ← NTT⁻¹(t̂ᵀ ∘ ŷ) + e2 + μ
    let mut v = inner_product_ntt(p, |j| t_hat[j], &y_hat);
    ntt_inverse(&mut v);
    let v = v.add(&e2).add(&mu);

    // line 23–24: c2 ← ByteEncode_dv(Compress_dv(v)); c ← c1 ‖ c2
    poly_compress_encode(&v, p.dv, &mut c[c1_len * k..]);
}

/// Algorithm 15 K-PKE.Decrypt(dk_PKE, c). Returns m.
pub(crate) fn decrypt(p: &Params, dk: &[u8], c: &[u8]) -> [u8; 32] {
    let k = p.k;
    assert!(dk.len() == p.dk_pke_len() && c.len() == p.ct_len());
    let c1_len = 32 * p.du as usize;

    // lines 1–5: u′, v′ from the ciphertext; ŝ from the key.
    // line 6: w ← v′ − NTT⁻¹(ŝᵀ ∘ NTT(u′)).
    let mut acc = Poly::ZERO;
    for i in 0..k {
        let mut u_i = poly_decode_decompress(p.du, &c[c1_len * i..c1_len * (i + 1)]);
        ntt(&mut u_i);
        let s_hat_i = poly_decode12(&dk[384 * i..384 * (i + 1)]);
        acc = acc.add(&multiply_ntts(&s_hat_i, &u_i));
    }
    ntt_inverse(&mut acc);
    let v = poly_decode_decompress(p.dv, &c[c1_len * k..]);
    let w = v.sub(&acc);

    // line 7: m ← ByteEncode_1(Compress_1(w)). w is secret: Compress is the
    // KyberSlash-sensitive step, which is why it uses no division.
    let mut m = [0u8; 32];
    poly_compress_encode(&w, 1, &mut m);
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{ML_KEM_512, ML_KEM_768, ML_KEM_1024};
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]
        /// Decrypt(Encrypt(m)) = m for honestly generated keys. (This can
        /// fail with probability about 2^-139 or less, the "decryption
        /// failure rate", which is far too small to ever see.)
        #[test]
        fn encrypt_decrypt_round_trip(d: [u8; 32], m: [u8; 32], r: [u8; 32], which in 0usize..3) {
            let p = [ML_KEM_512, ML_KEM_768, ML_KEM_1024][which];
            let mut ek = vec![0u8; p.ek_len()];
            let mut dk = vec![0u8; p.dk_pke_len()];
            keygen(&p, &d, &mut ek, &mut dk);
            let mut c = vec![0u8; p.ct_len()];
            encrypt(&p, &ek, &m, &r, &mut c);
            prop_assert_eq!(decrypt(&p, &dk, &c), m);
        }
    }
}
