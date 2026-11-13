//! ML-KEM internal algorithms (FIPS 203 §6) and input checks (§7.2, §7.3).
//!
//! These work on byte slices with a runtime [`Params`]. The typed public API
//! in `lib.rs` (`ml_kem_512`, …) wraps them with fixed-size arrays.
//!
//! # The Fujisaki–Okamoto (FO) transform in one paragraph
//! Encaps does not encrypt a random key directly. It picks a random m,
//! derives *both* the shared key K and the encryption randomness r from
//! G(m ‖ H(ek)), and encrypts m with that r. Encryption is therefore
//! deterministic given m, so Decaps can decrypt to m′, re-encrypt with the
//! same derived r′, and check that it gets the *same* ciphertext. A
//! ciphertext that an attacker tampered with or crafted will not
//! re-encrypt to itself, and is rejected. That is what turns K-PKE (secure
//! against passive attackers) into a KEM secure against chosen-ciphertext
//! attacks (IND-CCA2). LEARNING.md §3 explains why that matters.

use crate::ct::{ct_eq_bytes, ct_select_bytes};
use crate::encode::{byte_decode, byte_encode};
use crate::hash;
use crate::kpke;
use crate::params::{MAX_CT_LEN, Params};

/// Algorithm 16 ML-KEM.KeyGen_internal(d, z).
pub(crate) fn keygen_internal(
    p: &Params,
    d: &[u8; 32],
    z: &[u8; 32],
    ek: &mut [u8],
    dk: &mut [u8],
) {
    assert!(ek.len() == p.ek_len() && dk.len() == p.dk_len());
    let k384 = p.dk_pke_len();
    // line 1–2: (ek_PKE, dk_PKE) ← K-PKE.KeyGen(d); ek ← ek_PKE
    kpke::keygen(p, d, ek, &mut dk[..k384]);
    // line 3: dk ← dk_PKE ‖ ek ‖ H(ek) ‖ z
    let (_, rest) = dk.split_at_mut(k384);
    let (dk_ek, rest) = rest.split_at_mut(p.ek_len());
    let (dk_h, dk_z) = rest.split_at_mut(32);
    dk_ek.copy_from_slice(ek);
    dk_h.copy_from_slice(&hash::h(&[ek]));
    dk_z.copy_from_slice(z);
}

/// Algorithm 17 ML-KEM.Encaps_internal(ek, m). Writes c, returns K.
pub(crate) fn encaps_internal(p: &Params, ek: &[u8], m: &[u8; 32], c: &mut [u8]) -> [u8; 32] {
    // line 1: (K, r) ← G(m ‖ H(ek))
    let (k, r) = hash::g(&[m, &hash::h(&[ek])]);
    // line 2: c ← K-PKE.Encrypt(ek, m, r)
    kpke::encrypt(p, ek, m, &r, c);
    k
}

/// Algorithm 18 ML-KEM.Decaps_internal(dk, c). Returns K′.
///
/// **Constant time: required, and the most important function in the
/// crate.** An attacker controls c and can send many modified ciphertexts.
/// If *anything* observable depended on whether re-encryption matched (an
/// early return, a different branch, a comparison that stops at the first
/// differing byte), the attacker would learn, one query at a time, whether
/// their modification changed the decrypted m′. That is enough to recover
/// the secret key. So both candidate keys are always computed, the
/// comparison touches every byte, and the result is chosen with a mask.
pub(crate) fn decaps_internal(p: &Params, dk: &[u8], c: &[u8]) -> [u8; 32] {
    assert!(dk.len() == p.dk_len() && c.len() == p.ct_len());
    let k384 = p.dk_pke_len();
    // lines 1–4: split dk.
    let dk_pke = &dk[..k384];
    let ek_pke = &dk[k384..k384 + p.ek_len()];
    let h = &dk[k384 + p.ek_len()..k384 + p.ek_len() + 32];
    let z = &dk[k384 + p.ek_len() + 32..];

    // line 5: m′ ← K-PKE.Decrypt(dk_PKE, c)
    let m_prime = kpke::decrypt(p, dk_pke, c);
    // line 6: (K′, r′) ← G(m′ ‖ h)
    let (k_prime, r_prime) = hash::g(&[&m_prime, h]);
    // line 7: K̄ ← J(z ‖ c), the implicit-rejection key. Always computed,
    // even if it will not be used.
    let k_bar = hash::j(&[z, c]);
    // line 8: c′ ← K-PKE.Encrypt(ek_PKE, m′, r′)
    let mut c_prime_buf = [0u8; MAX_CT_LEN];
    let c_prime = &mut c_prime_buf[..p.ct_len()];
    kpke::encrypt(p, ek_pke, &m_prime, &r_prime, c_prime);

    // lines 9–11: if c ≠ c′ then K′ ← K̄, without a branch.
    let equal = ct_eq_bytes(c, c_prime); // 0xFF if equal, 0x00 if not
    let mut out = [0u8; 32];
    ct_select_bytes(&mut out, &k_prime, &k_bar, equal);
    out
}

/// Encapsulation key check (§7.2): type check (length) and modulus check
/// (eq. 7.1): ByteEncode_12(ByteDecode_12(ek[0 : 384k])) must equal
/// ek[0 : 384k]. In other words, every 12-bit value must be below q.
/// ek is public, so this may use ordinary comparisons.
pub(crate) fn ek_check(p: &Params, ek: &[u8]) -> bool {
    if ek.len() != p.ek_len() {
        return false;
    }
    let mut buf = [0u8; 384];
    for chunk in ek[..p.dk_pke_len()].chunks_exact(384) {
        byte_encode(12, &byte_decode(12, chunk), &mut buf);
        if buf[..] != chunk[..] {
            return false;
        }
    }
    true
}

/// Decapsulation key check (§7.3, items 2–3): type check (length) and hash
/// check (eq. 7.2): H(dk[384k : 768k + 32]) must equal dk[768k + 32 : 768k + 64].
/// Both sides are derived from the *public* ek, so nothing secret is
/// compared, but we use the constant-time comparison anyway: it costs
/// nothing here.
pub(crate) fn dk_check(p: &Params, dk: &[u8]) -> bool {
    if dk.len() != p.dk_len() {
        return false;
    }
    let k384 = p.dk_pke_len();
    let ek = &dk[k384..k384 + p.ek_len()];
    let h = &dk[k384 + p.ek_len()..k384 + p.ek_len() + 32];
    ct_eq_bytes(&hash::h(&[ek]), h) == 0xFF
}
