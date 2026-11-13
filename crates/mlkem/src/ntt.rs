//! The number-theoretic transform (FIPS 203 §4.3): Algorithms 9 to 12.
//!
//! # What this computes
//! X^256 + 1 factors mod q into 128 quadratics X^2 − γ_i, where
//! γ_i = ζ^(2·BitRev7(i)+1) and ζ = 17 is a primitive 256-th root of unity mod
//! q. The NTT maps f ∈ R_q to its 128 remainders f mod (X^2 − γ_i), each a
//! degree-1 polynomial (two coefficients). Multiplication then works on each
//! remainder separately: 128 tiny products instead of one 256×256 product.
//! This is an "incomplete" NTT. It stops at degree 1 because q − 1 is
//! divisible by 256 but not by 512, so there is no 512-th root of unity that
//! would split the quadratics any further.
//!
//! # How the fast version differs from the pseudocode
//! The pseudocode multiplies by ζ and reduces mod q. We store the ζ values in
//! Montgomery form (ζ·R mod q, R = 2^16), so [`fqmul`] (which multiplies and
//! divides by R) returns exactly ζ·x mod q, using only multiply, add and
//! shift. Additions are done without reducing ("lazy reduction"), which is
//! safe because we track how big the values can get (see each function).
//! The outputs match the pseudocode mod q, and the tests check this against
//! `spec.rs`.
//!
//! # Constant time
//! Every loop bound and array index comes from the loop counters, never from
//! coefficient values. The coefficients (which may be secret) only go
//! through `+`, `−` and `fqmul`.

use crate::field::{Q32, R2, barrett_reduce, fqmul, montgomery_reduce};
use crate::params::N;
use crate::poly::Poly;

const ZETA: i32 = 17;
const R_MOD_Q: i32 = (1 << 16) % Q32;

/// BitRev7: reverse the 7-bit binary representation of i (FIPS 203 §2.3).
const fn bitrev7(i: usize) -> usize {
    ((i as u8).reverse_bits() >> 1) as usize
}

const fn pow_mod(base: i32, mut exp: usize) -> i32 {
    let mut acc = 1;
    while exp > 0 {
        acc = acc * base % Q32;
        exp -= 1;
    }
    acc
}

/// Representative of x mod q in [−(q−1)/2, (q−1)/2]. This is compile-time
/// only (public constants), so the `if` here is fine.
const fn centered(x: i32) -> i16 {
    let x = x % Q32;
    (if x > Q32 / 2 { x - Q32 } else { x }) as i16
}

/// ζ^BitRev7(i) mod q in [0, q): FIPS 203 Appendix A, first table. The test
/// compares it against the table copied from the PDF.
pub(crate) const ZETAS: [i16; 128] = {
    let mut t = [0i16; 128];
    let mut i = 0;
    while i < 128 {
        t[i] = pow_mod(ZETA, bitrev7(i)) as i16;
        i += 1;
    }
    t
};

/// ζ^(2·BitRev7(i)+1) mod q in [0, q): Appendix A, second table.
pub(crate) const GAMMAS: [i16; 128] = {
    let mut t = [0i16; 128];
    let mut i = 0;
    while i < 128 {
        t[i] = pow_mod(ZETA, 2 * bitrev7(i) + 1) as i16;
        i += 1;
    }
    t
};

/// Same values in Montgomery form, centred, for use with `fqmul`.
const fn to_mont(table: [i16; 128]) -> [i16; 128] {
    let mut t = [0i16; 128];
    let mut i = 0;
    while i < 128 {
        t[i] = centered(table[i] as i32 * R_MOD_Q);
        i += 1;
    }
    t
}
const ZETAS_MONT: [i16; 128] = to_mont(ZETAS);
const GAMMAS_MONT: [i16; 128] = to_mont(GAMMAS);

/// 128^{-1} mod q = 3303 (Alg 10 line 14), in Montgomery form, so that
/// fqmul(x, F) = 3303·x mod q. This works out to 512.
const F_MONT: i16 = centered(3303 * R_MOD_Q);

/// Algorithm 9 NTT(f), in place.
///
/// Input: |f_i| < q. Output: |f_i| ≤ (q−1)/2 (NTT domain).
/// Bound: each of the 7 layers adds at most q to |f_i| (|fqmul| < q), so
/// before the final reduction |f_i| < 8q = 26632 < 2^15. No i16 overflow.
pub(crate) fn ntt(p: &mut Poly) {
    let f = &mut p.coeffs;
    let mut i = 1; // Alg 9 line 2
    let mut len = 128;
    while len >= 2 {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS_MONT[i]; // line 5: ζ^BitRev7(i) (Montgomery form)
            i += 1;
            for j in start..start + len {
                let t = fqmul(zeta, f[j + len]); // line 8: t = ζ·f[j+len]
                f[j + len] = f[j] - t; // line 9
                f[j] += t; // line 10
            }
            start += 2 * len;
        }
        len /= 2;
    }
    p.reduce();
}

/// Algorithm 10 NTT^{-1}(f_hat), in place.
///
/// Input: |f_i| < q. Output: |f_i| < q (polynomial domain).
/// Bound: line 9's sum is Barrett-reduced straight away, so every value
/// stays below 2q in absolute value.
pub(crate) fn ntt_inverse(p: &mut Poly) {
    let f = &mut p.coeffs;
    let mut i = 127; // Alg 10 line 2
    let mut len = 2;
    while len <= 128 {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS_MONT[i]; // line 5
            i -= 1;
            for j in start..start + len {
                let t = f[j]; // line 8
                f[j] = barrett_reduce(t + f[j + len]); // line 9
                f[j + len] = fqmul(zeta, f[j + len] - t); // line 10
            }
            start += 2 * len;
        }
        len *= 2;
    }
    for c in f.iter_mut() {
        *c = fqmul(*c, F_MONT); // line 14: multiply by 3303 = 128^{-1}
    }
}

/// Algorithm 12 BaseCaseMultiply: (a0 + a1·X)(b0 + b1·X) mod (X^2 − γ).
///
/// Inputs |a_i|, |b_i| < q. `gamma_mont` is γ·R mod q. Output |c_i| < q.
///
/// c0 = a0·b0 + a1·b1·γ. Compute t = fqmul(a1, b1) = a1·b1·R^{-1}. Then
/// t·(γ·R) = a1·b1·γ, so s0 = a0·b0 + t·γR is the *exact* c0 mod q, held in
/// an i32: |s0| < q^2 + q·q/2 ≈ 1.7·10^7, well under the q·2^15 ≈ 1.1·10^8
/// that `montgomery_reduce` accepts. Reducing gives s0·R^{-1}. One more
/// fqmul by R^2 mod q removes the R^{-1}, so the output is exactly c0.
/// c1 = a0·b1 + a1·b0 is handled the same way.
///
/// (The C reference skips the last R^2 step and folds the extra R^{-1} into
/// the inverse NTT's constant. That is faster, but then MultiplyNTTs on its
/// own no longer matches FIPS. We keep the exact version and note the
/// optimisation in LEARNING.md.)
#[inline]
fn base_case_multiply(a0: i16, a1: i16, b0: i16, b1: i16, gamma_mont: i16) -> (i16, i16) {
    let t = fqmul(a1, b1);
    let s0 = i32::from(a0) * i32::from(b0) + i32::from(t) * i32::from(gamma_mont);
    let s1 = i32::from(a0) * i32::from(b1) + i32::from(a1) * i32::from(b0);
    (
        fqmul(montgomery_reduce(s0), R2),
        fqmul(montgomery_reduce(s1), R2),
    )
}

/// Algorithm 11 MultiplyNTTs(f_hat, g_hat): the product in T_q.
/// Inputs |c| < q (NTT domain). Output |c| < q.
pub(crate) fn multiply_ntts(f: &Poly, g: &Poly) -> Poly {
    let mut h = Poly::ZERO;
    for i in 0..128 {
        let (c0, c1) = base_case_multiply(
            f.coeffs[2 * i],
            f.coeffs[2 * i + 1],
            g.coeffs[2 * i],
            g.coeffs[2 * i + 1],
            GAMMAS_MONT[i], // γ = ζ^(2·BitRev7(i)+1)
        );
        h.coeffs[2 * i] = c0;
        h.coeffs[2 * i + 1] = c1;
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::Q;
    use crate::spec;
    use proptest::prelude::*;

    fn from_spec(f: &[i64; N]) -> Poly {
        Poly {
            coeffs: f.map(|x| x as i16),
        }
    }
    fn to_spec(p: &Poly) -> [i64; N] {
        p.canonical().map(i64::from)
    }

    /// A random polynomial with coefficients anywhere in (−q, q). The full
    /// signed range is allowed so the overflow bounds above get tested too.
    fn any_poly() -> impl Strategy<Value = Poly> {
        prop::collection::vec(-(Q - 1)..Q, N).prop_map(|v| Poly {
            coeffs: v.try_into().unwrap(),
        })
    }

    #[test]
    fn tables_match_appendix_a() {
        for i in 0..128 {
            assert_eq!(i64::from(ZETAS[i]), spec::APPENDIX_A_ZETAS[i], "zeta {i}");
            assert_eq!(
                i64::from(GAMMAS[i]),
                spec::APPENDIX_A_GAMMAS[i].rem_euclid(spec::Q),
                "gamma {i}"
            );
        }
        assert_eq!(F_MONT, 512);
    }

    #[test]
    fn zeta_is_primitive_256th_root() {
        assert_eq!(pow_mod(ZETA, 128), Q32 - 1); // ζ^128 = −1
        assert_eq!(pow_mod(ZETA, 256), 1);
    }

    /// Worst-case magnitude input: every coefficient ±(q−1).
    #[test]
    fn extreme_inputs_do_not_overflow() {
        for sign in [1i16, -1] {
            let mut p = Poly {
                coeffs: [sign * (Q - 1); N],
            };
            let orig = to_spec(&p);
            ntt(&mut p);
            assert_eq!(to_spec(&p), spec::ntt(&orig));
            let prod = multiply_ntts(&p, &p);
            ntt_inverse(&mut p);
            assert_eq!(to_spec(&p), orig);
            let _ = prod;
        }
    }

    proptest! {
        #[test]
        fn ntt_matches_spec(p in any_poly()) {
            let mut q = p;
            ntt(&mut q);
            prop_assert!(q.coeffs.iter().all(|c| c.abs() <= (Q - 1) / 2));
            prop_assert_eq!(to_spec(&q), spec::ntt(&to_spec(&p)));
        }

        #[test]
        fn ntt_inverse_matches_spec(p in any_poly()) {
            let mut q = p;
            ntt_inverse(&mut q);
            prop_assert!(q.coeffs.iter().all(|c| c.abs() < Q));
            prop_assert_eq!(to_spec(&q), spec::ntt_inverse(&to_spec(&p)));
        }

        #[test]
        fn ntt_round_trip(p in any_poly()) {
            let mut q = p;
            ntt(&mut q);
            ntt_inverse(&mut q);
            prop_assert_eq!(to_spec(&q), to_spec(&p));
        }

        #[test]
        fn multiply_ntts_matches_spec(f in any_poly(), g in any_poly()) {
            let h = multiply_ntts(&f, &g);
            prop_assert!(h.coeffs.iter().all(|c| c.abs() < Q));
            prop_assert_eq!(to_spec(&h), spec::multiply_ntts(&to_spec(&f), &to_spec(&g)));
        }

        /// The whole point of the NTT: NTT^{-1}(NTT(f) ∘ NTT(g)) = f·g in R_q.
        #[test]
        fn ntt_multiplication_equals_schoolbook(f in any_poly(), g in any_poly()) {
            let (mut fh, mut gh) = (f, g);
            ntt(&mut fh);
            ntt(&mut gh);
            let mut h = multiply_ntts(&fh, &gh);
            ntt_inverse(&mut h);
            prop_assert_eq!(to_spec(&h), spec::schoolbook_mul(&to_spec(&f), &to_spec(&g)));
            // the spec's own pipeline agrees too
            let spec_h = spec::ntt_inverse(&spec::multiply_ntts(
                &spec::ntt(&to_spec(&f)), &spec::ntt(&to_spec(&g))));
            prop_assert_eq!(to_spec(&from_spec(&spec_h)), to_spec(&h));
        }
    }
}
