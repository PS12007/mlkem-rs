//! Arithmetic in Z_q, q = 3329 (Z_m notation: FIPS 203 §2.3; q: §8).
//!
//! # Representation
//! An element of Z_q is stored as an `i16` that is congruent to the value
//! mod q but not necessarily in [0, q). Each function says what range its
//! output is in. [`to_canonical`] maps to [0, q) when exact bytes are needed
//! (encoding, compression). Signed values make Montgomery reduction cheap
//! and let additions be "lazy" (reduce later, not after every `+`).
//!
//! # Why not just `%`?
//! `x % q` compiles to a multiply-and-shift when q is a compile-time constant
//! on x86-64, but that is up to the compiler. On other targets, or if q
//! is not visible as a constant, it becomes a `div`/`idiv` instruction, and
//! on many CPUs that takes longer or shorter depending on its input. With a
//! secret input that is a timing leak (KyberSlash). Barrett and Montgomery
//! reduction use only multiply, add, subtract and shift, so we *know* which
//! instructions run.
//!
//! # Constant-time notes
//! Nothing here branches or indexes memory. `>>` on a signed integer is an
//! arithmetic shift: `x >> 15` on an i16 is 0 if x ≥ 0 and −1 (all ones) if
//! x < 0. That gives a mask without a comparison.

use crate::params::Q;

pub(crate) const Q32: i32 = Q as i32;

/// q^{-1} mod 2^16, as a signed 16-bit value: q · QINV ≡ 1 (mod 2^16).
pub(crate) const QINV: i16 = -3327;

/// R mod q where R = 2^16 is the Montgomery radix. `x·R mod q` is
/// "x in Montgomery form".
pub(crate) const MONT: i16 = 2285;

/// R^2 mod q. Montgomery-multiplying by this converts x·R^{-1} back to x.
pub(crate) const R2: i16 = 1353;

// Check the constants at compile time instead of trusting hand arithmetic.
const _: () = {
    assert!((Q32 * QINV as i32) & 0xFFFF == 1);
    assert!((1i32 << 16) % Q32 == MONT as i32);
    assert!((MONT as i32 * MONT as i32) % Q32 == R2 as i32);
};

/// Montgomery reduction: returns r ≡ a · 2^{-16} (mod q), with −q < r < q.
///
/// Precondition: −q·2^15 ≤ a < q·2^15. Every caller multiplies two i16 values
/// where at least one is below q in absolute value, so this always holds.
///
/// How it works: pick t ≡ a·q^{-1} (mod 2^16). Then a − t·q ≡ 0 (mod 2^16),
/// so the shift by 16 is an *exact* division by 2^16, and the result is
/// still ≡ a·2^{-16} mod q because we only subtracted a multiple of q.
/// Range: |a − t·q| < q·2^15 + 2^15·q = q·2^16, so |r| < q.
#[inline]
pub(crate) fn montgomery_reduce(a: i32) -> i16 {
    // `as i16` keeps the low 16 bits; wrapping_mul is multiplication mod 2^16.
    let t = (a as i16).wrapping_mul(QINV);
    // Exact: the low 16 bits of (a - t*q) are zero.
    ((a - i32::from(t) * Q32) >> 16) as i16
}

/// Montgomery multiplication: returns ≡ a·b·2^{-16} (mod q), in (−q, q).
/// To get a plain product a·b, pass one operand in Montgomery form (b·R).
#[inline]
pub(crate) fn fqmul(a: i16, b: i16) -> i16 {
    montgomery_reduce(i32::from(a) * i32::from(b))
}

/// Barrett reduction: returns r ≡ a (mod q), with −(q−1)/2 ≤ r ≤ (q−1)/2.
/// Works for every i16 input.
///
/// How it works: V = round(2^26 / q), so a·V / 2^26 ≈ a / q. Rounding that
/// gives t = round(a / q) for all |a| < 2^15 (checked exhaustively by the
/// tests), and a − t·q is the centred remainder.
#[inline]
pub(crate) fn barrett_reduce(a: i16) -> i16 {
    const V: i32 = ((1 << 26) + Q32 / 2) / Q32; // 20159, computed at compile time
    let t = ((V * i32::from(a) + (1 << 25)) >> 26) as i16;
    // |t| can reach 10, and 10·q = 33290 does not fit in an i16, so `t * Q`
    // overflows (the tests caught this). The *final* value a − t·q always
    // fits in [−1664, 1664], and arithmetic mod 2^16 gives the right answer
    // whenever the true result fits, so wrapping operations are correct.
    // (The C reference code relies on the same 16-bit wraparound.)
    a.wrapping_sub(t.wrapping_mul(Q))
}

/// Maps a value in (−q, q) to its canonical representative in [0, q).
///
/// `a >> 15` is all ones when a < 0 and all zeros otherwise, so this adds
/// q only to negative values, with no branch.
#[inline]
pub(crate) fn to_canonical(a: i16) -> u16 {
    (a + ((a >> 15) & Q)) as u16
}

/// Conditionally subtracts q: maps [0, 2q) to [0, q) with no branch.
#[inline]
pub(crate) fn csubq(a: i16) -> i16 {
    let a = a - Q;
    a + ((a >> 15) & Q)
}

#[cfg(test)]
mod tests {
    use super::*;

    const QI: i64 = Q as i64;
    /// 2^{-16} mod q, computed independently: 2285 · 169 = 386165 = 116·q + 1.
    const R_INV: i64 = 169;

    #[test]
    fn r_inv_is_inverse() {
        assert_eq!((MONT as i64 * R_INV) % QI, 1);
    }

    /// Every input in the documented domain: 2·q·2^15 ≈ 2.2·10^8 values.
    #[test]
    fn montgomery_reduce_exhaustive() {
        let lim = Q32 << 15;
        for a in -lim..lim {
            let r = montgomery_reduce(a);
            assert!(r > -Q && r < Q, "range: a={a} r={r}");
            assert_eq!(
                (i64::from(r) - i64::from(a) * R_INV).rem_euclid(QI),
                0,
                "congruence: a={a}"
            );
        }
    }

    #[test]
    fn barrett_reduce_exhaustive() {
        for a in i16::MIN..=i16::MAX {
            let r = barrett_reduce(a);
            assert!(r.abs() <= (Q - 1) / 2, "range: a={a} r={r}");
            assert_eq!((i64::from(a) - i64::from(r)).rem_euclid(QI), 0, "a={a}");
        }
    }

    #[test]
    fn to_canonical_and_csubq_exhaustive() {
        for a in (-Q + 1)..Q {
            assert_eq!(i64::from(to_canonical(a)), i64::from(a).rem_euclid(QI));
        }
        for a in 0..(2 * Q32) {
            let a = a as i16;
            assert_eq!(i64::from(csubq(a)), i64::from(a) % QI);
        }
    }

    /// fqmul against plain integer arithmetic, for every a in (−q, q)
    /// against a spread of b values that includes the extremes.
    #[test]
    fn fqmul_matches_integer_math() {
        let bs = [-Q + 1, -1665, -1, 0, 1, 17, MONT, R2, 1664, Q - 1];
        for a in (-Q + 1)..Q {
            for &b in &bs {
                let r = fqmul(a, b);
                assert!(r > -Q && r < Q);
                let want = (i64::from(a) * i64::from(b) * R_INV).rem_euclid(QI);
                assert_eq!(i64::from(r).rem_euclid(QI), want, "a={a} b={b}");
            }
        }
    }
}
