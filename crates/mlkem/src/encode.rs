//! Conversion and compression (FIPS 203 §4.2.1): Compress_d / Decompress_d
//! (eqs. 4.7, 4.8), ByteEncode_d (Alg 5) and ByteDecode_d (Alg 6).
//!
//! BitsToBytes / BytesToBits (Alg 3, 4) define the bit order: bit i of the
//! stream is bit (i mod 8) of byte ⌊i/8⌋, i.e. least significant bit first.
//! The fast code below never builds an explicit bit array. It packs d-bit
//! values straight into bytes with a shift register, giving the same bytes
//! (tests compare against literal Alg 3–6 in `spec.rs`).

use crate::field::Q32;
use crate::params::{N, Q};
use crate::poly::Poly;

/// ⌊n / q⌋ = (n · M) >> 40 with M = ⌈2^40 / q⌉. The tests check that this is
/// exact for every n that `compress` can produce (n < 2^23).
///
/// Why it is exact: n·M / 2^40 = n/q + n·e/(q·2^40), where e = M·q − 2^40 < q.
/// The error term is below 2^23·q/(q·2^40) = 2^−17. The fractional part of
/// n/q is never in (1 − 1/q, 1), because 1/q ≈ 2^−11.7 is much bigger than
/// 2^−17. So adding the error never crosses an integer.
const COMPRESS_M: u64 = (1u64 << 40).div_ceil(Q32 as u64);

/// Compress_d (eq. 4.7): x ↦ ⌈(2^d / q) · x⌋ mod 2^d, for 1 ≤ d ≤ 11.
/// `x` must be canonical, in [0, q).
///
/// **Constant time: this is where KyberSlash happened.** In decryption
/// (Alg 15 line 7) x is a coefficient of w = v − s^T·u, which depends on the
/// secret key. The obvious code is `((x << d) + q/2) / q`. On some compilers
/// and CPUs that `/` becomes a `div` instruction whose latency depends on its
/// input, and measuring it many times recovers the key. Here the division is
/// a 64-bit multiply and a shift, whose timing does not depend on x.
///
/// Rounding: ⌈y⌋ is "round half up" (§2.3), i.e. ⌊y + 1/2⌋. With y = 2^d·x/q,
/// ⌊2^d·x/q + 1/2⌋ = ⌊(2^d·x + (q−1)/2) / q⌋. Exact ties cannot happen,
/// because 2^d·x/q = k + 1/2 would mean 2^(d+1)·x = (2k+1)·q, an even number
/// equal to an odd one.
#[inline]
pub(crate) fn compress(x: u16, d: u32) -> u16 {
    debug_assert!((1..=11).contains(&d) && x < Q as u16);
    let n = (u64::from(x) << d) + (Q32 as u64 - 1) / 2; // 2^d·x + 1664 < 2^23
    let quotient = (n * COMPRESS_M) >> 40; // = ⌊n / q⌋, no division
    (quotient as u16) & ((1u16 << d) - 1) // mod 2^d
}

/// Decompress_d (eq. 4.8): y ↦ ⌈(q / 2^d) · y⌋ = ⌊(q·y + 2^(d−1)) / 2^d⌋.
/// Division by a power of two is a shift. Output in [0, q).
#[inline]
pub(crate) fn decompress(y: u16, d: u32) -> u16 {
    debug_assert!((1..=11).contains(&d) && u32::from(y) < (1 << d));
    ((u32::from(y) * Q32 as u32 + (1 << (d - 1))) >> d) as u16
}

/// Algorithm 5 ByteEncode_d: 256 d-bit integers → 32·d bytes, 1 ≤ d ≤ 12.
///
/// Values must already be < 2^d (d < 12) or < q (d = 12). Each one is
/// masked to d bits, so out-of-range input cannot spill into its neighbour.
///
/// Constant time: the `while` loop runs a number of times fixed by d and
/// the position, never by the data, and every write goes to a public index.
pub(crate) fn byte_encode(d: u32, f: &[u16; N], out: &mut [u8]) {
    assert!((1..=12).contains(&d) && out.len() == 32 * d as usize);
    let mask = (1u32 << d) - 1;
    let mut acc: u32 = 0; // bit buffer, least significant bit = oldest bit
    let mut bits = 0; // number of valid bits in acc (always < 8 + 12)
    let mut pos = 0;
    for &c in f {
        acc |= (u32::from(c) & mask) << bits;
        bits += d;
        while bits >= 8 {
            out[pos] = acc as u8;
            pos += 1;
            acc >>= 8;
            bits -= 8;
        }
    }
}

/// Algorithm 6 ByteDecode_d: 32·d bytes → 256 integers mod m, where
/// m = 2^d for d < 12 and m = q for d = 12.
///
/// For d = 12 a 12-bit value can be up to 4095 ≥ q, and Alg 6 reduces it mod
/// q. The value may be secret (decoding the secret key dk_PKE), so the
/// reduction is a branch-free conditional subtraction: 4095 < 2q, so one
/// subtraction is enough.
pub(crate) fn byte_decode(d: u32, b: &[u8]) -> [u16; N] {
    assert!((1..=12).contains(&d) && b.len() == 32 * d as usize);
    let mask = (1u32 << d) - 1;
    let mut f = [0u16; N];
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut pos = 0;
    for c in &mut f {
        while bits < d {
            acc |= u32::from(b[pos]) << bits;
            pos += 1;
            bits += 8;
        }
        *c = (acc & mask) as u16;
        acc >>= d;
        bits -= d;
    }
    if d == 12 {
        // d is a public parameter, so this branch leaks nothing.
        for c in &mut f {
            *c = crate::field::csubq(*c as i16) as u16;
        }
    }
    f
}

// ---- Polynomial-level helpers used by K-PKE (§5) ----------------------

/// ByteEncode_12 of a polynomial (Alg 13 lines 19–20). Exact values in
/// [0, q) are encoded, so the output is canonical.
pub(crate) fn poly_encode12(p: &Poly, out: &mut [u8]) {
    byte_encode(12, &p.canonical(), out);
}

/// ByteDecode_12 into a polynomial. Output coefficients in [0, q).
pub(crate) fn poly_decode12(b: &[u8]) -> Poly {
    Poly {
        coeffs: byte_decode(12, b).map(|c| c as i16),
    }
}

/// ByteEncode_d(Compress_d(p)) (Alg 14 lines 22–23, Alg 15 line 7).
pub(crate) fn poly_compress_encode(p: &Poly, d: u32, out: &mut [u8]) {
    byte_encode(d, &p.canonical().map(|x| compress(x, d)), out);
}

/// Decompress_d(ByteDecode_d(b)) (Alg 14 line 20, Alg 15 lines 3–4).
/// Output coefficients in [0, q).
pub(crate) fn poly_decode_decompress(d: u32, b: &[u8]) -> Poly {
    Poly {
        coeffs: byte_decode(d, b).map(|y| decompress(y, d) as i16),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec;
    use proptest::prelude::*;

    #[test]
    fn compress_exhaustive_vs_spec() {
        for d in 1..=11 {
            for x in 0..Q as u16 {
                assert_eq!(
                    i64::from(compress(x, d)),
                    spec::compress(i64::from(x), d),
                    "d={d} x={x}"
                );
            }
        }
    }

    #[test]
    fn decompress_exhaustive_vs_spec_and_round_trip() {
        for d in 1..=11 {
            for y in 0..(1u16 << d) {
                let x = decompress(y, d);
                assert_eq!(i64::from(x), spec::decompress(i64::from(y), d));
                assert!(x < Q as u16);
                // FIPS 203 §4.2.1: Compress_d(Decompress_d(y)) = y.
                assert_eq!(compress(x, d), y, "d={d} y={y}");
            }
        }
    }

    /// The multiply-and-shift division is exact for every n compress can
    /// produce, and a bit beyond.
    #[test]
    fn magic_division_is_exact() {
        for n in 0u64..(1 << 23) {
            assert_eq!((n * COMPRESS_M) >> 40, n / Q32 as u64, "n={n}");
        }
    }

    fn values(d: u32) -> impl Strategy<Value = [u16; N]> {
        let max = if d == 12 { Q as u16 } else { 1u16 << d };
        prop::collection::vec(0..max, N).prop_map(|v| v.try_into().unwrap())
    }

    proptest! {
        #[test]
        fn encode_matches_spec_and_round_trips(
            (d, f) in (1u32..=12).prop_flat_map(|d| (Just(d), values(d)))
        ) {
            let mut out = vec![0u8; 32 * d as usize];
            byte_encode(d, &f, &mut out);
            prop_assert_eq!(&out, &spec::byte_encode(d, &f.map(i64::from)));
            prop_assert_eq!(byte_decode(d, &out), f);
        }

        /// Arbitrary bytes, including 12-bit values ≥ q that must be reduced.
        #[test]
        fn decode_arbitrary_bytes_matches_spec(d in 1u32..=12,
                                               b in prop::collection::vec(any::<u8>(), 384)) {
            let b = &b[..32 * d as usize];
            prop_assert_eq!(byte_decode(d, b).map(i64::from), spec::byte_decode(d, b));
        }
    }
}
