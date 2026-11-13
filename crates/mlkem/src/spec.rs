//! Slow, literal transcriptions of the FIPS 203 pseudocode, used ONLY as test
//! oracles. Compiled only under `cfg(test)`.
//!
//! These functions use plain `i64` and `rem_euclid` (that is, `mod q`) and
//! follow the line numbers of each algorithm, so they are easy to check by
//! eye against the PDF. They are *not* constant time and *not* fast. The
//! optimised code in the other modules is tested against them.

use crate::params::N;

pub const Q: i64 = 3329;

fn m(x: i64) -> i64 {
    x.rem_euclid(Q)
}

/// FIPS 203 Appendix A, first table: ζ^BitRev7(i) mod q for i = 0..127,
/// copied from the PDF (used by Algorithms 9 and 10).
#[rustfmt::skip]
pub const APPENDIX_A_ZETAS: [i64; 128] = [
    1, 1729, 2580, 3289, 2642, 630, 1897, 848,
    1062, 1919, 193, 797, 2786, 3260, 569, 1746,
    296, 2447, 1339, 1476, 3046, 56, 2240, 1333,
    1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
    289, 331, 3253, 1756, 1197, 2304, 2277, 2055,
    650, 1977, 2513, 632, 2865, 33, 1320, 1915,
    2319, 1435, 807, 452, 1438, 2868, 1534, 2402,
    2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
    17, 2761, 583, 2649, 1637, 723, 2288, 1100,
    1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
    1703, 1651, 2789, 1789, 1847, 952, 1461, 2687,
    939, 2308, 2437, 2388, 733, 2337, 268, 641,
    1584, 2298, 2037, 3220, 375, 2549, 2090, 1645,
    1063, 319, 2773, 757, 2099, 561, 2466, 2594,
    2804, 1092, 403, 1026, 1143, 2150, 2775, 886,
    1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
];

/// FIPS 203 Appendix A, second table: ζ^(2·BitRev7(i)+1) mod q for
/// i = 0..127, copied from the PDF *as printed* (signed; used by Alg 11).
#[rustfmt::skip]
pub const APPENDIX_A_GAMMAS: [i64; 128] = [
    17, -17, 2761, -2761, 583, -583, 2649, -2649,
    1637, -1637, 723, -723, 2288, -2288, 1100, -1100,
    1409, -1409, 2662, -2662, 3281, -3281, 233, -233,
    756, -756, 2156, -2156, 3015, -3015, 3050, -3050,
    1703, -1703, 1651, -1651, 2789, -2789, 1789, -1789,
    1847, -1847, 952, -952, 1461, -1461, 2687, -2687,
    939, -939, 2308, -2308, 2437, -2437, 2388, -2388,
    733, -733, 2337, -2337, 268, -268, 641, -641,
    1584, -1584, 2298, -2298, 2037, -2037, 3220, -3220,
    375, -375, 2549, -2549, 2090, -2090, 1645, -1645,
    1063, -1063, 319, -319, 2773, -2773, 757, -757,
    2099, -2099, 561, -561, 2466, -2466, 2594, -2594,
    2804, -2804, 1092, -1092, 403, -403, 1026, -1026,
    1143, -1143, 2150, -2150, 2775, -2775, 886, -886,
    1722, -1722, 1212, -1212, 1874, -1874, 1029, -1029,
    2110, -2110, 2935, -2935, 885, -885, 2154, -2154,
];

/// Algorithm 9 NTT(f), §4.3.
pub fn ntt(f: &[i64; N]) -> [i64; N] {
    let mut f_hat = *f; // 1
    let mut i = 1; // 2
    let mut len = 128; // 3
    while len >= 2 {
        let mut start = 0; // 4
        while start < 256 {
            let zeta = APPENDIX_A_ZETAS[i]; // 5
            i += 1; // 6
            for j in start..start + len {
                // 7
                let t = m(zeta * f_hat[j + len]); // 8
                f_hat[j + len] = m(f_hat[j] - t); // 9
                f_hat[j] = m(f_hat[j] + t); // 10
            }
            start += 2 * len;
        }
        len /= 2;
    }
    f_hat // 14
}

/// Algorithm 10 NTT^{-1}(f_hat), §4.3.
pub fn ntt_inverse(f_hat: &[i64; N]) -> [i64; N] {
    let mut f = *f_hat; // 1
    let mut i = 127; // 2
    let mut len = 2; // 3
    while len <= 128 {
        let mut start = 0; // 4
        while start < 256 {
            let zeta = APPENDIX_A_ZETAS[i]; // 5
            i -= 1; // 6
            for j in start..start + len {
                // 7
                let t = f[j]; // 8
                f[j] = m(t + f[j + len]); // 9
                f[j + len] = m(zeta * (f[j + len] - t)); // 10
            }
            start += 2 * len;
        }
        len *= 2;
    }
    f.map(|x| m(x * 3303)) // 14: 3303 = 128^{-1} mod q
}

/// Algorithm 12 BaseCaseMultiply(a0, a1, b0, b1, γ), §4.3.1.
pub fn base_case_multiply(a0: i64, a1: i64, b0: i64, b1: i64, gamma: i64) -> (i64, i64) {
    let c0 = m(a0 * b0 + m(a1 * b1) * gamma); // 1
    let c1 = m(a0 * b1 + a1 * b0); // 2
    (c0, c1)
}

/// Algorithm 11 MultiplyNTTs(f_hat, g_hat), §4.3.1.
pub fn multiply_ntts(f: &[i64; N], g: &[i64; N]) -> [i64; N] {
    let mut h = [0; N];
    for i in 0..128 {
        let (c0, c1) = base_case_multiply(
            f[2 * i],
            f[2 * i + 1],
            g[2 * i],
            g[2 * i + 1],
            APPENDIX_A_GAMMAS[i],
        );
        h[2 * i] = c0;
        h[2 * i + 1] = c1;
    }
    h
}

/// Textbook multiplication in R_q = Z_q[X]/(X^256 + 1) (§2.3 / §4.3),
/// O(n^2). Because X^256 = −1, a term X^(i+j) with i+j ≥ 256 wraps round to
/// X^(i+j−256) with its sign flipped ("negacyclic").
pub fn schoolbook_mul(f: &[i64; N], g: &[i64; N]) -> [i64; N] {
    let mut h = [0i64; N];
    for i in 0..N {
        for j in 0..N {
            let p = f[i] * g[j];
            if i + j < N {
                h[i + j] += p;
            } else {
                h[i + j - N] -= p;
            }
        }
    }
    h.map(m)
}
