//! The Keccak-f[1600] permutation (FIPS 202 §3).
//!
//! FIPS 202: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
//!
//! # State layout
//! FIPS 202 describes the 1600-bit state as a 5×5×64 array A[x, y, z]. A
//! "lane" A[x, y, ·] is 64 bits, so it fits exactly in one `u64` with bit z of
//! the lane at bit position z. We store lane (x, y) at index `x + 5*y`
//! (FIPS 202 §3.1.2). Bytes enter the lanes little-endian (§B.1).
//!
//! # Constant time
//! Keccak is naturally constant time: only XOR, AND, NOT and rotations by
//! *constant* amounts, and no tables indexed by data (the round constant is
//! indexed by the round counter). That is one reason it was chosen for SHA-3.

/// Number of rounds for Keccak-f[1600]: 12 + 2·ℓ with ℓ = log2(64) = 6.
const ROUNDS: usize = 24;

/// rc(t) from FIPS 202 Algorithm 5: one output bit of an 8-bit LFSR with
/// feedback polynomial x^8 + x^6 + x^5 + x^4 + 1.
///
/// We keep the register R as an integer with bit k = R[k]. Then "R = 0 ‖ R"
/// is `r <<= 1`. XORing R[8] into R[0], R[4], R[5] and R[6], and then
/// truncating to 8 bits, is the single XOR with 0x171 (bits 8, 6, 5, 4, 0)
/// whenever bit 8 is set.
const fn rc_bit(t: usize) -> u64 {
    let t = t % 255; // Alg 5 step 1: if t mod 255 = 0, return 1
    let mut r: u16 = 1; // step 2: R = 10000000 (R[0] = 1)
    let mut i = 0;
    while i < t {
        r <<= 1;
        if r & 0x100 != 0 {
            r ^= 0x171;
        }
        i += 1;
    }
    (r & 1) as u64 // step 4: return R[0]
}

/// The 24 round constants used by ι (FIPS 202 Algorithm 6). For round i_r,
/// bit 2^j − 1 of RC is rc(j + 7·i_r), for j = 0..6.
const RC: [u64; ROUNDS] = {
    let mut rc = [0u64; ROUNDS];
    let mut ir = 0;
    while ir < ROUNDS {
        let mut j = 0;
        while j <= 6 {
            rc[ir] |= rc_bit(j + 7 * ir) << ((1 << j) - 1);
            j += 1;
        }
        ir += 1;
    }
    rc
};

/// Rotation offsets for ρ (FIPS 202 Algorithm 2), indexed by `x + 5*y`.
/// Start at (x, y) = (1, 0). Step t gets offset (t+1)(t+2)/2 mod 64, then
/// moves to (y, (2x + 3y) mod 5). Lane (0, 0) is never rotated.
const RHO: [u32; 25] = {
    let mut r = [0u32; 25];
    let (mut x, mut y) = (1usize, 0usize);
    let mut t = 0;
    while t < 24 {
        r[x + 5 * y] = (((t + 1) * (t + 2) / 2) % 64) as u32;
        let next_y = (2 * x + 3 * y) % 5;
        x = y;
        y = next_y;
        t += 1;
    }
    r
};

/// x + 1, x + 2 and x − 1 (mod 5) as tables. The indices are public loop
/// counters, so `%` would be harmless. But at opt-level 0 the compiler emits
/// a real `div` for it, and with tables the assembly check can require
/// "no division anywhere in this crate, at any optimisation level" with
/// no exceptions.
const PLUS1: [usize; 5] = [1, 2, 3, 4, 0];
const PLUS2: [usize; 5] = [2, 3, 4, 0, 1];
const MINUS1: [usize; 5] = [4, 0, 1, 2, 3];

/// π source index for each destination (x, y): lane (x + 3y mod 5, x).
const PI_SRC: [usize; 25] = {
    let mut t = [0usize; 25];
    let mut i = 0;
    while i < 25 {
        let (x, y) = (i % 5, i / 5); // compile time only
        t[i] = (x + 3 * y) % 5 + 5 * x;
        i += 1;
    }
    t
};

/// Keccak-f[1600] = 24 rounds of θ, ρ, π, χ, ι (FIPS 202 §3.3, Alg 7).
pub(crate) fn f1600(a: &mut [u64; 25]) {
    for rc in RC {
        // θ (Alg 1): XOR each bit with the parities of two nearby columns.
        // C[x] = parity of column x. D[x] = C[x−1] ⊕ rot(C[x+1], 1).
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            let d = c[MINUS1[x]] ^ c[PLUS1[x]].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }

        // ρ (Alg 2) and π (Alg 3) together: π moves lane (x+3y mod 5, x) to
        // position (x, y). ρ rotates each lane by its own fixed offset.
        let mut b = [0u64; 25];
        for i in 0..25 {
            let src = PI_SRC[i];
            b[i] = a[src].rotate_left(RHO[src]);
        }

        // χ (Alg 4): the only non-linear step.
        // A[x,y] = B[x,y] ⊕ (¬B[x+1,y] ∧ B[x+2,y]).
        for y in 0..5 {
            for x in 0..5 {
                a[x + 5 * y] = b[x + 5 * y] ^ (!b[PLUS1[x] + 5 * y] & b[PLUS2[x] + 5 * y]);
            }
        }

        // ι (Alg 6): break the symmetry between rounds.
        a[0] ^= rc;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// First, second and last round constants as listed in the Keccak
    /// reference (and checked indirectly by every permutation test below).
    #[test]
    fn round_constants() {
        assert_eq!(RC[0], 0x0000_0000_0000_0001);
        assert_eq!(RC[1], 0x0000_0000_0000_8082);
        assert_eq!(RC[23], 0x8000_0000_8000_8008);
        assert_eq!(RHO[0], 0); // lane (0,0) is never rotated
        assert_eq!(RHO[1], 1); // t = 0 at (1,0): (1·2)/2 = 1
    }

    #[test]
    fn zero_state_matches_reference_crate() {
        let (mut ours, mut theirs) = ([0u64; 25], [0u64; 25]);
        f1600(&mut ours);
        keccak::f1600(&mut theirs);
        assert_eq!(ours, theirs);
    }

    proptest! {
        #[test]
        fn matches_reference_crate(state in any::<[u64; 25]>()) {
            let (mut ours, mut theirs) = (state, state);
            f1600(&mut ours);
            keccak::f1600(&mut theirs);
            prop_assert_eq!(ours, theirs);
        }
    }
}
