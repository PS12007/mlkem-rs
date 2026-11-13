//! Sampling (FIPS 203 §4.2.2): SampleNTT (Alg 7) and SamplePolyCBD_η (Alg 8).

use crate::params::{N, Q};
use crate::poly::Poly;

/// An extendable-output stream, i.e. FIPS 203's XOF.Squeeze (§4.1).
/// Phase 2 implements this for SHAKE128. The tests here use a plain byte
/// slice.
///
/// Squeezing is a stream: squeezing 3 bytes 56 times gives the same bytes as
/// squeezing 168 bytes once. That is why `sample_ntt` can read whole
/// 168-byte blocks (the SHAKE128 rate) while Alg 7 reads 3 bytes at a time.
pub(crate) trait XofReader {
    fn squeeze(&mut self, out: &mut [u8]);
}

/// Algorithm 7 SampleNTT: rejection-sample a uniform element of T_q.
///
/// The caller has already run XOF.Init and XOF.Absorb(ρ‖j‖i) (lines 1–2).
/// This function runs lines 3–17. Output coefficients are in [0, q).
///
/// **Constant time: not needed here, and that is deliberate.** The loop
/// takes a data-dependent number of steps, and the `if`s branch on the
/// candidate values. That is fine only because the input is the public seed
/// ρ, which is part of the encapsulation key. Timing can reveal at most
/// something about ρ, which an attacker already has. (If secret data were ever
/// fed in here, this would be a leak.)
///
/// Appendix B says the loop should not be bounded. We follow that: it ends
/// with probability 1, and needing more than 280 iterations has probability
/// about 2^−261.
pub(crate) fn sample_ntt(xof: &mut impl XofReader) -> Poly {
    let mut a = Poly::ZERO;
    let mut j = 0; // line 3
    let mut block = [0u8; 168];
    loop {
        // line 4: while j < 256
        xof.squeeze(&mut block);
        for c in block.chunks_exact(3) {
            // line 5: C = next 3 bytes
            let d1 = u16::from(c[0]) | ((u16::from(c[1]) & 0x0F) << 8); // line 6
            let d2 = (u16::from(c[1]) >> 4) | (u16::from(c[2]) << 4); // line 7
            if d1 < Q as u16 {
                // line 8
                a.coeffs[j] = d1 as i16; // line 9
                j += 1; // line 10
            }
            if d2 < Q as u16 && j < N {
                // line 12
                a.coeffs[j] = d2 as i16; // line 13
                j += 1; // line 14
            }
            if j == N {
                return a; // line 17
            }
        }
    }
}

/// Algorithm 8 SamplePolyCBD_η: a polynomial with small coefficients from
/// the centred binomial distribution, given 64·η bytes of PRF output.
///
/// Coefficient i is x − y, where x is the sum of η bits and y is the sum of the
/// next η bits. So it lies in [−η, η], and it is most likely to be 0. It is
/// returned as a signed i16 (≡ x − y mod q, which is what Alg 8 line 5 means).
///
/// **Constant time: required.** These bytes become the secret s and the error
/// e. Bit positions depend only on the loop counters (i, j). The bit
/// *values* are only shifted, masked and added, never compared or used as
/// indices.
pub(crate) fn sample_poly_cbd(eta: usize, b: &[u8]) -> Poly {
    assert!((eta == 2 || eta == 3) && b.len() == 64 * eta);
    // bit k of the stream = bit (k mod 8) of byte ⌊k/8⌋ (BytesToBits, Alg 4)
    let bit = |k: usize| i16::from((b[k / 8] >> (k % 8)) & 1);
    let mut f = Poly::ZERO;
    for i in 0..N {
        let mut x = 0; // line 3
        let mut y = 0; // line 4
        for j in 0..eta {
            x += bit(2 * i * eta + j);
            y += bit(2 * i * eta + eta + j);
        }
        f.coeffs[i] = x - y; // line 5
    }
    f
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::spec;
    use proptest::prelude::*;

    /// A finite byte stream that panics if the sampler reads past the end.
    pub(crate) struct SliceXof<'a>(pub &'a [u8]);
    impl XofReader for SliceXof<'_> {
        fn squeeze(&mut self, out: &mut [u8]) {
            let (head, tail) = self.0.split_at(out.len());
            out.copy_from_slice(head);
            self.0 = tail;
        }
    }

    /// A whole first block of 0xFF bytes (every candidate is 0xFFF = 4095 ≥ q,
    /// so all are rejected), then 128 triples giving two accepted values each.
    #[test]
    fn rejects_out_of_range_values() {
        let mut s = vec![0xFF; 168];
        for _ in 0..128 {
            s.extend_from_slice(&[0x01, 0x20, 0x00]); // d1 = 1, d2 = 2
        }
        s.resize(168 * 4, 0xFF);
        let a = sample_ntt(&mut SliceXof(&s));
        for i in 0..128 {
            assert_eq!((a.coeffs[2 * i], a.coeffs[2 * i + 1]), (1, 2));
        }
    }

    /// The d2-dropped edge case (Alg 7 line 12, "and j < 256"): d1 fills the
    /// last slot, so the valid d2 in the same triple must be thrown away.
    #[test]
    fn last_d2_is_dropped() {
        let mut s = vec![];
        s.extend_from_slice(&[0x05, 0xF0, 0xFF]); // d1 = 5, d2 = 0xFFF rejected
        for _ in 0..127 {
            s.extend_from_slice(&[0x01, 0x20, 0x00]); // two values each
        }
        // j = 255 now. d1 = 7 is accepted (j becomes 256), d2 = 9 must be dropped.
        s.extend_from_slice(&[0x07, 0x90, 0x00]);
        s.resize(168 * 3, 0);
        let a = sample_ntt(&mut SliceXof(&s));
        assert_eq!(a.coeffs[0], 5);
        assert_eq!(a.coeffs[255], 7);
        assert_eq!(a.canonical().map(i64::from), spec::sample_ntt(&s));
    }

    proptest! {
        #[test]
        fn sample_ntt_matches_spec(s in prop::collection::vec(any::<u8>(), 168 * 8)) {
            let a = sample_ntt(&mut SliceXof(&s));
            prop_assert!(a.coeffs.iter().all(|&c| (0..Q).contains(&c)));
            prop_assert_eq!(a.canonical().map(i64::from), spec::sample_ntt(&s));
        }

        #[test]
        fn cbd_matches_spec(eta in 2usize..=3, b in prop::collection::vec(any::<u8>(), 192)) {
            let b = &b[..64 * eta];
            let f = sample_poly_cbd(eta, b);
            let e = eta as i16;
            prop_assert!(f.coeffs.iter().all(|&c| (-e..=e).contains(&c)));
            prop_assert_eq!(f.canonical().map(i64::from), spec::sample_poly_cbd(eta, b));
        }
    }
}
