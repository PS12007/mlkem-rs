//! Polynomials in R_q = Z_q[X]/(X^256 + 1), and their NTT representations
//! in T_q (FIPS 203 §2.3 / §4.3).
//!
//! The same struct holds both. Which domain a `Poly` is in follows from where
//! it came from (`ntt::ntt` output, `sample_ntt` output, etc.) and is noted
//! at each use. A real library might make these two different types so the
//! compiler catches mix-ups. That alternative is discussed in LEARNING.md.

use crate::field::{barrett_reduce, to_canonical};
use crate::params::N;

/// 256 coefficients, each stored as an `i16` congruent to its value mod q.
///
/// **Invariant**: every coefficient satisfies |c| < q between operations,
/// unless a function says otherwise. Functions that need exact values in
/// [0, q) call [`Poly::canonical`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Poly {
    pub(crate) coeffs: [i16; N],
}

impl Poly {
    pub(crate) const ZERO: Poly = Poly { coeffs: [0; N] };

    /// Coefficient-wise addition. With inputs below q in absolute value the
    /// sum is below 2q, then Barrett brings it back to |c| ≤ (q−1)/2.
    pub(crate) fn add(&self, other: &Poly) -> Poly {
        let mut r = Poly::ZERO;
        for i in 0..N {
            r.coeffs[i] = barrett_reduce(self.coeffs[i] + other.coeffs[i]);
        }
        r
    }

    /// Coefficient-wise subtraction, reduced the same way as `add`.
    pub(crate) fn sub(&self, other: &Poly) -> Poly {
        let mut r = Poly::ZERO;
        for i in 0..N {
            r.coeffs[i] = barrett_reduce(self.coeffs[i] - other.coeffs[i]);
        }
        r
    }

    /// Barrett-reduces every coefficient to |c| ≤ (q−1)/2. Accepts any i16.
    pub(crate) fn reduce(&mut self) {
        for c in &mut self.coeffs {
            *c = barrett_reduce(*c);
        }
    }

    /// Exact representatives in [0, q).
    pub(crate) fn canonical(&self) -> [u16; N] {
        self.coeffs.map(to_canonical)
    }
}
