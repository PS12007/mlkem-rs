//! Parameter sets (FIPS 203 §8, Tables 2 and 3).

/// n = 256: every polynomial has 256 coefficients (FIPS 203 §8).
pub const N: usize = 256;

/// q = 3329 = 13·2^8 + 1, the prime modulus (FIPS 203 §8).
///
/// q is prime, and 256 divides q − 1 = 3328 = 13·256. That is why Z_q has a
/// primitive 256-th root of unity (ζ = 17), which is what makes the NTT work.
pub const Q: i16 = 3329;

/// One ML-KEM parameter set (FIPS 203 Table 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    pub name: &'static str,
    /// Module rank: vectors have k polynomials, the matrix A is k × k.
    pub k: usize,
    /// CBD parameter for s, e (KeyGen) and y (Encrypt).
    pub eta1: usize,
    /// CBD parameter for e1, e2 (Encrypt).
    pub eta2: usize,
    /// Compression bits for u (the vector part of the ciphertext).
    pub du: u32,
    /// Compression bits for v (the polynomial part of the ciphertext).
    pub dv: u32,
}

impl Params {
    /// Encapsulation key: 384·k + 32 bytes (Alg 16 output; Table 3).
    pub const fn ek_len(&self) -> usize {
        384 * self.k + 32
    }
    /// Decapsulation key: 768·k + 96 bytes (Alg 16 output; Table 3).
    pub const fn dk_len(&self) -> usize {
        768 * self.k + 96
    }
    /// Ciphertext: 32·(du·k + dv) bytes (Alg 17 output; Table 3).
    pub const fn ct_len(&self) -> usize {
        32 * (self.du as usize * self.k + self.dv as usize)
    }
    /// K-PKE decryption key, the first part of dk: 384·k bytes.
    pub(crate) const fn dk_pke_len(&self) -> usize {
        384 * self.k
    }
}

pub const ML_KEM_512: Params = Params {
    name: "ML-KEM-512",
    k: 2,
    eta1: 3,
    eta2: 2,
    du: 10,
    dv: 4,
};

pub const ML_KEM_768: Params = Params {
    name: "ML-KEM-768",
    k: 3,
    eta1: 2,
    eta2: 2,
    du: 10,
    dv: 4,
};

pub const ML_KEM_1024: Params = Params {
    name: "ML-KEM-1024",
    k: 4,
    eta1: 2,
    eta2: 2,
    du: 11,
    dv: 5,
};

/// Largest k, ciphertext and encapsulation key over all parameter sets, so
/// scratch buffers can live on the stack with a fixed size.
pub(crate) const MAX_K: usize = 4;
pub(crate) const MAX_CT_LEN: usize = ML_KEM_1024.ct_len();

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS 203 Table 3, copied from the PDF.
    #[test]
    fn sizes_match_table_3() {
        for (p, ek, dk, ct) in [
            (ML_KEM_512, 800, 1632, 768),
            (ML_KEM_768, 1184, 2400, 1088),
            (ML_KEM_1024, 1568, 3168, 1568),
        ] {
            assert_eq!(
                (p.ek_len(), p.dk_len(), p.ct_len()),
                (ek, dk, ct),
                "{}",
                p.name
            );
        }
    }
}
