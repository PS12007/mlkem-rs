//! The sponge construction and SHA-3 padding (FIPS 202 §4, §5.1, §6).
//!
//! A sponge has a 1600-bit state split into a *rate* part (r bits, which
//! data is XORed into) and a *capacity* part (c = 1600 − r bits, never touched
//! directly). Security is about c/2 bits, so:
//!
//! | function  | rate (bytes) | capacity (bits) | used in ML-KEM as |
//! |-----------|-------------:|----------------:|-------------------|
//! | SHA3-256  | 136          | 512             | H                 |
//! | SHA3-512  |  72          | 1024            | G                 |
//! | SHAKE128  | 168          | 256             | XOF               |
//! | SHAKE256  | 136          | 512             | J, PRF            |
//!
//! Absorbing: XOR `rate` bytes into the state, permute, repeat. Padding
//! (pad10*1) and a domain-separation suffix are added after the last
//! message byte. Squeezing: read `rate` bytes, permute, repeat.
//!
//! Lengths are public. Branches here depend only on byte positions, never
//! on byte values.

use super::keccak::f1600;

/// Domain-separation suffix plus the first padding bit, as one byte.
///
/// FIPS 202 appends the bits `01` (SHA3) or `1111` (SHAKE) to the message,
/// then pad10*1 starts with a `1`. Bits go into bytes least significant bit
/// first, so SHA3 gives bits 0,1,1 = 0b110 = 0x06, and SHAKE gives
/// 1,1,1,1,1 = 0x1F. The final `1` of pad10*1 is bit 7 of the last rate byte
/// (0x80).
pub(crate) const SHA3_SUFFIX: u8 = 0x06;
pub(crate) const SHAKE_SUFFIX: u8 = 0x1F;

#[derive(Clone)]
pub(crate) struct Sponge<const RATE: usize> {
    state: [u64; 25],
    /// Next byte position inside the rate part, in 0..RATE.
    pos: usize,
}

impl<const RATE: usize> Sponge<RATE> {
    pub(crate) const fn new() -> Self {
        assert!(RATE % 8 == 0 && RATE < 200);
        Self {
            state: [0; 25],
            pos: 0,
        }
    }

    #[inline]
    fn xor_byte(&mut self, i: usize, b: u8) {
        self.state[i / 8] ^= u64::from(b) << (8 * (i % 8));
    }

    pub(crate) fn absorb(&mut self, mut data: &[u8]) {
        // Fast path: whole blocks when aligned, 8 bytes (one lane) at a time.
        while self.pos == 0 && data.len() >= RATE {
            let (block, rest) = data.split_at(RATE);
            for (lane, bytes) in self.state.iter_mut().zip(block.chunks_exact(8)) {
                *lane ^= u64::from_le_bytes(bytes.try_into().unwrap());
            }
            f1600(&mut self.state);
            data = rest;
        }
        // Slow path: byte by byte, for unaligned starts and the tail.
        for &b in data {
            self.xor_byte(self.pos, b);
            self.pos += 1;
            if self.pos == RATE {
                f1600(&mut self.state);
                self.pos = 0;
            }
        }
    }

    /// Pads, permutes, and switches to squeezing (FIPS 202 Alg 8 steps 1–6).
    /// When pos = RATE − 1, both XORs hit the same byte (e.g. 0x06 ^ 0x80 =
    /// 0x86), which is exactly what pad10*1 requires.
    pub(crate) fn finalize(mut self, suffix: u8) -> Squeezer<RATE> {
        self.xor_byte(self.pos, suffix);
        self.xor_byte(RATE - 1, 0x80);
        f1600(&mut self.state);
        Squeezer {
            state: self.state,
            pos: 0,
        }
    }
}

/// A sponge in the squeezing phase. Separate type, so the compiler forbids
/// absorbing after output has started.
#[derive(Clone)]
pub(crate) struct Squeezer<const RATE: usize> {
    state: [u64; 25],
    pos: usize,
}

impl<const RATE: usize> Squeezer<RATE> {
    /// FIPS 202 Alg 8 steps 7–10. Calls may use any sizes: the output is one
    /// continuous stream.
    pub(crate) fn squeeze(&mut self, out: &mut [u8]) {
        for o in out {
            if self.pos == RATE {
                f1600(&mut self.state);
                self.pos = 0;
            }
            *o = (self.state[self.pos / 8] >> (8 * (self.pos % 8))) as u8;
            self.pos += 1;
        }
    }
}

// The state is a function of everything absorbed, which is often secret
// (d ‖ k in KeyGen, m ‖ H(ek) in Encaps, s ‖ N in the PRF). Squeezed output
// is also derivable from it. Wipe it when the sponge goes away.
impl<const RATE: usize> Drop for Sponge<RATE> {
    fn drop(&mut self) {
        crate::zeroize::wipe(&mut self.state);
    }
}
impl<const RATE: usize> Drop for Squeezer<RATE> {
    fn drop(&mut self) {
        crate::zeroize::wipe(&mut self.state);
    }
}
