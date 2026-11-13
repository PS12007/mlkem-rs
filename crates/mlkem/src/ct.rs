//! Constant-time building blocks.
//!
//! The rule for the whole crate: a value that depends on a secret must never
//! decide
//!   1. which branch runs (`if secret { .. }`),
//!   2. which memory address is read or written (`table[secret]`), or
//!   3. the input of an instruction whose latency depends on its data
//!      (`div`/`idiv` on x86: this is the KyberSlash bug, see LEARNING.md).
//!
//! The tools for this are *masks*: a word that is either all zeros or all
//! ones. "if c then a else b" becomes `b ^ (mask & (a ^ b))`, which runs the
//! same instructions whatever the value of `c`.
//!
//! Rust and LLVM do not promise constant-time code. The optimiser can work
//! out that a mask is always 0 or !0 and turn the expression back into a
//! branch. [`core::hint::black_box`] hides the value from the optimiser at
//! the points where that would be tempting. It is documented as
//! "best effort", so phase 4 checks the generated assembly as well.

use core::hint::black_box;

/// Returns `0xFFFF_FFFF` if `x == 0`, otherwise `0`, with no branch.
#[inline]
pub(crate) fn is_zero_mask_u32(x: u32) -> u32 {
    // If x != 0, then x or its two's-complement negation -x has the top bit
    // set (for x = 2^31 both do). If x == 0, both are 0. So bit 31 of
    // (x | -x) is exactly "x != 0".
    let nonzero = (x | x.wrapping_neg()) >> 31; // 1 if x != 0, else 0
    // 1 - 1 = 0 ; 0 - 1 = 0xFFFF_FFFF. black_box stops LLVM from noticing
    // that `nonzero` is a boolean and re-introducing a branch/cmov chain.
    black_box(nonzero).wrapping_sub(1)
}

/// Compares two byte strings of the same (public) length.
/// Returns `0xFF` if they are equal, else `0x00`.
///
/// Every byte is visited, whatever the data. A normal `==` on slices may
/// stop at the first difference, and the time it takes then leaks *where*
/// the strings first differ. Phase 3 uses this function for the FO
/// re-encryption check in decapsulation.
pub(crate) fn ct_eq_bytes(a: &[u8], b: &[u8]) -> u8 {
    assert_eq!(a.len(), b.len(), "lengths are public and must match");
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b) {
        acc |= x ^ y; // stays 0 only if every byte pair is equal
    }
    is_zero_mask_u32(u32::from(acc)) as u8
}

/// Writes `a` into `out` if `mask == 0xFF`, or `b` if `mask == 0x00`.
/// Any other mask value is a bug.
///
/// Phase 3 uses this for implicit rejection: choose between the real
/// shared key and the rejection key without branching on which one it is.
pub(crate) fn ct_select_bytes(out: &mut [u8], a: &[u8], b: &[u8], mask: u8) {
    assert!(out.len() == a.len() && a.len() == b.len());
    let mask = black_box(mask);
    for ((o, x), y) in out.iter_mut().zip(a).zip(b) {
        *o = y ^ (mask & (x ^ y));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn is_zero_mask_edges() {
        assert_eq!(is_zero_mask_u32(0), u32::MAX);
        for x in [1, 2, 0x7FFF_FFFF, 0x8000_0000, 0x8000_0001, u32::MAX] {
            assert_eq!(is_zero_mask_u32(x), 0, "x = {x:#x}");
        }
    }

    #[test]
    fn eq_and_select_basic() {
        assert_eq!(ct_eq_bytes(b"", b""), 0xFF);
        assert_eq!(ct_eq_bytes(b"abc", b"abc"), 0xFF);
        assert_eq!(ct_eq_bytes(b"abc", b"abd"), 0x00);
        assert_eq!(ct_eq_bytes(b"\x00bc", b"\x80bc"), 0x00);
        let mut out = [0u8; 3];
        ct_select_bytes(&mut out, b"aaa", b"bbb", 0xFF);
        assert_eq!(&out, b"aaa");
        ct_select_bytes(&mut out, b"aaa", b"bbb", 0x00);
        assert_eq!(&out, b"bbb");
    }

    proptest! {
        #[test]
        fn is_zero_mask_matches_eq(x: u32) {
            prop_assert_eq!(is_zero_mask_u32(x), if x == 0 { u32::MAX } else { 0 });
        }

        #[test]
        fn ct_eq_matches_slice_eq(a in prop::collection::vec(any::<u8>(), 0..64),
                                  flip in any::<prop::sample::Index>(),
                                  bit in 0u8..8, do_flip: bool) {
            let mut b = a.clone();
            if do_flip && !b.is_empty() {
                let i = flip.index(b.len());
                b[i] ^= 1 << bit;
            }
            prop_assert_eq!(ct_eq_bytes(&a, &b), if a == b { 0xFF } else { 0x00 });
        }
    }
}
