//! Wiping secrets from memory when they are no longer needed.
//!
//! Why this needs care: after the last use of a buffer, writing zeros to it
//! is a "dead store" (nothing reads it again), and optimisers delete dead
//! stores. A *volatile* write is one the compiler must perform exactly as
//! written. The compiler fence afterwards stops it from moving the wipe
//! past later code. This is the same technique the `zeroize` crate uses.
//!
//! What it does NOT do (see Limits in README.md): it cannot wipe copies the
//! compiler made on its own. Values moved between variables, spilled
//! registers, or the stack frames of functions that have already returned
//! may still hold secret bytes. Rust gives no way to control those from safe
//! (or even unsafe) code. Wiping the named buffers removes the long-lived
//! copies, which are the ones most likely to leak (core dumps, swap, a later
//! memory-disclosure bug).

use core::sync::atomic::{Ordering, compiler_fence};

/// Overwrite every element of `buf` with its default (zero) value, with
/// writes the optimiser may not remove.
#[allow(unsafe_code)]
pub(crate) fn wipe<T: Copy + Default>(buf: &mut [T]) {
    for x in buf.iter_mut() {
        // SAFETY: `x` is a live, aligned, exclusive reference to a `T`
        // (it comes from `iter_mut` on a `&mut [T]`), so writing one `T`
        // through it is sound. `T: Copy` means there is no destructor to
        // skip. Volatile only stops the compiler eliding the store.
        unsafe { core::ptr::write_volatile(x, T::default()) };
    }
    compiler_fence(Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wipes_everything() {
        let mut a = [0xABu8; 37];
        wipe(&mut a);
        assert_eq!(a, [0u8; 37]);
        let mut b = [-1234i16; 256];
        wipe(&mut b);
        assert!(b.iter().all(|&x| x == 0));
        let mut c = [u64::MAX; 25];
        wipe(&mut c);
        assert_eq!(c, [0u64; 25]);
    }
}
