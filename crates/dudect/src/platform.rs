//! Windows / x86-64 specifics: a cycle-resolution timer, thread pinning and
//! priority. This crate (not the mlkem library) is where the `unsafe` FFI
//! for these lives. Every call is a plain Win32 function with no pointers
//! except where noted.

use core::arch::x86_64::{__cpuid, _mm_lfence, _rdtsc};
use core::ffi::c_void;

type Handle = *mut c_void;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentThread() -> Handle; // a pseudo-handle, never needs closing
    fn GetCurrentProcess() -> Handle; // likewise
    fn SetThreadAffinityMask(thread: Handle, mask: usize) -> usize; // 0 = failure
    fn SetThreadPriority(thread: Handle, priority: i32) -> i32; // BOOL
    fn SetPriorityClass(process: Handle, class: u32) -> i32; // BOOL
    fn GetCurrentProcessorNumber() -> u32;
    fn QueryPerformanceCounter(count: *mut i64) -> i32;
    fn QueryPerformanceFrequency(freq: *mut i64) -> i32;
}

const HIGH_PRIORITY_CLASS: u32 = 0x0000_0080;
const THREAD_PRIORITY_TIME_CRITICAL: i32 = 15;

/// Read the time-stamp counter, serialised with LFENCE on both sides.
///
/// RDTSC is not ordered with respect to the surrounding instructions: the
/// CPU may execute it early or late. LFENCE waits until all earlier
/// instructions have completed locally before later ones start, so the
/// measured window really contains the function call. Modern x86 TSCs are
/// "invariant": they tick at a constant rate (not the current core clock),
/// so ticks are comparable across turbo and power states.
#[inline(always)]
pub fn ticks() -> u64 {
    // SAFETY: LFENCE and RDTSC are available on every x86-64 CPU (SSE2 is
    // part of the x86-64 baseline) and have no memory-safety preconditions.
    #[allow(unused_unsafe)]
    unsafe {
        _mm_lfence();
        let t = _rdtsc();
        _mm_lfence();
        t
    }
}

/// Full memory fence: every earlier load and store has completed. Called
/// after preparing an input and before starting the clock, so the stores
/// that wrote the input are not still draining from the store buffer while
/// the timed code runs (that drain time would differ between the classes).
#[inline(always)]
pub fn fence() {
    // SAFETY: MFENCE is part of the x86-64 baseline and has no
    // preconditions.
    #[allow(unused_unsafe)]
    unsafe {
        core::arch::x86_64::_mm_mfence()
    };
}

fn qpc() -> i64 {
    let mut v = 0i64;
    // SAFETY: `v` is a valid, writable i64 for the duration of the call.
    unsafe { QueryPerformanceCounter(&mut v) };
    v
}

/// TSC ticks per second, measured against the OS high-resolution clock
/// (QueryPerformanceCounter) over about 200 ms. This also cross-checks the
/// two timers against each other.
pub fn tsc_hz() -> f64 {
    let mut f = 0i64;
    // SAFETY: `f` is a valid, writable i64 for the duration of the call.
    unsafe { QueryPerformanceFrequency(&mut f) };
    let (q0, t0) = (qpc(), ticks());
    while qpc() - q0 < f / 5 {}
    let (q1, t1) = (qpc(), ticks());
    (t1 - t0) as f64 / ((q1 - q0) as f64 / f as f64)
}

pub fn qpc_hz() -> i64 {
    let mut f = 0i64;
    // SAFETY: as above.
    unsafe { QueryPerformanceFrequency(&mut f) };
    f
}

/// The CPU's brand string from CPUID leaves 0x8000_0002..4.
pub fn cpu_brand() -> String {
    let mut bytes = Vec::with_capacity(48);
    for leaf in 0x8000_0002u32..=0x8000_0004 {
        // SAFETY: CPUID is available on every x86-64 CPU, and these
        // extended leaves exist on every CPU that has a brand string
        // (all x86-64 parts).
        #[allow(unused_unsafe)]
        let r = unsafe { __cpuid(leaf) };
        for reg in [r.eax, r.ebx, r.ecx, r.edx] {
            bytes.extend_from_slice(&reg.to_le_bytes());
        }
    }
    String::from_utf8_lossy(&bytes)
        .trim_matches(char::from(0))
        .trim()
        .to_string()
}

/// Pin the calling thread to one logical CPU and raise its priority, to
/// cut down noise from the scheduler moving us around or preempting us.
/// Returns a human-readable description of what was done.
pub fn pin_and_prioritize(cpu: usize) -> Result<String, String> {
    if cpu >= usize::BITS as usize {
        return Err(format!("cpu index {cpu} too large"));
    }
    // SAFETY: the pseudo-handles are always valid for the current
    // thread/process; the other arguments are plain integers.
    unsafe {
        if SetThreadAffinityMask(GetCurrentThread(), 1usize << cpu) == 0 {
            return Err(format!("SetThreadAffinityMask(cpu {cpu}) failed"));
        }
        let class_ok = SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS) != 0;
        let thread_ok = SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL) != 0;
        // Let the scheduler move us onto the chosen CPU before we check.
        std::thread::yield_now();
        let now = GetCurrentProcessorNumber();
        Ok(format!(
            "pinned to logical CPU {cpu} (running on {now}); process HIGH_PRIORITY_CLASS {}; \
             thread TIME_CRITICAL {}",
            if class_ok { "ok" } else { "FAILED" },
            if thread_ok { "ok" } else { "FAILED" }
        ))
    }
}
