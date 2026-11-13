//! mlkem-dudect: a statistical timing-leak tester for the mlkem crate,
//! following the dudect method (Reparaz, Balasch, Verbauwhede, DATE 2017).
//!
//! For one target operation it repeatedly:
//!   1. picks an input class at random: 0 = a FIXED input, 1 = a RANDOM one;
//!   2. prepares the input (not timed) with the SAME instructions for both
//!      classes: a random candidate is always generated, and the class only
//!      selects which of two cached buffers is copied into the working slot;
//!   3. drains pending stores (MFENCE), then times the operation with the
//!      serialised TSC.
//!
//! Then it runs Welch's t-test between the two classes' timings, uncropped
//! and cropped at dudect's percentile points, and reports the largest |t|.
//!
//! Interpretation (conventional thresholds):
//!   |t| < 4.5        no leak detected at this sample size
//!   4.5 ≤ |t| < 10   possible leak: re-run with more measurements
//!   |t| ≥ 10         leak: timing depends on the input class
//! A test that passes does NOT prove constant time; it only failed to find a
//! difference with this many measurements on this machine.
//!
//! "aa-*" targets are A/A controls: both classes get identical data through
//! the same code path. They must NOT show a leak, otherwise the harness
//! itself is creating differences.
//!
//! Usage:
//!   mlkem-dudect --target <name> [--n MEASUREMENTS] [--cpu LOGICAL_CPU]
//!                [--crops K] [--seed S]
//!   mlkem-dudect --list

#![cfg_attr(not(windows), allow(dead_code))]

#[cfg(windows)]
mod platform;
mod stats;

#[cfg(not(windows))]
fn main() {
    eprintln!("mlkem-dudect currently supports Windows on x86-64 only.");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() {
    if let Err(e) = app::run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
mod app {
    use crate::platform;
    use crate::stats::TestSet;
    use mlkem::{RandomSource, hazmat, ml_kem_768};
    use std::hint::black_box;

    /// xoshiro256** (Blackman, Vigna), seeded from the OS RNG. Used for the
    /// random-class inputs and the class choice: fast and statistically
    /// good, and its outputs are not secrets of the system under test.
    pub struct Rng([u64; 4]);
    impl Rng {
        pub fn from_seed(seed: u64) -> Self {
            // SplitMix64 to expand one word into four well-mixed words.
            let mut z = seed;
            let mut next = || {
                z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
                let mut x = z;
                x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                x ^ (x >> 31)
            };
            Rng([next(), next(), next(), next()])
        }
        pub fn next_u64(&mut self) -> u64 {
            let s = &mut self.0;
            let result = s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
            let t = s[1] << 17;
            s[2] ^= s[0];
            s[3] ^= s[1];
            s[1] ^= s[2];
            s[0] ^= s[3];
            s[2] ^= t;
            s[3] = s[3].rotate_left(45);
            result
        }
        pub fn fill(&mut self, buf: &mut [u8]) {
            for chunk in buf.chunks_mut(8) {
                let v = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&v[..chunk.len()]);
            }
        }
        pub fn array<const L: usize>(&mut self) -> [u8; L] {
            let mut a = [0u8; L];
            self.fill(&mut a);
            a
        }
    }

    fn random_poly(rng: &mut Rng) -> [i16; 256] {
        // Uniform enough in [0, q): the bias of `% 3329` on 64-bit values is
        // about 2^-52, irrelevant here.
        core::array::from_fn(|_| (rng.next_u64() % 3329) as i16)
    }

    /// One operation under test.
    pub trait Target {
        /// What class 0 and class 1 mean for this target.
        fn describe(&self) -> &'static str;
        /// Time one batch. `classes[i]` is the class of measurement i;
        /// `out[i]` receives its duration in TSC ticks.
        fn measure_batch(&mut self, classes: &[u8], rng: &mut Rng, out: &mut [u64]);
    }

    /// Generic harness: input type T, fixed context C (keys etc.).
    ///
    /// Design (the canonical dudect structure, arrived at after two harness
    /// artifacts, see LEARNING.md section 5): all inputs of a batch are
    /// generated *first*, into one array; class-0 entries hold their own
    /// copy of the fixed input. The timed loop then walks the array with no
    /// class-dependent code at all, so the only thing that differs between
    /// the classes is the data value of the input.
    struct Harness<T: Copy, C> {
        desc: &'static str,
        ctx: C,
        fixed: T,
        inputs: Vec<T>,
        /// A/A control: class-1 inputs are also copies of the fixed input,
        /// so both classes see identical data.
        aa: bool,
        gen_input: fn(&C, &mut Rng) -> T,
        op: fn(&C, &T),
    }

    impl<T: Copy, C> Target for Harness<T, C> {
        fn describe(&self) -> &'static str {
            self.desc
        }
        fn measure_batch(&mut self, classes: &[u8], rng: &mut Rng, out: &mut [u64]) {
            // 1. Prepare every input of the batch (not timed).
            self.inputs.clear();
            for &c in classes {
                let x = if c == 0 || self.aa {
                    self.fixed
                } else {
                    (self.gen_input)(&self.ctx, rng)
                };
                self.inputs.push(x);
            }
            // 2. Time each one. Nothing in this loop depends on the class.
            for (x, o) in self.inputs.iter().zip(out.iter_mut()) {
                platform::fence();
                let t0 = platform::ticks();
                (self.op)(&self.ctx, black_box(x));
                let t1 = platform::ticks();
                *o = t1.wrapping_sub(t0);
            }
        }
    }

    const TARGETS: [&str; 10] = [
        "aa-ct-eq",
        "ct-eq",
        "message-encode",
        "message-encode-zero",
        "u-encode-zero",
        "aa-decaps-ct",
        "decaps-ct",
        "decaps-valid",
        "encaps-m",
        "keygen-d",
    ];

    fn make_target(name: &str, rng: &mut Rng) -> Option<Box<dyn Target>> {
        let (ek, dk) = ml_kem_768::generate_internal(&rng.array(), &rng.array());
        let (c, _) = ek.encapsulate_internal(&rng.array());
        let (dk, c) = (*dk.as_bytes(), *c.as_bytes());
        // Any target can be run as an A/A control by prefixing "aa-".
        let aa = name.starts_with("aa-");
        let name = name.strip_prefix("aa-").unwrap_or(name);
        Some(match name {
            "ct-eq" => {
                let a: [u8; 1088] = rng.array();
                Box::new(Harness {
                    desc: "ct_eq_bytes over 1088 bytes (ML-KEM-768 ciphertext size). class 0: \
                           second input EQUAL to the first; class 1: second input random",
                    ctx: a,
                    fixed: a,
                    inputs: Vec::new(),
                    aa,
                    gen_input: |_, r| r.array(),
                    op: |a, b| {
                        black_box(hazmat::ct_eq_1088(black_box(a), b));
                    },
                })
            }
            "message-encode" => Box::new(Harness {
                desc: "ByteEncode_1(Compress_1(w)) on 256 coefficients (Decrypt line 7, the \
                       KyberSlash2 site). class 0: one fixed w; class 1: random w",
                ctx: (),
                fixed: random_poly(rng),
                inputs: Vec::new(),
                aa,
                gen_input: |_, r| random_poly(r),
                op: |_, w| {
                    black_box(hazmat::message_encode(w));
                },
            }),
            // dudect's classic choice of an *extreme* fixed input: w = 0 gives
            // the smallest dividend (1664) and quotient (0) in every one of the
            // 256 divisions, maximising any operand-dependent latency gap.
            "message-encode-zero" => Box::new(Harness {
                desc: "ByteEncode_1(Compress_1(w)) (Decrypt line 7, KyberSlash2 site). \
                       class 0: w = 0 (all coefficients); class 1: random w",
                ctx: (),
                fixed: [0i16; 256],
                inputs: Vec::new(),
                aa,
                gen_input: |_, r| random_poly(r),
                op: |_, w| {
                    black_box(hazmat::message_encode(w));
                },
            }),
            "u-encode-zero" => Box::new(Harness {
                desc: "ByteEncode_11(Compress_11(u)) (Encrypt line 22 at du = 11, KyberSlash1 \
                       site). class 0: u = 0; class 1: random u",
                ctx: (),
                fixed: [0i16; 256],
                inputs: Vec::new(),
                aa,
                gen_input: |_, r| random_poly(r),
                op: |_, u| {
                    black_box(hazmat::u_encode_d11(u));
                },
            }),
            "decaps-ct" => Box::new(Harness {
                desc: "ML-KEM-768 Decaps with one fixed key. class 0: one fixed VALID \
                       ciphertext (re-encryption matches, K' returned); class 1: random \
                       ciphertexts (re-encryption fails, implicit rejection)",
                ctx: dk,
                fixed: c,
                inputs: Vec::new(),
                aa,
                gen_input: |_, r| r.array(),
                op: |dk, c| {
                    black_box(hazmat::decaps_768(black_box(dk), c));
                },
            }),
            "decaps-valid" => Box::new(Harness {
                desc: "ML-KEM-768 Decaps with one fixed key, both classes VALID ciphertexts. \
                       class 0: one fixed ciphertext; class 1: a fresh ciphertext of a random m",
                ctx: (dk, ek),
                fixed: c,
                inputs: Vec::new(),
                aa,
                gen_input: |(_, ek), r| *ek.encapsulate_internal(&r.array()).0.as_bytes(),
                op: |(dk, _), c| {
                    black_box(hazmat::decaps_768(black_box(dk), c));
                },
            }),
            "encaps-m" => Box::new(Harness {
                desc: "ML-KEM-768 Encaps_internal with one fixed key. class 0: fixed m; \
                       class 1: random m",
                ctx: ek,
                fixed: rng.array(),
                inputs: Vec::new(),
                aa,
                gen_input: |_, r| r.array(),
                op: |ek, m| {
                    black_box(black_box(ek).encapsulate_internal(m));
                },
            }),
            "keygen-d" => Box::new(Harness {
                desc: "ML-KEM-768 KeyGen_internal(d, z) with fixed z. class 0: fixed d; \
                       class 1: random d",
                ctx: rng.array::<32>(),
                fixed: rng.array(),
                inputs: Vec::new(),
                aa,
                gen_input: |_, r| r.array(),
                op: |z, d| {
                    black_box(ml_kem_768::generate_internal(d, black_box(z)));
                },
            }),
            _ => return None,
        })
    }

    // ---- measurement -----------------------------------------------------

    const BATCH: usize = 1000;

    /// Run `count` measurements in batches; returns (class, ticks) pairs.
    fn measure_many(
        t: &mut dyn Target,
        count: u64,
        rng: &mut Rng,
        mut sink: impl FnMut(usize, u64),
    ) {
        let mut classes = vec![0u8; BATCH];
        let mut out = vec![0u64; BATCH];
        let mut left = count;
        while left > 0 {
            let b = (left as usize).min(BATCH);
            for c in &mut classes[..b] {
                *c = (rng.next_u64() >> 63) as u8;
            }
            t.measure_batch(&classes[..b], rng, &mut out[..b]);
            for i in 0..b {
                sink(classes[i] as usize, out[i]);
            }
            left -= b as u64;
        }
    }

    struct Args {
        target: String,
        n: u64,
        cpu: usize,
        crops: usize,
        seed: Option<u64>,
    }

    fn parse_args() -> Result<Option<Args>, String> {
        let mut a = Args {
            target: String::new(),
            n: 1_000_000,
            cpu: 2,
            crops: 100,
            seed: None,
        };
        let mut it = std::env::args().skip(1);
        while let Some(flag) = it.next() {
            let mut val = || it.next().ok_or(format!("{flag} needs a value"));
            match flag.as_str() {
                "--list" => {
                    for t in TARGETS {
                        println!("{t}");
                    }
                    return Ok(None);
                }
                "--target" => a.target = val()?,
                "--n" => {
                    a.n = val()?
                        .replace('_', "")
                        .parse()
                        .map_err(|e| format!("--n: {e}"))?
                }
                "--cpu" => a.cpu = val()?.parse().map_err(|e| format!("--cpu: {e}"))?,
                "--crops" => a.crops = val()?.parse().map_err(|e| format!("--crops: {e}"))?,
                "--seed" => a.seed = Some(val()?.parse().map_err(|e| format!("--seed: {e}"))?),
                other => return Err(format!("unknown argument {other}")),
            }
        }
        if a.target.is_empty() {
            return Err(format!("--target required, one of: {}", TARGETS.join(", ")));
        }
        Ok(Some(a))
    }

    fn verdict(t: f64) -> &'static str {
        if t < 4.5 {
            "no leak detected (max |t| < 4.5)"
        } else if t < 10.0 {
            "POSSIBLE LEAK (4.5 <= max |t| < 10): re-run with more measurements"
        } else {
            "LEAK (max |t| >= 10): timing depends on the input class"
        }
    }

    pub fn run() -> Result<(), String> {
        let Some(args) = parse_args()? else {
            return Ok(());
        };
        let seed = match args.seed {
            Some(s) => s,
            None => {
                let mut b = [0u8; 8];
                mlkem::OsRng.fill_bytes(&mut b).map_err(|e| e.to_string())?;
                u64::from_le_bytes(b)
            }
        };
        let mut rng = Rng::from_seed(seed);
        let mut target = make_target(&args.target, &mut rng).ok_or(format!(
            "unknown target {}; one of: {}",
            args.target,
            TARGETS.join(", ")
        ))?;

        let pin = platform::pin_and_prioritize(args.cpu)?;
        let tsc_hz = platform::tsc_hz();
        let leaky = if mlkem::LEAKY_FEATURES.is_empty() {
            "none (normal build)".to_string()
        } else {
            format!(
                "*** DELIBERATELY LEAKY BUILD: {} ***",
                mlkem::LEAKY_FEATURES.join(", ")
            )
        };
        println!("# mlkem-dudect");
        println!("target:        {}", args.target);
        println!("description:   {}", target.describe());
        if args.target.starts_with("aa-") {
            println!("               A/A CONTROL: both classes receive identical data");
        }
        println!("leaky features: {leaky}");
        println!("cpu:           {}", platform::cpu_brand());
        println!("scheduling:    {pin}");
        println!(
            "timer:         RDTSC with LFENCE, MFENCE before each measurement; TSC = {:.1} MHz \
             (measured against QPC at {} Hz)",
            tsc_hz / 1e6,
            platform::qpc_hz()
        );
        println!("measurements:  {} (+ warm-up and calibration)", args.n);
        println!(
            "crops:         uncropped + {} dudect percentile crops",
            args.crops
        );
        println!("seed:          {seed}");
        println!();

        // Warm-up: caches, branch predictors, CPU frequency.
        let warm = (args.n / 100).clamp(1_000, 20_000);
        measure_many(target.as_mut(), warm, &mut rng, |_, _| {});
        // Calibration sample for the crop thresholds (both classes mixed).
        let mut cal = Vec::new();
        measure_many(target.as_mut(), warm, &mut rng, |_, dt| cal.push(dt));
        let mut tests = TestSet::new(&mut cal, args.crops);

        let start = std::time::Instant::now();
        let step = (args.n / 10).max(1);
        let mut i = 0u64;
        let mut progress = Vec::new();
        measure_many(target.as_mut(), args.n, &mut rng, |c, dt| {
            tests.push(c, dt);
            i += 1;
            if i % step == 0 {
                progress.push(i);
            }
        });
        for i in progress {
            if i == args.n {
                let (idx, t) = tests.max_abs_t();
                println!(
                    "progress n={i:>10}  max|t| = {t:>8.2}  ({})  elapsed {:.0} s",
                    tests.tests[idx].0,
                    start.elapsed().as_secs_f64()
                );
            }
        }

        let u = &tests.tests[0].2;
        println!();
        println!(
            "uncropped means: class 0 = {:.1} ticks ({:.1} ns), class 1 = {:.1} ticks ({:.1} ns)",
            u.mean(0),
            u.mean(0) / tsc_hz * 1e9,
            u.mean(1),
            u.mean(1) / tsc_hz * 1e9
        );
        println!();
        println!(
            "{:<18} {:>12} {:>10} {:>10} {:>12} {:>12} {:>9}",
            "test", "threshold", "n0", "n1", "mean0", "mean1", "t"
        );
        for (name, thr, w) in &tests.tests {
            println!(
                "{:<18} {:>12} {:>10} {:>10} {:>12.1} {:>12.1} {:>9.2}",
                name,
                thr.map_or("-".to_string(), |t| t.to_string()),
                w.n(0),
                w.n(1),
                w.mean(0),
                w.mean(1),
                w.t()
            );
        }
        let (idx, t) = tests.max_abs_t();
        println!();
        println!("max |t| = {t:.2} ({})", tests.tests[idx].0);
        println!("verdict: {}", verdict(t));
        Ok(())
    }
}
