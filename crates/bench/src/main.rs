//! mlkem-bench: times this crate's KeyGen, Encaps and Decaps against
//! RustCrypto's `ml-kem`, for all three parameter sets.
//!
//! No benchmark framework (criterion etc.): the method is small enough to
//! write and defend line by line, and it adds no dependencies.
//!
//! Method:
//! - Pin to one logical CPU at high priority (shared with mlkem-dudect).
//! - Precompute 64 random inputs (seeds d, z and messages m) and use the
//!   SAME inputs for both implementations, cycling through them. KeyGen's
//!   time varies with the seed (rejection sampling), so equal inputs matter.
//! - Before timing, check that both produce byte-identical outputs on every
//!   input: we must be timing the same computation.
//! - Time each call on its own with the serialised TSC (overhead ~40
//!   cycles, under 0.1% of the fastest operation here).
//! - Alternate the two implementations in rounds (ours, theirs, theirs,
//!   ours, ...) so slow drift (temperature, turbo budget) hits both equally.
//!   The first round is a warm-up and is discarded.
//! - Report the median, and the 5th and 95th percentiles. The median is
//!   robust to interrupts in a way the mean is not.
//!
//! Usage: mlkem-bench [--cpu N] [--rounds R] [--samples S]

#![cfg_attr(not(windows), allow(dead_code))]

#[cfg(windows)]
#[path = "../../dudect/src/platform.rs"]
#[allow(dead_code)]
mod platform;

#[cfg(not(windows))]
fn main() {
    eprintln!("mlkem-bench currently supports Windows on x86-64 only.");
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
    use ml_kem::array::Array;
    #[allow(deprecated)]
    use ml_kem::{Decapsulate, ExpandedKeyEncoding, KeyExport};
    use mlkem::RandomSource;
    use std::hint::black_box;

    const INPUTS: usize = 64;

    struct Inputs {
        d: Vec<[u8; 32]>,
        z: Vec<[u8; 32]>,
        m: Vec<[u8; 32]>,
    }

    /// One operation of one implementation: `call(i)` runs it on input i.
    struct Bench<'a> {
        name: &'static str,
        call: Box<dyn FnMut(usize) + 'a>,
    }

    fn bench<'a>(name: &'static str, call: impl FnMut(usize) + 'a) -> Bench<'a> {
        Bench {
            name,
            call: Box::new(call),
        }
    }

    /// Time the benches in alternating order (A B C, C B A, A B C, ...), so
    /// slow drift affects all of them equally. Round 0 is a warm-up.
    /// Returns ticks per call, per bench.
    fn measure(benches: &mut [Bench], rounds: usize, samples: usize) -> Vec<Vec<u64>> {
        let mut out = vec![Vec::new(); benches.len()];
        for round in 0..=rounds {
            let mut order: Vec<usize> = (0..benches.len()).collect();
            if round % 2 == 1 {
                order.reverse();
            }
            for which in order {
                let b = &mut benches[which];
                for s in 0..samples {
                    let i = (round * samples + s) % INPUTS;
                    let t0 = platform::ticks();
                    (b.call)(black_box(i));
                    let t1 = platform::ticks();
                    if round > 0 {
                        out[which].push(t1 - t0);
                    }
                }
            }
        }
        out
    }

    fn pct(sorted: &[u64], p: f64) -> u64 {
        sorted[((sorted.len() - 1) as f64 * p).round() as usize]
    }

    // Implementations compared, per operation:
    //   mlkem         this crate, through its public API. Keys are stored as
    //                 bytes, so every call decodes them, and Encaps hashes
    //                 H(ek) (FIPS 203 Alg 17 line 1) every time.
    //   ml-kem        RustCrypto, with its parsed key objects (decoded
    //                 polynomials and H(ek) cached inside the key).
    //   ml-kem/bytes  RustCrypto, but parsing the key from bytes in every
    //                 call, like mlkem does. Its parsers also run the FIPS
    //                 203 §7 key checks, which mlkem does once, in
    //                 `from_bytes`, so this variant is charged a bit MORE
    //                 than mlkem. The fair comparison lies between the two.
    macro_rules! param_set {
        ($ours:ident, $theirs:ty, $label:literal, $inp:expr, $rows:expr, $rounds:expr, $samples:expr, $hz:expr) => {{
            use mlkem::$ours as ours;
            type Dk = ml_kem::DecapsulationKey<$theirs>;
            type Ek = ml_kem::EncapsulationKey<$theirs>;
            let inp: &Inputs = $inp;
            let seed = |i: usize| {
                let mut s = [0u8; 64];
                s[..32].copy_from_slice(&inp.d[i]);
                s[32..].copy_from_slice(&inp.z[i]);
                Array::from(s)
            };

            // Keys and ciphertexts for both, and a check that they agree.
            let our_keys: Vec<_> = (0..INPUTS)
                .map(|i| ours::generate_internal(&inp.d[i], &inp.z[i]))
                .collect();
            let their_dks: Vec<Dk> = (0..INPUTS).map(|i| Dk::from_seed(seed(i))).collect();
            let their_eks: Vec<Ek> = their_dks
                .iter()
                .map(|dk| dk.encapsulation_key().clone())
                .collect();
            let their_ek_bytes: Vec<_> = their_eks.iter().map(|ek| ek.to_bytes()).collect();
            #[allow(deprecated)]
            let their_dk_bytes: Vec<_> =
                their_dks.iter().map(|dk| dk.to_expanded_bytes()).collect();
            let our_cts: Vec<_> = (0..INPUTS)
                .map(|i| our_keys[i].0.encapsulate_internal(&inp.m[i]).0)
                .collect();
            let their_cts: Vec<_> = (0..INPUTS)
                .map(|i| {
                    their_eks[i]
                        .encapsulate_deterministic(&Array::from(inp.m[i]))
                        .0
                })
                .collect();
            for i in 0..INPUTS {
                if our_cts[i].as_bytes()[..] != their_cts[i][..]
                    || our_keys[i].0.as_bytes()[..] != their_ek_bytes[i][..]
                    || our_keys[i].1.as_bytes()[..] != their_dk_bytes[i][..]
                {
                    return Err(format!(
                        "{}: keys or ciphertexts differ on input {i}",
                        $label
                    ));
                }
                let (k1, k2) = (
                    our_keys[i].1.decapsulate(&our_cts[i]),
                    their_dks[i].decapsulate(&their_cts[i]),
                );
                if k1.as_bytes()[..] != k2[..] {
                    return Err(format!("{}: shared secrets differ on input {i}", $label));
                }
            }

            let mut ops: Vec<(&str, Vec<Bench>)> = vec![
                (
                    "KeyGen",
                    vec![
                        bench("mlkem", |i| {
                            black_box(ours::generate_internal(&inp.d[i], &inp.z[i]));
                        }),
                        bench("ml-kem", |i| {
                            black_box(Dk::from_seed(seed(i)));
                        }),
                    ],
                ),
                (
                    "Encaps",
                    vec![
                        bench("mlkem", |i| {
                            black_box(our_keys[i].0.encapsulate_internal(&inp.m[i]));
                        }),
                        bench("ml-kem", |i| {
                            black_box(
                                their_eks[i].encapsulate_deterministic(&Array::from(inp.m[i])),
                            );
                        }),
                        bench("ml-kem/bytes", |i| {
                            let ek = Ek::new(&their_ek_bytes[i]).unwrap();
                            black_box(ek.encapsulate_deterministic(&Array::from(inp.m[i])));
                        }),
                    ],
                ),
                (
                    "Decaps",
                    vec![
                        bench("mlkem", |i| {
                            black_box(our_keys[i].1.decapsulate(&our_cts[i]));
                        }),
                        bench("ml-kem", |i| {
                            black_box(their_dks[i].decapsulate(&their_cts[i]));
                        }),
                        bench("ml-kem/bytes", |i| {
                            #[allow(deprecated)]
                            let dk = Dk::from_expanded_bytes(&their_dk_bytes[i]).unwrap();
                            black_box(dk.decapsulate(&their_cts[i]));
                        }),
                    ],
                ),
            ];
            for (op, benches) in &mut ops {
                let t = measure(benches, $rounds, $samples);
                let mut med = Vec::new();
                for (w, b) in benches.iter().enumerate() {
                    let mut v = t[w].clone();
                    v.sort_unstable();
                    let us = |x: u64| x as f64 / $hz * 1e6;
                    med.push(us(pct(&v, 0.5)));
                    $rows.push(format!(
                        "{:<12} {:<7} {:<13} {:>10.2} {:>10.2} {:>10.2} {:>10.0} {:>8}",
                        $label,
                        op,
                        b.name,
                        med[w],
                        us(pct(&v, 0.05)),
                        us(pct(&v, 0.95)),
                        1e6 / med[w],
                        v.len()
                    ));
                }
                for w in 1..benches.len() {
                    $rows.push(format!(
                        "{:<12} {:<7} {:<13} ratio mlkem / {} (medians) = {:.2}",
                        $label,
                        op,
                        "",
                        benches[w].name,
                        med[0] / med[w]
                    ));
                }
            }
        }};
    }

    pub fn run() -> Result<(), String> {
        let (mut cpu, mut rounds, mut samples) = (2usize, 10usize, 300usize);
        let mut it = std::env::args().skip(1);
        while let Some(flag) = it.next() {
            let v: usize = it
                .next()
                .ok_or(format!("{flag} needs a value"))?
                .parse()
                .map_err(|e| format!("{flag}: {e}"))?;
            match flag.as_str() {
                "--cpu" => cpu = v,
                "--rounds" => rounds = v,
                "--samples" => samples = v,
                other => return Err(format!("unknown argument {other}")),
            }
        }
        if rounds == 0 || samples == 0 {
            return Err("--rounds and --samples must be positive".into());
        }

        let pin = platform::pin_and_prioritize(cpu)?;
        let hz = platform::tsc_hz();
        let mut rng = mlkem::OsRng;
        let mut arr = || -> Result<Vec<[u8; 32]>, String> {
            let mut v = vec![[0u8; 32]; INPUTS];
            for x in &mut v {
                rng.fill_bytes(x).map_err(|e| e.to_string())?;
            }
            Ok(v)
        };
        let inp = Inputs {
            d: arr()?,
            z: arr()?,
            m: arr()?,
        };

        println!("# mlkem-bench");
        println!("cpu:        {}", platform::cpu_brand());
        println!("scheduling: {pin}");
        println!("timer:      RDTSC with LFENCE; TSC = {:.1} MHz", hz / 1e6);
        println!(
            "method:     {INPUTS} random inputs shared by both implementations (outputs checked \
             equal); {rounds} timed rounds x {samples} calls per implementation, alternating \
             ABBA, after 1 warm-up round"
        );
        println!("compared:   ml-kem 0.3.3 (RustCrypto), same compiler and profile");
        println!();

        let mut rows = vec![format!(
            "{:<12} {:<7} {:<13} {:>10} {:>10} {:>10} {:>10} {:>8}",
            "param set", "op", "impl", "median us", "p5 us", "p95 us", "ops/s", "n"
        )];
        param_set!(
            ml_kem_512,
            ml_kem::MlKem512,
            "ML-KEM-512",
            &inp,
            rows,
            rounds,
            samples,
            hz
        );
        param_set!(
            ml_kem_768,
            ml_kem::MlKem768,
            "ML-KEM-768",
            &inp,
            rows,
            rounds,
            samples,
            hz
        );
        param_set!(
            ml_kem_1024,
            ml_kem::MlKem1024,
            "ML-KEM-1024",
            &inp,
            rows,
            rounds,
            samples,
            hz
        );
        for r in rows {
            println!("{r}");
        }

        // Building blocks of this crate (hazmat probes), to explain where
        // the time goes. Only Keccak-f has a like-for-like reference here.
        println!();
        println!(
            "building blocks (median over {} blocks of 100 calls, after warm-up):",
            rounds * samples
        );
        println!("{:<44} {:>10} {:>10}", "function", "ns", "ticks");
        // Each closure owns its state (`move`). NTT and Keccak-f are applied
        // to their own output again and again: the values drift, but this
        // code is constant time, so the values do not change the timing.
        let (mut st1, mut st2) = ([0u64; 25], [0u64; 25]);
        let poly: [i16; 256] = core::array::from_fn(|i| ((i * 1337) % 3329) as i16);
        let (mut p1, mut p2) = (poly, poly);
        let b128 = [0x5au8; 128];
        let b384 = [0xa5u8; 384];
        type Prim = (&'static str, Box<dyn FnMut()>);
        let mut prims: Vec<Prim> = vec![
            (
                "Keccak-f[1600], mlkem",
                Box::new(move || mlkem::hazmat::keccak_f1600(black_box(&mut st1))),
            ),
            (
                "Keccak-f[1600], keccak 0.1 crate (RustCrypto)",
                Box::new(move || keccak::f1600(black_box(&mut st2))),
            ),
            (
                "NTT",
                Box::new(move || mlkem::hazmat::ntt(black_box(&mut p1))),
            ),
            (
                "inverse NTT",
                Box::new(move || mlkem::hazmat::ntt_inverse(black_box(&mut p2))),
            ),
            (
                "MultiplyNTTs (one polynomial pair)",
                Box::new(move || {
                    black_box(mlkem::hazmat::multiply_ntts(
                        black_box(&poly),
                        black_box(&poly),
                    ));
                }),
            ),
            (
                "SamplePolyCBD, eta = 2",
                Box::new(move || {
                    black_box(mlkem::hazmat::cbd_eta2(black_box(&b128)));
                }),
            ),
            (
                "ByteDecode_12 (one polynomial)",
                Box::new(move || {
                    black_box(mlkem::hazmat::decode12(black_box(&b384)));
                }),
            ),
        ];
        // Sub-microsecond functions: time blocks of BLOCK calls and divide,
        // so the timer's own overhead (~40 ticks) and its granularity do not
        // distort the result.
        const BLOCK: u64 = 100;
        for (name, f) in &mut prims {
            let n = rounds * samples;
            let mut v = Vec::with_capacity(n);
            for k in 0..2 * n {
                let t0 = platform::ticks();
                for _ in 0..BLOCK {
                    f();
                }
                let t1 = platform::ticks();
                if k >= n {
                    v.push(t1 - t0);
                }
            }
            v.sort_unstable();
            let m = pct(&v, 0.5) as f64 / BLOCK as f64;
            println!("{:<44} {:>10.0} {:>10.0}", name, m / hz * 1e9, m);
        }
        Ok(())
    }
}
