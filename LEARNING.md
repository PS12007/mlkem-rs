# LEARNING.md

Notes written alongside the code, one section per phase. The aim is that
you can explain and defend every line of this repository in an interview.
Section and algorithm numbers refer to FIPS 203 (August 2024).

---

## Phase 1: Field arithmetic, NTT, encoding, sampling

### 1.1 Why quantum computers break RSA and elliptic curves (Shor)

RSA is secure only if factoring a large N = p·q is hard. Elliptic-curve
cryptography (ECDH, ECDSA) is secure only if the discrete logarithm is hard:
given P and Q = x·P, find x. The best classical algorithms for both are
far too slow at real key sizes (sub-exponential for factoring, exponential
for elliptic curves).

Both problems hide a **period**. Pick a random a and look at
f(x) = a^x mod N. The sequence repeats with some period r. If you know r,
you can usually factor N with a gcd: gcd(a^(r/2) − 1, N) is often p or q.
Classically, finding r is as hard as factoring. A quantum computer can put
x into a superposition of all values at once, compute f on all of them, and
then apply the **quantum Fourier transform**. This makes the period stand
out the way a frequency stands out in a signal. That is **Shor's algorithm**
(1994): polynomial time for factoring and for discrete logs, including on
elliptic curves.

How big a machine is needed? Published estimates keep falling: about 20
million noisy qubits for RSA-2048 (Gidney and Ekerå, 2019), and under a
million in a 2025 estimate by Gidney. No such machine exists yet. The worry
is **harvest now, decrypt later**: traffic recorded today can be decrypted
once one does. Key exchange is therefore what is being replaced first, and
ML-KEM is the replacement.

Symmetric cryptography (AES, SHA-3) only faces Grover's algorithm, a
square-root speed-up for brute force. Doubling key sizes is enough, which
is why ML-KEM can safely use SHA-3 and SHAKE inside.

**Why lattices resist Shor.** Shor needs a hidden periodic structure in an
abelian (commutative) group, which is what the quantum Fourier transform
can find. Nobody has found such structure in lattice problems. The best known
quantum attacks on them are only slightly better than the classical ones.
That is evidence, not proof (see 1.2).

### 1.2 Lattices, LWE and Module-LWE

A **lattice** is all integer combinations of some basis vectors: a regular
grid of points, but in hundreds of dimensions and with a skewed basis.
Finding a very short non-zero vector in it (the Shortest Vector Problem) is
easy in 2 dimensions and appears to take exponential time in 500.

**Learning With Errors (LWE).** You are given a random matrix A and
b = A·s + e (mod q), where s is secret and e is a vector of *small* random
errors. Find s.
- Without e this is a school exercise: Gaussian elimination.
- With e, elimination fails: every row operation mixes and multiplies the
  errors until they are as big as q and wipe out the information.
- Regev (2005) proved that solving *average* LWE instances would let you
  solve *worst-case* lattice problems (with a quantum reduction). That is
  the main theoretical reason to trust LWE.

**From LWE to Module-LWE.** Plain LWE needs a big n×n matrix of numbers,
so keys are large. Ring-LWE replaces numbers with polynomials in
R_q = Z_q[X]/(X^256 + 1). One polynomial stands in for a whole 256×256
structured block, so keys shrink by a factor of about 256. Module-LWE sits
in between: a small k×k *matrix of polynomials*.
- ML-KEM-512 / -768 / -1024 use k = 2 / 3 / 4. The name is the dimension:
  256·k.
- k is the security dial. Ring structure for speed, a module of rank k for
  flexibility, and less algebraic structure than pure Ring-LWE.

**In ML-KEM** (phase 3) the public key is t = A·s + e. A is a k×k matrix
expanded from a public 32-byte seed ρ (that is SampleNTT). s and e come from
the centred binomial distribution (that is SamplePolyCBD).

**The core idea of the encryption, in one line.** To send a bit m, add
m·⌈q/2⌋ to something that only the key holder can make "nearly zero". The
key holder subtracts, gets m·q/2 + (small noise), and rounds: near 0 means 0,
near q/2 means 1. That rounding is exactly Compress_1, and the m·q/2 is
Decompress_1, both in `encode.rs`.

**"Believed hard" means:** decades of cryptanalysis, attacks (BKZ lattice
reduction) whose cost grows exponentially with the dimension, the worst-case
reduction above, and six-plus years of the NIST competition. It is not a proof.
Module lattices have more structure than general lattices, and that
structure is where people keep looking for weaknesses.

### 1.3 Arithmetic mod q: Barrett and Montgomery

**Why q = 3329?** It is prime. 3328 = 2^8 · 13, so 256 divides q − 1, and
that guarantees a primitive 256-th root of unity mod q (ζ = 17) for the NTT.
It is small: 12 bits, so a coefficient fits in an `i16` with spare room for
lazy additions, and a product of two fits in an `i32`.

**Why not `%`?** The remainder `%` is defined by a division. Whether the
compiler turns `x % 3329` into a cheap multiply or emits a real `div`
depends on the compiler, the target and the optimisation level. A real
`div` has data-dependent latency on many CPUs, which leaks secrets (1.5).
So we write reduction ourselves using only multiply, add, subtract and
shift.

**Barrett reduction** (`field::barrett_reduce`). Precompute
V = round(2^26 / q) = 20159 once. For any a, t = round(a·V / 2^26) is
round(a/q), the quotient. Then a − t·q is the remainder, in [−1664, 1664].
Dividing by q becomes multiplying by an approximation of 1/q and shifting.

**Montgomery reduction** (`field::montgomery_reduce`). It does not compute
a mod q. It computes a · 2^(−16) mod q, which turns out to be just as useful:
1. t = a · q^(−1) mod 2^16 (the low 16 bits of a product).
2. a − t·q is now divisible by 2^16 (that was the point of choosing t),
   so `>> 16` divides exactly.
3. We subtracted only a multiple of q, so the result is a/2^16 mod q.

To multiply x by a constant ζ, store ζ·2^16 mod q ("Montgomery form")
ahead of time. Then montgomery_reduce(x · ζ·2^16) = x·ζ. One multiply, one
reduction, no division. The NTT tables are stored this way.

**Signed representation.** Coefficients are `i16` values congruent to the
true value, kept in (−q, q), not [0, q). `x >> 15` on a negative i16 gives
all ones, and on a non-negative one gives all zeros, which is a free mask:
`x + ((x >> 15) & q)` maps (−q, q) to [0, q) with no branch
(`field::to_canonical`).

### 1.4 The NTT: why it makes multiplication fast

Multiplying two polynomials of 256 coefficients the textbook way takes
256 × 256 = 65,536 multiplications (`spec::schoolbook_mul`). ML-KEM does
many such products per operation, so this has to be faster.

**The idea (Chinese Remainder Theorem).** If a modulus factors, you can
work modulo each factor separately and combine at the end. Mod q,

    X^256 + 1 = (X^128 − ζ^64)(X^128 + ζ^64)     because ζ^128 = −1

Write f = f_lo + X^128 · f_hi. Modulo (X^128 − c), X^128 is just c, so
f ≡ f_lo + c·f_hi. Modulo (X^128 + c), f ≡ f_lo − c·f_hi. That is
Algorithm 9 lines 8–10:

    t          = zeta · f[j + len]      // c · f_hi
    f[j + len] = f[j] − t               // f_lo − c·f_hi
    f[j]       = f[j] + t               // f_lo + c·f_hi

This is the **butterfly**. For the first layer, zeta = ZETAS[1] = 17^64 mod q
= 1729, the second entry of Appendix A. Each factor splits again, 7 times
in total: 256 → 128 → … → 2. That leaves 128 pieces f mod (X^2 − γ_i), each
of degree 1.

**Why "incomplete" (stops at degree 1).** Splitting X^2 − γ into two
linear factors would need √γ, which means a primitive 512-th root of unity.
That needs 512 | q − 1, but q − 1 = 2^8 · 13. So the last step is
BaseCaseMultiply (Alg 12): multiply two degree-1 polynomials mod X^2 − γ,
which is 5 multiplications.

**Cost.** Forward NTT: 7 layers × 128 multiplications = 896. Pointwise
product: 128 × 5. Then one inverse NTT. A typical product (a public matrix
entry already in the NTT domain times a secret vector in the NTT domain)
is a few thousand multiplications instead of 65,536. ML-KEM even keeps keys
in the NTT domain so that most transforms happen only once.

**Bit-reversed order.** The butterflies leave the outputs in bit-reversed
order (BitRev7). FIPS 203 does not reorder them: both parties use the same
order, so reordering would be wasted work. That is why the tables are
indexed by BitRev7(i).

**Inverse NTT** (Alg 10) runs the butterflies backwards ("Gentleman–Sande"
form). Undoing one CRT split really needs a division by 2. To save work,
each of the 7 layers leaves that out, and line 14 makes up for all of them
at once by multiplying by 2^(−7) = 128^(−1) = 3303 mod q.

### 1.5 Constant time in phase 1 (preview; full treatment in phases 4–5)

A timing attack measures how long an operation takes, many times, and works
out secret data from the differences. Three sources of timing differences
matter:
1. **branches** on secrets (different code runs, plus branch-predictor
   effects),
2. **memory addresses** chosen by secrets (cache hits versus misses),
3. **variable-time instructions** on secrets (`div` on x86, among others).

Where phase 1 handles secrets, and what we did:

| Function | Secret? | Treatment |
|---|---|---|
| `compress` | yes (decryption, encryption) | division by q replaced by multiply + shift |
| `byte_decode(12, …)` | yes (secret key) | branch-free `csubq` instead of `if x >= q` |
| `sample_poly_cbd` | yes (s, e, noise) | only shifts/masks/adds on secret bits, public indices |
| `ntt`, `ntt_inverse`, `multiply_ntts` | yes (s) | fixed loop structure, indices from counters only |
| `barrett_reduce`, `montgomery_reduce`, `to_canonical` | yes | arithmetic and arithmetic shifts only |
| `ct_eq_bytes`, `ct_select_bytes` | yes (phase 3) | always touch every byte, masks instead of `if` |
| `sample_ntt` | **no**, input is public ρ | rejection loop is allowed to vary in time |

**KyberSlash** (2023–24) was exactly rule 3. The reference C code computed
`((x << d) + q/2) / q` on secret x. On some compilers and platforms that is a
real `div`, and its timing leaked the secret key. Our `compress` cannot
produce a `div`. Phase 4 checks this in the assembly, and phase 5 builds a
leaky version on purpose and measures the difference.

### 1.6 Design decisions and alternatives

- **`i16` signed coefficients with lazy reduction** (as in the C reference
  code), rather than always keeping values in [0, q). This is faster, and
  Montgomery reduction is naturally signed. The cost is that you must track
  bounds. Every function documents its input/output range, and the tests
  run with overflow checks on to prove the bounds hold. Alternative: `u16`
  values always in [0, q), which is simpler to reason about but needs a
  reduction after every operation.
- **Exact `multiply_ntts`.** BaseCaseMultiply finishes with an extra
  multiplication by R^2 so the output is exactly FIPS's value. The C
  reference skips it and corrects for the stray 2^(−16) factor later, inside
  the inverse NTT's constant. That saves 256 multiplications per product, but
  MultiplyNTTs on its own then no longer matches the standard. We chose
  "every function matches FIPS on its own" over speed. It is a possible
  optimisation for phase 6.
- **One `Poly` type for both domains.** A stricter design has two newtypes,
  `Poly` and `NttPoly`, so the compiler rejects multiplying in the wrong
  domain. We keep one type because it is simpler, and the property tests
  would catch a domain mix-up. It is a reasonable interview "what would you
  change?" answer.
- **Literal oracles in `spec.rs`.** Every fast function is tested against a
  slow, line-by-line copy of the FIPS pseudocode using plain `% q`. This is
  **differential testing**: two independent implementations must agree on
  thousands of random inputs. The Appendix A tables were copied from the
  PDF text and compared against values our code *computes* (17^BitRev7(i)
  mod q). Two independent sources agreeing is much stronger than either on
  its own.
- **Exhaustive tests where the domain is small.** Montgomery reduction is
  tested on every input it accepts (about 2.2·10^8 values), Barrett on every
  `i16`, Compress and Decompress on every (d, x). Random testing can miss a
  single bad input. Exhaustive testing cannot.
- **Compress via ⌊n·M / 2^40⌋ with M = ⌈2^40/q⌉.** One constant for every d,
  and the exactness proof is in the comment on `encode.rs::COMPRESS_M`. The
  C reference uses smaller hand-picked constants per d with 32-bit maths,
  which suits 32-bit microcontrollers better.
- **SampleNTT reads 168-byte blocks** (the SHAKE128 rate) instead of 3 bytes
  at a time. This is equivalent because squeezing is a continuous stream.
- **No runtime dependencies.** The crate is `no_std` with
  `#![forbid(unsafe_code)]`. `proptest` is a dev-dependency only.
- **Clippy's `needless_range_loop` is allowed** project-wide, so loops read
  like the pseudocode (`for i in 0..128`).

### 1.7 What went wrong

- **Barrett reduction overflowed.** `t * Q` with t = 10 is 33,290, which
  does not fit in an `i16`. The final result a − t·q always fits, and
  arithmetic mod 2^16 is exact whenever the true result fits, so the fix is
  `wrapping_mul` / `wrapping_sub`. The C reference silently relies on the
  same wraparound. Rust's overflow checks (on in the test profile) caught
  it on the first run. This is the reason they are left on.
- **A weak property test.** The first version of the encode test drew its
  values from a fixed-seed generator, so every case tested the same values.
  It was caught when re-reading before the commit, and replaced with
  `prop_flat_map`. Lesson: a passing test is not automatically a useful
  test.
- **Tooling on Windows.** The PDF could not be rendered (no poppler), so its
  text was extracted with `pypdf`. A PowerShell 5.1 find-and-replace also
  re-saved two source files with the wrong text encoding, garbling
  characters like `§` and `≤`. It was repaired before committing. Lesson:
  edit source files with an editor, not with PowerShell's
  `Get-Content`/`Set-Content` on Windows PowerShell 5.1.

### 1.8 Interview questions

**Q1. Why does ML-KEM use n = 256 and q = 3329?**
q is prime and 256 divides q − 1, so Z_q has a primitive 256-th root of
unity (ζ = 17). That lets X^256 + 1 split into 128 quadratic factors, which
makes a fast NTT possible. q is small enough (12 bits) that coefficients fit
in 16-bit words with room for lazy additions, and products fit in 32 bits.
n = 256 matches the 256-bit (32-byte) shared secret and message, one bit per
coefficient. Security is scaled with the module rank k, not with n.

**Q2. Explain the NTT and why ML-KEM's is "incomplete".**
It is a Chinese-Remainder decomposition. X^256 + 1 = (X^128 − ζ^64)(X^128 + ζ^64),
and reducing f = f_lo + X^128·f_hi modulo the two factors gives f_lo ± ζ^64·f_hi:
one multiplication per pair, the butterfly. Repeating this 7 times gives
128 residues mod X^2 − γ_i. Multiplying in that representation is 128 small
independent products. The cost is O(n log n) instead of O(n^2). It stops at
degree 1 because splitting X^2 − γ needs a 512-th root of unity, and
512 ∤ q − 1 = 2^8·13.

**Q3. What is Montgomery reduction and why use it instead of `%`?**
It computes a·2^(−16) mod q using a multiply by q^(−1) mod 2^16, a
subtraction and an exact shift, with no division. Pre-multiplying constants
by 2^16 cancels the 2^(−16), so x·ζ mod q becomes one multiply plus one
reduction. Avoiding `%` matters for speed, and also for security: `%` and `/`
can compile to a `div` instruction whose timing depends on its input, which
is the KyberSlash leak.

**Q4. How do you know your NTT is correct?**
Four independent checks. (1) The ζ tables computed in code match Appendix A
copied from the PDF. (2) `ntt`, `ntt_inverse` and `multiply_ntts` match
literal line-by-line transcriptions of Algorithms 9–12 on random inputs.
(3) NTT⁻¹(NTT(f) ∘ NTT(g)) equals schoolbook multiplication in R_q, which
checks the mathematics and not just agreement with my own reading of the
pseudocode. (4) Tests run with overflow checks and with worst-case inputs
(every coefficient ±(q − 1)), so the documented i16 bounds really hold.

**Q5. Which phase-1 functions must be constant time, and why is
SampleNTT's data-dependent loop acceptable?**
Anything that touches s, e, the noise, or the decryption intermediate w:
compress, decode of the secret key, CBD sampling, the NTT and the field
reductions. SampleNTT only ever processes the expansion of ρ, which is part
of the public key. Its timing can reveal something only about data the
attacker already has. If someone later fed it secret data, it would become
a leak, which is why the comment states the assumption explicitly.

---

## Phase 2: Keccak, SHA-3 and SHAKE

Reference: FIPS 202, https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
Code: `crates/mlkem/src/hash/`.

### 2.1 What ML-KEM needs hashing for

FIPS 203 §4.1 defines five wrappers, and every one is SHA-3 or SHAKE:

| Wrapper | Definition | Used for |
|---|---|---|
| H(s) | SHA3-256(s) | hash of the public key, H(ek), stored in the secret key |
| J(s) | SHAKE256(s, 256 bits) | the implicit-rejection key K̄ = J(z ‖ c) (phase 3) |
| G(c) | SHA3-512(c), split into two 32-byte halves | derive (ρ, σ) from d. Derive (K, r) from m ‖ H(ek) |
| PRF_η(s, b) | SHAKE256(s ‖ b, 64·η bytes) | noise bytes for SamplePolyCBD |
| XOF | SHAKE128, incremental | expand ρ into the matrix A (SampleNTT) |

In a security proof these play the role of "random oracles": functions
whose outputs look completely random and unrelated to each other. Using
four different constructions (or different inputs) keeps the roles
separate.

### 2.2 The sponge construction

Picture the 1600-bit Keccak state as a sponge with two parts:
- the **rate** r: the part you pour data into and squeeze output from,
- the **capacity** c = 1600 − r: never touched directly. It is the hidden
  part that gives security, about c/2 bits against collisions.

**Absorbing:** XOR r bits of message into the rate part, run the
permutation f, repeat. **Squeezing:** read r bits, run f, repeat, for as
long as you want output. That is why SHAKE is an *extendable-output
function*: it can produce any number of bytes. SampleNTT needs a
variable amount, because it throws some candidates away.

Choosing r trades speed for security. SHAKE128 has a 168-byte rate
(c = 256), and SHA3-512 only 72 bytes (c = 1024). The table is in
`sponge.rs`.

**Padding and domain separation.** After the last message byte we append a
few *suffix* bits, then "pad10*1": a 1, as many 0s as needed, then a final 1
at the end of the block. The suffix is `01` for SHA3 and `1111` for SHAKE, so
the same message hashed by SHA3-256 and by SHAKE256 (same rate, 136 bytes)
gives unrelated outputs. Bits fill each byte from the least significant end,
so the suffix plus the first pad bit is the byte **0x06** (SHA3) or **0x1F**
(SHAKE), and the final pad bit is **0x80** in the last byte of the block.
If the message ends one byte before the block boundary, both land in the
same byte: 0x06 ^ 0x80 = 0x86. We test that case for every rate.

### 2.3 Keccak-f[1600]: the permutation

The state is a 5 × 5 grid of 64-bit lanes. A round has five steps, and
there are 24 rounds:

1. **θ (theta), diffusion across columns.** Each bit is XORed with the
   parity of two neighbouring columns. One flipped input bit spreads to
   about 11 bits.
2. **ρ (rho), diffusion within lanes.** Each lane is rotated by its own
   fixed amount (the triangular numbers (t+1)(t+2)/2 mod 64 along a walk
   over the grid).
3. **π (pi), diffusion across lanes.** The lanes swap positions:
   (x, y) → (y, 2x + 3y mod 5).
4. **χ (chi), the only non-linear step.** a ⊕ (¬b ∧ c) along each row.
   Without a non-linear step, the whole function would be a linear map and
   easy to invert with algebra.
5. **ι (iota)** XORs a round constant into one lane, so the rounds are not
   all identical. That blocks "slide" attacks, which exploit identical
   rounds.

We do not type in the 24 round constants or the 25 rotation offsets. They
are **computed at compile time** from FIPS 202's definitions: the 8-bit LFSR
of Algorithm 5 and the (x, y) walk of Algorithm 2. Then a typo cannot
hide in a table, and the code shows *where* the numbers come from.

**Constant time.** Keccak uses only XOR, AND, NOT and rotations by constant
amounts, with no tables indexed by data. It is constant time by design.
Compare AES in software, whose table lookups (S-boxes) are a classic
cache-timing leak.

### 2.4 Design decisions and alternatives

- **Typestate: absorbing and squeezing are different types.**
  `Sponge::finalize(self)` *consumes* the absorbing sponge and returns a
  `Squeezer`. Absorbing after squeezing would be a bug, and now it does not
  compile. Alternative: one struct with a runtime flag.
- **Inputs as `&[&[u8]]`.** FIPS 203 hashes concatenations such as d ‖ k and
  z ‖ c. Absorbing the pieces one after another is mathematically the same
  as absorbing the concatenation (tested), and needs no heap (`no_std`).
- **Two absorb paths.** Whole aligned blocks are XORed in a lane (8 bytes) at
  a time. Everything else goes byte by byte. Simple, and fast enough. A
  faster version would also handle unaligned blocks lane by lane, and
  possibly use the SHA-3 instructions that newer ARM CPUs have.
- **Not wiping the state afterwards.** After hashing secrets (e.g. G(d ‖ k))
  the Keccak state left in memory is derived from secrets. Wiping it
  reliably needs volatile writes, which in Rust means `unsafe` or a crate
  like `zeroize`. This crate forbids `unsafe`, so phase 4 will decide how to
  handle zeroisation, and it is listed under Limits.

### 2.5 Testing, and testing the tests

- **Known answers:** SHA3-256("") , SHA3-256("abc") and SHAKE128("", 256)
  from NIST's published example values.
- **Differential testing** against RustCrypto (dev-dependency only):
  - the permutation against `keccak::f1600` on random states;
  - all four functions on *every* message length from 0 to 505 bytes,
    which crosses every rate boundary (72, 136, 168) several times;
  - inputs split at random points;
  - SHAKE output squeezed in random-size pieces;
  - SampleNTT on our SHAKE128 against the literal Algorithm 7 on theirs.
- **Mutation check.** To see whether the tests can fail, I changed the
  SHAKE suffix from 0x1F to 0x1E (one bit) and re-ran them: **6 of 35
  tests failed**, which is every test that uses SHAKE. Then I reverted it.
  A test suite that never fails when you break the code is worthless. This
  is a quick way to check.

### 2.6 What went wrong

- **The newest `sha3` crate (0.12) no longer contains SHAKE128/256.** The
  cross-check needs SHAKE, so the dev-dependencies are pinned to `sha3 0.10`
  and `keccak 0.1`, which are long-established versions with the API
  `keccak::f1600(&mut [u64; 25])`. I read both crates' source before
  writing tests against them rather than guessing their APIs.
- **Leftover files from the mutation run.** proptest saves failing cases to
  `proptest-regressions/` so it can re-run them. The ones saved while the
  code was deliberately broken were deleted, not committed.

### 2.7 Interview questions

**Q1. Explain the sponge construction and what the capacity does.**
A 1600-bit state is split into rate r and capacity c. Absorb: XOR r-bit
blocks into the state and permute. Squeeze: output r bits at a time,
permuting in between. The capacity is never directly read or written by
the user, and generic attacks cost about 2^(c/2). That is why SHAKE128
(c = 256) gives 128-bit security and SHA3-512 (c = 1024) uses a small rate.

**Q2. Why does ML-KEM use SHAKE128 for matrix generation instead of
SHA3-256?**
SampleNTT needs an unknown amount of output, because rejection sampling
discards about 19% of the 12-bit candidates (4096 − 3329 of every 4096).
An XOF gives any length from one call. SHAKE128's 168-byte rate is the
largest available, so it is the fastest per byte. The matrix only needs
to look random, not to be secret, so 128-bit security is enough.

**Q3. How do SHA3-256 and SHAKE256 avoid colliding when they use the same
rate?**
Domain separation: a different suffix (`01` versus `1111`) is appended
before padding, so the inputs to the permutation always differ in the
last block.

**Q4. Is your Keccak constant time? How would you argue it?**
Yes, by construction. The operations are XOR, AND, NOT and fixed rotations.
The only table, the round constants, is indexed by the round number. Loop
counts depend only on input *length*, which is public in every ML-KEM use.
In phase 4 the compiled assembly is checked for branches as well.

**Q5. How did you make sure your tests would actually catch a bug?**
Differential tests against an independent implementation, at every length
around the block boundaries, not just random lengths. Then a deliberate
mutation (one bit of padding changed) to confirm that the suite fails:
6 of 35 tests did, which is all the SHAKE-dependent ones.

---

## Phase 3: K-PKE, ML-KEM and the official test vectors

Code: `kpke.rs` (§5, Alg 13–15), `kem.rs` (§6–7, Alg 16–18 and the input
checks), `lib.rs` (the typed API, Alg 19–21), `rng.rs` (OS randomness).
Tests: `tests/acvp.rs`, `tests/crosscheck.rs`, `tests/props.rs`.

### 3.1 K-PKE: encryption from Module-LWE

Write everything as vectors and matrices of polynomials in R_q.

**KeyGen (Alg 13).** Expand a public matrix A from a seed ρ. Sample a
secret s and an error e with small coefficients. Publish
**t = A·s + e** and ρ. Recovering s from (A, t) is exactly the Module-LWE
problem from §1.2.

**Encrypt (Alg 14)** a 32-byte message m. Sample fresh small y, e1, e2 and
compute

    u = Aᵀ·y + e1                   (k polynomials)
    v = tᵀ·y + e2 + μ               (one polynomial), μ = m's bits × ⌈q/2⌋

To anyone without s, (u, v) looks like random Module-LWE samples.

**Decrypt (Alg 15).** Compute w = v − sᵀ·u. Expanding everything:

    w = (sᵀAᵀy + eᵀy) + e2 + μ − (sᵀAᵀy + sᵀe1)
      = μ + (eᵀy + e2 − sᵀe1)        ← the big terms cancel
      = μ + small noise

Every term in the bracket is a product of small things, so each coefficient
of w is near 0 (bit 0) or near q/2 (bit 1). Compress_1 rounds it to the
nearer one. Decryption fails only if the noise exceeds q/4. FIPS 203
Table 1 gives the failure rates as 2^−138.8 (ML-KEM-512), 2^−164.8 (768) and
2^−174.8 (1024): too rare to ever observe.

**Why compress the ciphertext?** Uncompressed, u and v need 12 bits per
coefficient: (k + 1) × 384 bytes, or 1536 bytes for ML-KEM-768. Rounding
u to du = 10 bits and v to dv = 4 bits adds a little more noise (still well
under q/4) and gives 1088 bytes, about 29% smaller.

**Everything happens in the NTT domain.** Â, ŝ and t̂ are stored and
transmitted *already transformed* (FIPS 203 even defines the key format
that way). The products Â∘ŝ, Âᵀ∘ŷ and t̂ᵀ∘ŷ are therefore cheap pointwise
products. Only y, e, u′ and the final sums need (inverse) NTTs.

### 3.2 Why K-PKE alone is not enough: chosen-ciphertext attacks

K-PKE is secure against an attacker who only *watches* (IND-CPA). Real
protocols let attackers *send* things. Suppose a server reuses its key
pair, and an attacker sends a *modified* ciphertext. If the server's
behaviour shows whether decryption gave the "same" m (for example, the
handshake continues or fails), each query tells the attacker whether their
change pushed some coefficient of the noise across the q/4 boundary. That
boundary position depends on s. A few thousand such queries recover the
whole secret key. These are "key-mismatch" or "reaction" attacks, and they
are real: they work against plain LWE encryption.

### 3.3 The Fujisaki–Okamoto transform and implicit rejection

ML-KEM wraps K-PKE so that tampering gains the attacker nothing.

**Encaps (Alg 17).** Pick random m. Derive **(K, r) = G(m ‖ H(ek))**:
both the shared key *and the encryption randomness* come from m. Encrypt
m with that r. Output c, keep K.

**Decaps (Alg 18).** Decrypt c to m′. Recompute (K′, r′) = G(m′ ‖ H(ek)).
**Re-encrypt** m′ with r′ to get c′. Because encryption is now deterministic
given m, an honest c re-encrypts to *exactly* itself. Any modified or
crafted c almost certainly does not.
- If c = c′: return K′.
- If c ≠ c′: return **K̄ = J(z ‖ c)**, where z is a secret random value
  stored in dk.

That second branch is **implicit rejection**. Instead of returning an error,
Decaps returns a key that looks random, is the same every time for the same
c, and depends on a secret the attacker does not know. From the outside, a
rejected ciphertext and a valid one behave the same way: you get 32 bytes
that will not match the attacker's key. The reaction attack loses its
signal, because whatever the attacker sends, the result no longer depends
on whether m′ moved in a way that reveals s.

**Why hash H(ek) into G?** It binds the shared key to the specific
public key, so a ciphertext made for one key cannot be reused against
another. It also stops an attacker who targets many keys at once from
sharing work between them. Storing H(ek) inside dk saves recomputing it on
every Decaps.

**Constant time matters most here.** If Decaps took a different time for
c = c′ than for c ≠ c′ (an early return, an `if`, a `memcmp` that stops at
the first difference), the timing would give back the exact signal that
implicit rejection removed. So `kem::decaps_internal` always computes both
K′ and K̄, compares all bytes with `ct_eq_bytes`, and picks one with a mask
(`ct_select_bytes`). This is not hypothetical: Guo, Johansson and Nilsson
(CRYPTO 2020, "A Key-Recovery Timing Attack on Post-Quantum Primitives
Using the Fujisaki–Okamoto Transformation and Its Application on
FrodoKEM") recovered secret keys from a non-constant-time comparison in
exactly this step.

### 3.4 The input checks (§7.2, §7.3)

- **Encapsulation key, modulus check:** decode the 12-bit values of t̂
  and re-encode them. The bytes must not change, which is the same as every
  value being < q. A value like 4000 would be silently reduced mod q by
  ByteDecode_12, so two different byte strings would act as the same key
  while hashing to different H(ek). That is a mismatch FIPS forbids.
- **Decapsulation key, hash check:** the stored H(ek) must equal the hash
  of the stored ek. This catches corruption or splicing of two keys.
- **Type checks** are lengths. In the typed API (`ml_kem_768::Ciphertext`
  and so on) the length is part of the type, so a wrong-length input
  cannot even be passed. `TryFrom<&[u8]>` performs the length check.

The checks live in the constructors (`EncapsulationKey::from_bytes`,
`DecapsulationKey::from_bytes`), so an *unchecked* key cannot reach Encaps
or Decaps. FIPS 203 says these "shall not be run" with unchecked inputs,
and making it impossible is stronger than documenting it.

### 3.5 Design decisions and alternatives

- **Slice-based core plus macro-generated typed API.** Rust's const
  generics cannot yet compute array lengths like `[u8; 384*K + 32]` from a
  generic parameter on stable. The core (`kpke.rs`, `kem.rs`) therefore
  takes slices and a runtime `Params`, and a macro stamps out
  `ml_kem_512` / `768` / `1024` with fixed arrays. Alternative: one generic
  type using a crate like `hybrid-array` (RustCrypto's approach), which
  means a dependency and harder-to-read types.
- **The matrix is never stored.** Each Â entry is regenerated when needed.
  KeyGen and Encrypt each use every entry once, so this costs nothing. A
  server doing many Encaps to one key could cache Â (FIPS 203 §3.3 allows
  it), which is a speed-up for phase 6 to measure.
- **Internal functions are public** (`generate_internal`,
  `encapsulate_internal`) and documented as "testing only". FIPS 203 §6
  says they *should not* be offered to applications. The official vectors
  and the timing harness both need them. Alternative: put them behind a
  `hazmat` Cargo feature.
- **One `unsafe` block.** `OsRng` calls Windows' `BCryptGenRandom`. The
  crate uses `#![deny(unsafe_code)]` with one `#[allow]` on that module, plus
  a `// SAFETY:` comment explaining why the call is sound. Alternative: the
  `getrandom` crate, which is a dependency, but portable.
- **Secrets are wiped on drop, best effort.** `DecapsulationKey` and
  `SharedSecret` zero their bytes on drop, and the ML-KEM-level seeds d, z
  and m are wiped after use. Intermediate values (s, m′, the Keccak state,
  stack copies) are not. Doing that properly needs `zeroize`-style volatile
  writes. Phase 4 decides, and it is a Limit.
- **`SharedSecret` equality is constant time**, and its `Debug` output does
  not show the bytes, so it cannot leak through logs.

### 3.6 Validation

| What | How many | Source of truth |
|---|---|---|
| NIST ACVP KeyGen | 75 | NIST's expected ek, dk |
| NIST ACVP Encaps | 75 | NIST's expected c, K |
| NIST ACVP Decaps | 30 (15 tampered) | NIST's expected K, including the rejection key |
| NIST ACVP key checks | 60 (30 invalid) | NIST's pass/fail |
| Cross-check vs RustCrypto `ml-kem` 0.3.3 | 256 per parameter set by default | byte equality of ek, dk, c, K, and K for random ciphertexts |
| Property tests | 256 each by default | round trip; bit-flip gives exactly J(z ‖ c′) (computed with the *reference* SHAKE256); invalid keys rejected |
| Extended run | 100,000 per property | same properties with PROPTEST_CASES = 100,000. All passed: 234 s on an i7-14700HX, at commit `2a4acce` (raw output: `results/extended-proptest.txt`, from `scripts/extended-proptest.ps1`). The K-PKE unit round trip is pinned to 32 cases and is not affected. |

**Mutation check.** I made Decaps always return K′, which disables implicit
rejection, and re-ran everything. It failed the NIST vectors, all three
cross-checks and the bit-flip property. Then I reverted it. A single
safety-critical line is guarded by three independent kinds of test.

**Fuzzing.** `cargo-fuzz` needs the nightly toolchain (a download of
several hundred MB) and libFuzzer, which is fragile on Windows/MSVC. Under
this project's no-big-downloads rule, the substitute is the extended
property-test run above: the same input-mutation idea, at high volume,
with invariants checked on every case. What it does *not* give is
coverage-guided input generation. That is a Limit.

### 3.7 What went wrong

- **Very little, for a reason.** Phases 1 and 2 had tested every building
  block against literal pseudocode, so phase 3 passed all 240 NIST vectors
  on the first run. The time spent on per-function oracles is what paid
  off here.
- **The reference crate's API had moved on.** `ml-kem` 0.3 builds keys from
  64-byte seeds and marks the FIPS "expanded" dk format as deprecated, so
  the cross-check uses `from_seed(d ‖ z)` and `to_expanded_bytes()`. As in
  phase 2, I read the crate source before writing the tests.
- **A borrow-checker error** in the cross-check: comparing slices of two
  temporary keys inside one `assert` statement. Binding them to variables
  first fixed it.
- **The encapDecap vector file is marked `isSample: true`.** It is NIST's
  publicly published sample set, not a private validation run. Passing it
  is strong evidence of correctness, not a certification.

### 3.8 Interview questions

**Q1. Walk through why ML-KEM decryption works.**
w = v − sᵀu = μ + (eᵀy + e2 − sᵀe1), plus compression error. The A terms
cancel because sᵀ(Aᵀy) = (As)ᵀy. What remains is a sum of products of
small polynomials, so each coefficient of w is within q/4 of 0 or of q/2,
and rounding (Compress_1) recovers each bit. It fails only if the noise
exceeds q/4, which happens with probability 2^−138.8 or less (FIPS 203
Table 1).

**Q2. What does the Fujisaki–Okamoto transform add, and what attack does it
stop?**
It makes encryption deterministic given m, by deriving the randomness r from
G(m ‖ H(ek)), and Decaps re-encrypts the decrypted m′ and checks that it
gets the same ciphertext. Without it, an attacker who can submit modified
ciphertexts to a key that is reused, and observe success or failure, learns
on which side of a decryption threshold the noise falls. That depends on s,
and enough queries recover the key. With FO, every modified ciphertext is
rejected, and the output no longer depends on s.

**Q3. Why implicit rejection instead of returning an error?**
An error is a signal, and signals are what CCA attacks feed on. Returning
J(z ‖ c), a deterministic pseudorandom key, makes rejected and accepted
ciphertexts look the same to the outside. The protocol still fails safely
later, because the keys do not match. It also gives cleaner security proofs.
And it has to be done in constant time, or timing brings the signal back.

**Q4. What do the encapsulation key and decapsulation key checks protect
against?**
The modulus check rejects encodings with values ≥ q, which ByteDecode
would otherwise reduce silently, so two different byte strings would
behave as one key but hash differently. The hash check catches a dk whose
embedded ek and H(ek) do not match (corrupted or spliced keys). The type
checks reject wrong lengths. In my API, the checks happen in the
constructors, so unchecked keys cannot reach Encaps or Decaps.

**Q5. How do you know your ML-KEM is correct?**
Four layers. (1) All 240 official NIST ACVP cases for KeyGen, Encaps,
Decaps (including tampered ciphertexts) and both key checks. (2)
Byte-for-byte agreement with an independent implementation (RustCrypto
`ml-kem`) on random seeds, messages and random ciphertexts. (3) Property
tests of the KEM's defining behaviour, at 256 cases normally and 100,000 in
an extended run. (4) Mutation checks showing those tests fail when I break
the code on purpose. Underneath all of that, every building block was
already checked against literal pseudocode in phases 1 and 2.

---

## Phase 4: Constant-time review and the assembly check

Code: `hazmat.rs` (probes), `zeroize.rs`, `scripts/asm-check.ps1`,
`scripts/asm_check.py`. Results: `results/asm-check.txt` and
`results/asm/*.s`.

### 4.1 How a timing attack works

An attacker does not need to read memory. It is enough to **measure how long
something takes**, many times, and correlate the measurements with inputs
they choose or observe. If the time depends even slightly on a secret, say
a few CPU cycles, then averaging over thousands of measurements makes that
difference visible through network noise. Classic results: Kocher (1996)
recovered RSA keys from the timing of modular exponentiation, and Brumley
and Boneh (2003) did it to OpenSSL over a network.

A program's time depends on secrets in three main ways:

1. **Branches.** `if secret { A } else { B }` runs different instructions.
   Even if A and B take equally long, the branch predictor learns the
   pattern, and mispredictions cost 15–20 cycles.
2. **Memory addresses.** `table[secret]` loads from an address chosen by the
   secret. Whether that line is in the cache (about 4 cycles) or not
   (about 100+) leaks the index. Cache attacks on AES T-tables are the
   classic example. A co-located attacker can even *prime* the cache and
   watch which lines you evict.
3. **Variable-latency instructions.** On most x86 CPUs, `div`/`idiv` takes
   fewer cycles for some operands than others. Some other platforms have
   data-dependent multipliers (e.g. the ARM Cortex-M3's long multiply,
   which finishes early for small operands). KyberSlash is this case
   (phase 5 measures it).

**Constant-time code** means: no secret-dependent branch, no
secret-dependent address, and no variable-latency instruction on secret
operands. Then the *sequence* of instructions and addresses is the same
for every secret, so the timing is too. Note that "constant time" does
**not** mean "always takes exactly the same number of nanoseconds". It means
the time does not depend on secrets.

### 4.2 Every place in this crate where it matters

| Where | Secret involved | Technique | Evidence |
|---|---|---|---|
| `field::barrett_reduce`, `montgomery_reduce`, `fqmul` | every coefficient of s, e, y, w | multiply/shift only; arithmetic right shift for signs | asm: 0 branches, 0 div at every level |
| `field::to_canonical`, `csubq` | same | sign mask `x >> 15` instead of `if x < 0` | asm: 0 branches (csubq uses `cmov`) |
| `encode::compress` (d = 1, 4, 5, 10, 11) | w (Decrypt), u, v (Encrypt) | `/ q` replaced by `× ⌈2^40/q⌉ >> 40` | asm: `imul; add; shr 40; and`. No div at any level |
| `encode::decompress` (d = 1) | m in Encrypt | `(q·y + 1) >> 1` | asm: 0 branches |
| `encode::byte_decode(12)` | ŝ from dk | branch-free `csubq` | loop branches only (reviewed) |
| `encode::byte_encode` | m, compressed u/v | bit-packing loop, counts fixed by d | loop branches only (reviewed) |
| `sample::sample_poly_cbd` | s, e, y, e1, e2 | bits extracted by shift/mask at public positions | one loop branch (reviewed) |
| `ntt::ntt`, `ntt_inverse`, `multiply_ntts` | ŝ, ŷ, products | fixed butterfly schedule; table indices from loop counters | loop branches only (reviewed) |
| `hash::keccak::f1600` and sponge | σ, r, m, K, PRF output | XOR/AND/NOT/fixed rotations; no data-indexed tables | one round-loop branch |
| `ct::ct_eq_bytes` | c vs c′ in Decaps | OR-accumulate all bytes, mask at end, never exits early | loop branch on the counter only |
| `ct::ct_select_bytes` | K′ vs K̄ | `b ^ (mask & (a ^ b))` with `black_box(mask)` | 0 branches when unrolled |
| `kem::decaps_internal` | everything above | both keys always computed, compared and selected by mask, wipes on both paths | no div in its whole call tree at any level |
| `kem::dk_check` | H(ek) vs stored h (public, but cheap to protect) | `ct_eq_bytes` | |
| **Not constant time, by design** | | | |
| `sample::sample_ntt` | none: input is public ρ | rejection loop | documented |
| `kem::ek_check` | none: ek is public | early return on the first bad value | documented |
| length / type checks | none: lengths are public | | |

### 4.3 Why check the assembly at all?

Rust, like C, promises *what* a program computes, not *how long* it takes.
The optimiser is free to turn a mask back into a branch if it thinks that
is faster, or to turn `x / 3329` into a `div` (at some optimisation levels)
or into a multiply (at others). Source code alone cannot prove constant
time. The compiled instructions can.

**Probes.** Small functions such as `compress` get inlined into their
callers, so they have no assembly of their own. The `hazmat` feature (off
by default) adds `#[inline(never)]` wrappers (`hazmat::compress_d1`,
`hazmat::ct_eq_1088`, …) so each one is emitted as a separate function.
`hazmat::decaps_768` covers the whole composed algorithm, because code
inlined into a caller can compile differently from the stand-alone version.

**The check** (`scripts/asm-check.ps1`, run in CI with `-SkipShowAsm`):
1. Build the crate at **every optimisation level** (0, 1, 2, 3, s, z),
   emitting assembly.
2. Parse each function, follow its calls, and count `div`/`idiv`,
   conditional jumps (`jcc`), `cmov` and `setcc`.
3. Rules:
   - **No `div`/`idiv` in any `mlkem` function.** Two exceptions are
     allow-listed by name, with reasons: at opt-level z, the compiler
     divides the public key's *length* by 384 to compute loop bounds.
   - **No conditional branch at all** in "leaf" probes (field arithmetic,
     compress, decompress, masks) or anything they call.
   - "Loop" probes may branch, but every branch is printed with the two
     instructions before it, for review. I reviewed all 33 at opt-level 3.
     Each compares a loop counter or a length with a constant, is a bounds
     check, or is the function's own `assert!` on the public parameter d.
   - No indirect jumps, except one allow-listed jump table inside
     `core::sync::atomic::compiler_fence` at opt-level 0, which switches on
     the constant `SeqCst`.
4. `cmov` and `setcc` are allowed: on x86 they have no data-dependent
   timing, because no jump is taken.

### 4.4 What the check found

- **opt-level 2 and 3 (normal release builds): clean.** `compress_d1`, the
  KyberSlash2 site, compiles to `imul; add; shr 40; and 1`. The compiler
  vectorised `to_canonical` inside `poly_compress_encode` into
  `psraw 15; pand 3329` over 8 values at once.
- **`ct_eq_bytes` turned into `testb; setne`.** LLVM *recognised* our
  `(x | −x) >> 31` trick and replaced it with its own comparison. That is
  fine here (`setne` is constant time), but it shows that the compiler
  understands what masks mean and could just as well have produced a
  branch. That is why we check.
- **opt-level 0 with debug assertions (a `cargo build` debug build) is NOT
  branch-free.** Two things add branches on secret data:
  - Rust's overflow checks (`jo`, jump-if-overflow, after secret
    arithmetic);
  - my own `debug_assert!(x < q)` in `compress`, which compares the secret
    x itself.

  `compress_d1`'s call tree has 13 conditional branches in that build
  versus 0 in release. Given the bound analysis, they are never taken, so
  timing should not vary, but their conditions are computed from secrets.
  **Constant time is only claimed for release builds.** That build is
  reported as INFO, not checked as a rule.
- **opt-level 0, s and z contain `div` instructions**, all on public values:
  in Rust's standard library (`chunks_exact`, iterator size hints: slice
  length divided by chunk size), and at opt-level z in `ek_check` and
  `encrypt` (key length ÷ 384). **Our Keccak had `% 5` on loop counters,
  which became `div` at opt-level 0.** It was public, but I replaced it with
  tables, so the rule "no `div` in our code" holds with only the two
  documented exceptions.
- **The same source gives a different "constant-time status" per
  optimisation level.** That is the KyberSlash lesson in miniature: the
  reference C code's `/ q` was a multiply at -O2 on x86, but a real `div`
  elsewhere.
- CI runs the same check on whatever stable compiler GitHub installs. At
  the time of writing that was rustc 1.100.0, while results/ came from
  1.99.1. Both passed.

### 4.5 Wiping secrets (zeroisation)

After use, secrets remain in memory (stack, freed buffers) until something
overwrites them. A later bug, a crash dump or swapped-out memory can expose
them. Writing zeros at the end of a function is a **dead store**, because
nothing reads the buffer again, so the optimiser deletes it.

`zeroize::wipe` uses `core::ptr::write_volatile`, which the compiler must
perform, followed by a compiler fence. That is the same approach as the
widely used `zeroize` crate, in about 10 lines, so the crate keeps zero
runtime dependencies. It is the second and last `unsafe` block in the crate.
It is applied to: s, e, y, e1, e2, μ, v, w, the PRF output buffers, σ,
G's output, m′, K′, r′, K̄, c′, and the Keccak state (`Drop` on the sponge
types). Owned key types (`DecapsulationKey`, `SharedSecret`) wipe on
`Drop`.

**Evidence it survives optimisation:** the check counts stores of the
constant 0 in Decaps' call tree at opt-level 3: 64 byte stores in `hash::g`
(its 64-byte output), 136 in `decaps_internal`, 25+ eight-byte stores in
each sponge drop.

**What it cannot do:** copies the compiler makes (moves between stack
slots, spilled registers, frames of functions that already returned) are
outside our control. That is a Limit for every Rust and C implementation;
only a few C libraries go further, by explicitly clearing the stack.

### 4.6 Design decisions and alternatives

- **Write our own volatile wipe instead of depending on `zeroize`.** This
  keeps "no runtime dependencies", and the code is tiny and reviewed. The
  alternative is the audited crate, which is the better choice for a real
  product.
- **Probes behind a feature, instead of always public.** The default build
  has no extra API. Alternative: `#[no_mangle]` exports. That needs
  `unsafe` in edition 2024, and pollutes the symbol table.
- **Our own assembly parser (~200 lines of Python)** instead of a formal
  tool. Alternatives:
  - **ctgrind / Valgrind memcheck** (mark secrets "uninitialised" and see
    if any branch depends on them): precise, but Linux-only.
  - **Binsec/Rel, ct-verif:** formal verification, much stronger, heavy.
  - **Dynamic testing (dudect, phase 5):** measures real timing, catches
    what static checks miss (CPU behaviour), but only statistically.

  Ours is a cheap static gate that runs in CI on Windows and catches the
  most common regressions (a `/`, an `if` on a secret, an early-exit
  compare).
- **Leaf versus loop classification is manual.** The script cannot prove
  that a loop branch depends only on a counter. A human reviewed them at
  opt-level 3. It is listed as a limit.

### 4.7 What went wrong

- **Overflow checks re-enabled at opt-level 0.** Passing `-C opt-level=0`
  silently turns debug assertions and overflow checks back on, because
  their defaults follow the opt-level. My first run therefore "failed"
  every leaf probe. The fix was a separate build with the checks off, plus
  reporting the checked build as information (it is a real finding about
  debug builds).
- **`cargo asm` index confusion.** Its function index is the position in
  the *filtered* list for each query, not a global one. The first saved
  listings were empty. Fixed, and the script now fails if a listing has no
  `ret`/`jmp`.
- **A stale build.** Deleting the `.s` file but not the build cache made
  cargo think everything was up to date, so no assembly was produced.
  Fixed by a fresh target directory per optimisation level.
- **PowerShell 7 on CI quotes arguments differently from Windows
  PowerShell 5.1**, and CI's newer cargo put its output in a different
  folder. The script now passes argument arrays directly and searches for
  the output file.
- **Two allow-list entries.** The alternative was to restructure
  `ek_check`/`encrypt` until opt-level z stopped dividing by 384. That
  fights the compiler for no security gain (the values are public), so the
  reviewed exceptions are documented instead.

### 4.8 Interview questions

**Q1. What does "constant time" mean, and how did you check your code is?**
No branch, memory address or variable-latency instruction depends on a
secret, so the sequence of instructions and addresses is identical for all
secrets. I wrote it with masks and arithmetic, then checked the *compiled*
code: a script builds at every optimisation level, emits assembly, and
fails on any `div` in my code or any conditional branch in the leaf
functions. It lists loop branches for manual review. It runs in CI. Phase 5
adds a statistical timing test of the real binary.

**Q2. Why can't you just trust the source code?**
Because the compiler only preserves what a program computes, not its
timing. I saw this happen: LLVM rewrote my branch-free zero test into
`setne`, the same `% 5` became a `div` at opt-level 0 but not at 3, and
debug builds add branches after secret arithmetic (overflow checks and
`debug_assert!`s).
KyberSlash itself was division by a constant that some compilers turned
into a `div`.

**Q3. Is `cmov` constant time? What about `setcc`?**
On x86, yes: both always execute and their latency does not depend on the
condition, because no jump is taken and the predictor is not involved. That
is why the check allows them and forbids `jcc`. Other architectures need
their own analysis.

**Q4. Why does zeroising need `volatile`, and what does it still miss?**
A final write of zeros to a buffer nobody reads again is a dead store, and
the optimiser removes it. A volatile write must be performed. I checked
that the zero stores are present in the optimised assembly. It cannot reach
copies the compiler made on its own (spills, moved values, dead stack
frames), so wiping is risk reduction, not a guarantee.

**Q5. What are the limits of your constant-time evidence?**
(1) Only x86-64 (MSVC target) was checked. Other targets, including WASM,
need their own check. (2) Loop branches were judged by a person, at
opt-level 3. (3) The check sees instructions, not microarchitecture:
effects like frequency scaling (Hertzbleed), data-dependent prefetchers, or
a future CPU with variable-time multiply are out of scope. (4) Debug builds
are not constant time. Phase 5's measurements complement this, but a
statistical test can only fail to find a leak, never prove there is none.

---

## Phase 5: Measuring timing leaks (dudect)

Code: `crates/dudect` (the `mlkem-dudect` binary), the `leaky-kyberslash`
and `leaky-early-exit` features of `mlkem`, `scripts/dudect.ps1`. Results:
`results/dudect/summary.txt` and one raw file per run in
`results/dudect/<build>/`.

Phase 4 checked the *instructions*. This phase measures the *time* the real
binary takes on a real CPU, which catches what a static check cannot see:
the CPU's own behaviour (variable-latency instructions, caches, predictors).

### 5.1 The dudect method

dudect ("Dude, is my code constant time?", Reparaz, Balasch and
Verbauwhede, DATE 2017) needs no model of the CPU. It asks one statistical
question:

1. Choose two **input classes**. Class 0 is one **fixed** input, class 1 is
   a fresh **random** input each time. Choose the fixed input to be
   "extreme" where possible (all-zero coefficients, an equal comparison),
   because that maximises any data-dependent difference.
2. Run the operation millions of times, picking the class at random each
   time, and record the duration of each run.
3. Compare the two timing distributions with **Welch's t-test**:
   t = (mean₀ − mean₁) / √(var₀/n₀ + var₁/n₁). Welch's version does not
   assume equal variances, which matters here: random inputs often have a
   wider spread than a fixed one.

If timing does not depend on the data, both classes have the same mean and
|t| stays small however many samples you take. If it does, |t| grows like
√n. Conventional thresholds: |t| < 4.5 nothing detected, |t| ≥ 10 a leak.

**Cropping.** Timing has a long right tail (interrupts, context switches,
cache misses caused by other programs). One 50 µs interrupt drowns a
2-cycle difference in the mean. So, like dudect, the tester also runs the
t-test on only the measurements below the p-th percentile, for 100 values
of p from 6.7% to 99.9% (`stats::dudect_crop_points`), and reports the
**maximum |t| over all 101 tests**.

**Consequence of taking a maximum:** with 101 (correlated) tests, the
maximum |t| of perfectly constant-time code is not around 0.8 (the mean of
one |t|) but typically 1.5 to 3. That is why every target is run next to an
**A/A control** (`aa-` prefix): both classes get the identical fixed data
through exactly the same code. Its result is the noise floor for that
target on that core. A real target must be judged against its control, not
against 0.

**What a pass means.** "No leak detected" means only that *this* many
measurements on *this* CPU could not tell the classes apart. It is not a
proof (see phase 4 for the static side). A fail is strong evidence, but only
once the A/A control shows the harness itself is not the cause.

### 5.2 Timing on Windows, on a hybrid CPU

- **Timer:** `RDTSC` with `LFENCE` on both sides. RDTSC is not ordered with
  the surrounding instructions; LFENCE waits until earlier instructions have
  completed, so the window really contains the call. The TSC is
  *invariant* (constant rate, independent of turbo), here 2304 MHz. The
  tester measures it against `QueryPerformanceCounter` at start-up as a
  cross-check.
- **MFENCE before each measurement**, so stores that wrote the input have
  drained from the store buffer before the clock starts.
- **Pinning and priority:** `SetThreadAffinityMask` to one logical CPU,
  `HIGH_PRIORITY_CLASS` and a `TIME_CRITICAL` thread, so the scheduler does
  not migrate or preempt us mid-run.
- **P-cores and E-cores.** The i7-14700HX is hybrid: logical CPUs 0–15 are
  8 hyper-threaded P-cores (Raptor Cove), 16–27 are 12 E-cores (Gracemont)
  that share an L2 per cluster of 4. They are different
  microarchitectures, so instruction latencies and cache behaviour differ.
  Every result is measured on both, cpu 2 (P) and cpu 20 (E). This turned
  out to matter in both directions (5.3, 5.6).
- **Batching** (the canonical dudect structure): for each batch of 1000,
  choose all classes, generate all inputs, copy the whole batch once more
  with one memcpy, then time each input in a loop that contains no
  class-dependent code at all. Why each step exists is in 5.6.

### 5.3 KyberSlash, and proving the tester can see a leak

A tester that never reports anything might simply be blind. So the crate has
two **deliberately leaky builds** (Cargo features, never on by default; the
tester prints a warning banner when one is compiled in). They are the
*positive controls*.

**KyberSlash** (Bernstein et al., 2024) is the bug the reference Kyber code
had: `Compress` computed `((x << d) + q/2) / q` on secret x. Division by the
constant q is normally compiled into a multiply and shift, but on some
compilers, optimisation levels and targets it became a real `div`
instruction, whose latency on many CPUs depends on its operands. Measuring
that recovered keys.
- *KyberSlash1*: Compress_du on u in Encrypt (line 22). In Decaps the
  re-encryption runs on the secret m′, so it leaks. ML-KEM-768 uses du = 10;
  the probe `hazmat::u_encode_d11` uses d = 11 (ML-KEM-1024), the largest
  dividends.
- *KyberSlash2*: Compress_1 in Decrypt (line 7) on w = v − sᵀu. d = 1, so
  the dividends are small (2x + 1664 < 8322).

`leaky-kyberslash` hides q behind `black_box` so the compiler must emit
`div`. `leaky-early-exit` makes the FO re-encryption check return at the
first differing byte.

Measured (10⁷ samples for the encode targets, 10⁶ for Decaps):

| leaky build, target | P-core (cpu 2) | E-core (cpu 20) | A/A control P / E |
|---|---|---|---|
| early-exit, `decaps-ct` (fixed valid c vs random c) | **660** | **202** | 2.7 / 3.5 |
| early-exit, `decaps-valid` (both classes valid) | 2.5 | 2.8 | (same) |
| kyberslash, `u-encode-zero` (d = 11) | 2.6 | **19857** | 1.3 / 3.1 |
| kyberslash, `message-encode-zero` (d = 1, w = 0) | 3.0 | 2.4 | (same) |
| kyberslash, `message-encode` (d = 1, fixed random w) | 1.2 | 1.8 | (same) |

What this shows:
- **Early exit is caught on both core types.** With a valid ciphertext the
  leaky compare scans all 1088 bytes; a random one fails at the first byte.
  The mean difference is about 970 ticks (≈ 420 ns) on the P-core.
  `decaps-valid` being clean is also the right answer: there the compare
  always runs to the end. The leak shows only when *validity* differs,
  which is exactly what an attacker probing the FO check controls.
- **The `div` leak depends on the core.** On the E-core, 256 divisions with
  random dividends of up to 23 bits take on average ≈ 450 ticks longer than
  with dividend 1664 (all-zero u): about 1.8 ticks per division,
  |t| ≈ 20 000. On the P-core the same binary shows nothing. Gracemont's
  divider is operand-dependent for these values; Raptor Cove's apparently
  is not. "Not detected on my laptop's fast cores" would have been the wrong
  conclusion: an attacker picks the core.
- **KyberSlash2 (d = 1) is not detected here**, on either core, at 10⁷
  samples. Its dividends are below 2¹³, and these dividers seem to have a
  fixed latency in that range. That is a limit of this machine, not a sign
  the code is safe: the published KyberSlash2 attacks used other CPUs. The
  normal build has no `div` anyway, and the phase-4 assembly check forbids
  it at every optimisation level.

### 5.4 The normal build

| target | what differs between classes | P-core | E-core |
|---|---|---|---|
| `aa-ct-eq` (control) | nothing | 3.0 | 1.9 |
| `ct-eq` | second input equal vs random (1088 B) | 2.4 | 1.4 |
| `message-encode` | fixed random w vs random w | 1.4 | 1.8 |
| `message-encode-zero` | w = 0 vs random | 1.7 | 1.3 |
| `u-encode-zero` | u = 0 vs random (d = 11) | 1.6 | 1.6 |
| `aa-decaps-ct` (control) | nothing | 1.9 | 2.9 |
| `decaps-ct` | valid fixed c vs random c (implicit rejection) | 2.9 | 1.9 |
| `decaps-valid` | fixed valid c vs fresh valid c | 2.3 | 1.2 |
| `encaps-m` | fixed m vs random m | 1.3 | 1.7 |
| `aa-keygen-d` (control) | nothing | 2.2 | 3.6 |
| `keygen-d` | fixed d vs random d | **4480** | **2500** |

Every target stays below 4.5 and inside the range the A/A controls reach
(1.9–3.6), except `keygen-d`, and that one is
expected.

**KeyGen's timing leak is real, and harmless.** KeyGen computes
(ρ, σ) = G(d‖k) and then expands the matrix Â from ρ with `SampleNTT`,
which is *rejection sampling*: it reads 12-bit candidates and throws away
those ≥ q, so the number of SHAKE128 blocks it needs varies with ρ. A fixed
d means a fixed ρ and one fixed running time; random d gives varying ones
(means 39.8 µs vs 44.0 µs on the P-core). But ρ is **public**: it is the
last 32 bytes of the encapsulation key, so timing reveals something about a
value everyone already has. FIPS 203 specifies rejection sampling knowing
this, and phase 4's table lists `sample_ntt` as "not constant time, by
design". The secret σ only feeds CBD sampling, which takes fixed time. So
the tester is right to flag it, and the code is right not to care. It is a
reminder that a dudect "leak" means "the time depends on the input", and a
human still has to ask *which* input and whether it is secret.

(Encaps and Decaps also call SampleNTT, but with a fixed key ρ is the same
for both classes, so it does not show.)

### 5.5 Design decisions and alternatives

- **Write the tester instead of using the dudect C code or the
  `dudect-bencher` crate.** Writing it was the point of the phase, and both
  would have needed adapting to Windows (timer, pinning) anyway. The
  statistics are ~180 lines with unit tests (`stats.rs`).
- **Fixed-vs-random classes**, as in the paper. Alternatives: fixed-vs-fixed
  (two chosen extreme inputs) is more sensitive for one specific hypothesis,
  and random-vs-random with a secret-derived label is what real attacks
  correlate on. Fixed-vs-random needs no hypothesis about *where* the leak
  is.
- **RDTSC, not QueryPerformanceCounter.** QPC ticks at 10 MHz here (100 ns),
  far coarser than the effects measured (< 1 ns per division).
- **No system tuning** (turbo off, isolated cores, SMT off): that needs
  admin changes to the laptop. The cost is noise, which the crops and the
  A/A controls deal with; weak leaks just need more samples.
- **Max |t| over crops, judged against an A/A control**, instead of a
  corrected significance level. A Bonferroni-style correction over 101
  correlated tests would be too conservative; the control measures the
  actual floor.

### 5.6 What went wrong

This phase was mostly about the harness lying. Four times the tester
reported a leak in constant-time code. Each was found because an A/A
control, which by construction cannot leak, also "leaked".

1. **Class-dependent input preparation right before timing.** The first
   harness copied the fixed input for class 0 and wrote RNG output for
   class 1, then started the clock while the stores were still draining.
   A/A |t| up to 122. Fixed with identical preparation and an MFENCE.
2. **`if class == 0` before timing.** Even with equal work, the branch
   history differed per class, and that changed the predictions for the
   timed code's own loops.
3. **A branchless select still left class-dependent cache and store state.**
   The fix for 1–3 was canonical dudect batching: generate all inputs first,
   then time them in a loop with no class-dependent code. A/A fell to
   about 1.5.
4. **Batching was not enough on the E-cores.** With 10⁷ samples, the normal
   build's `ct-eq` gave |t| = 19 on cpus 16, 20 and 24, only in the
   ≥ 99th-percentile crops, while the P-cores were clean. The A/A control
   said 1.8, but it was not doing the same work: for class 1 it skipped the
   RNG call. Once it generated (and threw away) the random input like the
   real test does, **the A/A control also showed |t| ≈ 11 on the E-cores.**
   Slots written by different code (a copy of a cached value vs an RNG fill
   followed by a copy) ended up in different cache states, and the E-cores
   made that visible (likely through the L2 they share per cluster of four).
   Fix: copy the whole batch once more with one memcpy and time against the
   copy. A/A and real targets are now 1.2–3.6 everywhere.

   **This also changed a result.** Before the fix, the KyberSlash build's
   d = 1 targets showed |t| 11 and 38 on the E-core, and I had them down as
   detected. After it they are 2.4 and 1.8. Those "detections" were at
   least partly the artifact: the *normal* build had shown 9.8 on the same
   target with the old harness.

Lesson: **an A/A control is only valid if it does exactly the same work as
the real test, with only the data changed.** A control that takes a
shortcut can be clean while the test is not.

Smaller problems:
- PowerShell variables are case-insensitive: `$n` inside the script
  silently overwrote the `$N` parameter, so every run used the same count.
- The first full run was killed halfway through when the laptop ran low on
  memory. The script now has `-Resume` and rebuilds `summary.txt` from all
  result files, recording each run's commit. The leaky builds were measured
  at commits 6eff2ac and d250c07 (a script-only change in between). The
  normal build was measured again at d02f443, after phase 6 changed the
  sponge code (6.6); the earlier normal-build numbers were similar.

### 5.7 Interview questions

**Q1. How does dudect decide whether code is constant time?**
It times the code on two input classes, a fixed input and random inputs,
interleaved at random, and runs Welch's t-test on the two timing samples,
also on the data cropped below many percentiles to cut off the noisy tail.
If the maximum |t| stays below about 4.5, nothing was detected; above 10,
the timing depends on the input. It cannot prove constant time, only fail
to find a difference with n samples.

**Q2. Why Welch's t-test, and why crop?**
Welch's version does not assume both classes have the same variance, and a
fixed input usually has a narrower spread than random ones. Cropping,
because timing distributions have a heavy right tail from interrupts: one
outlier moves a mean more than the effect being looked for, so testing the
fast bulk separately is far more sensitive.

**Q3. What is an A/A test and why did you need one?**
Both classes get identical data through identical code, so any |t| it
shows comes from the harness, or from taking the maximum over 101 tests.
It caught four harness bugs that produced false leaks (|t| 11–122) in
correct code. The last one taught me that the control must do exactly the
same work as the real test.

**Q4. Your KeyGen "leaks" with |t| over 4000. Is that a vulnerability?**
No. The time varies because SampleNTT rejection-samples the matrix from ρ,
and ρ is published in the encapsulation key. KeyGen's A/A control is 2.2 (P) and 3.6 (E),
so the harness is fine; the dependence is real but on public data, and
FIPS 203 accepts it. A t-test says *that* the time depends on the input,
not whether that input is secret.

**Q5. You found KyberSlash on the E-core but not on the P-core. What does
that tell you?**
That constant-time evidence is per microarchitecture. The same binary's
`div` showed |t| ≈ 20 000 on Gracemont and nothing on Raptor Cove, and the
d = 1 version showed nothing on either, although it was exploited on other
CPUs. So you avoid variable-latency instructions on secrets by
construction (checked statically in phase 4), and treat measurements as
evidence, not proof.

---

## Phase 6: Performance, compared with RustCrypto's ml-kem

Code: `crates/bench` (the `mlkem-bench` binary), `scripts/bench.ps1`, and
one optimisation in `hash/sponge.rs`. Results: `results/bench/` —
`baseline-cpu*.txt` (before the optimisation) and `current-cpu*.txt`.

### 6.1 Why no benchmark framework

The usual tool is `criterion`. I wrote ~400 lines instead, for three
reasons: no new dependencies or downloads (the comparison crate `ml-kem` was
already a dev-dependency for the cross-check tests), the timer and CPU
pinning already existed in the timing tester and are reused (`#[path]`
include of `crates/dudect/src/platform.rs`), and every line can be
explained. What I give up: criterion's bootstrap confidence intervals,
outlier classification and regression tracking between runs.

### 6.2 Method

- **Same inputs for both implementations.** 64 random (d, z, m) triples,
  cycled. KeyGen's time depends on the seed (rejection sampling, see 5.4),
  so two implementations timed on different seeds would not be comparable.
- **Check before timing.** For every input, both implementations must give
  byte-identical ek, dk, ciphertext and shared secret. Otherwise the
  benchmark could be timing two different computations.
- **Every call timed separately** with LFENCE-serialised RDTSC; overhead
  about 40 ticks, under 0.2% of the fastest operation. For the building
  blocks (0.35–1.5 µs), blocks of 100 calls are timed and divided, so the
  timer overhead and granularity do not distort them.
- **Alternating order** (A B C, C B A, ...) over 20 rounds of 500 calls,
  after one discarded warm-up round. Turbo, temperature and power budget
  drift over seconds; alternating spreads that drift evenly.
- **Median, with 5th and 95th percentiles.** The mean is pulled up by
  interrupts; the median is not. 10 000 calls per entry.
- **Pinned** to cpu 2 (P-core) and cpu 20 (E-core), high priority. Both are
  reported, because they are different microarchitectures.
- Both crates built by the same compiler (rustc 1.99.1), release profile,
  default target CPU (no `-C target-cpu=native`, so no AVX2 for either).

### 6.3 What is compared, and why there are two ml-kem rows

The two APIs store keys differently, and that matters:

- **mlkem** (this crate) keeps keys as **bytes**. Every Encaps decodes t̂ from
  ek and computes H(ek) (FIPS 203 Alg 17 line 1); every Decaps decodes ŝ and
  t̂ from dk.
- **ml-kem** parses a key once into an object that holds the decoded
  polynomials **and caches H(ek)**. Per call it skips all of that.

So `ml-kem/bytes` is also timed: it parses the key from bytes in every call,
like mlkem. That variant is charged slightly *more* than mlkem, because its
parsers also run the FIPS 203 §7 input checks, which mlkem runs once in
`from_bytes`. A fair comparison lies between the two ml-kem rows.

### 6.4 Results (P-core, cpu 2, medians in µs)

| | KeyGen mlkem | ml-kem | Encaps mlkem | ml-kem | ml-kem/bytes | Decaps mlkem | ml-kem | ml-kem/bytes |
|---|---|---|---|---|---|---|---|---|
| ML-KEM-512 | 25.7 | 21.8 | 31.1 | 21.6 | 24.4 | 40.0 | 27.8 | 31.2 |
| ML-KEM-768 | 42.1 | 38.8 | 49.2 | 38.7 | 43.1 | 60.5 | 47.5 | 52.4 |
| ML-KEM-1024 | 65.3 | 62.7 | 73.3 | 62.3 | 68.1 | 87.8 | 73.7 | 80.3 |

Ratios mlkem / ml-kem: KeyGen 1.04–1.18; Encaps and Decaps 1.18–1.44
against the cached objects, **1.08–1.28 against ml-kem/bytes**. The E-core
(cpu 20) shows the same pattern, 1.06–1.41 (`current-cpu20.txt`).

In plain numbers: ML-KEM-768 does about 20 000 encapsulations or 16 500
decapsulations per second on one P-core.

Building blocks (P-core): Keccak-f[1600] 350 ns, **the same as RustCrypto's
`keccak` crate (352 ns)**; NTT 830 ns; inverse NTT 1036 ns; one MultiplyNTTs
420 ns; CBD 406 ns (η = 2) and 705 ns (η = 3); ByteDecode_12 374 ns.

The gap is largest for ML-KEM-512. Its η = 3 CBD is slower, but that adds
only about 0.6 µs per operation, so it does not explain the gap; I have not
pinned the rest down (see 6.5).

### 6.5 Where the time goes (an estimate, not a profile)

Without a profiler (none installed, and installing one breaks the
no-big-downloads rule), I estimated ML-KEM-768 Encaps from the building
blocks times the number of calls the algorithm makes:

| part | count | µs |
|---|---|---|
| Keccak-f: H(ek) 9, G 1, SampleNTT 9 × 3, PRF 7 | 44 | 15.4 |
| NTT (ŷ) | 3 | 2.5 |
| inverse NTT (u, v) | 4 | 4.1 |
| MultiplyNTTs (Âᵀŷ: 9, t̂ᵀŷ: 3) | 12 | 5.0 |
| SamplePolyCBD (y, e1, e2) | 7 | 2.8 |
| ByteDecode_12 (t̂) | 3 | 1.1 |
| **sum** | | **30.9** of 49.2 measured |

(SampleNTT typically needs 3 SHAKE128 blocks: 168 bytes give 112
candidates, of which 3329/4096 ≈ 81% are accepted, so 256 coefficients need
about 2.8 blocks.)

So roughly 18 µs is "glue": SampleNTT's parsing loop, Compress/ByteEncode
of u and v, additions, reductions, and copying 512-byte polynomials. The
same accounting for ml-kem, *assuming* its building blocks cost the same as
ours (verified only for Keccak-f), leaves about 12 µs. Most of the gap is there,
plus H(ek) and decoding (about 4 µs), which ml-kem caches. Keccak, the
biggest single cost, is not the difference.

### 6.6 The optimisation: squeezing whole lanes

The first measurement (`baseline-*`) showed mlkem 1.13–1.52× slower. The
sponge's `squeeze` produced output **one byte at a time**, with a branch
and a shift per byte. SampleNTT alone squeezes 27 × 168 = 4536 bytes per
ML-KEM-768 Encaps. I added a fast path: at a lane boundary, copy whole
8-byte lanes (`u64::to_le_bytes`), and fall back to bytes only for an
unaligned start or a tail shorter than 8 bytes.

- Effect: ML-KEM-768 KeyGen 46.1 → 42.1 µs, Encaps 53.2 → 49.2, Decaps
  65.0 → 60.5 (7–9%), similar for the other sets.
- Correctness: the existing tests compare the sponge with the `sha3` crate
  for every input length across three block boundaries, and for squeezes in
  random-sized chunks (which hit both paths); I also ran the hash tests with
  20 000 proptest cases, and the ACVP vectors still pass.
- Constant time: the branches depend only on the position and length,
  which are public. The assembly check passes at every optimisation level
  after the change, and the normal-build timing tests were re-run on the
  new code (`results/dudect/normal/`).

**Not done, on purpose:** caching H(ek) and the decoded key inside the key
types (as ml-kem does) would remove ~4 µs per Encaps, but it changes the API
from "a key is checked bytes" to "a key is a parsed object", and the bytes
version maps one-to-one onto FIPS 203. SIMD (AVX2) NTTs, as in the
optimised C implementations, would be the next big step and are out of
scope for a from-scratch learning project. CBD still extracts one bit at a
time, written exactly like Algorithm 8.

### 6.7 What went wrong

- **A clippy failure got committed.** I piped `cargo clippy` into `head`,
  which hides its exit code, so the commit went ahead. Fixed in the next
  commit. Lesson: never pipe a gate's output when its exit code matters.
- **An identical result looked suspicious.** Our Keccak-f and the reference
  crate first measured exactly 864 ticks each. Timing single 350 ns calls
  includes the timer overhead and its granularity, so I switched the
  building blocks to blocks of 100 calls. They still matched (806 vs 812):
  the result was real, and the method is better.
- **The first comparison was unfair** in a way that flattered ml-kem: its
  key objects cache work that our byte-based API redoes on every call. The
  `ml-kem/bytes` row was added to show the size of that effect (about 10%).
- **Building the crate while the timing tester ran** would have added noise
  to the dudect measurements, so measurements and builds were never run at
  the same time.

### 6.8 Interview questions

**Q1. How did you make sure the benchmark is fair?**
Same inputs for both, outputs checked byte-identical before timing, same
compiler and flags, alternating order to spread drift, medians over 10 000
calls, pinned cores, and both P-core and E-core. And I measured ml-kem two
ways, because its API caches work that mine repeats on every call.

**Q2. Why the median and not the mean?**
Timing has a long right tail: interrupts and context switches add tens of
microseconds now and then. A few of those move the mean a lot and the
median hardly at all. The 5th and 95th percentiles are reported to show the
spread.

**Q3. Your implementation is 10–40% slower than RustCrypto's. Why?**
Not in hashing: our Keccak-f is as fast as theirs. About 4 µs per Encaps is
H(ek) and key decoding that they cache in the key object. The rest is glue
code around the building blocks. My estimate from building-block timings
explains 31 of 49 µs for ML-KEM-768 Encaps; the remainder is parsing,
encoding and copying. A profiler would be the next step.

**Q4. You optimised the sponge. How do you know you did not break it or
make it leak?**
It is tested against the reference SHA-3 implementation for every length
across block boundaries and for random squeeze chunk sizes, plus the
official vectors. Its new branches depend only on positions and lengths,
which are public; the assembly check still passes at every level, and the
timing tests were re-run on the new build.

**Q5. What would make it much faster?**
Vectorising the NTT and base multiplication with AVX2 (16 coefficients per
instruction), a 4-way parallel Keccak for SampleNTT and PRF (they are
independent), caching the parsed key, and avoiding copies of whole
polynomials. Each is a trade against readability, which is the point of
this project.

---

## Phase 7: WebAssembly

Code: `crates/wasm` (the `mlkem-wasm` cdylib), `scripts/wasm/*.mjs` (Node),
`scripts/wasm-check.ps1` + `scripts/wasm_check.py`, `scripts/wasm-bench.ps1`,
`scripts/wasm-dudect.ps1`. Results: `results/wasm-check.txt`,
`results/wasm/`. No downloads: the wasm32 target, Node 24 and nothing else.

### 7.1 Why WebAssembly is its own constant-time question

WASM is a portable instruction set. A browser or Node does not run it
directly: its engine (V8 here) **compiles it again** into x86 or ARM machine
code, with its own compiler and its own choices. So there are three layers,
each of which can break constant time:

1. our Rust source;
2. LLVM's compilation of it to WASM instructions (checked statically, 7.3);
3. V8's compilation of WASM to machine code, at run time, possibly twice
   (Liftoff, a fast baseline compiler, then TurboFan, an optimising one,
   for hot code). Nothing in the repository can see this machine code, so it
   is checked by measuring (7.5).

### 7.2 The module: no wasm-bindgen

`crates/wasm` is `no_std`, has no allocator and no dependencies other than
`mlkem`. It exports plain `extern "C"` functions taking pointers into the
module's linear memory: `mlkem_768_keygen(d, z, ek_out, dk_out)`,
`mlkem_768_encaps(ek, m, c_out, k_out) -> i32`, `mlkem_768_decaps(dk, c,
k_out) -> i32`, the key checks, and lengths, for each parameter set.
JavaScript writes inputs at or above the exported `__heap_base`, calls the
function, and reads the outputs. A panic traps (`unreachable`). The module
is 58 KB.

**Randomness.** A bare WASM module has no RNG. The exports are FIPS 203's
`_internal` functions, so the caller supplies d, z, m and must take them from
`crypto.getRandomValues`. That is why §6 says not to offer `_internal`
functions to applications: a real binding would draw the seeds itself.

**Alternative:** wasm-bindgen generates the JavaScript glue and handles
`Uint8Array` conversion. It is the normal choice for a product; it was not
used because it adds dependencies, a download (the `wasm-bindgen` CLI), and
glue code that is not ours to explain.

**Correctness:** `scripts/wasm/acvp.mjs` runs all 240 NIST ACVP cases
against the `.wasm` in Node, with the same case counts as the Rust test.
All pass. To check that this test can fail, a copy with one expected byte
flipped failed all 75 KeyGen cases. CI runs it.

### 7.3 The instruction check, and a finding about division

`scripts/wasm-check.ps1` builds the crate for wasm32 at every optimisation
level, emits LLVM's textual WASM assembly, and applies the x86 rules
(`wasm_check.py`): no division (`i32/i64.div_*`, `rem_*`) in our code, and no
conditional control flow (`br_if`, `if`, `br_table`) in any leaf function or
anything it calls. `select` (WASM's cmov) is reported but allowed.

**Finding: LLVM's WASM backend keeps division by a constant.** On x86,
`x / 3329` compiles to a multiply and shift. For wasm32 it stays
`i32.div_u` (checked with a two-line probe): the backend treats division as
cheap and leaves it to the engine. So code like the KyberSlash reference
`/ q`, which happened to be safe in many native builds, is a real division
in WASM, at every optimisation level. Our Compress uses an explicit multiply
(`× ⌈2^40/q⌉ >> 40`), so it does not matter here. But it shows again that
"the compiler will optimise the division away" is not a security argument.

Results (`results/wasm-check.txt`): PASS at opt-levels 0 (without debug
checks), 1, 2, 3, s and z. Three functions contain reviewed divisions
`/ 384` and `% 384`: `chunks_exact(384)` loop bounds over the 384k-byte key
parts, where k is the public parameter, so all public lengths. The debug
build with overflow checks has branches in leaf functions, as on x86, and is
reported as information only.

**Positive control:** the script also builds `leaky-kyberslash` and requires
the checker to flag the division in Compress. It does, otherwise the script
fails. (It also flags a branch: WASM division traps on a zero divisor, and
because the leaky divisor is hidden behind `black_box`, Rust adds a
divide-by-zero check.)

### 7.4 Speed (Node 24, V8 13.6)

Medians in µs, `scripts/wasm-bench.ps1`, same method as phase 6:

| P-core (cpu 2) | KeyGen | Encaps | Decaps | vs native |
|---|---|---|---|---|
| ML-KEM-512, default tiering | 59.5 | 71.1 | 90.3 | 2.3× |
| ML-KEM-768, default tiering | 95.4 | 112.6 | 146.6 | 2.3–2.4× |
| ML-KEM-1024, default tiering | 147.2 | 188.9 | 229.4 | 2.3–2.6× |
| ML-KEM-768, Liftoff only | 236.2 | 278.7 | 321.1 | 5.3–5.7× |

On the E-core, ML-KEM-768 takes 162 / 180 / 217 µs (default tiering).
About 7 000 decapsulations per second on one P-core, in JavaScript's
runtime.

Why slower than native: I did not profile V8's output. Plausible reasons are
that TurboFan's register allocation and instruction selection are weaker
than LLVM's, and that WASM's 128-bit SIMD was not enabled (but our native
build uses no explicit SIMD either). Liftoff makes no attempt to optimise,
which is the point of a baseline compiler: it compiles fast, so code starts
quickly.

Note on method: pinning a whole Node process to one CPU also pins V8's
background compiler and garbage-collector threads to it. That is a likely
reason why the P-core 95th percentiles are wide (about 1.8× the median).
The medians are stable between runs.

### 7.5 Timing leaks in the code V8 actually runs

`scripts/wasm/dudect.mjs` ports the phase 5 tester to JavaScript: same
classes, batching, normalising copy, A/A controls, Welch t-test with 100
crops. The timer is `process.hrtime.bigint()` (100 ns resolution on Windows),
which is coarse but fine for operations of 1.5 µs and 170 µs. A warm-up runs
first, so V8 has tiered up to TurboFan. Targets: ML-KEM-768 Decaps
(`decaps-ct`, 2·10⁵ samples) and ByteEncode_11(Compress_11(u))
(`u-encode-zero`, 10⁶ samples, exported only with the `probes` feature).

| build, target | P-core | E-core | A/A P / E |
|---|---|---|---|
| normal, `decaps-ct` | 1.9 | 0.9 | 2.7 / 2.8 |
| normal, `u-encode-zero` | 1.3 | 1.5 | 1.0 / 1.2 |
| leaky-early-exit, `decaps-ct` | **46** | **57** | 1.6 / 2.4 |
| leaky-kyberslash, `u-encode-zero` | 1.8 | **713** | 2.2 / 1.9 |

The same picture as native (5.3–5.4):
- The normal build shows nothing on either core.
- The early-exit leak survives into WASM and V8's machine code.
- **The KyberSlash division leaks through V8 too, and again only on the
  E-core**: a random u takes 148 ns longer per polynomial than u = 0
  (1931 vs 1783 ns). That is evidently V8 compiling `i32.div_u` with an
  unknown divisor to the hardware `div` (inferred from the timing; V8's
  machine code was not inspected), whose latency on Gracemont depends on
  the operands. So
  WASM code inherits the timing behaviour of the CPU it ends up on, and a web
  page cannot choose which core it runs on.

Not tested: Liftoff-compiled code under the timing test (it runs only until
tier-up), other engines (SpiderMonkey, JavaScriptCore, wasmtime) and other
CPUs. Each compiles WASM differently.

### 7.6 Design decisions and alternatives

- **Plain C ABI over wasm-bindgen**: no dependencies, everything visible;
  the cost is manual pointer handling in JavaScript (7.2).
- **Node rather than a browser**: scriptable, already installed, and the
  same V8 engine as Chrome. Browsers also coarsen `performance.now()` (to
  tens of microseconds or more, as a Spectre mitigation), which would make the timing test much
  slower to converge, though not impossible (attackers average too).
- **Exporting `_internal` functions**: needed for the ACVP vectors and keeps
  the module RNG-free; a production binding would hide them.
- **The `probes` feature** exports one internal function only for the timing
  test, as `hazmat` does natively. It is off by default.

### 7.7 What went wrong

- **`__heap_base` was not exported.** Node could not find free memory to put
  inputs in. This toolchain's linker does not export it by default, so `build.rs`
  passes `--export=__heap_base` to the linker, for wasm32 targets only.
- I expected the division finding (7.3) the other way round: I assumed LLVM
  would strength-reduce constant division on every target. Checking the
  instructions instead of assuming was what found it.

### 7.8 Interview questions

**Q1. Your code is constant time on x86. Why isn't that enough for WASM?**
Because the WASM is compiled twice more: by LLVM to WASM instructions and by
the engine to machine code at run time. I checked the first statically (no
division, no branches in leaf functions, at every optimisation level, with a
positive control) and the second by running the timing test inside Node
against the code V8 generated.

**Q2. What did you find about division in WASM?**
LLVM keeps `x / constant` as a real `i32.div_u` for wasm32, where on x86 it
becomes a multiply. V8 then emits a hardware `div`. With the deliberately
leaky build, the timing test detected it at |t| = 713 on an E-core and not at
all on a P-core, exactly as with native code. So in WASM a KyberSlash-style
division is a leak on every optimisation level, on CPUs with a variable
divider.

**Q3. How does JavaScript call your WASM without wasm-bindgen?**
The module exports functions taking i32 pointers into its linear memory.
JavaScript gets the memory as an ArrayBuffer, writes inputs above
`__heap_base` (exported by the linker), calls the function, and reads the
outputs back. There is no allocator in the module, so the caller manages that
memory.

**Q4. Where does randomness come from?**
Nowhere inside the module. The caller passes the seeds d, z and m, which must
come from `crypto.getRandomValues`. That is FIPS 203's `_internal` interface,
fine for test vectors, but a real binding should generate them itself so a
caller cannot pass weak or repeated seeds.

**Q5. How fast is it, and why the two numbers?**
ML-KEM-768 Decaps takes 147 µs in Node under normal tiering, 2.4× native;
with V8's baseline compiler only it is 321 µs, 5.3×. V8 first compiles
quickly with Liftoff and re-compiles hot functions with TurboFan, so
short-lived code runs at the slower speed. Both are reported because a page
that runs a single key exchange may never reach TurboFan.
