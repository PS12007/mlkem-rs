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
