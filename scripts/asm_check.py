"""Constant-time assembly check for the mlkem crate (phase 4).

Reads one rustc-emitted assembly file (AT&T syntax, x86-64, COFF/Windows)
built with `--features hazmat`, and reports, for every function and every
`mlkem::hazmat::*` probe *including everything it calls*:

  div   - div/idiv instructions (variable latency on most x86 CPUs: the
          KyberSlash class of leak). Rule: zero in any mlkem function.
          core:: library functions may divide *slice lengths* (public); they
          are listed so a human can confirm that.
  jcc   - conditional jumps (je, jne, jb, ...). Rule for "leaf" probes
          (field arithmetic, compression, masks): zero. For "loop" probes
          the loops' own back-edges are expected; each is listed for review.
  cmov / setcc - conditional move / set. These run in constant time on x86
          (no branch is taken), so they are reported but allowed.

Usage: python scripts/asm_check.py LABEL file.s
Exit code 1 if any rule is broken.
"""
import os
import re
import sys

# Allow `python -I scripts/asm_check.py` (isolated mode does not put the
# script's directory on sys.path).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from asm_divs import readable  # noqa: E402

LEAF = {  # must contain no conditional branch at all, nor any callee with one
    "barrett_reduce", "montgomery_reduce", "fqmul", "to_canonical", "csubq",
    "compress_d1", "compress_d4", "compress_d5", "compress_d10", "compress_d11",
    "decompress_d1", "is_zero_mask",
}
LOOP = {  # loops over public bounds are expected: no div allowed, jcc reviewed
    "message_encode", "decode12", "cbd_eta2", "cbd_eta3", "ntt", "ntt_inverse",
    "multiply_ntts", "ct_eq_32", "ct_eq_1088", "ct_select_32", "keccak_f1600",
    "decaps_768",
}

# Divisions found in mlkem code and reviewed by hand. Key: (build label,
# function). Each one must divide a PUBLIC value; the reason says which.
# Anything not listed here fails the check.
REVIEWED_DIVS = {
    ("opt-level=z", "mlkem::kem::ek_check"):
        "divw by 384: ek[..384k].chunks_exact(384) computes len/384; ek is the public key",
    ("opt-level=z", "mlkem::kpke::encrypt"):
        "divq by 384 of the ek slice length (3rd argument, r8): loop-bound computation "
        "for the t-hat decoding loop; ek is the public key",
}


def is_reviewed_div(label, name):
    return (label, name) in REVIEWED_DIVS


# Functions allowed to contain an indirect call/jump (any build), with the
# reason the target cannot depend on a secret. Any other indirect control
# flow fails, because the checker cannot follow it.
REVIEWED_INDIRECT = {
    "core::sync::atomic::compiler_fence::mlkem":
        "opt-level 0 only: jump table on the Ordering argument, which our "
        "zeroize::wipe always passes as the constant SeqCst",
}


def has_indirect(insns):
    return any(m in ("call", "callq", "jmp", "jmpq") and o.strip().startswith("*")
               for m, o in insns)

INSN = re.compile(r"^\s+([a-z][a-z0-9]*)\b\s*(.*)$")


def parse(path):
    """Return {symbol: [(mnemonic, operands), ...]} for every function."""
    funcs, cur, defs = {}, None, set()
    for raw in open(path, encoding="utf-8", errors="replace"):
        line = raw.rstrip("\n")
        s = line.strip()
        if s.startswith(".def"):
            defs.add(s.split(None, 1)[1].rstrip(";"))
            continue
        if not line.startswith(("\t", " ")) and s.endswith(":") and s[:-1] in defs:
            cur = s[:-1]
            funcs[cur] = []
            continue
        if cur is None:
            continue
        if s == ".seh_endproc":
            cur = None
            continue
        m = INSN.match(line)
        if m and not s.startswith("."):
            funcs[cur].append((m.group(1), m.group(2)))
    return funcs


def is_div(mn):
    return re.fullmatch(r"i?div[bwlq]?", mn) is not None


def is_jcc(mn):
    return mn.startswith("j") and mn not in ("jmp", "jmpq")


def callees(insns):
    out = set()
    for mn, ops in insns:
        if mn in ("call", "callq", "jmp", "jmpq"):
            t = ops.strip()
            if t.startswith("*"):
                out.add("<indirect>")
            elif not t.startswith(".L"):
                out.add(t.replace("__imp_", "").split("@")[0])
    return out


def closure(sym, funcs):
    seen, todo = set(), [sym]
    while todo:
        f = todo.pop()
        if f in seen:
            continue
        seen.add(f)
        if f in funcs:
            todo.extend(callees(funcs[f]))
    return seen


def stats(insns):
    return {
        "insns": len(insns),
        "div": sum(is_div(m) for m, _ in insns),
        "jcc": sum(is_jcc(m) for m, _ in insns),
        "cmov": sum(m.startswith("cmov") for m, _ in insns),
        "setcc": sum(m.startswith("set") for m, _ in insns),
    }


def is_ours(name):
    return name.startswith("mlkem::")


def main(label, path, strict=True):
    funcs = parse(path)
    failures = []
    print(f"## {label}: {path.replace(chr(92), '/').split('/')[-1]}, {len(funcs)} functions")
    if not strict:
        print("(informational build: findings are reported but do not fail the check)")

    # 1. Every division anywhere in the file.
    print("\n### div/idiv instructions (all functions)")
    any_div = False
    for f, insns in sorted(funcs.items(), key=lambda kv: readable(kv[0])):
        n = stats(insns)["div"]
        if n:
            any_div = True
            name = readable(f)
            if not is_ours(name):
                verdict = "allowed: core library, slice-length arithmetic (public)"
            elif is_reviewed_div(label, name):
                verdict = "reviewed: " + REVIEWED_DIVS[(label, name)]
            else:
                verdict = "FAIL (unreviewed division in mlkem code)"
                failures.append(f"{label}: div in {name}")
            print(f"- {name}: {n}  -> {verdict}")
    if not any_div:
        print("- none")

    # 2. Per-probe report, including callees.
    print("\n### hazmat probes (own code + everything called)")
    print(f"{'probe':<18} {'class':<5} {'insns':>6} {'div':>4} {'jcc':>4} {'cmov':>5} {'setcc':>6}  callees")
    probes = {readable(f).rsplit("::", 1)[-1]: f for f in funcs if "::hazmat::" in readable(f)}
    for name in sorted(LEAF | LOOP):
        cls = "leaf" if name in LEAF else "loop"
        sym = probes.get(name)
        if sym is None:
            print(f"{name:<18} {cls:<5} (not found: inlined away or renamed)")
            failures.append(f"{label}: probe {name} not found")
            continue
        total = {"insns": 0, "div": 0, "jcc": 0, "cmov": 0, "setcc": 0}
        called = sorted(c for c in closure(sym, funcs) if c != sym)
        for f in closure(sym, funcs):
            if f in funcs:
                st = stats(funcs[f])
                # Divisions already judged in section 1 (core library length
                # arithmetic, or reviewed) are not counted again here.
                if st["div"] and (not is_ours(readable(f)) or is_reviewed_div(label, readable(f))):
                    st["div"] = 0
                for k, v in st.items():
                    total[k] += v
        ext = [readable(c) if c in funcs else c for c in called]
        print(f"{name:<18} {cls:<5} {total['insns']:>6} {total['div']:>4} {total['jcc']:>4} "
              f"{total['cmov']:>5} {total['setcc']:>6}  {', '.join(ext) if ext else '-'}")
        if total["div"]:
            failures.append(f"{label}: {name} reaches a div")
        if cls == "leaf" and total["jcc"]:
            failures.append(f"{label}: leaf probe {name} has {total['jcc']} conditional branch(es)")
        for f in closure(sym, funcs):
            if f in funcs and has_indirect(funcs[f]):
                rn = readable(f)
                if rn in REVIEWED_INDIRECT:
                    print(f"{'':<18} note: indirect jump in {rn} reviewed: {REVIEWED_INDIRECT[rn]}")
                else:
                    failures.append(f"{label}: {name} reaches an indirect call/jump in {rn} (cannot be checked)")

    # 3. Every conditional branch in the loop probes (not decaps_768, which is
    #    these same pieces composed), with the instructions that set the
    #    flags, for manual review: each must test a loop counter, a length or
    #    a bounds check, never a secret value.
    print("\n### conditional branches in loop probes, for review")
    for name in sorted(LOOP - {"decaps_768"}):
        sym = probes.get(name)
        if sym is None:
            continue
        for f in sorted(closure(sym, funcs)):
            insns = funcs.get(f, [])
            for i, (mn, ops) in enumerate(insns):
                if is_jcc(mn):
                    ctx = "; ".join(f"{m} {o}".strip() for m, o in insns[max(0, i - 2):i])
                    print(f"- {name} [{readable(f)}] #{i}: {ctx} ; {mn} {ops}")

    print("\n### verdict")
    word = "FAIL" if strict else "INFO"
    if failures:
        for f in failures:
            print(f"{word} {f}")
    else:
        print("PASS: no unreviewed div/idiv in mlkem code; no conditional branch in any leaf probe")
    return 1 if (failures and strict) else 0


if __name__ == "__main__":
    strict = "--info" not in sys.argv
    args = [a for a in sys.argv[1:] if a != "--info"]
    sys.exit(main(args[0], args[1], strict))
