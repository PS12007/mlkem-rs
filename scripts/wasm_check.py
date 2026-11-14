"""Constant-time instruction check for the WebAssembly build (phase 7).

The WASM counterpart of asm_check.py. Reads one rustc-emitted WebAssembly
assembly file (LLVM's textual .s format for wasm32), built with
`--features hazmat`, and checks, for every function and every
`mlkem::hazmat::*` probe *including everything it calls*:

  div  - i32/i64 div_s, div_u, rem_s, rem_u. Rule: none in mlkem code,
         except reviewed ones whose divisor is a public constant applied to
         a public length. This matters more in WASM than on x86: LLVM's
         wasm32 backend does NOT turn division by a constant into a
         multiply (it treats division as cheap and leaves that to the
         engine), so `x / 3329` stays a real division instruction.
  br   - conditional control flow: br_if, if, br_table. Rule for "leaf"
         probes: none at all, in the probe or anything it calls.
  select - WASM's conditional select (like cmov). Allowed and reported:
         engines normally compile it to cmov, but nothing guarantees that.
  call_indirect - fails the check (cannot be followed), unless reviewed.

Usage: python -I scripts/wasm_check.py LABEL file.s [--info]
Exit code 1 if any rule is broken (unless --info).
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from asm_check import LEAF, LOOP  # noqa: E402  same probe classes as x86
from asm_divs import readable  # noqa: E402

DIV = re.compile(r"i(32|64)\.(div|rem)_[su]")
BRANCH = {"br_if", "if", "br_table"}

# Divisions in mlkem code, reviewed by hand. Key: function; value: (the only
# divisor allowed, reason). Every division in such a function must be
# directly preceded by `i32.const <divisor>`; anything else fails.
REVIEWED_DIVS = {
    "mlkem::kem::keygen_internal": (384,
        "dk_pke_len() / 384 and % 384: loop bounds over the 384k-byte key "
        "(k is the public parameter)"),
    "mlkem::kem::ek_check": (384,
        "ek[..dk_pke_len()].chunks_exact(384): length % 384; ek is public"),
    "mlkem::kpke::encrypt": (384,
        "ek t-hat part split into 384-byte chunks: length % 384; ek is public"),
    "mlkem::kpke::keygen": (384, "dk_pke_len() split into 384-byte chunks: public length"),
    "mlkem::kpke::decrypt": (384, "dk split into 384-byte chunks: public length"),
    "mlkem::kem::decaps_internal": (384, "dk split into 384-byte chunks: public length"),
    "mlkem::kem::encaps_internal": (384, "ek split into 384-byte chunks: public length"),
}

INSN = re.compile(r"^\s+([a-z][a-z0-9_.]*)\b\s*(.*)$")


def parse(path):
    """Return {symbol: [(mnemonic, operands), ...]} for every function."""
    funcs, cur = {}, None
    for raw in open(path, encoding="utf-8", errors="replace"):
        line = raw.rstrip("\n")
        s = line.strip()
        if not line.startswith(("\t", " ")) and s.endswith(":") and not s.startswith("."):
            cur = s[:-1]
            funcs[cur] = []
            continue
        if cur is None:
            continue
        if s == "end_function":
            cur = None
            continue
        m = INSN.match(line)
        if m and not s.startswith("."):
            funcs[cur].append((m.group(1), m.group(2).strip()))
    # Labels that are data, not functions, have no instructions.
    return {f: i for f, i in funcs.items() if i}


def callees(insns):
    out = set()
    for mn, ops in insns:
        if mn == "call":
            out.add(ops.split()[0])
        elif mn == "call_indirect":
            out.add("<indirect>")
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


def divs(insns):
    """[(index, mnemonic, divisor constant or None)] for every division."""
    out = []
    for i, (mn, _) in enumerate(insns):
        if DIV.fullmatch(mn):
            prev_mn, prev_ops = insns[i - 1] if i else ("", "")
            const = int(prev_ops) if prev_mn in ("i32.const", "i64.const") and prev_ops.lstrip("-").isdigit() else None
            out.append((i, mn, const))
    return out


def is_ours(name):
    return name.startswith("mlkem::")


def div_verdict(name, d):
    """None if this division is acceptable, else a failure reason."""
    if not is_ours(name):
        return None  # core library: slice-length arithmetic, listed for review
    _, _, const = d
    if name in REVIEWED_DIVS and const == REVIEWED_DIVS[name][0]:
        return None
    return f"unreviewed {d[1]} (divisor {const if const is not None else 'not a constant'})"


def main(label, path, strict=True):
    funcs = parse(path)
    failures = []
    print(f"## {label}: {os.path.basename(path)}, {len(funcs)} functions")
    if not strict:
        print("(informational build: findings are reported but do not fail the check)")

    print("\n### division instructions (all functions)")
    any_div = False
    for f, insns in sorted(funcs.items(), key=lambda kv: readable(kv[0])):
        ds = divs(insns)
        if not ds:
            continue
        any_div = True
        name = readable(f)
        consts = sorted({str(c) for _, _, c in ds})
        bad = [r for r in (div_verdict(name, d) for d in ds) if r]
        if not is_ours(name):
            verdict = "allowed: core library, slice-length arithmetic (public)"
        elif bad:
            verdict = "FAIL: " + "; ".join(sorted(set(bad)))
            failures.append(f"{label}: {name}: {bad[0]}")
        else:
            verdict = "reviewed: " + REVIEWED_DIVS[name][1]
        print(f"- {name}: {len(ds)} (divisors {', '.join(consts)})  -> {verdict}")
    if not any_div:
        print("- none")

    print("\n### hazmat probes (own code + everything called)")
    print(f"{'probe':<18} {'class':<5} {'insns':>6} {'div':>4} {'br':>4} {'select':>6}  callees")
    probes = {readable(f).rsplit("::", 1)[-1]: f for f in funcs if "::hazmat::" in readable(f)}
    for name in sorted(LEAF | LOOP):
        cls = "leaf" if name in LEAF else "loop"
        sym = probes.get(name)
        if sym is None:
            print(f"{name:<18} {cls:<5} (not found: inlined away or renamed)")
            failures.append(f"{label}: probe {name} not found")
            continue
        n_ins = n_div = n_br = n_sel = 0
        reach = closure(sym, funcs)
        for f in reach:
            insns = funcs.get(f, [])
            n_ins += len(insns)
            n_div += sum(1 for d in divs(insns) if div_verdict(readable(f), d))
            n_br += sum(m in BRANCH for m, _ in insns)
            n_sel += sum(m == "select" for m, _ in insns)
            if any(m == "call_indirect" for m, _ in insns):
                failures.append(f"{label}: {name} reaches call_indirect in {readable(f)}")
        called = sorted(readable(c) for c in reach if c != sym)
        print(f"{name:<18} {cls:<5} {n_ins:>6} {n_div:>4} {n_br:>4} {n_sel:>6}  "
              f"{', '.join(called) if called else '-'}")
        if n_div:
            failures.append(f"{label}: {name} reaches an unreviewed division")
        if cls == "leaf" and n_br:
            failures.append(f"{label}: leaf probe {name} has {n_br} conditional branch(es)")

    print("\n### verdict")
    word = "FAIL" if strict else "INFO"
    if failures:
        for f in failures:
            print(f"{word} {f}")
    else:
        print("PASS: no unreviewed division in mlkem code; no conditional branch in any leaf probe")
    return 1 if (failures and strict) else 0


if __name__ == "__main__":
    strict = "--info" not in sys.argv
    args = [a for a in sys.argv[1:] if a != "--info"]
    sys.exit(main(args[0], args[1], strict))
