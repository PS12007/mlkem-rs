"""List every div/idiv instruction in a rustc-emitted .s file, grouped by the
function it is in, with a readable name and the instruction itself.

Usage: python scripts/asm_divs.py path/to/file.s

The symbol names are Rust "v0" mangled (_R...). A full demangler is not
needed for a report: the identifiers inside are length-prefixed
(e.g. 6encode8compress), so we pull those out to get a readable path.
"""
import re
import sys

IDENT = re.compile(r"(?<![0-9])([1-9][0-9]*)([A-Za-z_][A-Za-z0-9_]*)")
SKIP = {"core", "alloc", "std"}


def readable(sym: str) -> str:
    """Pull length-prefixed identifiers out of a v0-mangled symbol."""
    # Drop crate disambiguators ("Cs7uUmbfRqPp3_4core" -> "C4core") and
    # back-references ("B1x_"), which would otherwise look like identifiers.
    sym = re.sub(r"Cs[0-9A-Za-z]*_", "C", sym)
    sym = re.sub(r"B[0-9A-Za-z]*_", "", sym)
    out, i = [], 0
    while i < len(sym):
        m = IDENT.search(sym, i)
        if not m:
            break
        n, rest = int(m.group(1)), sym[m.start(2):]
        if n <= len(rest):
            out.append(rest[:n])
            i = m.start(2) + n
        else:
            i = m.end()
    return "::".join(out) if out else sym


def scan(path):
    func, found = None, {}
    for line in open(path, encoding="utf-8", errors="replace"):
        s = line.strip()
        if s.startswith(".def") and "@feat" not in s:
            func = s.split(None, 1)[1].rstrip(";")
        m = re.match(r"(i?div[a-z]*)\s+(.*)", s)
        if m and func:
            found.setdefault(func, []).append(f"{m.group(1)} {m.group(2)}")
    return found


if __name__ == "__main__":
    found = scan(sys.argv[1])
    total = sum(len(v) for v in found.values())
    print(f"{total} div/idiv instruction(s) in {len(found)} function(s)")
    for func, instrs in sorted(found.items(), key=lambda kv: readable(kv[0])):
        print(f"- {readable(func)}")
        for ins in instrs:
            print(f"    {ins}")
