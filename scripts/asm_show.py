"""Print the instructions of one function (by readable-name suffix) with
indices, optionally only a range: python scripts/asm_show.py file.s NAME [FROM TO]."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from asm_check import parse  # noqa: E402
from asm_divs import readable  # noqa: E402

funcs = parse(sys.argv[1])
want = sys.argv[2]
lo = int(sys.argv[3]) if len(sys.argv) > 3 else 0
hi = int(sys.argv[4]) if len(sys.argv) > 4 else 10**9
for sym, insns in funcs.items():
    if readable(sym).endswith(want):
        print(f"== {readable(sym)} ({len(insns)} instructions)")
        for i, (mn, ops) in enumerate(insns):
            if lo <= i <= hi:
                print(f"{i:5} {mn} {ops}")
