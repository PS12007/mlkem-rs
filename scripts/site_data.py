"""Extracts the numbers the website shows (docs/) from the committed raw
results, so that every figure on the site traces back to results/.

Usage: python -I scripts/site_data.py   (writes docs/data.json)
"""
import json
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(ROOT, "results")

PROGRESS = re.compile(r"^progress n=\s*(\d+)\s+max\|t\| =\s*([0-9.]+)", re.M)
MAXT = re.compile(r"^max \|t\| = ([0-9.]+) \(([^)]*)\)", re.M)
COMMIT = re.compile(r"^commit:\s+([0-9a-f]{7})", re.M)


def dudect_runs(base, platform):
    runs = []
    for build in sorted(os.listdir(base)):
        d = os.path.join(base, build)
        if not os.path.isdir(d):
            continue
        for f in sorted(os.listdir(d)):
            m = re.fullmatch(r"(.+)-cpu(\d+)\.txt", f)
            if not m:
                continue
            text = open(os.path.join(d, f), encoding="utf-8").read()
            mt = MAXT.search(text)
            runs.append({
                "platform": platform,
                "build": build,
                "target": m.group(1),
                "cpu": int(m.group(2)),
                "core": "P" if int(m.group(2)) < 16 else "E",
                "maxT": float(mt.group(1)),
                "progress": [[int(n), float(t)] for n, t in PROGRESS.findall(text)],
                "commit": COMMIT.search(text).group(1),
                "source": os.path.relpath(os.path.join(d, f), ROOT).replace(os.sep, "/"),
            })
    return runs


def native_bench(path):
    rows = []
    for line in open(path, encoding="utf-8"):
        m = re.match(r"^(ML-KEM-\d+)\s+(KeyGen|Encaps|Decaps)\s+(mlkem|ml-kem/bytes|ml-kem)\s+([0-9.]+)", line)
        if m:
            rows.append({"set": m.group(1), "op": m.group(2), "impl": m.group(3), "us": float(m.group(4))})
    return rows


def wasm_bench(path):
    rows, tier = [], None
    for line in open(path, encoding="utf-8"):
        if line.startswith("v8 flags:"):
            tier = "liftoff" if "liftoff-only" in line else "default"
        m = re.match(r"^(ML-KEM-\d+)\s+(KeyGen|Encaps|Decaps)\s+([0-9.]+)", line)
        if m:
            rows.append({"set": m.group(1), "op": m.group(2), "tier": tier, "us": float(m.group(3))})
    return rows


def keccak(path):
    out = {}
    for line in open(path, encoding="utf-8"):
        m = re.match(r"^Keccak-f\[1600\], (mlkem|keccak 0.1 crate.*?)\s+(\d+)\s", line)
        if m:
            out["mlkem" if m.group(1) == "mlkem" else "rustcrypto"] = int(m.group(2))
    return out


def main():
    data = {
        "dudect": dudect_runs(os.path.join(RES, "dudect"), "native")
        + dudect_runs(os.path.join(RES, "wasm", "dudect"), "wasm"),
        "bench": {
            "native": native_bench(os.path.join(RES, "bench", "current-cpu2.txt")),
            "baseline": native_bench(os.path.join(RES, "bench", "baseline-cpu2.txt")),
            "wasm": wasm_bench(os.path.join(RES, "wasm", "bench-cpu2.txt")),
            "keccakNs": keccak(os.path.join(RES, "bench", "current-cpu2.txt")),
        },
        "sources": {
            "bench": "results/bench/current-cpu2.txt",
            "baseline": "results/bench/baseline-cpu2.txt",
            "wasmBench": "results/wasm/bench-cpu2.txt",
        },
    }
    out = os.path.join(ROOT, "docs", "data.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=1)
        f.write("\n")
    print(f"{out}: {len(data['dudect'])} timing runs, "
          f"{len(data['bench']['native'])} native + {len(data['bench']['wasm'])} wasm bench rows")


if __name__ == "__main__":
    main()
