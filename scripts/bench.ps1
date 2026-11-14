# Benchmarks mlkem against RustCrypto's ml-kem (crates/bench) on one P-core
# and one E-core. Raw output, with machine and commit details, goes to
# results/bench/<label>-cpu<N>.txt.
#
# Usage:  powershell -ExecutionPolicy Bypass -File scripts\bench.ps1 `
#             [-Label current] [-Cpus 2,20] [-Rounds 20] [-Samples 500]
#
# On the i7-14700HX logical CPUs 0-15 are P-cores and 16-27 are E-cores.
# Builds with --offline: the benchmark must not download anything.

param(
    [string]$Label = 'current',
    [int[]]$Cpus = @(2, 20),
    [int]$Rounds = 20,
    [int]$Samples = 500
)

$root = Split-Path -Parent $PSScriptRoot
$outDir = Join-Path $root 'results\bench'
New-Item -ItemType Directory -Force $outDir | Out-Null
$utf8 = New-Object Text.UTF8Encoding $false

& cargo build --offline --release -p mlkem-bench
if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }

$commit = (git -C $root rev-parse HEAD).Trim()
$dirty = if (git -C $root status --porcelain -- . ':!results') { ' (uncommitted changes present)' } else { '' }
$rustc = (rustc -V).Trim()
$exe = Join-Path $root 'target\release\mlkem-bench.exe'

foreach ($cpu in $Cpus) {
    Write-Host "-- cpu $cpu"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $log = & $exe --cpu $cpu --rounds $Rounds --samples $Samples
    if ($LASTEXITCODE -ne 0) { throw "mlkem-bench failed on cpu $cpu" }
    $sw.Stop()
    $header = @(
        "# scripts/bench.ps1 run, label '$Label'",
        "date:    $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz'))",
        "commit:  $commit$dirty",
        "rustc:   $rustc",
        "profile: release (opt-level 3), default target CPU (no -C target-cpu=native)",
        "command: mlkem-bench --cpu $cpu --rounds $Rounds --samples $Samples",
        "wall:    $([math]::Round($sw.Elapsed.TotalSeconds, 1)) s",
        ""
    )
    $file = Join-Path $outDir "$Label-cpu$cpu.txt"
    [IO.File]::WriteAllText($file, ((($header + $log) -join "`n") + "`n"), $utf8)
    $log | Where-Object { $_ -match 'ratio|Keccak' }
    "raw output: $file"
}
