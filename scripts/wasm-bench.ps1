# Benchmarks the WebAssembly build of mlkem in Node (scripts/wasm/bench.mjs)
# under V8's two compilers, pinned to one P-core and one E-core, at high
# priority. Raw output goes to results/wasm/bench-cpu<N>.txt.
#
#   default        V8's normal tiering: Liftoff first, hot code re-compiled
#                  by TurboFan (what a browser or Node app actually gets)
#   --liftoff-only V8's baseline compiler only (cold code, short-lived pages)
#
# Usage:  powershell -ExecutionPolicy Bypass -File scripts\wasm-bench.ps1 `
#             [-Cpus 2,20] [-Rounds 20] [-Samples 500]
# Builds with --offline. Requires Node and the wasm32-unknown-unknown target.

param(
    [int[]]$Cpus = @(2, 20),
    [int]$Rounds = 20,
    [int]$Samples = 500
)

$root = Split-Path -Parent $PSScriptRoot
$outDir = Join-Path $root 'results\wasm'
New-Item -ItemType Directory -Force $outDir | Out-Null
$utf8 = New-Object Text.UTF8Encoding $false

& cargo build --offline --release -p mlkem-wasm --target wasm32-unknown-unknown
if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }
$wasm = Join-Path $root 'target\wasm32-unknown-unknown\release\mlkem_wasm.wasm'
$js = Join-Path $root 'scripts\wasm\bench.mjs'

$commit = (git -C $root rev-parse HEAD).Trim()
$dirty = if (git -C $root status --porcelain -- . ':!results') { ' (uncommitted changes present)' } else { '' }
$cpuName = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name.Trim()

foreach ($cpu in $Cpus) {
    $mask = '{0:X}' -f ([int64]1 -shl $cpu)
    $log = @(
        "# scripts/wasm-bench.ps1",
        "date:    $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz'))",
        "commit:  $commit$dirty",
        "rustc:   $((rustc -V).Trim()), wasm32-unknown-unknown, release",
        "wasm:    $((Get-Item $wasm).Length) bytes",
        "cpu:     $cpuName, pinned to logical CPU $cpu (start /affinity $mask /high)",
        ""
    )
    foreach ($flags in @('', '--liftoff-only')) {
        Write-Host "-- cpu $cpu, node $flags"
        # `start /affinity` sets the CPU mask when the process is created.
        $cmd = "start `"`" /b /wait /high /affinity $mask node $flags `"$js`" `"$wasm`" $Rounds $Samples"
        $out = cmd /c $cmd
        if ($LASTEXITCODE -ne 0) { throw "node failed (cpu $cpu, flags '$flags')" }
        $log += $out
        $log += ""
        $out | Where-Object { $_ -match 'flags|ML-KEM-768' }
    }
    $file = Join-Path $outDir "bench-cpu$cpu.txt"
    [IO.File]::WriteAllText($file, (($log -join "`n") + "`n"), $utf8)
    "raw output: $file"
}
