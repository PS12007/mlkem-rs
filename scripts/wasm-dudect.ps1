# Timing-leak test of the WebAssembly build in Node (scripts/wasm/dudect.mjs),
# for the normal build and the two deliberately leaky builds (positive
# controls), each target next to its A/A control, pinned to one P-core and
# one E-core. Raw output: results/wasm/dudect/<build>/<target>-cpu<N>.txt;
# table: results/wasm/dudect/summary.txt.
#
# Usage:  powershell -ExecutionPolicy Bypass -File scripts\wasm-dudect.ps1 `
#             [-NDecaps 200000] [-NEncode 1000000] [-Cpus 2,20]
# Builds with --offline. Requires Node and the wasm32-unknown-unknown target.

param(
    [int]$NDecaps = 200000,
    [int]$NEncode = 1000000,
    [int[]]$Cpus = @(2, 20)
)

$root = Split-Path -Parent $PSScriptRoot
$outDir = Join-Path $root 'results\wasm\dudect'
$binDir = Join-Path $root 'target\wasm-dudect'
New-Item -ItemType Directory -Force $outDir, $binDir | Out-Null
$utf8 = New-Object Text.UTF8Encoding $false
$js = Join-Path $root 'scripts\wasm\dudect.mjs'

$builds = [ordered]@{
    'normal'     = @('probes', @('aa-decaps-ct', 'decaps-ct', 'aa-u-encode-zero', 'u-encode-zero'))
    'early-exit' = @('probes,leaky-early-exit', @('aa-decaps-ct', 'decaps-ct'))
    'kyberslash' = @('probes,leaky-kyberslash', @('aa-u-encode-zero', 'u-encode-zero'))
}

$commit = (git -C $root rev-parse HEAD).Trim()
$dirty = if (git -C $root status --porcelain -- . ':!results') { ' (uncommitted changes present)' } else { '' }
$fmt = '{0,-11} {1,-18} {2,4} {3,9} {4,10} {5,-20} {6}'
$summary = @(
    "# mlkem WebAssembly dudect summary (Node $(node --version))",
    "date:    $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz'))",
    "commit:  $commit$dirty",
    "script:  scripts/wasm-dudect.ps1 -NDecaps $NDecaps -NEncode $NEncode -Cpus $($Cpus -join ',')",
    "",
    "thresholds: max|t| < 4.5 no leak detected; 4.5-10 possible; >= 10 leak",
    "",
    ($fmt -f 'build', 'target', 'cpu', 'n', 'max|t|', 'at', 'verdict')
)

foreach ($build in $builds.Keys) {
    $features, $targets = $builds[$build]
    & cargo build --offline -q --release -p mlkem-wasm --target wasm32-unknown-unknown --features $features
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed for $build" }
    $wasm = Join-Path $binDir "$build.wasm"
    Copy-Item -Force (Join-Path $root 'target\wasm32-unknown-unknown\release\mlkem_wasm.wasm') $wasm
    New-Item -ItemType Directory -Force (Join-Path $outDir $build) | Out-Null
    foreach ($cpu in $Cpus) {
        $mask = '{0:X}' -f ([int64]1 -shl $cpu)
        foreach ($t in $targets) {
            $count = if ($t -like '*decaps*') { $NDecaps } else { $NEncode }
            Write-Host "-- $build / $t / cpu $cpu / n $count"
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $out = cmd /c "start `"`" /b /wait /high /affinity $mask node `"$js`" `"$wasm`" $t $count"
            if ($LASTEXITCODE -ne 0) { throw "node failed: $build $t cpu $cpu" }
            $sw.Stop()
            $header = @(
                "# scripts/wasm-dudect.ps1 run",
                "build:   $build (--features $features)",
                "commit:  $commit$dirty",
                "rustc:   $((rustc -V).Trim()), wasm32-unknown-unknown, release",
                "command: start /affinity $mask /high node scripts/wasm/dudect.mjs $build.wasm $t $count",
                "wall:    $([math]::Round($sw.Elapsed.TotalSeconds, 1)) s",
                ""
            )
            [IO.File]::WriteAllText((Join-Path $outDir "$build\$t-cpu$cpu.txt"), ((($header + $out) -join "`n") + "`n"), $utf8)
            $text = $out -join "`n"
            $m = [regex]::Match($text, 'max \|t\| = ([0-9.]+) \(([^)]*)\)')
            $v = [regex]::Match($text, '(?m)^verdict: ([^(\r\n]*)').Groups[1].Value.Trim()
            $line = $fmt -f $build, $t, $cpu, $count, $m.Groups[1].Value, $m.Groups[2].Value, $v
            $summary += $line
            Write-Host "   $line"
        }
    }
}
[IO.File]::WriteAllText((Join-Path $outDir 'summary.txt'), (($summary -join "`n") + "`n"), $utf8)
$summary | Select-Object -Skip 7
