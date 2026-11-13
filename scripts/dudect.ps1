# Runs the mlkem-dudect timing-leak tester over every target, on one P-core
# and one E-core, for the normal build and for both deliberately leaky
# builds. Each run's raw output goes to results/dudect/<build>/<target>-cpu<N>.txt
# and a one-line-per-run table to results/dudect/summary.txt.
#
# The leaky builds exist only to show that the tester CAN find a leak
# (a positive control); the aa-* targets are A/A controls that must NOT
# show one (a negative control). See LEARNING.md section 5.
#
# Usage:  powershell -ExecutionPolicy Bypass -File scripts\dudect.ps1 `
#             [-N 1000000] [-NCheap 10000000] [-Cpus 2,20] [-Only normal,kyberslash,early-exit]
#
# On the i7-14700HX logical CPUs 0-15 are P-cores (8 cores x 2 threads) and
# 16-27 are E-cores, so the defaults pin to one of each.

param(
    [long]$N = 1000000,        # measurements for the slow targets (whole KEM operations)
    [long]$NCheap = 10000000,  # measurements for the fast targets (sub-microsecond)
    [int[]]$Cpus = @(2, 20),
    [string[]]$Only = @('normal', 'kyberslash', 'early-exit')
)


$root = Split-Path -Parent $PSScriptRoot
$outDir = Join-Path $root 'results\dudect'
New-Item -ItemType Directory -Force $outDir | Out-Null
$utf8 = New-Object Text.UTF8Encoding $false

$cheap = @('ct-eq', 'message-encode', 'message-encode-zero', 'u-encode-zero')

# build name -> (cargo feature, targets). Leaky builds only run the targets
# that exercise the leaky code, each next to its own A/A control.
$builds = [ordered]@{
    'normal'     = @('', @('aa-ct-eq', 'ct-eq', 'message-encode', 'message-encode-zero',
                           'u-encode-zero', 'aa-decaps-ct', 'decaps-ct', 'decaps-valid',
                           'encaps-m', 'aa-keygen-d', 'keygen-d'))
    'kyberslash' = @('leaky-kyberslash', @('aa-message-encode-zero', 'message-encode-zero',
                                          'message-encode', 'u-encode-zero'))
    'early-exit' = @('leaky-early-exit', @('aa-decaps-ct', 'decaps-ct', 'decaps-valid'))
}

$commit = (git -C $root rev-parse HEAD).Trim()
$dirty = if (git -C $root status --porcelain) { ' (uncommitted changes present)' } else { '' }
$rustc = (rustc -V).Trim()
$summary = @(
    "# mlkem-dudect summary",
    "date:    $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz'))",
    "commit:  $commit$dirty",
    "rustc:   $rustc",
    "script:  scripts/dudect.ps1 -N $N -NCheap $NCheap -Cpus $($Cpus -join ',')",
    "",
    "thresholds: max|t| < 4.5 no leak detected; 4.5-10 possible; >= 10 leak",
    "",
    ('{0,-11} {1,-22} {2,4} {3,10} {4,10} {5,-20} {6}' -f 'build', 'target', 'cpu', 'n', 'max|t|', 'at', 'verdict')
)

$exe = Join-Path $root 'target\release\mlkem-dudect.exe'
$sw = [Diagnostics.Stopwatch]::StartNew()
foreach ($build in $builds.Keys) {
    if ($Only -notcontains $build) { continue }
    $feature, $targets = $builds[$build]
    $cargoArgs = @('build', '--release', '-p', 'mlkem-dudect')
    if ($feature) { $cargoArgs += @('--features', $feature) }
    Write-Host "== build: $build (cargo $($cargoArgs -join ' '))"
    & cargo @cargoArgs
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed for $build" }

    $buildDir = Join-Path $outDir $build
    New-Item -ItemType Directory -Force $buildDir | Out-Null
    foreach ($cpu in $Cpus) {
        foreach ($t in $targets) {
            $count = if ($cheap -contains ($t -replace '^aa-', '')) { $NCheap } else { $N }
            Write-Host "-- $build / $t / cpu $cpu / n $count"
            $runSw = [Diagnostics.Stopwatch]::StartNew()
            # Stream the progress lines to the console while also keeping them.
            $log = & $exe --target $t --n $count --cpu $cpu | ForEach-Object { Write-Host "   $_"; $_ }
            if ($LASTEXITCODE -ne 0) { throw "mlkem-dudect failed: $build $t cpu $cpu" }
            $runSw.Stop()
            $header = @(
                "# scripts/dudect.ps1 run",
                "build:   $build$(if ($feature) { " (--features $feature)" })",
                "commit:  $commit$dirty",
                "rustc:   $rustc",
                "command: mlkem-dudect --target $t --n $count --cpu $cpu",
                "wall:    $([math]::Round($runSw.Elapsed.TotalSeconds, 1)) s",
                ""
            )
            $file = Join-Path $buildDir "$t-cpu$cpu.txt"
            [IO.File]::WriteAllText($file, ((($header + $log) -join "`n") + "`n"), $utf8)

            $m = [regex]::Match(($log -join "`n"), 'max \|t\| = ([0-9.]+) \(([^)]*)\)')
            $v = (($log | Select-String '^verdict: (.*)$').Matches[0].Groups[1].Value) -replace ' \(.*$', ''
            $summary += ('{0,-11} {1,-22} {2,4} {3,10} {4,10} {5,-20} {6}' -f $build, $t, $cpu, $count, $m.Groups[1].Value, $m.Groups[2].Value, $v)
        }
    }
}
# Leave the normal build in target/ so the next `cargo build` is not leaky.
& cargo build --release -p mlkem-dudect
$sw.Stop()
$summary += @("", "total wall time: $([math]::Round($sw.Elapsed.TotalMinutes, 1)) min")
[IO.File]::WriteAllText((Join-Path $outDir 'summary.txt'), (($summary -join "`n") + "`n"), $utf8)
$summary | Select-Object -Skip 8
