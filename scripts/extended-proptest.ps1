# Runs the whole test suite with many more property-test cases than the
# default 256 (the substitute for cargo-fuzz; see LEARNING.md section 3).
# Raw output, with machine and commit details, goes to results/.
#
# Usage:  powershell -ExecutionPolicy Bypass -File scripts\extended-proptest.ps1 [-Cases 100000]

param([int]$Cases = 100000)

$root = Split-Path -Parent $PSScriptRoot
$resultsDir = Join-Path $root 'results'
New-Item -ItemType Directory -Force $resultsDir | Out-Null
$outFile = Join-Path $resultsDir 'extended-proptest.txt'

$cpu = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name.Trim()
$commit = (git -C $root rev-parse HEAD).Trim()
$dirty = if (git -C $root status --porcelain) { ' (uncommitted changes present)' } else { '' }
$rustc = (rustc -V).Trim()

$header = @(
    "# extended property-test run",
    "date:    $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz'))",
    "commit:  $commit$dirty",
    "rustc:   $rustc",
    "cpu:     $cpu",
    "command: PROPTEST_CASES=$Cases cargo test --workspace --no-fail-fast",
    ""
)

$env:PROPTEST_CASES = "$Cases"
$sw = [Diagnostics.Stopwatch]::StartNew()
# cmd merges cargo's stderr into stdout without PowerShell 5.1 turning
# stderr lines into error records.
$log = cmd /c "cargo test --workspace --no-fail-fast 2>&1"
$exit = $LASTEXITCODE
$sw.Stop()
Remove-Item Env:PROPTEST_CASES

$footer = @("", "exit code: $exit", "wall time: $([math]::Round($sw.Elapsed.TotalSeconds, 1)) s")
$all = $header + $log + $footer
# UTF-8 without BOM, LF line endings.
[IO.File]::WriteAllText($outFile, (($all -join "`n") + "`n"), (New-Object Text.UTF8Encoding $false))

$log | Select-String 'test result' | ForEach-Object { $_.Line }
"exit code: $exit; wall time: $([math]::Round($sw.Elapsed.TotalSeconds, 1)) s; raw output: $outFile"
exit $exit
