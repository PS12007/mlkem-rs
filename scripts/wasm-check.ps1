# Constant-time instruction check for the WebAssembly build (phase 7).
#
# Builds the mlkem crate (with the `hazmat` probes) for wasm32-unknown-unknown
# at every optimisation level, emits WebAssembly assembly, and runs
# scripts/wasm_check.py on each (same rules as the x86 check):
#   - no division in mlkem code, except reviewed /384 and %384 on lengths;
#   - no conditional branch in any "leaf" probe or anything it calls.
# Then a POSITIVE CONTROL: the deliberately leaky `leaky-kyberslash` build
# at opt-level 3 must be reported as failing (a real division in Compress);
# if the checker does not catch it, this script fails.
#
# Requires: the wasm32-unknown-unknown target (rustup target add
# wasm32-unknown-unknown) and Python 3. Builds with --offline.
# Usage:  powershell -ExecutionPolicy Bypass -File scripts\wasm-check.ps1

$root = Split-Path -Parent $PSScriptRoot
$outFile = Join-Path $root 'results\wasm-check.txt'
$commit = (git -C $root rev-parse HEAD).Trim()
$dirty = if (git -C $root status --porcelain --untracked-files=no -- . ':!results') { ' (uncommitted changes present)' } else { '' }
$log = @(
    "# constant-time instruction check, WebAssembly (wasm32-unknown-unknown)",
    "date:    $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz'))",
    "commit:  $commit$dirty",
    "rustc:   $((rustc -V).Trim())",
    ""
)

function Build-Asm($label, $flags, $features) {
    $td = Join-Path $root ("target\wasm-check\" + ($label -replace '[^a-z0-9]', '_'))
    if (Test-Path $td) { Remove-Item -Recurse -Force $td }
    $cargoArgs = @('rustc', '-q', '--offline', '-p', 'mlkem', '--lib', '--release',
                   '--target', 'wasm32-unknown-unknown', '--features', $features,
                   '--target-dir', $td, '--', '--emit', 'asm') + $flags.Split(' ')
    $out = & cargo @cargoArgs 2>&1 | ForEach-Object { "$_" }
    if ($LASTEXITCODE -ne 0) { return @($null, $out) }
    $s = Get-ChildItem -Path $td -Recurse -Filter 'mlkem-*.s' -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
    return @($s, $out)
}

$failed = $false
$builds = @(
    @('opt-level=0', '-C opt-level=0 -C debug-assertions=off -C overflow-checks=off', $true),
    @('opt-level=0+checks', '-C opt-level=0', $false),
    @('opt-level=1', '-C opt-level=1', $true),
    @('opt-level=2', '-C opt-level=2', $true),
    @('opt-level=3', '-C opt-level=3', $true),
    @('opt-level=s', '-C opt-level=s', $true),
    @('opt-level=z', '-C opt-level=z', $true)
)
$py = Join-Path $root 'scripts\wasm_check.py'
foreach ($b in $builds) {
    $label, $flags, $strict = $b
    $s, $out = Build-Asm $label $flags 'hazmat'
    if (-not $s) { $log += "build failed or no .s for $label"; $log += $out; $failed = $true; continue }
    $pyArgs = @('-I', $py)
    if (-not $strict) { $pyArgs += '--info' }
    $report = & python @pyArgs $label $s 2>&1 | ForEach-Object { "$_" }
    if ($LASTEXITCODE -ne 0) { $failed = $true }
    $log += $report
    $log += ""
}

# Positive control: the KyberSlash build must be caught.
$label = 'positive control: leaky-kyberslash, opt-level=3'
$s, $out = Build-Asm 'leaky' '-C opt-level=3' 'hazmat,leaky-kyberslash'
if (-not $s) {
    $log += "build failed for $label"; $log += $out; $failed = $true
} else {
    $report = & python -I $py --info $label $s 2>&1 | ForEach-Object { "$_" }
    $caught = [bool]($report | Select-String -Pattern 'INFO .*compress_d1 reaches an unreviewed division')
    $log += $report
    $log += "positive control: $(if ($caught) { 'CAUGHT (as required): the division in Compress is detected' } else { 'NOT CAUGHT: the checker is blind, FAIL' })"
    if (-not $caught) { $failed = $true }
}
$log += ""
$log += "overall: $(if ($failed) { 'FAIL' } else { 'PASS at every optimisation level; positive control caught' })"

[IO.File]::WriteAllText($outFile, (($log -join "`n") + "`n"), (New-Object Text.UTF8Encoding $false))
$log | Select-String -Pattern '^## |^PASS|^FAIL|^positive|^overall' | ForEach-Object { $_.Line }
"raw output: $outFile"
if ($failed) { exit 1 }
