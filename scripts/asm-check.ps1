# Constant-time assembly check (phase 4).
#
# Builds the mlkem crate (with the `hazmat` probes) at every optimisation
# level rustc offers, emits assembly, and runs scripts/asm_check.py on each:
#   - no div/idiv in any mlkem function (KyberSlash class);
#   - no conditional branch in any "leaf" probe or anything it calls;
#   - every conditional branch in "loop" probes listed for manual review.
# Also saves the opt-level 3 assembly of every probe under results/asm/.
#
# Requires: Rust stable (MSVC), Python 3, and (unless -SkipShowAsm)
# cargo-show-asm (cargo install cargo-show-asm).
# Usage:  powershell -ExecutionPolicy Bypass -File scripts\asm-check.ps1 [-SkipShowAsm]
# CI runs it with -SkipShowAsm: the pass/fail analysis does not need it.

param([switch]$SkipShowAsm)

$root = Split-Path -Parent $PSScriptRoot
$results = Join-Path $root 'results'
$asmDir = Join-Path $results 'asm'
New-Item -ItemType Directory -Force $asmDir | Out-Null
$outFile = Join-Path $results 'asm-check.txt'

$cpu = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name.Trim()
$commit = (git -C $root rev-parse HEAD).Trim()
$dirty = if (git -C $root status --porcelain) { ' (uncommitted changes present)' } else { '' }
$log = @(
    "# constant-time assembly check",
    "date:    $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz'))",
    "commit:  $commit$dirty",
    "rustc:   $((rustc -V).Trim())",
    "target:  $(((rustc -vV) | Select-String '^host:').ToString().Split(' ')[1])",
    "cpu:     $cpu (only relevant for target-cpu=native; we use the default x86-64 baseline)",
    ""
)

$failed = $false
# Each build: label, rustc flags, strict (fails the check) or informational.
# Passing -C opt-level=0 also switches rustc's debug assertions and overflow
# checks back on (their default follows opt-level). "opt-level=0" turns them
# off to match a release build; "opt-level=0+checks" keeps them, like the
# `dev` profile, and is informational: overflow checks are branches on the
# result of (possibly secret) arithmetic.
$builds = @(
    @('opt-level=0', '-C opt-level=0 -C debug-assertions=off -C overflow-checks=off', $true),
    @('opt-level=0+checks', '-C opt-level=0', $false),
    @('opt-level=1', '-C opt-level=1', $true),
    @('opt-level=2', '-C opt-level=2', $true),
    @('opt-level=3', '-C opt-level=3', $true),
    @('opt-level=s', '-C opt-level=s', $true),
    @('opt-level=z', '-C opt-level=z', $true)
)
foreach ($b in $builds) {
    $label, $flags, $strict = $b
    $td = Join-Path $root ("target\asm-check\" + ($label -replace '[^a-z0-9]', '_'))
    if (Test-Path $td) { Remove-Item -Recurse -Force $td }
    $build = cmd /c "cargo rustc -q -p mlkem --lib --release --features hazmat --target-dir `"$td`" -- --emit asm $flags 2>&1"
    if ($LASTEXITCODE -ne 0) { $log += "build failed: $label"; $log += $build; $failed = $true; continue }
    $s = (Get-ChildItem "$td\release\deps\mlkem-*.s" | Select-Object -First 1).FullName
    $info = if ($strict) { '' } else { '--info' }
    Push-Location (Join-Path $root 'scripts')
    $report = cmd /c "python -I asm_check.py $info $label `"$s`" 2>&1"
    if ($LASTEXITCODE -ne 0) { $failed = $true }
    Pop-Location
    $log += $report
    $log += ""
}

# Human-readable per-probe assembly at the default release level, via cargo-show-asm.
$probes = 'barrett_reduce', 'montgomery_reduce', 'fqmul', 'to_canonical', 'csubq',
          'compress_d1', 'compress_d4', 'compress_d5', 'compress_d10', 'compress_d11',
          'decompress_d1', 'message_encode', 'decode12', 'cbd_eta2', 'cbd_eta3',
          'is_zero_mask', 'ct_eq_32', 'ct_eq_1088', 'ct_select_32', 'keccak_f1600'
Push-Location $root
$list = if ($SkipShowAsm) { @() } else { cmd /c "cargo asm -p mlkem --lib --release --features hazmat --intel mlkem::hazmat:: 2>&1" }
foreach ($p in $(if ($SkipShowAsm) { @() } else { $probes })) {
    # cargo-show-asm matches by substring and lists candidates with an index.
    $line = $list | Select-String -Pattern "^\s*(\d+) `"mlkem::hazmat::$p`"" | Select-Object -First 1
    if (-not $line) { $log += "cargo-show-asm: probe $p not found"; $failed = $true; continue }
    $idx = $line.Matches[0].Groups[1].Value
    $asm = cmd /c "cargo asm -p mlkem --lib --release --features hazmat --intel --simplify mlkem::hazmat::$p $idx 2>nul"
    [IO.File]::WriteAllText((Join-Path $asmDir "$p.s"), (($asm -join "`n") + "`n"), (New-Object Text.UTF8Encoding $false))
}
Pop-Location
$log += if ($SkipShowAsm) { "per-probe listings skipped (-SkipShowAsm)" } else { "per-probe Intel-syntax assembly (opt-level 3, cargo-show-asm): results/asm/<probe>.s" }
$log += "overall: $(if ($failed) { 'FAIL' } else { 'PASS at every optimisation level' })"

[IO.File]::WriteAllText($outFile, (($log -join "`n") + "`n"), (New-Object Text.UTF8Encoding $false))
$log | Select-String -Pattern '^## |^PASS|^FAIL|^INFO|^overall' | ForEach-Object { $_.Line }
"raw output: $outFile"
if ($failed) { exit 1 }
