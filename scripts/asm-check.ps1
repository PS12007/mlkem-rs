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
$dirty = if (git -C $root status --porcelain --untracked-files=no) { ' (uncommitted changes present)' } else { '' }
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
    # Call the tools directly with argument arrays (no `cmd /c "..."`):
    # Windows PowerShell 5.1 and PowerShell 7 quote nested arguments for
    # cmd differently, which broke the --target-dir path on the CI runner.
    $cargoArgs = @('rustc', '-q', '-p', 'mlkem', '--lib', '--release', '--features', 'hazmat',
                   '--target-dir', $td, '--', '--emit', 'asm') + $flags.Split(' ')
    $build = & cargo @cargoArgs 2>&1 | ForEach-Object { "$_" }
    if ($LASTEXITCODE -ne 0) { $log += "build failed: $label"; $log += $build; $failed = $true; continue }
    $s = (Get-ChildItem (Join-Path $td 'release\deps\mlkem-*.s') | Select-Object -First 1).FullName
    $pyArgs = @('-I', (Join-Path $root 'scripts\asm_check.py'))
    if (-not $strict) { $pyArgs += '--info' }
    $pyArgs += @($label, $s)
    $report = & python @pyArgs 2>&1 | ForEach-Object { "$_" }
    if ($LASTEXITCODE -ne 0) { $failed = $true }
    $log += $report
    $log += ""
}

# Human-readable per-probe assembly at the default release level, via cargo-show-asm.
$probes = 'barrett_reduce', 'montgomery_reduce', 'fqmul', 'to_canonical', 'csubq',
          'compress_d1', 'compress_d4', 'compress_d5', 'compress_d10', 'compress_d11',
          'decompress_d1', 'message_encode', 'decode12', 'cbd_eta2', 'cbd_eta3',
          'is_zero_mask', 'ct_eq_32', 'ct_eq_1088', 'ct_select_32', 'keccak_f1600'
Push-Location $root
# --context 1: also print the functions each probe calls (some probes are a
# single tail-call `jmp` into the real function).
$showAsm = 'cargo asm -p mlkem --lib --release --features hazmat --intel --simplify --context 1'
foreach ($p in $(if ($SkipShowAsm) { @() } else { $probes })) {
    # cargo-show-asm matches by substring. If several functions match (e.g.
    # compress_d1 also matches compress_d10), it prints a numbered list
    # instead of code, and the number is the position in THAT list.
    $asm = cmd /c "$showAsm mlkem::hazmat::$p 2>&1"
    if ($asm -match 'Try one of those') {
        $line = $asm | Select-String -Pattern "^\s*(\d+) `"mlkem::hazmat::$p`"" | Select-Object -First 1
        if (-not $line) { $log += "cargo-show-asm: probe $p not found"; $failed = $true; continue }
        $asm = cmd /c "$showAsm mlkem::hazmat::$p $($line.Matches[0].Groups[1].Value) 2>&1"
    }
    $asm = $asm | Where-Object { $_ -notmatch '^\s*(Compiling|Finished|Blocking|warning: )' }
    if (-not ($asm -match '^\s+(ret|jmp)\b')) { $log += "cargo-show-asm: no code for $p"; $failed = $true }
    [IO.File]::WriteAllText((Join-Path $asmDir "$p.s"), (($asm -join "`n") + "`n"), (New-Object Text.UTF8Encoding $false))
}
Pop-Location
$log += if ($SkipShowAsm) { "per-probe listings skipped (-SkipShowAsm)" } else { "per-probe Intel-syntax assembly (opt-level 3, cargo-show-asm): results/asm/<probe>.s" }
$log += "overall: $(if ($failed) { 'FAIL' } else { 'PASS at every optimisation level' })"

[IO.File]::WriteAllText($outFile, (($log -join "`n") + "`n"), (New-Object Text.UTF8Encoding $false))
$log | Select-String -Pattern '^## |^PASS|^FAIL|^INFO|^overall' | ForEach-Object { $_.Line }
"raw output: $outFile"
if ($failed) { exit 1 }
