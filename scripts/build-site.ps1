# Rebuilds the website in docs/ (served by GitHub Pages from main:/docs):
#   - docs/mlkem_wasm.wasm: the normal WebAssembly build, for the live demo;
#   - docs/data.json: every number the site shows, extracted from results/
#     by scripts/site_data.py, so the site never carries hand-typed figures.
# Run it after re-running any of the result scripts, then commit docs/.
#
# Usage:  powershell -ExecutionPolicy Bypass -File scripts\build-site.ps1
# Preview: python -m http.server -d docs 8000, then open http://localhost:8000
# Builds with --offline.

$root = Split-Path -Parent $PSScriptRoot
& cargo build --offline --release -p mlkem-wasm --target wasm32-unknown-unknown
if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }
Copy-Item -Force (Join-Path $root 'target\wasm32-unknown-unknown\release\mlkem_wasm.wasm') (Join-Path $root 'docs\mlkem_wasm.wasm')
& python -I (Join-Path $root 'scripts\site_data.py')
if ($LASTEXITCODE -ne 0) { throw 'site_data.py failed' }
"docs/ updated: mlkem_wasm.wasm ($((Get-Item (Join-Path $root 'docs\mlkem_wasm.wasm')).Length) bytes), data.json"
