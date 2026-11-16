# One command to run Adolfiro-Australia AI on Windows.
#   .\start.ps1              open the lab in your browser
#   .\start.ps1 matrix       run every attack in both modes
#   .\start.ps1 run 3        run one module in the terminal
#   .\start.ps1 test         run the test suite
#   .\start.ps1 maestro      print the MAESTRO threat model
#   .\start.ps1 site         serve the course site
Set-Location -Path $PSScriptRoot
$py = if ($env:PYTHON) { $env:PYTHON } else { "python" }
if (-not (Test-Path ".venv")) { & $py -m venv .venv }
. .\.venv\Scripts\Activate.ps1
pip install -q -r requirements.txt

$cmd = if ($args.Count -gt 0) { $args[0] } else { "app" }
$rest = if ($args.Count -gt 1) { $args[1..($args.Count - 1)] } else { @() }
switch ($cmd) {
  "app"     { Write-Host "Opening the lab at http://localhost:8501"; python -m streamlit run app.py }
  "matrix"  { python -m au.cli matrix }
  "run"     { python -m au.cli run @rest }
  "test"    { python -m pytest -q }
  "maestro" { python -m au.cli maestro }
  "site"    { Write-Host "Serving http://localhost:8000"; python -m http.server 8000 --directory docs }
  default   { python -m au.cli $cmd @rest }
}
