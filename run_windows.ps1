
$ErrorActionPreference = 'Stop'

$ProjectRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
    $ProjectRoot = $PWD.Path
}

Set-Location $ProjectRoot

$Python = Join-Path $ProjectRoot '.venv\Scripts\python.exe'
$EnvFile = Join-Path $ProjectRoot '.env'
$EnvExample = Join-Path $ProjectRoot '.env.example'

if (-not (Test-Path $Python)) {
    python -m venv .venv
}

if (-not (Test-Path $EnvFile)) {
    Copy-Item $EnvExample $EnvFile
    Write-Host 'Created .env. Configure your local settings.'
}

& $Python -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }

& $Python -m py_compile app.py database.py generate_key.py
if ($LASTEXITCODE -ne 0) { throw 'Syntax check failed.' }

Write-Host 'Setup and syntax checks passed.' -ForegroundColor Green
Write-Host 'Start the application with: .\.venv\Scripts\python.exe app.py'
