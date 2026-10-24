$ErrorActionPreference = 'Stop'
$Python = '.\.venv\Scripts\python.exe'

if (!(Test-Path $Python)) {
    Write-Host 'Creating isolated Python environment (.venv)...'
    python -m venv .venv
}

& $Python -m pip install --upgrade pip
& $Python -m pip install -r requirements.txt

if (!(Test-Path '.env')) {
    Copy-Item '.env.example' '.env'
    Write-Host ''
    Write-Host 'Created .env from .env.example.' -ForegroundColor Yellow
    Write-Host 'Edit .env with your MySQL settings and generated secret keys before starting the app.'
}

& $Python -m compileall -q app.py database.py
Write-Host ''
Write-Host 'Python setup and syntax check complete.' -ForegroundColor Green
Write-Host 'Next: run schema.sql in MySQL, configure .env, then execute:'
Write-Host '  .\.venv\Scripts\python.exe app.py'
Write-Host 'This script does not install or start the MySQL server.'
