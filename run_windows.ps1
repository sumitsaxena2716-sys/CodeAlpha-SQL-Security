$ErrorActionPreference = 'Stop'
if (!(Test-Path '.env')) { Copy-Item '.env.example' '.env'; Write-Host 'Created .env from .env.example. Edit it before running.' }
python -m pip install -r requirements.txt
python generate_key.py
Write-Host 'Copy the key above into AES_256_KEY in .env, then run: python app.py'
