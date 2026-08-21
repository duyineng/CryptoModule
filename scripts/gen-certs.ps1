# Generate a local lab PKI for KMC / mock KMS.
# Usage (from repo root):
#   powershell -ExecutionPolicy Bypass -File .\scripts\gen-certs.ps1
#
# Layout:
#   certs/ca/       Root CA  (ca.key stays here only)
#   certs/kms/      What the mock KMS needs
#   certs/client/   What KMC loads at runtime

$ErrorActionPreference = 'Stop'

function Find-OpenSSL {
    $cmd = Get-Command openssl -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }

    $candidates = @(
        'd:\Program Files\Git\usr\bin\openssl.exe',
        'C:\Program Files\Git\usr\bin\openssl.exe',
        'C:\Program Files (x86)\Git\usr\bin\openssl.exe',
        'C:\Program Files\OpenSSL-Win64\bin\openssl.exe',
        'C:\Program Files\OpenSSL\bin\openssl.exe',
        (Join-Path $env:LOCALAPPDATA 'Programs\Git\usr\bin\openssl.exe')
    )

    foreach ($path in $candidates) {
        if ($path -and (Test-Path -LiteralPath $path)) {
            return $path
        }
    }

    throw 'OpenSSL not found. Install Git for Windows or add openssl.exe to PATH.'
}

function Invoke-OpenSSL {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OpenSSL,
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    & $OpenSSL @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "OpenSSL failed ($LASTEXITCODE): openssl $($Arguments -join ' ')"
    }
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$certsRoot = Join-Path $repoRoot 'certs'
$openssl = Find-OpenSSL

Write-Host "Using OpenSSL: $openssl"
& $openssl version

# Git's OpenSSL can fail on non-ASCII paths. Build in TEMP, then copy.
$workRoot = Join-Path $env:TEMP 'kmc-lab-pki'
if (Test-Path -LiteralPath $workRoot) {
    Remove-Item -LiteralPath $workRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $workRoot | Out-Null

$serverExt = Join-Path $workRoot 'server.ext'
$clientExt = Join-Path $workRoot 'client.ext'

@'
basicConstraints = CA:FALSE
keyUsage = digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:kms.example.com,DNS:localhost,IP:127.0.0.1
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
'@ | Set-Content -LiteralPath $serverExt -Encoding ascii

@'
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = DNS:outlet001
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
'@ | Set-Content -LiteralPath $clientExt -Encoding ascii

Push-Location $workRoot
try {
    Invoke-OpenSSL $openssl @('genrsa', '-out', 'ca.key', '4096')
    Invoke-OpenSSL $openssl @(
        'req', '-x509', '-new', '-key', 'ca.key', '-sha256', '-days', '3650',
        '-out', 'ca.crt', '-subj', '/CN=LabRootCA',
        '-addext', 'basicConstraints=critical,CA:TRUE',
        '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
        '-addext', 'subjectKeyIdentifier=hash'
    )

    Invoke-OpenSSL $openssl @('genrsa', '-out', 'server.key', '2048')
    Invoke-OpenSSL $openssl @(
        'req', '-new', '-key', 'server.key', '-out', 'server.csr',
        '-subj', '/CN=kms.example.com'
    )
    Invoke-OpenSSL $openssl @(
        'x509', '-req', '-in', 'server.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key',
        '-CAcreateserial', '-out', 'server.crt', '-days', '365', '-sha256',
        '-extfile', 'server.ext'
    )

    Invoke-OpenSSL $openssl @('genrsa', '-out', 'terminal.key', '2048')
    Invoke-OpenSSL $openssl @(
        'req', '-new', '-key', 'terminal.key', '-out', 'terminal.csr',
        '-subj', '/CN=outlet001'
    )
    Invoke-OpenSSL $openssl @(
        'x509', '-req', '-in', 'terminal.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key',
        '-CAcreateserial', '-out', 'terminal.crt', '-days', '365', '-sha256',
        '-extfile', 'client.ext'
    )

    Invoke-OpenSSL $openssl @('verify', '-CAfile', 'ca.crt', 'server.crt')
    Invoke-OpenSSL $openssl @('verify', '-CAfile', 'ca.crt', 'terminal.crt')
}
finally {
    Pop-Location
}

$caDir = Join-Path $certsRoot 'ca'
$kmsDir = Join-Path $certsRoot 'kms'
$clientDir = Join-Path $certsRoot 'client'

foreach ($dir in @($caDir, $kmsDir, $clientDir)) {
    if (Test-Path -LiteralPath $dir) {
        Remove-Item -LiteralPath $dir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $dir | Out-Null
}

Copy-Item -LiteralPath (Join-Path $workRoot 'ca.key')        -Destination (Join-Path $caDir 'ca.key')
Copy-Item -LiteralPath (Join-Path $workRoot 'ca.crt')        -Destination (Join-Path $caDir 'ca.crt')

Copy-Item -LiteralPath (Join-Path $workRoot 'ca.crt')        -Destination (Join-Path $kmsDir 'ca.crt')
Copy-Item -LiteralPath (Join-Path $workRoot 'server.key')    -Destination (Join-Path $kmsDir 'server.key')
Copy-Item -LiteralPath (Join-Path $workRoot 'server.crt')    -Destination (Join-Path $kmsDir 'server.crt')

Copy-Item -LiteralPath (Join-Path $workRoot 'ca.crt')        -Destination (Join-Path $clientDir 'ca.crt')
Copy-Item -LiteralPath (Join-Path $workRoot 'terminal.key')  -Destination (Join-Path $clientDir 'terminal.key')
Copy-Item -LiteralPath (Join-Path $workRoot 'terminal.crt')  -Destination (Join-Path $clientDir 'terminal.crt')

Remove-Item -LiteralPath $workRoot -Recurse -Force

Write-Host ''
Write-Host "Wrote lab certificates under: $certsRoot"
Write-Host '  certs/ca/       ca.key, ca.crt'
Write-Host '  certs/kms/      ca.crt, server.key, server.crt'
Write-Host '  certs/client/   ca.crt, terminal.key, terminal.crt'
Write-Host ''
Write-Host 'KMC only loads certs/client/. Do not copy ca.key or server.key into the client directory.'
