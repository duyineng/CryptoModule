$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$venv = Join-Path $repoRoot '.venv'
$python = Join-Path $venv 'Scripts\python.exe'

if (-not (Test-Path -LiteralPath $python)) {
    py -3 -m venv $venv
}

& $python -m pip install --upgrade pip
& $python -m pip install -r (Join-Path $repoRoot 'kms\requirements.txt')
$protoDir = Join-Path $repoRoot 'proto'
$pythonOut = Join-Path $repoRoot 'kms'
$protoFile = Join-Path $protoDir 'kmc.proto'
& $python -m grpc_tools.protoc "-I$protoDir" "--python_out=$pythonOut" $protoFile
if ($LASTEXITCODE -ne 0) {
    throw "Python Protobuf generation failed with exit code $LASTEXITCODE"
}

Write-Host "Python environment and generated Protobuf module ready: $python"
