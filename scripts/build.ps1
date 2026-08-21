$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$cmake = 'D:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
$env:VCPKG_ROOT = 'D:\dev\vcpkg'

if (-not (Test-Path -LiteralPath $cmake)) {
    throw "VS2022 CMake not found: $cmake"
}
if (-not (Test-Path -LiteralPath (Join-Path $env:VCPKG_ROOT 'vcpkg.exe'))) {
    throw "vcpkg not found under VCPKG_ROOT: $env:VCPKG_ROOT"
}

Push-Location $repoRoot
try {
    & $cmake --preset vs2022 --fresh
    if ($LASTEXITCODE -ne 0) {
        throw "CMake configure failed with exit code $LASTEXITCODE"
    }
    & $cmake --build --preset debug
    if ($LASTEXITCODE -ne 0) {
        throw "CMake build failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}
