# Crypto Module Lab

Minimal end-to-end implementation of the design:

```text
sdk_demo -- Windows named pipe + protobuf --> KMC
KMC      -- HTTPS + mTLS + protobuf -------> KMS
KMS      -- encrypted key material --------> SQLite
```

The KMC is a normal console executable for development. It does not contain
Windows Service APIs.

## Components

- `kmc.exe`: C++17, libcurl with OpenSSL, Protobuf, OpenSSL EVP AES-256-GCM.
- `sdk_demo.exe`: sends encrypt/decrypt requests over a Windows named pipe.
- `kms/server.py`: Python HTTPS server requiring a client certificate.
- `kms/data/kms.db`: SQLite metadata and AES-GCM-encrypted work-key material.
- `proto/kmc.proto`: shared wire contract.

## Prerequisites

- Visual Studio 2022 with Desktop development with C++.
- VS2022 CMake component.
- vcpkg at `D:\dev\vcpkg` or update `scripts/build.ps1`/`VCPKG_ROOT`.
- An ASCII-only dependency directory. The included preset uses
  `D:\dev\vcpkg_installed\crypto-module` because some Windows build tools
  mishandle non-ASCII library paths.
- Python 3.11 or newer.

## Build

From PowerShell:

```powershell
.\scripts\setup-python.ps1
.\scripts\build.ps1
```

The vcpkg manifest installs curl with its OpenSSL backend, OpenSSL, and
Protobuf. CMake generates the C++ Protobuf sources; `setup-python.ps1`
generates the Python Protobuf module.

## Run

Open three PowerShell terminals from the repository root.

Terminal 1:

```powershell
.\scripts\run-kms.ps1
```

Terminal 2:

```powershell
.\build\kmc\Debug\kmc.exe .\build\kmc\Debug\kmc.ini
```

Terminal 3:

```powershell
.\build\kmc\Debug\sdk_demo.exe "hello crypto module"
```

Expected SDK output includes the generated `key_id`, ciphertext length, and
the original plaintext after authenticated decryption.

The lab certificates are under `certs/`. Regenerate them with:

```powershell
.\scripts\gen-certs.ps1
```

Never deploy `certs/ca/ca.key` to a client machine.
