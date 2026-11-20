#!/usr/bin/env bash
# Cross-compile the payload DLL. Run on Linux (Kali/Ubuntu).
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    echo "[!] missing cross-compiler: sudo apt install -y gcc-mingw-w64-x86-64" >&2
    exit 1
fi

x86_64-w64-mingw32-gcc -shared -O2 -o version.dll src/dll.c

echo "[+] built: $(pwd)/version.dll"
file version.dll
