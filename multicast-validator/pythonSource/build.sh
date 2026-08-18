#!/usr/bin/env bash
#
# build.sh — rebuild the single-file `mcast_validator` binary WITH the paramiko fix.
#
# WHY:
#   The upstream `mcast_validator` binary froze an OLD paramiko that cannot
#   negotiate rsa-sha2 host keys. On ACI 6.x the leaf/spine sshd only offers
#   rsa-sha2 host-key algorithms, so the old binary fails with:
#       "Incompatible ssh peer (no acceptable host key)"
#   This rebuild freezes paramiko 2.12.0 (rsa-sha2 capable) into the binary.
#
# WHERE TO RUN (IMPORTANT):
#   PyInstaller does NOT cross-compile. The APIC is Linux x86_64, so you must
#   build on a Linux x86_64 host. You CANNOT build the APIC binary on macOS.
#   For maximum APIC compatibility, build on an OLD-glibc host (CentOS 7 /
#   manylinux2014 == glibc 2.17). A one-shot Docker way to do that from any
#   machine (incl. Apple-Silicon macOS, via amd64 emulation):
#
#     docker run --rm --platform linux/amd64 \
#       -v "$(pwd)":/src -w /src quay.io/pypa/manylinux2014_x86_64 \
#       bash -c 'PYTHON=/opt/python/cp39-cp39/bin/python bash build.sh'
#
#   The finished binary lands at ./dist/mcast_validator (maps back to your
#   host via the -v mount).
#
# DIRECT (on a real Linux x86_64 host):
#     bash build.sh
#
set -euo pipefail

PYTHON="${PYTHON:-python3}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Support both layouts: build.sh sitting next to __main__.py (Desktop copy) OR
# with the source under ./pythonSource (repo layout).
if [ -f "$HERE/__main__.py" ]; then
    SRC="$HERE"
elif [ -f "$HERE/pythonSource/__main__.py" ]; then
    SRC="$HERE/pythonSource"
else
    echo "ERROR: cannot find __main__.py next to build.sh or under ./pythonSource" >&2
    exit 1
fi
cd "$SRC"

echo "== Build host =="
uname -sm

# Refuse to build on macOS: the output would be a Mach-O binary useless on the APIC.
if [ "$(uname -s)" = "Darwin" ]; then
    echo "ERROR: Building on macOS produces a macOS binary that will NOT run on the APIC." >&2
    echo "       Use the Docker command in the header of this script, or a Linux x86_64 host." >&2
    exit 2
fi

VENV="$(mktemp -d)/mcast_build_venv"
echo "== Creating build venv at $VENV =="
"$PYTHON" -m venv "$VENV"
# shellcheck disable=SC1091
source "$VENV/bin/activate"

python -m pip install --upgrade pip >/dev/null
# paramiko 2.12.0 = rsa-sha2 capable (the fix); pull its compiled deps too.
python -m pip install "paramiko==2.12.0" pyinstaller

echo "== Running PyInstaller (onefile) =="
pyinstaller --onefile --clean --noconfirm --strip --name mcast_validator \
  --collect-all paramiko \
  --collect-all cryptography \
  --collect-all nacl \
  --collect-all bcrypt \
  --hidden-import mcast \
  --hidden-import utils \
  __main__.py

echo
echo "== Done =="
echo "Binary: $SRC/dist/mcast_validator"
file "$SRC/dist/mcast_validator" || true
"$SRC/dist/mcast_validator" --help 2>/dev/null | head -20 || true

echo
echo "Frozen paramiko version check:"
strings "$SRC/dist/mcast_validator" 2>/dev/null | grep -m1 -E "^2\.12\.0$" \
  && echo "  (paramiko 2.12.0 string present)" \
  || echo "  (version string not found via strings; run the binary on the APIC to confirm)"
