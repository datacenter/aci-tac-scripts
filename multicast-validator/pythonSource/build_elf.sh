#!/usr/bin/env bash
#
# build_elf.sh — RUN INSIDE a manylinux2014 (CentOS 7 / glibc 2.17) x86_64
#                container. Produces a REAL ELF x86-64 PyInstaller binary
#                (`dist/mcast_validator`) with the paramiko rsa-sha2 fix, so it
#                matches the ORIGINAL upstream binary in kind but works on
#                ACI 6.x leaf/spine SSH.
#
# WHY glibc 2.17: the original binary was built against very old glibc for max
# APIC compatibility. manylinux2014 == CentOS 7 == glibc 2.17, so the resulting
# binary runs on any RHEL7/8/9-era APIC.
#
# WHY yum python (not /opt/python/*): the manylinux /opt/python interpreters are
# built statically (no libpython.so); PyInstaller REQUIRES a shared libpython.
# CentOS 7's system python3 RPM ships a shared libpython3.6m.so, so we use that.
# Python 3.6 -> pin PyInstaller 4.10 (last line supporting 3.6) and let pip pick
# cp36-compatible cryptography/bcrypt/pynacl wheels (all manylinux2014).
#
# INVOKE FROM macOS/host:
#   export PATH="/opt/podman/bin:$PATH"
#   cd .../multicast-validator/pythonSource
#   podman run --rm --platform linux/amd64 -v "$PWD":/src -w /src \
#       quay.io/pypa/manylinux2014_x86_64 bash build_elf.sh
#
set -euo pipefail

echo "== Container platform =="
uname -sm
cat /etc/redhat-release 2>/dev/null || true

echo "== Install shared-library Python (CentOS 7 python3) =="
yum install -y python3 python3-devel >/tmp/yum.log 2>&1 || { echo "YUM_FAIL"; tail -30 /tmp/yum.log; exit 3; }
PYBIN="$(command -v python3)"
echo "python3: $PYBIN -> $($PYBIN --version 2>&1)"

echo "== Create build venv =="
"$PYBIN" -m venv /tmp/bvenv
# shellcheck disable=SC1091
source /tmp/bvenv/bin/activate

echo "== Install PyInstaller 4.10 + paramiko 2.12.0 (py3.6-compatible) =="
python -m pip install --upgrade "pip<22" "setuptools<60" wheel >/tmp/pip1.log 2>&1
python -m pip install "pyinstaller==4.10" "paramiko==2.12.0" >/tmp/pip2.log 2>&1 || { echo "PIP_FAIL"; tail -40 /tmp/pip2.log; exit 4; }
echo "-- resolved versions --"
python -m pip freeze 2>/dev/null | grep -iE "^(pyinstaller|paramiko|cryptography|bcrypt|pynacl|cffi|six)==" || true

echo "== Clean stale build state =="
rm -rf build dist mcast_validator.spec __pycache__

echo "== PyInstaller onefile build =="
pyinstaller --onefile --clean --noconfirm --name mcast_validator \
  --paths . \
  --collect-all paramiko \
  --collect-all cryptography \
  --collect-submodules nacl \
  --collect-submodules bcrypt \
  --hidden-import mcast \
  --hidden-import utils \
  __main__.py >/tmp/pyi.log 2>&1 || { echo "PYINSTALLER_FAIL"; tail -60 /tmp/pyi.log; exit 5; }

echo "== Result =="
file dist/mcast_validator
ls -lh dist/mcast_validator
echo "-- max GLIBC symbol version required (compatibility floor) --"
objdump -T dist/mcast_validator 2>/dev/null | grep -oE "GLIBC_[0-9.]+" | sort -V | uniq | tail -5 || true
echo "-- embedded paramiko version --"
strings dist/mcast_validator 2>/dev/null | grep -m1 -E "^2\.12\.0$" && echo "  (paramiko 2.12.0 present)" || echo "  (version string check inconclusive)"
echo "BUILD_OK"
