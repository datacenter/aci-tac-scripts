#!/usr/bin/env bash
#
# build_pyz.sh — package the patched tool into a SINGLE self-contained file
#                (`mcast_validator`) that runs on the APIC, just like the
#                original PyInstaller binary — but WITH the paramiko fix.
#
# WHY A ZIPAPP (not PyInstaller):
#   PyInstaller cannot cross-compile, so the original ELF binary can only be
#   rebuilt on a Linux x86_64 host. A Python "zipapp" is pure-Python packaging,
#   so it can be built ANYWHERE (incl. macOS) yet runs on the APIC using the
#   APIC's own interpreter (/opt/cisco/system-venv3/bin/python3).
#
#   We bundle the pure-Python paramiko 2.12.0 (rsa-sha2 capable -> fixes the
#   "Incompatible ssh peer (no acceptable host key)" error on ACI 6.x) plus a
#   copy of six. The compiled crypto deps (cryptography/bcrypt/nacl) are NOT
#   bundled — the APIC already ships them as deps of its own paramiko.
#
# OUTPUT:
#   ./dist/mcast_validator   (a single executable file; scp it to the APIC)
#
# RUN ON THE APIC:
#   ./mcast_validator -u <user> -t <tenant> -v <vrf> -r <rcvr> -s <src> -g <grp>
#   (or:  /opt/cisco/system-venv3/bin/python3 mcast_validator ... )
#
set -euo pipefail

APIC_PY="/opt/cisco/system-venv3/bin/python3"   # shebang baked into the artifact
PARAMIKO_VER="2.12.0"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Locate the patched source (next to this script, or under ./pythonSource).
if [ -f "$HERE/__main__.py" ]; then
    SRC="$HERE"
elif [ -f "$HERE/pythonSource/__main__.py" ]; then
    SRC="$HERE/pythonSource"
else
    echo "ERROR: cannot find __main__.py next to build_pyz.sh or under ./pythonSource" >&2
    exit 1
fi

BUILDPY="${PYTHON:-python3}"           # any local python3 >= 3.7 can build a zipapp
OUT_DIR="$SRC/dist"
STAGE="$(mktemp -d)/mcast_stage"
mkdir -p "$STAGE" "$OUT_DIR"

echo "== Staging application =="
cp "$SRC/__main__.py" "$SRC/mcast.py" "$SRC/utils.py" "$STAGE/"

echo "== Adding pure-Python paramiko $PARAMIKO_VER (rsa-sha2 fix) at archive root =="
if [ -d "$SRC/vendor/paramiko" ]; then
    cp -r "$SRC/vendor/paramiko" "$STAGE/paramiko"
else
    DL="$(mktemp -d)"
    "$BUILDPY" -m pip download "paramiko==$PARAMIKO_VER" --no-deps -d "$DL" >/dev/null
    ( cd "$DL" && unzip -oq paramiko-*.whl )
    cp -r "$DL/paramiko" "$STAGE/paramiko"
fi

echo "== Adding pure-Python six (defensive) =="
DLS="$(mktemp -d)"
if "$BUILDPY" -m pip download six --no-deps -d "$DLS" >/dev/null 2>&1; then
    ( cd "$DLS" && unzip -oq six-*.whl 2>/dev/null || true )
    [ -f "$DLS/six.py" ] && cp "$DLS/six.py" "$STAGE/six.py" || echo "  (six.py not found; APIC copy will be used)"
fi

# Drop any bytecode caches so the artifact is clean/small.
find "$STAGE" -name "__pycache__" -type d -prune -exec rm -rf {} + 2>/dev/null || true

echo "== Building zipapp -> $OUT_DIR/mcast_validator =="
# The staging dir already contains __main__.py, so zipapp uses it as the entry
# point automatically. -p bakes the APIC shebang and marks the file executable.
"$BUILDPY" -m zipapp "$STAGE" -o "$OUT_DIR/mcast_validator" -p "$APIC_PY" -c
chmod +x "$OUT_DIR/mcast_validator"

echo
echo "== Verify =="
echo "shebang: $(head -1 "$OUT_DIR/mcast_validator")"
"$BUILDPY" - "$OUT_DIR/mcast_validator" <<'PYEOF'
import sys, zipfile
p = sys.argv[1]
z = zipfile.ZipFile(p)
names = z.namelist()
assert "__main__.py" in names, "missing __main__.py"
assert any(n.startswith("paramiko/") for n in names), "missing bundled paramiko"
print("zipapp OK: __main__.py + paramiko/ present ({} entries)".format(len(names)))
print("paramiko bundled:", "six.py bundled" if "six.py" in names else "six from APIC")
PYEOF
ls -lh "$OUT_DIR/mcast_validator"
echo
echo "Done. scp '$OUT_DIR/mcast_validator' to the APIC and run it there."
