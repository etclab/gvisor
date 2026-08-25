#!/bin/bash
# Build OVMF (guest firmware) into the local prefix.
#
# Why this exists instead of `AMDSEV/build.sh ovmf`:
#   AMDSEV's common.sh tracks edk2 `master` and hardcodes the `GCC5` toolchain tag.
#   edk2 master has since renamed that tag to `GCC`, so build.sh fails with
#   "[GCC5] not defined. No toolchain available for build!".
#   AMDSEV's own stable-commits comment says its snp-latest pairing is
#   edk2-stable202502, so we pin that tag: it is a real pin rather than a moving
#   branch, and it still defines GCC5. The toolchain tag is autodetected either way.
#
# Everything else (build command, output files, destination) matches common.sh's
# build_install_ovmf.
set -eu

STACK="$(dirname "$(readlink -f "$0")")"
OVMF_GIT_URL="https://github.com/tianocore/edk2.git"
OVMF_TAG="${OVMF_TAG:-edk2-stable202502}"
SRC="$STACK/AMDSEV/ovmf"
DEST="$STACK/usr/local/share/qemu"

[ -d "$SRC" ] || git clone "$OVMF_GIT_URL" "$SRC"
cd "$SRC"
git remote get-url current >/dev/null 2>&1 || git remote add current "$OVMF_GIT_URL"
git remote set-url current "$OVMF_GIT_URL"
git fetch --tags current
git checkout "$OVMF_TAG"
git submodule update --init --recursive

# Pick whichever toolchain tag this edk2 revision actually defines.
if grep -q '^DEFINE GCC5_' BaseTools/Conf/tools_def.template; then
  GCCVERS=GCC5
else
  GCCVERS=GCC
fi
echo "using edk2 toolchain tag: $GCCVERS"

make -C BaseTools clean
make -C BaseTools -j "$(getconf _NPROCESSORS_ONLN)"
set +u; . ./edksetup.sh --reconfig; set -u

nice build -q --cmd-len=64436 -n "$(getconf _NPROCESSORS_ONLN)" -t "$GCCVERS" \
     -a X64 -p OvmfPkg/OvmfPkgX64.dsc

mkdir -p "$DEST"
cp -f "Build/OvmfX64/DEBUG_$GCCVERS/FV/OVMF_CODE.fd" "$DEST"
cp -f "Build/OvmfX64/DEBUG_$GCCVERS/FV/OVMF_VARS.fd" "$DEST"
cp -f "Build/OvmfX64/DEBUG_$GCCVERS/FV/OVMF.fd"      "$DEST"

git rev-parse HEAD > "$STACK/AMDSEV/source-commit.ovmf.full"
echo "OVMF installed to $DEST from $OVMF_TAG ($(git rev-parse HEAD))"
