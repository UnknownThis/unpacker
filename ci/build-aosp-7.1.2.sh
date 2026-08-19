#!/bin/bash
set -euo pipefail

WORKSPACE=${WORKSPACE:-/workspace}
AOSP_DIR=${AOSP_DIR:-$WORKSPACE/aosp}
LOG_DIR=${LOG_DIR:-$WORKSPACE/ci-logs}
JOBS=${JOBS:-4}

mkdir -p "$LOG_DIR"
exec > >(tee "$LOG_DIR/aosp-build.log") 2>&1

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  bc \
  bison \
  build-essential \
  ca-certificates \
  curl \
  file \
  flex \
  g++-multilib \
  gcc-multilib \
  git \
  gnupg \
  lib32ncurses5-dev \
  lib32readline-dev \
  lib32z1-dev \
  libc6-dev-i386 \
  libgl1-mesa-dev \
  liblz4-tool \
  libncurses5 \
  libncurses5-dev \
  libssl-dev \
  libtinfo5 \
  libxml2-utils \
  lzop \
  openjdk-8-jdk \
  python2 \
  python3 \
  rsync \
  unzip \
  x11proto-core-dev \
  xsltproc \
  zip \
  zlib1g-dev

ln -sf /usr/bin/python2 /usr/local/bin/python
curl -fsSL https://storage.googleapis.com/git-repo-downloads/repo -o /usr/local/bin/repo
chmod 0755 /usr/local/bin/repo

git config --global user.email "actions@github.com"
git config --global user.name "GitHub Actions"
git config --global http.version HTTP/1.1

mkdir -p "$AOSP_DIR"
cd "$AOSP_DIR"
if [ ! -d .repo ]; then
  repo init \
    -u https://android.googlesource.com/platform/manifest \
    -b android-7.1.2_r33 \
    --depth=1
fi

repo sync \
  -c \
  --force-sync \
  --no-clone-bundle \
  --no-tags \
  --optimized-fetch \
  -j"$JOBS"

df -h /
du -sh "$AOSP_DIR" "$AOSP_DIR/.repo" || true

rsync -a "$WORKSPACE/android-7.1.2_r33/art/" "$AOSP_DIR/art/"
rsync -a "$WORKSPACE/android-7.1.2_r33/frameworks/" "$AOSP_DIR/frameworks/"

set +u
source build/envsetup.sh
lunch aosp_sailfish-userdebug
set -u
export USE_CCACHE=0
make -j"$JOBS" libart libartd

PRODUCT_OUT="$AOSP_DIR/out/target/product/sailfish"
find "$PRODUCT_OUT" -type f \( \
  -name 'libart.so' -o \
  -name 'libartd.so' -o \
  -name 'dex2oat' \
\) -print | sort | tee "$LOG_DIR/artifacts.txt"

df -h /
