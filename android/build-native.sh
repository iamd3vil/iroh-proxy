#!/bin/sh
# Builds libiroh_proxy_android.so for each ABI into app/src/main/jniLibs.
# Usage: build-native.sh <ndk dir>   (Gradle passes it; otherwise $ANDROID_NDK_HOME)
set -eu
NDK=${1:-${ANDROID_NDK_HOME:?pass the NDK dir or set ANDROID_NDK_HOME}}
API=26 # = minSdk
case "$(uname -s)" in
  Darwin) HOST=darwin-x86_64 ;; # also the host tag on Apple silicon
  *) HOST=linux-x86_64 ;;
esac
BIN=$NDK/toolchains/llvm/prebuilt/$HOST/bin
HERE=$(cd "$(dirname "$0")" && pwd)

export CARGO_PROFILE_RELEASE_STRIP=true
# 16 KB page alignment, required on Android 15+ devices with 16 KB pages.
export RUSTFLAGS="-C link-arg=-Wl,-z,max-page-size=16384"
export AR="$BIN/llvm-ar"

for pair in aarch64-linux-android:arm64-v8a x86_64-linux-android:x86_64; do
  target=${pair%%:*} abi=${pair##*:}
  cc="$BIN/$target$API-clang"
  target_env=$(echo "$target" | tr a-z- A-Z_)
  env "CC_$(echo "$target" | tr - _)=$cc" "CARGO_TARGET_${target_env}_LINKER=$cc" \
    cargo build --manifest-path "$HERE/native/Cargo.toml" --release --target "$target"
  mkdir -p "$HERE/app/src/main/jniLibs/$abi"
  cp "$HERE/../target/$target/release/libiroh_proxy_android.so" "$HERE/app/src/main/jniLibs/$abi/"
done
