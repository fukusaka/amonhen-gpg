#!/bin/sh
# Swift から使う Rust のコア（静的ライブラリ）をビルドし、UniFFI で Swift のバインディングを生成する。
# 生成したもの（C のヘッダーと Swift のコード）はコミットせず、ビルドのたびに作り直す。
set -eu
cd "$(dirname "$0")/.."
# アプリの対応する最も古い macOS（apps/macos/Package.swift の platforms）に合わせる
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-14.4}"
cargo build --release -p amonhen-gpg-ffi
out="$(mktemp -d)"
trap 'rm -r "$out"' EXIT
cargo run --quiet --release -p amonhen-gpg-ffi --features bindgen --bin uniffi-bindgen -- \
    generate --language swift --out-dir "$out" target/release/libamonhen_gpg_ffi.dylib
kit=apps/macos/Sources/AmonhenGpgKit/Generated
ffi=apps/macos/Sources/CAmonhenGpg
mkdir -p "$kit" "$ffi"
cp "$out/amonhen_gpg_ffi.swift" "$kit/"
cp "$out/CAmonhenGpg.h" "$ffi/"
# SwiftPM の systemLibrary は module.modulemap という名前を探す
cp "$out/CAmonhenGpg.modulemap" "$ffi/module.modulemap"
