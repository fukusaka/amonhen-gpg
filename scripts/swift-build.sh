#!/bin/sh
# apps/macos で swift build を実行する（引数はそのまま渡す）。先に scripts/build-core.sh を実行しておくこと。
#   scripts/swift-build.sh [-c release] [--product AmonhenGpg] [--show-bin-path]
# Swift 6.4 はリンクで clang に SDK を --sysroot で渡し、clang は SDK の版を読まないので、アプリに記録される SDK の版が
# 最低の版（14.4）になる。macOS はそれを古い SDK で作ったアプリとみなして昔の見た目で出すので、-isysroot で渡し直す。
set -eu
cd "$(dirname "$0")/../apps/macos"
sdk=$(xcrun --sdk macosx --show-sdk-path)
exec swift build -Xswiftc -Xclang-linker -Xswiftc -isysroot -Xswiftc -Xclang-linker -Xswiftc "$sdk" "$@"
