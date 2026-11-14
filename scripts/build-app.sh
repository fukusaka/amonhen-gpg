#!/bin/sh
# Amonhen GPG.app を作る（Rust のコア → Swift のリリースビルド → 組み立てと署名 → zip → 公証）。
#   scripts/build-app.sh [stable|snapshot]
# 出力: dist/<アプリ名>.app と dist/<アプリ名>-<版>.zip（最後の行に zip の場所）。
# snapshot は正式版と並べて入れられるように、名前とバンドル ID を変える。
# 署名: AMONHEN_SIGN_IDENTITY にキーチェーンの証明書の名前があればそれで、なければ ad-hoc（scripts/codesign.sh）。
# 公証: 公証の鍵（scripts/notarize.sh）があれば公証して結果を綴じ込む。
# gpg は入っていない。アプリは PATH と Homebrew・GPG Suite の場所から探す（GpgProgram.locate）。
set -eu
cd "$(dirname "$0")/.."
mode=${1:-stable}
version=$(scripts/version.sh "$mode")
case "$mode" in
stable)
    name="Amonhen GPG"
    bundle_id="io.github.fukusaka.amonhen.gpg"
    ;;
snapshot)
    name="Amonhen GPG Snapshot"
    bundle_id="io.github.fukusaka.amonhen.gpg.snapshot"
    ;;
*)
    echo "usage: $0 [stable|snapshot]" >&2
    exit 2
    ;;
esac
# CFBundleVersion は数字とピリオドだけ。snapshot は「次の patch」＋コミット数にする。
build_number=$(echo "$version" | sed -E 's/-snapshot\.([0-9]+).*/.\1/')

scripts/build-core.sh >&2
# Swift 6.4 はリンクで clang に SDK を --sysroot で渡し、clang は SDK の版を読まないので、アプリに記録される SDK の版が
# 最低の版（14.4）になる。macOS はそれを古い SDK で作ったアプリとみなして昔の見た目で出すので、-isysroot で渡し直す。
sdk=$(xcrun --sdk macosx --show-sdk-path)
set -- -c release -Xswiftc -Xclang-linker -Xswiftc -isysroot -Xswiftc -Xclang-linker -Xswiftc "$sdk"
(cd apps/macos && swift build "$@" --product AmonhenGpg >&2)
bin=$(cd apps/macos && swift build "$@" --show-bin-path)/AmonhenGpg

app="dist/$name.app"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$bin" "$app/Contents/MacOS/AmonhenGpg"
# ほかの Mac でも動くよう、OS のもの以外のライブラリを指していないか確かめる。
if otool -L "$app/Contents/MacOS/AmonhenGpg" | tail -n +2 | grep -vE '^[[:space:]]+(/System/Library/|/usr/lib/)'; then
    echo "the app links libraries outside the system (above)" >&2
    exit 1
fi
# 記録された SDK の版が、ビルドに使った SDK の版と同じか（違えば macOS が古い見た目で出す）。
built_sdk=$(otool -l "$app/Contents/MacOS/AmonhenGpg" | awk '/LC_BUILD_VERSION/ { found = 1 } found && $1 == "sdk" { print $2; exit }')
if [ "$built_sdk" != "$(xcrun --sdk macosx --show-sdk-version)" ]; then
    echo "the app records SDK $built_sdk, not $(xcrun --sdk macosx --show-sdk-version)" >&2
    exit 1
fi
# 画面の文字の訳（apps/macos/Sources/AmonhenGpg/Localization.swift は .app なら Resources から読む）。
cp -R apps/macos/Localization/*.lproj "$app/Contents/Resources/"
cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>$name</string>
    <key>CFBundleDisplayName</key><string>$name</string>
    <key>CFBundleIdentifier</key><string>$bundle_id</string>
    <key>CFBundleExecutable</key><string>AmonhenGpg</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleDevelopmentRegion</key><string>en</string>
    <key>CFBundleLocalizations</key><array><string>en</string><string>ja</string></array>
    <key>CFBundleShortVersionString</key><string>$version</string>
    <key>CFBundleVersion</key><string>$build_number</string>
    <key>LSMinimumSystemVersion</key><string>14.4</string>
    <key>NSHighResolutionCapable</key><true/>
    <key>NSPrincipalClass</key><string>NSApplication</string>
</dict>
</plist>
PLIST
scripts/codesign.sh "$app"
codesign --verify --strict "$app"

zip="dist/$(echo "$name" | tr ' ' '-')-$version.zip"
rm -f "$zip"
ditto -c -k --keepParent "$app" "$zip"
# 出力は標準エラーへ（最後の行は zip の場所）。
scripts/notarize.sh "$app" "$zip" >&2
echo "$zip"
