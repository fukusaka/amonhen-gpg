#!/bin/sh
# 手元で Amonhen GPG.app を作る（Rust のコア → Swift のリリースビルド → 組み立てと署名）。
#   scripts/build-app.sh
# 出力: dist/Amonhen GPG.app（最後の行にその場所）。
# 署名: AMONHEN_SIGN_IDENTITY にキーチェーンの証明書の名前があればそれで、なければ ad-hoc。
# gpg は入っていない。アプリは PATH と Homebrew・GPG Suite の場所から探す（GpgProgram.locate）。
set -eu
cd "$(dirname "$0")/.."
name="Amonhen GPG"
bundle_id="io.github.fukusaka.amonhen.gpg"
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)

scripts/build-core.sh >&2
(cd apps/macos && swift build -c release --product AmonhenGpg >&2)
bin=$(cd apps/macos && swift build -c release --show-bin-path)/AmonhenGpg

app="dist/$name.app"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$bin" "$app/Contents/MacOS/AmonhenGpg"
# ほかの Mac でも動くよう、OS のもの以外のライブラリを指していないか確かめる。
if otool -L "$app/Contents/MacOS/AmonhenGpg" | tail -n +2 | grep -vE '^[[:space:]]+(/System/Library/|/usr/lib/)'; then
    echo "the app links libraries outside the system (above)" >&2
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
    <key>CFBundleVersion</key><string>$version</string>
    <key>LSMinimumSystemVersion</key><string>14.4</string>
    <key>NSHighResolutionCapable</key><true/>
    <key>NSPrincipalClass</key><string>NSApplication</string>
</dict>
</plist>
PLIST
identity=${AMONHEN_SIGN_IDENTITY:--}
case $identity in
"Developer ID Application"*) codesign --force --sign "$identity" --options runtime --timestamp "$app" ;;
*) codesign --force --sign "$identity" --timestamp=none "$app" ;;
esac
codesign --verify --strict "$app"
echo "$app"
