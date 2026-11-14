#!/bin/sh
# Apple の公証（notarization）に出し、結果をアプリに綴じ込んで zip を作り直す。Developer ID で署名したものだけが通る。
#   scripts/notarize.sh <app> <app の zip>
# 鍵は App Store Connect の API キー: AMONHEN_NOTARY_KEY（.p8 の中身を base64）・AMONHEN_NOTARY_KEY_ID・
# AMONHEN_NOTARY_ISSUER。どれかがなければ何もしない。
set -eu
app=$1 zip=$2
if [ -z "${AMONHEN_NOTARY_KEY:-}" ] || [ -z "${AMONHEN_NOTARY_KEY_ID:-}" ] || [ -z "${AMONHEN_NOTARY_ISSUER:-}" ]; then
    echo "公証の鍵がないので、公証しない"
    exit 0
fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
echo "$AMONHEN_NOTARY_KEY" | base64 --decode > "$work/key.p8"
xcrun notarytool submit "$zip" --key "$work/key.p8" --key-id "$AMONHEN_NOTARY_KEY_ID" \
    --issuer "$AMONHEN_NOTARY_ISSUER" --wait --timeout 30m
xcrun stapler staple "$app"
xcrun stapler validate "$app"
rm -f "$zip"
ditto -c -k --keepParent "$app" "$zip"
