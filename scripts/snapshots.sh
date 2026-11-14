#!/bin/sh
# 見た目の確認用に、サンプルの鍵束（scripts/sample-keyring.sh）ですべての画面とシートを撮る。利用者の鍵束には触らない。
#   scripts/snapshots.sh [出力先（既定 dist/snapshots）] [light|dark（既定はシステムの設定）]
# 出力: <出力先>/<画面>.png・sheet-<シート>.png（1 行に 1 つ、その場所）。
# 本物の窓を開いて撮る（AmonhenGpg --snapshot）ので、撮る間は窓が出る。初めは、起動したアプリ（端末など）に
# 「画面収録」の許可が要る。
set -eu
cd "$(dirname "$0")/.."
out=${1:-dist/snapshots}
appearance=${2:-}
scripts/build-core.sh >&2
scripts/swift-build.sh --product AmonhenGpg >&2
bin=$(scripts/swift-build.sh --show-bin-path)/AmonhenGpg
home=$(scripts/sample-keyring.sh)
trap 'gpgconf --homedir "$home" --kill all; rm -rf "$home"' EXIT
mkdir -p "$out"
# 一時保管に入れる鍵のファイル
stage="$home/stage.asc"
gpg --homedir "$home" --batch --armor --export carol@example.net > "$stage" 2>/dev/null
shoot() {
    name=$1
    shift
    "$bin" --homedir "$home" ${appearance:+--appearance "$appearance"} --snapshot "$out/$name.png" "$@"
    echo "$out/$name.png"
}
shoot mine --place mine
shoot others --place others
shoot staging --place staging --stage "$stage"
for sheet in extend create revoke certify details otherdetails delete userids; do
    shoot "sheet-$sheet" --sheet "$sheet"
done
