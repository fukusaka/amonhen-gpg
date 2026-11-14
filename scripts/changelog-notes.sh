#!/bin/sh
# CHANGELOG.md から、ある版の要約を取り出す（GitHub の Release の説明に使う）。
#   scripts/changelog-notes.sh <版>     例: 0.1.0
# ## [<版>] の見出しのすぐ下の段落（最初の ### の前まで）と、CHANGELOG 全体へのリンク。
# 要約がなければ失敗する（CHANGELOG を直し忘れたまま出さない）。
set -eu
cd "$(dirname "$0")/.."
summary=$(awk -v heading="## [$1]" '
    /^## / { in_version = (index($0, heading) == 1); next }
    in_version && /^### / { in_version = 0 }
    in_version { print }
' CHANGELOG.md | sed -e '/./,$!d')
if [ -z "$(echo "$summary" | tr -d '[:space:]')" ]; then
    echo "CHANGELOG.md の [$1] に要約がない（見出しのすぐ下に短い段落を書く）" >&2
    exit 1
fi
# CHANGELOG は行を折り返して書くので、段落ごとに 1 行にする（GitHub の説明は改行をそのまま改行にする）。
printf '%s\n' "$summary" | awk 'BEGIN { RS = ""; ORS = "\n\n" } { gsub(/\n/, " "); print }'
echo "All changes: https://github.com/fukusaka/amonhen-gpg/blob/main/CHANGELOG.md"
