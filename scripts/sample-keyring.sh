#!/bin/bash
# 画面の確認用の鍵束を一時ディレクトリに作り、その場所を表示する。利用者の鍵束には触らない。
# 使い方: (cd apps/macos && .build/debug/AmonhenGpg --homedir "$(../../scripts/sample-keyring.sh)" --snapshot out.png)
# 終わったら gpgconf --homedir <場所> --kill all で gpg-agent を止め、ディレクトリを消す。
set -eu
H=$(mktemp -d)
O=$(mktemp -d)
for d in "$H" "$O"; do
  : > "$d/empty"
  printf 'pinentry-mode loopback\npassphrase-file %s\n' "$d/empty" > "$d/gpg.conf"
done
g() { gpg --homedir "$H" --batch --no-tty "$@" >/dev/null 2>&1; }
o() { gpg --homedir "$O" --batch --no-tty "$@" 2>/dev/null; }
fpr() { gpg --homedir "$H" --batch --no-tty --with-colons --list-keys "$1" 2>/dev/null | awk -F: '/^fpr/{print $10; exit}'; }
# 使える鍵: 署名・証明の主鍵、暗号化と認証のサブ鍵（SSH に出す）、期限は 20 日後
g --quick-gen-key 'Alice Example <alice@example.com>' ed25519 cert,sign 20d
A=$(fpr alice@example.com)
g --quick-add-key "$A" cv25519 encr 20d
g --quick-add-key "$A" ed25519 auth 20d
AUTH=$(gpg --homedir "$H" --batch --no-tty --with-colons --with-keygrip --list-keys "$A" 2>/dev/null | awk -F: '/^sub/{s=$12} /^grp/{if(s=="a")print $10}' | tail -1)
gpg-connect-agent --homedir "$H" "KEYATTR $AUTH Use-for-ssh: true" /bye >/dev/null
# 秘密鍵は別の PC にある自分の鍵
g --quick-gen-key 'Alice Home <alice@home.example>' ed25519 default never
B=$(fpr alice@home.example)
g --yes --delete-secret-keys "$B"
# 使えた鍵: 期限切れ（昔の時刻で作る）と失効
g --faked-system-time 20190301T000000! --quick-gen-key 'Alice 2019 <alice@old.example>' ed25519 default 2y
C=$(fpr alice@old.example)
g --quick-gen-key 'Alice Work 2021 <alice@work.example>' ed25519 default never
D=$(fpr alice@work.example)
printf 'revkey\ny\n2\n\ny\nsave\n' | g --command-fd 0 --edit-key "$D"
# 他者の鍵: 署名して確認済みにしたものと、未確認のもの
o --quick-gen-key 'Bob Builder <bob@example.org>' ed25519 default never
o --quick-gen-key 'Carol <carol@example.net>' ed25519 default never
# Bob の鍵には、手元にない人（Dave）の署名も付けておく（詳細の「ほかに何人の署名」）
o --quick-gen-key 'Dave <dave@example.com>' ed25519 default never
o --local-user dave@example.com --quick-sign-key "$(gpg --homedir "$O" --with-colons --list-keys bob@example.org 2>/dev/null | awk -F: '/^fpr/{print $10; exit}')" >/dev/null
gpg --homedir "$O" --batch --no-tty --export bob@example.org carol@example.net 2>/dev/null | g --import
BOB=$(fpr bob@example.org)
g --local-user "$A" --quick-lsign-key "$BOB"
gpgconf --homedir "$O" --kill all
rm -r "$O"
echo "$H"
