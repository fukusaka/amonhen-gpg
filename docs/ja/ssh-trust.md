# SSH の鍵・ホストの鍵・git の署名者（設計のメモ）

[English](../ssh-trust.md)

2026-11-16 に書いた。問題を整理するためのメモで、決定ではない。アプリは GnuPG の純粋なフロントエンドと定めており、以下の多くはその外にあるので、手を広げるかはまだ決めていない（[未決事項](#未決事項)）。

## 問題

SSH と git で使う鍵と、その鍵への信頼が散らばっていて、全体を見る手段がない。

| | 置き場所 | 何が困るか |
|---|---|---|
| SSH の秘密鍵 | `~/.ssh` のファイル、ssh-agent、macOS のキーチェーン、gpg-agent、スマートカード、パスワード管理ソフト | どの鍵がどこにあり、`SSH_AUTH_SOCK` の先のエージェントがどの鍵を出しているかが分かりにくい |
| SSH の公開鍵 | サーバーの `authorized_keys`、GitHub・GitLab に登録した鍵 | どの秘密鍵の公開鍵で、どこに登録したかを追いにくい |
| ホストの鍵 | `~/.ssh/known_hosts`（ハッシュ化されていることが多い） | 最初の接続でフィンガープリントを照らし合わせずに受け入れがち（TOFU）。ホストの鍵が替わっても古い行が残る |
| git の検証用の公開鍵 | `gpg.ssh.allowedSignersFile` で指す手書きのファイル | 道具がなく、誰の鍵をどう確かめて入れたかの記録も残らない |

## アプリが今していること

すべて gpg-agent を通し、`~/.ssh` には書かない。

- 自分の鍵の認証サブ鍵を gpg-agent が SSH に出していれば、自分の鍵の画面に「SSH ✓ この Mac」と出す。
- 行のメニューで、認証サブ鍵の公開鍵を `authorized_keys` に書く 1 行としてコピー・書き出しする。
- SSH の段で、gpg-agent の SSH サポートを有効にし、OpenPGP の鍵でない SSH の鍵を並べ、それぞれを SSH に出すかを切り替え、既存の秘密鍵のファイル（`~/.ssh`）を `ssh-add` で gpg-agent に取り込む。ファイルは変えない。

gpg-agent の中で足りないところ（今の定めの内。1〜3 はこのメモの後に埋めた。バックアップは残っている）:

1. 自分の鍵を SSH に出すことがアプリからできない（取り込んだ SSH の鍵だけ）。コアには `set_ssh_key_enabled`（`Use-for-ssh`）がもうある。
2. 自分の鍵に認証サブ鍵を足せない。コアには `add_subkey`（`--quick-add-key`）がもうある。
3. 取り込んだ SSH の鍵の、公開鍵のコピー・書き出し、説明（comment）の表示、gpg-agent からの削除、バックアップがない。

## 他の OSS の扱い

2026-11-16 に調べた。出典のあるものは各プロジェクトの文書から、ほかは記憶によるもので確かめていない。

- **Seahorse**（GNOME の「パスワードと鍵」）は、GPG の鍵と並べて `~/.ssh` の SSH の鍵を作る・取り込む・バックアップする。known_hosts を扱う様子はない（[opensource.com](https://opensource.com/article/19/4/ssh-keys-seahorse)、[GNOME Wiki](https://wiki.gnome.org/Apps/Seahorse)）。
- **Kleopatra・GPG Keychain**: GPG（と S/MIME）だけ。確かめていない。
- **Secretive・KeePassXC・1Password**: 秘密鍵を自分で持ち、SSH のエージェントになる。確かめていない。ただし 1Password は SSH での git のコミット署名の設定を案内している（[1Password](https://developer.1password.com/docs/ssh/git-commit-signing)）。
- **ホストの鍵**: GUI は見つからず、`ssh-keyscan`・`ssh-keygen -F`・`ssh-keygen -R` を手で使う。GitHub はホストの鍵とフィンガープリントを `api.github.com/meta`（`ssh_keys`・`ssh_key_fingerprints`）と文書で公開しており、確かめ方は `ssh-keyscan` を `ssh-keygen -lf -` に通して比べる（[GitHub Changelog](https://github.blog/changelog/2022-01-18-githubs-ssh-host-keys-are-now-published-in-the-api/)、[GitHub Docs](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints)）。GitHub は 2023 年に RSA のホストの鍵を替えており、古いフィンガープリントがまだネットに残っているので、決め打ちせず取ってきて比べる（[GitHub Blog](https://github.blog/2023-03-23-we-updated-our-rsa-ssh-host-key/)）。SSH の証明書（known_hosts の `@cert-authority`。step-ca、Teleport）は、ホストごとの鍵を覚えること自体をなくす。確かめていない。
- **git の検証用の公開鍵**: 道具も決まった置き場所もなく、`~/.ssh`・リポジトリの中・コミットして共有するのがどれも慣習。1 行はメールアドレス、`namespaces="git"`、公開鍵（[GitLab Docs](https://docs.gitlab.com/user/project/repository/signed_commits/ssh)、[DEV](https://dev.to/calebhearth/signing-git-commits-with-your-ssh-key-2p4l)）。鍵を集めるのに `https://github.com/名前.keys` を使う例があるが、これはログイン用の鍵で、署名用とは限らない。sigstore の gitsign は、長く使う鍵を持たずに署名して、鍵の一覧をなくす。確かめていない。

まとめると、秘密鍵は持ち主（道具）ごとに分かれ、ホストの鍵と検証用の公開鍵には、信頼を確かめる道具がほとんどない。

## アプリの形に当てはめる

アプリの 3 つの場所と、「フィンガープリントを照らし合わせてから取り込む」決まりは、同じ問題に合う。

| 場所 | 今の GPG | SSH と git |
|---|---|---|
| 自分の鍵 | 自分の鍵を、使えるかどうかで | 自分の SSH の秘密鍵: それぞれがどこにあり、SSH に出ているか、公開鍵をどこに登録したか |
| 他者の鍵 | 確かめた鍵 | 人の SSH の署名鍵とメールアドレス（allowed signers）、ホストの鍵（known_hosts） |
| 一時保管 | 鍵サーバー・WKD・GitHub・GitLab・ファイルから取った鍵 | `ssh-keyscan` で取ったホストの鍵を `api.github.com/meta` や DNS の SSHFP と比べる。GitHub・GitLab から取った人の鍵を持ち主と照らし合わせる |

## 選択肢

1. **GnuPG に留める。** 上の gpg-agent の穴を埋めるだけ。
2. **「自分の鍵と、その信頼」に広げる。** gpg-agent の外の SSH の鍵、known_hosts、allowed signers も扱い、まず読むだけから始める。
3. **ここは 1 にし、SSH と git の信頼は別の道具として考える。**

1 は単独で成り立ち、どの場合にも要る。

### 1 つのアプリか、別のフロントエンドか

別のフロントエンド（3）にする理由:

- 定めがはっきりしたままになる。このアプリは gpg だけを動かし、もう一方は ssh・ssh-keygen・git を動かし、ファイルを読み書きする。
- 信頼の形が違う。GPG には有効性と署名があるが、known_hosts と allowed signers はただの一覧で、どう確かめて入れたかの記録がないので、別の道具がその記録を自分で持つことになる。
- 壊れ方が違う。known_hosts や allowed signers のファイルを壊すと、サーバーに入れなくなったり署名が検証できなくなったりするので、別の注意が要る。

1 つのアプリ（2）にする理由:

- 自分の鍵が 1 つの一覧になる。分けると、gpg-agent が持つ SSH の鍵が両方のアプリに出る。
- 一時保管とフィンガープリントの照合を 2 回作らずに済む。

中間の道: SSH と git の側は別のフロントエンドとして設計し、Rust のコードは共有する（このリポジトリの別の crate にし、`amonhen_gpg_core::process::command` と同じ一時保管の考え方を使う）。gpg-agent の SSH の鍵は二重に管理せず、このアプリのコアから読む。2 つめのアプリにするか、このアプリの 1 つの場所にするかは、その後で決められる。

## 広げるなら

- **書く前に読む。** まず、鍵がどこにあるか、known_hosts の古い行や重複、allowed signers のファイルの中身を見せる。
- **利用者のファイルを直接書き換えない。** アプリが持つファイルを作って利用者に指してもらう（`git config gpg.ssh.allowedSignersFile`、ssh の `UserKnownHostsFile`）ことを優先し、利用者のファイルの書き換えは道具（`ssh-keygen -R`）に任せる。
- **ssh-agent やパスワード管理ソフトの鍵は扱わない。** 見せるだけにする。鍵は持っている道具のもの。
- **GPG と同じ決まりを守る。** 鍵は完全なフィンガープリントで指し、パスフレーズはその道具自身の画面だけで聞き、子プロセスは `amonhen_gpg_core::process::command` で起動し、テストは一時的なディレクトリだけで行う（利用者の `~/.ssh` には触らない）。

## 未決事項

- アプリを GnuPG の純粋なフロントエンドのままにするか（1・3）、広げるか（2）。
- 広げるなら、アプリが持つファイルを何にし、どこに置き、ssh と git にどう指してもらうか。
- GitHub から取るとき、署名用の鍵とログイン用の鍵をどう分けるか（API は署名用の鍵を別に返すが、`.keys` は分けない）。
- ハッシュ化された known_hosts の行を、意味のある形で見せられるか（利用者が入れたホスト名と照らし合わせるしかない）。
