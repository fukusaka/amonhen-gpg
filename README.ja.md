<h1><img src="docs/images/banner.png" alt="Amonhen GPG"></h1>

[![CI](https://github.com/fukusaka/amonhen-gpg/actions/workflows/ci.yml/badge.svg)](https://github.com/fukusaka/amonhen-gpg/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/fukusaka/amonhen-gpg)](https://github.com/fukusaka/amonhen-gpg/releases/latest)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#ライセンス)

[English](README.md)

自分の鍵を、使える状態で失わずに持ち続けるための GnuPG のフロントエンド。自分の鍵のどれで署名・復号・ログインが
できるか、それがどこにあるか（この Mac かスマートカードか）を示し、期限が切れる前や失いそうなときに知らせます。

![Amonhen GPG の「自分の鍵」。あと 19 日で期限が切れ、バックアップのない使える鍵、秘密鍵が別のマシンにある鍵、使えた鍵](docs/images/my-keys.png)

## できること

- **自分の鍵が主役** — 自分の鍵を「使える」「この Mac では使えない」「使えた鍵」に分けて並べます。鍵ごとに、署名・
  復号・認証ができるか、どこでできるかを出します。
- **失わない** — バックアップや失効証明書のない鍵、期限が近い鍵を知らせます。鍵とサブ鍵の期限をまとめて延ばせます。
  秘密鍵を消すときは、先にバックアップを求め、フィンガープリントの最後の桁を打ってもらいます。
- **名前とメールアドレス** — 鍵の名前とメールアドレスを足す・主にする・失効させる。パスフレーズを変える。鍵を失効させ、
  鍵サーバーに送ってほかの人に知らせる。
- **他者の鍵** — 持ち主とフィンガープリントを照らし合わせてから確認済みにし、誰が確認したかを見られます。メールアドレス
  （WKD か keys.openpgp.org）やフィンガープリントで探した鍵、GitHub・GitLab の利用者が公開している鍵は、取り込むまで
  一時保管の鍵束に置きます。
- **SSH** — 認証用のサブ鍵を gpg-agent 経由で SSH に使う。SSH サポートを有効にする。既存の SSH の鍵を取り込む。
  `authorized_keys` に書く公開鍵をコピーする。
- **純粋なフロントエンド** — 暗号の処理はすべて GnuPG が行います。パスフレーズは pinentry が聞き、アプリは触れません。

> [!WARNING]
> 開発の途中です。機能は予告なく変わることがあります。保証はありません。秘密鍵のバックアップは取っておいてください。

## インストール

Mac（macOS 14.4 以降、Apple シリコン）で、GnuPG 2.4.6 以降（`brew install gnupg pinentry-mac`）を入れたうえで:

```sh
curl -fsSL https://raw.githubusercontent.com/fukusaka/amonhen-gpg/main/scripts/install-app.sh | sh -s -- stable
```

[最新の正式版](https://github.com/fukusaka/amonhen-gpg/releases/latest)を `Amonhen GPG.app` として
`/Applications` に入れます。新しくするときも同じ行を実行します。手で取ってくる方法、開発中の snapshot、ほかの
フォルダに入れる方法、取ってきたものの確かめ方は、[インストール](docs/ja/install.md)を見てください。

## 文書

- [インストール](docs/ja/install.md)
- [画面の方針](docs/ja/ui.md): それぞれの場所に何を出すか、アプリで何ができるか
- [アーキテクチャ](docs/ja/architecture.md): Rust のコア、バインディング、gpg の動かし方
- [GPG の GUI の調査](docs/ja/gpg-gui-survey.md)
- [SSH の鍵・ホストの鍵・git の署名者](docs/ja/ssh-trust.md): 設計のメモ（git の allowed signers を扱うと決めた）
- [git の allowed signers](docs/ja/allowed-signers.md): 設計（まだ作っていない）
- [開発](docs/ja/development.md): ビルド、テスト、画面の確かめ方

## ライセンス

[MIT](LICENSE-MIT) か [Apache License 2.0](LICENSE-APACHE) の、好きな方で。
