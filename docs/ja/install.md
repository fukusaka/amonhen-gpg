# インストール

[English](../install.md)

配っているものは、すべて [Releases](https://github.com/fukusaka/amonhen-gpg/releases) にあります。リリースは 2 種類です。

- **正式版**: タグは `v<版>`。最新のものに Latest の印が付きます。
- **snapshot**: 開発中の最新版。テストが通るたびに作り直します。

> [!NOTE]
> 正式版は公証してあり、macOS で警告なしに開けます。snapshot は署名してありますが、公証していません。下のスクリプトで
> 入れるか、取ってきたあとに一度だけシステム設定の「プライバシーとセキュリティ」で許可してください。

## GnuPG

アプリはフロントエンドなので、GnuPG 2.4.1 以降と、画面を出せる pinentry が要ります（gpg が古ければ、アプリは一覧の上に警告を出します）。
[Homebrew](https://brew.sh) なら:

```sh
brew install gnupg pinentry-mac
```

[GPG Suite](https://gpgtools.org) や MacGPG2 でも使えます。アプリは `gpg` を `PATH`、Homebrew、GPG Suite の場所から
探し（設定 ⌘, で選んだものがあればそれを使い）、ふだんの鍵束（`~/.gnupg`）を開きます。パスフレーズの画面を出せないときは、`gpg-agent.conf` に足す
`pinentry-program` の行を示します。

## アプリ（macOS）

1. `Amonhen-GPG-<版>.zip`（snapshot は `Amonhen-GPG-Snapshot-<版>.zip`）を取ってきます。
2. 展開して、`Amonhen GPG.app` を `/Applications` に移します。snapshot は `Amonhen GPG Snapshot.app` という名前なので、
   両方を並べて置けます。
3. 開きます。

## 1 行で入れる・新しくする

最新のリリースを探して取ってきて、入れます（入っていれば置き換えます）。要るのは `curl` だけです。

```sh
curl -fsSL https://raw.githubusercontent.com/fukusaka/amonhen-gpg/main/scripts/install-app.sh | sh -s -- stable
```

`stable` を `snapshot` にすると、開発中の最新版が入ります。新しくするときも同じ行を実行します。アプリを
開いたまま新しくすると、スクリプトがそう知らせ、次に開いたときから新しい版になります。この方法で取ってきたアプリには
quarantine の印が付かないので、macOS は確かめずに開きます。

入れる先は `/Applications` です。`--user`（`sh -s -- --user stable`）を付けると自分のアプリケーションフォルダ
（`~/Applications`）に、`--system` は `/Applications` に、`--dir <フォルダ>` は好きなフォルダ（なければ作る）に
入れます。どれも付けなければ、今入っているところを新しくします。

リポジトリを clone してあれば、`scripts/install-app.sh` をそのまま実行できます。

## 取ってきたものを確かめる

Release に載せたファイルには、このリポジトリの CI がどのコミットから作ったかを示す証明（attestation）が付いています。
[GitHub CLI](https://cli.github.com/) で確かめられます。

```sh
gh attestation verify <ファイル> --repo fukusaka/amonhen-gpg
```

## 動く環境

- macOS 14.4 以降、Apple シリコン。
- GnuPG 2.4.1 以降と、画面を出せる pinentry（pinentry-mac）。
