# 開発

[English](../development.md)

ビルド、テスト、画面の確かめ方。設計は [architecture.md](architecture.md) と [ui.md](ui.md) を見てください。

テストも画面の撮影も `~/.gnupg` には触りません。一時的な鍵束を使います。アプリやテストを自分の鍵束に向けないで
ください。

## ビルドとテスト

```sh
cargo test --workspace                      # Rust。結合テストは一時的な --homedir で gpg を動かす
cargo clippy --workspace --all-targets -- -D warnings
scripts/build-core.sh && (cd apps/macos && swift test)
scripts/build-app.sh snapshot               # dist/Amonhen GPG Snapshot.app とその zip
```

`.github/workflows` のワークフローを変えたら、[actionlint](https://github.com/rhysd/actionlint) と
[zizmor](https://docs.zizmor.sh)（`brew install actionlint zizmor`）で確かめます。

```sh
actionlint && zizmor --persona=pedantic .
```

- `scripts/build-core.sh` は Rust のコアを静的ライブラリとしてビルドし、Swift のバインディングを生成します（生成物は
  コミットしません）。
- `scripts/swift-build.sh` は `apps/macos` で `swift build` を実行し、アプリに本当の SDK の版を記録させます（Swift 6.4
  のままでは対応する最低の版が記録され、macOS が昔の見た目で出します）。
- `scripts/build-app.sh [stable|snapshot]` は、`AMONHEN_SIGN_IDENTITY` があればそれで署名し（なければ ad-hoc）、
  App Store Connect の API キーがあれば公証します（`scripts/notarize.sh`）。
- 結合テストは `gpg` がなければ飛ばします。鍵サーバーを使うテストは、`scripts/test-keyserver.sh up`（Podman）で
  手元に鍵サーバーを立て、`AMONHEN_TEST_KEYSERVER=hkp://127.0.0.1:11371` を付けたときだけ動きます。

## 画面を確かめる

```sh
scripts/snapshots.sh [dist/snapshots] [light|dark]
```

デバッグ版をビルドし、サンプルの鍵束（`scripts/sample-keyring.sh`）を作って、3 つの場所とすべてのシートを撮り、
最後にその鍵束の gpg-agent を止めます。本物の窓を開いて `screencapture` で撮るので、初めはスクリプトを動かす
アプリに「画面収録」の許可が要ります。

1 枚だけ撮るとき:

```sh
"$(scripts/swift-build.sh --show-bin-path)/AmonhenGpg" --homedir "$(scripts/sample-keyring.sh)" --snapshot out.png --place mine
```

起動の引数: `--homedir <dir>`、`--gpg <path>`（設定で選んだ gpg より先）、`--keyserver <url>`、`--snapshot <file.png>`（窓を撮って終わる）、
`--place mine|others|staging`、`--sheet extend|create|revoke|certify|details|detailnames|detailkeys|detailsignatures|otherdetails|delete|userids`、
`--stage <file>`（先に鍵のファイルを一時保管に入れる）、`--appearance light|dark`、`--search <text>`（検索欄に入れておく）。
`--place`・`--search`・`--stage`・`--appearance` は `--snapshot` なしでも効く。窓を開いて、ほかの方法で操作して撮るため
（`screencapture` には画面収録の許可が要り、ssh からのセッションにはない）。

## アイコンとバナー

どちらもコードで描いています。スクリプトを直して、もう一度実行します。

```sh
swift scripts/make-icon.swift      # apps/macos/Icons（16・32・64 px を確かめる AppIcon-sizes.png も）
swift scripts/make-banner.swift    # docs/images/banner.png
```

## リリース

CI（`.github/workflows/ci.yml`）は、`main` への push と pull request のたびにテストを流します。ただし、Markdown のファイルか `docs/` だけを変える pull request では流しません（CodeQL も同じ）。`main` では、通ったら署名した
snapshot を作り、`snapshot` の pre-release を置き換えます。`Cargo.toml` と同じ版の `v<版>` のタグを打ち、CI が
通っていれば、ビルドして公証し、承認されたら正式版を出します（`release.yml`）。署名と公証の secret は、環境
`release` に置いてあります。環境 `publish` は secret を持たず承認者を求めるので、Release は誰かが承認してから
作られます。

利用者から見える変更は、`CHANGELOG.md`（英語だけ）の `Unreleased` に書きます。コミットごとではなく、リリースごとに
まとめます。版を出すときは:

1. `CHANGELOG.md` の `## Unreleased` を `## [x.y.z] - YYYY-MM-DD` に改め、そのすぐ下に短い要約の段落があることを
   確かめる。要約は Release の説明になり（`scripts/changelog-notes.sh x.y.z`）、なければリリースが止まる。
2. `Cargo.toml` の `version` を `x.y.z` にし、`main` にマージして CI を待つ。
3. 必要なら、先に署名と公証を確かめる: `main` で Build のワークフローを手で起動する
   （`gh workflow run build.yml --ref main`）。正式版と同じく app を作って署名・公証し、zip を 1 週間、成果物に残す。
   Release は作らない。
4. そのコミットに `vx.y.z` のタグを打って push する。
5. Release のワークフローが Publish で止まったら、その実行から成果物 `app` を落とし、公証した zip を確かめて、
   成果物が残っている 1 週間のうちに承認する（実行の画面の Review deployments）。却下すれば Release は作られない。
   後でやり直すなら、同じ実行の失敗したジョブを流し直す。
