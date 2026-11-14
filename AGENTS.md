# amonhen-gpgui

Amonhen GPG: GnuPG の純粋なフロントエンド（自分の GPG・SSH の鍵の管理）。

- コア: Rust
- FE: SwiftUI（macOS）
- 設計: `docs/architecture.md`
- 画面: `docs/ui.md`
- 開発の手順: `docs/development.md`

## 決まり

- 利用者の `~/.gnupg` に触らない。開発・テスト・撮影は一時的な `--homedir` だけで。
- 鍵は完全なフィンガープリントで指す。パスフレーズは扱わない（pinentry に任せる）。
- 子プロセスは `amonhen_gpg_core::process::command` で起動する。
- コミットは機能ごとに分け、それぞれでビルドとテストを通す。
- push・リリース・設定の変更は確かめてから。大事な決定は推測で進めない。
- 文書は英語が正で、日本語版を `README.ja.md`・`docs/ja/` に置き、両方を直す。

## 確認

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
scripts/build-core.sh && (cd apps/macos && swift test)
scripts/snapshots.sh                    # 画面を撮る
actionlint && zizmor --persona=pedantic .   # ワークフローを変えたとき
```
