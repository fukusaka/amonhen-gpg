# GPG GUI 調査

調査日: 2026-11-11。各ツールの公式サイト・ドキュメントをもとにまとめた。
未読: Kleopatra / KGpg のハンドブック、GpgFrontend の詳細ガイド（鍵生成・スマートカード・失効など）、GPG Keychain FAQ の記事本文。そのため一部の項目は「不明」のまま。

## 全体比較

| | GPG Suite (Keychain) | Kleopatra | GpgFrontend | Seahorse | KGpg | gpg-tui |
|---|---|---|---|---|---|---|
| 対応 OS | macOS | Windows (Gpg4win), Linux | Win / Mac / Linux | Linux (GNOME) | Linux (KDE) | ターミナル |
| 最新版 | 安定版の番号は不明 | 26.08.3 (2026-11-05)、Gpg4win 5.1.1 (2026-09-23) | v2.2.x 系 | 不明 | 26.08.3 (2026-11-05) | 不明 |
| 扱う範囲 | 鍵管理と OS・メール連携 | 鍵管理、暗号操作、スマートカード | 鍵管理、暗号操作、メール | 鍵とパスワードの一元管理 | 鍵管理 | 鍵管理のみ |
| 中身 | MacGPG (GnuPG) | GnuPG | GnuPG と Rust rPGP を切り替え可能。C++/Qt | GNOME Keyring | GnuPG | Rust と GPGME、足りない操作は gpg CLI |
| ファイル・テキストの暗号化 | Services メニューから | ファイル操作と Notepad | File Panel と Text Editor | 不明 | 不明 | 非対応 |
| スマートカード | FAQ 記事のみ | 非常に充実 (OpenPGP / PIV、YubiKey) | 秘密鍵をカードへ移せる | 不明 | 不明 | 不明 |
| 料金 | GPG Mail は有料 (年額サブスクへ移行中) | 無料 | 無料 (GPLv3) | 無料 | 無料 | 無料 (MIT) |

## ツール別

### GPG Suite / GPG Keychain (macOS)

- **画面:** 鍵の一覧が 1 つあるだけのシンプルな構成。ツールバーに新規作成・インポート・エクスポート・検索があり、「秘密鍵のみ表示」のチェックボックスがある。
- **鍵の生成:** 名前とメールアドレスを入れるだけで作れる。鍵長・有効期限・アルゴリズムは詳細表示で設定する。生成時に鍵サーバーへのアップロードも選べる。
- **右クリックメニュー:** 鍵サーバーへの送信、鍵の更新、鍵の詳細の管理。
- **暗号化:** アプリ自体には暗号化の画面がない。macOS の Services メニュー（GPG Services）を使い、どのアプリのテキスト・ファイル・フォルダにも暗号化・署名をかけられる。
- **GPG Mail:** Apple Mail の拡張。作成画面に暗号化と署名のボタンが加わり、受信メールには「Security:」ヘッダーが表示される。有料で、年額サブスクに移行中。
- **強み:** 既定値が良く、数クリックで済む手軽さ。
- **弱み:** 信頼度・有効性の表示、鍵への署名、WKD に対応している記述は見つからなかった。

### Kleopatra (KDE / Gpg4win)

- **扱えるもの:** OpenPGP と S/MIME (X.509) の両方。
- **鍵の取得と公開:** 鍵サーバー、LDAP、WKD での検索とアップロード。
- **鍵の信頼度と有効期限:** どちらも設定できる。
- **スマートカード (OpenPGP / PIV):**
  - PIN と PUK の変更
  - カード保有者情報の変更
  - カード上での鍵生成
  - 既存の秘密鍵のカードへのコピー
  - SSH 認証用の鍵の作成
  - YubiKey / Gnuk は追加ドライバーなしで使える
- **テキスト:** Notepad 画面でテキストを暗号化・復号・検証できる。
- **ファイルマネージャー連携:** Dolphin や Explorer から直接ファイルを暗号化できる。
- **評価:** 機能が最も網羅的で、「全部入り」の代表。

### GpgFrontend (クロスプラットフォーム)

UI の構成が最もはっきり文書化されている。

```
┌ ツールバー (File / Operations / Keys) ──────────────┐
│ ワークスペース (タブ)           │ Key ToolBox       │
│  ・File Panel (一括処理)       │  Type/Usage/Email │
│  ・Text Editor                │  /Status/期限     │
│  ・Mail Editor (EML)          │                   │
├ ステータスパネル (操作結果レポート) ──────────────────┤
└ ステータスバー ─────────────────────────────────────┘
```

- **鍵一覧の表示:**
  - 種別: `pub`、`pub/sec`、`pub/sec^`（カード上の鍵）、`group`
  - 用途: C/E/S/A
  - 状態: OK / 期限間近 / 期限切れ / 失効 / 無効
- **右クリックメニュー:** 所有者の信頼度設定、カテゴリへの追加、鍵の詳細表示。
- **鍵の生成:** New Keypair ボタンの右クリックまたは長押しでクイック生成。
- **鍵サーバー:** KeyServerSync モジュールで公開と更新。
- **操作の結果:** 毎回「SECURITY OPERATION REPORT」としてまとめて表示する。
- **Text Editor:** UTF-8 のプレーンテキストで、上限は 4 MB。
- **その他の機能:** USB で持ち運べるポータブルモード、プロファイル、複数の鍵データベース、耐量子暗号 (ML-KEM / ML-DSA / SLH-DSA)、モジュールによる拡張。

### Seahorse (GNOME)

- **扱えるもの:** PGP 鍵・SSH 鍵・パスワードをまとめて管理する。
- **主な機能:** 鍵サーバーとの同期、鍵への署名と公開、パスフレーズのキャッシュ、バックアップ、フォト ID の追加。
- **状況:** 旧 wiki は閉鎖されており、まとまった最新ドキュメントは見つからなかった。

### KGpg (KDE)

- **扱えるもの:** 鍵の管理、インポートとエクスポート、署名・信頼度・有効期限の確認。
- **位置づけ:** 「シンプル」を前面に出した軽量なツール。

### gpg-tui (ターミナル)

- **操作:** vim 風の 1 文字キー。`g` 生成、`i` インポート、`x` エクスポート、`s` 署名、`e` 編集、`f` 受信、`u` 送信、`d` 削除。
- **表示:** 信頼度は `[q] [n] [m] [f] [u] [?]`、失効は `[rev]`、有効期限は `(Y-m-d)`。
- **シェル連携:** `--select` で選んだ鍵 ID を出力できる。例: `gpg -e -r $(gpg-tui --select key-id)`
- **範囲:** 鍵管理に特化しており、gpg の全機能を網羅するつもりはないと明言している。

## 新しい GPG GUI を作るときの示唆

1. **鍵一覧がホーム画面になる。** どのツールもそうしている。GpgFrontend の「種別・用途・状態」の列は情報が詰まっていて分かりやすい見本。
2. **信頼度と有効性の見せ方が差の出やすい点。** GPG Suite は簡素すぎ、gpg-tui は記号ばかりで初心者には読みにくいので、改善の余地がある。
3. **暗号化の入り口は 3 つある。** OS 連携 (GPG Suite)、専用のワークスペース (GpgFrontend、Kleopatra)、クリップボード。macOS 向けなら Services 連携は外せない。
4. **スマートカード対応は Kleopatra が最も成熟している。** YubiKey 利用者は多いので、参考にする価値がある。
5. **操作結果を 1 か所にまとめて報告する** GpgFrontend の方式は、検証結果のように誤解しやすい情報を伝えるのに向いている。

## 出典

- [KDE Apps: Kleopatra](https://apps.kde.org/kleopatra/)
- [Gpg4win](https://www.gpg4win.org/)
- [GPGTools](https://gpgtools.org/)
- [GPG Keychain FAQ](https://gpgtools.tenderapp.com/kb/gpg-keychain-faq)
- [GpgFrontend](https://www.gpgfrontend.bktus.com/)
- [GpgFrontend: Understand Interface](https://www.gpgfrontend.bktus.com/guides/understand-interface/)
- [GpgFrontend GitHub](https://github.com/saturneric/GpgFrontend)
- [Seahorse wiki (アーカイブ)](https://wiki.gnome.org/Apps/Seahorse)
- [Seahorse GitLab](https://gitlab.gnome.org/GNOME/seahorse)
- [KDE Apps: KGpg](https://apps.kde.org/kgpg/)
- [gpg-tui GitHub](https://github.com/orhun/gpg-tui)
- [Help Net Security: GUI frontends for GnuPG](https://www.helpnetsecurity.com/2025/01/24/gnupg-gui-frontends/)
