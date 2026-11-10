# amonhen-gpgui アーキテクチャ（初版）

## 要件

- GnuPG の**純粋なフロントエンド**とする。暗号処理・鍵の保管は GnuPG が行い、本アプリは独自に暗号を実装しない。
- 最初のスコープは**鍵管理**に限る。暗号化・復号・署名・検証は後回し。
- **UI と BE (core) を完全に分離する。**
- core は Rust で書き、堅牢にする。
- UI は SwiftUI (macOS) / GTK4 (Linux) / WinUI 3 (Windows) を想定する。
- **GPG 鍵と SSH 鍵**を扱う。

## 全体構成

```
┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│  SwiftUI    │ │   GTK4      │ │  WinUI 3    │   UI: 表示と入力だけ
│  (Swift)    │ │  (Rust)     │ │  (C#)       │
└──────┬──────┘ └──────┬──────┘ └──────┬──────┘
       │ UniFFI        │ Rust API      │ UniFFI (C#)
┌──────┴───────────────┴───────────────┴──────┐
│ amonhen-ffi    バインディング層 (薄い)          │
├─────────────────────────────────────────────┤
│ amonhen-core   ドメインモデル / ユースケース      │
│                gpg エンジン (プロセス実行・解析)  │
└──────┬───────────────────────┬──────────────┘
       │ gpg / gpgconf          │ Assuan (gpg-connect-agent)
┌──────┴───────────────────────┴──────────────┐
│ GnuPG  (gpg, gpg-agent, pinentry, scdaemon)  │
└─────────────────────────────────────────────┘
```

### 分離のルール

- UI は core の公開 API（ユースケースとデータ型）しか知らない。gpg コマンドや colon 形式は UI に一切漏らさない。
- core は UI を知らない。表示文言・ローカライズは UI 側の責務とし、core はエラーを**種別コード＋構造化データ**で返す。
- 3 つの UI は同じ API 境界を通る。GTK4 版は Rust なので core を直接リンクできるが、その場合も `amonhen-ffi` と同じ公開 API だけを使う。
- API は「コマンド → 結果」の形に揃え、データ型はすべてシリアライズ可能にする。将来、core を別プロセス化（IPC）したくなっても API を変えずに移せる。

## core の設計

### GnuPG との接続方式（決定: gpg CLI を直接駆動）

| 方式 | 長所 | 短所 |
|---|---|---|
| **gpg CLI + `--with-colons` / `--status-fd`**（採用） | 依存が GnuPG 本体だけ。Rust だけで書けて 3 OS でビルドしやすい。GPGME 自身も内部で gpg を呼んでいる | 出力の解析を自前で持つ必要がある |
| GPGME（`gpgme` crate） | 公式の高水準 API | C ライブラリへの依存。特に Windows でのビルド・配布が重い。鍵編集は結局 edit-key 対話になる |
| `gpgme-json` | JSON で操作できる | ブラウザ拡張向けの Native Messaging サーバー。操作は keylist / createkey / import / export / delete と暗号操作のみで、有効期限・UID・サブ鍵・署名・信頼・失効・鍵サーバー・SSH を扱えない |
| Sequoia / rPGP 等 | Pure Rust | GnuPG の FE ではなくなる（要件外） |

gpg 本体には JSON / XML 出力がなく、GnuPG プロジェクトは `--with-colons` と status 行を機械向けインターフェースとしている。「純粋な FE」と「Rust で堅牢に」を両立するには CLI 直接駆動が最も素直。gpg の呼び出し部分は core 内で差し替え可能にしておき、将来暗号操作や S/MIME へ広げる際に GPGME への移行も検討できるようにする。

### パスフレーズを扱わない

パスフレーズの入力は gpg-agent が呼ぶ **pinentry** に任せる。本アプリのプロセスはパスフレーズ・秘密鍵の素材に一切触れない。これは「純粋な FE」の最大の利点で、セキュリティ上の境界にもなる。

### 堅牢性のための方針

- `#![forbid(unsafe_code)]`（FFI 層を除く）。
- gpg は常に `--batch --no-tty --with-colons --fixed-list-mode --status-fd` で起動し、`LC_ALL=C` を固定する。人間向け出力は解析しない。
- シェルを経由せず引数配列で起動する。ユーザー入力（UID・ファイル名）は検証し、オプションとの間に `--` を入れる。鍵の指定は常に完全なフィンガープリントで行う。
- 結果の判定は終了コードではなく **status 行**（`KEY_CREATED`, `IMPORT_OK`, `IMPORT_RES`, `ERROR`, `FAILURE` など）で行う。
- タイムアウトとキャンセルに対応する（pinentry 待ちは長時間になり得る）。
- 起動時に `gpgconf --list-dirs` / `gpg --version` で環境と最低バージョン（2.2 以上、推奨 2.4 以上）を確認する。
- テスト:
  - colon / status パーサーは単体テストとファズテスト。
  - 一時ディレクトリの `GNUPGHOME` と loopback pinentry を使い、実際の gpg に対する結合テスト。

### モジュール構成（案）

```
crates/
  amonhen-core/
    src/
      model/        Key, Subkey, UserId, Validity, Capability, SshKey ...
      gpg/          プロセス実行, colon パーサー, status パーサー
      agent/        gpg-agent との Assuan 通信 (SSH 鍵, keygrip)
      usecase/      list, generate, import, export, ... (UI に公開する API)
      error.rs      構造化エラー
  amonhen-ffi/      UniFFI 定義 (Swift / C# 向け)
apps/
  macos/            SwiftUI
  gtk/              GTK4 (gtk4-rs)
  windows/          WinUI 3 (C#)
```

### バインディング

- Swift: UniFFI（公式で対応）。
- C#: UniFFI のサードパーティ生成器 `uniffi-bindgen-cs`。成熟度に不安があれば、cbindgen による C ABI と P/Invoke に切り替える。
- GTK4: Rust（gtk4-rs）で書けば FFI 不要。

## 鍵管理の機能範囲（第 1 段階）

### GPG 鍵

| 機能 | gpg での実現 |
|---|---|
| 一覧・詳細（公開鍵 / 秘密鍵、サブ鍵、UID、有効性、所有者信頼、有効期限、用途 C/S/E/A、カード上の鍵） | `--list-keys` / `--list-secret-keys --with-colons --with-keygrip` |
| 生成 | `--quick-gen-key`、サブ鍵は `--quick-add-key` |
| インポート / エクスポート（公開鍵、秘密鍵、失効証明書） | `--import` / `--export` / `--export-secret-keys` |
| 有効期限の変更 | `--quick-set-expire` |
| UID の追加・失効・主 UID の設定 | `--quick-add-uid` / `--quick-revoke-uid` / `--quick-set-primary-uid` |
| 鍵への署名 | `--quick-sign-key` / `--quick-lsign-key` |
| 所有者信頼の設定 | `--edit-key` を `--command-fd` で対話駆動（quick 系コマンドがない操作は同様に扱う） |
| 失効 | 失効証明書（`openpgp-revocs.d`）のインポート |
| 削除 | `--delete-secret-and-public-key`（フィンガープリント指定） |
| 鍵サーバー / WKD | `--receive-keys` / `--send-keys` / `--locate-keys` |
| パスフレーズ変更 | `--passwd`（入力は pinentry） |

### SSH 鍵（gpg-agent 経由）

「純粋な FE」として、SSH 鍵も **gpg-agent が管理するもの**を対象にする。

| 機能 | 実現方法 |
|---|---|
| gpg-agent の SSH サポートの状態確認 | `gpgconf` で `enable-ssh-support` を確認し、SSH_AUTH_SOCK を案内する |
| SSH 鍵の一覧 | Assuan の `KEYINFO --ssh-list --ssh-fpr` |
| GPG の認証 (A) サブ鍵を SSH 鍵として使う | `--quick-add-key <FPR> ed25519 auth` で作成し、keygrip を `sshcontrol` に登録 |
| SSH 公開鍵の出力（authorized_keys 用） | `gpg --export-ssh-key` |
| 既存の SSH 秘密鍵の取り込み | `ssh-add` で gpg-agent に登録（パスフレーズは pinentry） |
| 有効化 / 無効化・確認要求の設定 | `sshcontrol` ファイルの編集 |

## 未決事項

1. **SSH 鍵の範囲:** `~/.ssh/` の鍵ファイルや OpenSSH の ssh-agent まで扱うか、gpg-agent 管理の鍵だけにするか。本案は後者。
2. **Windows の SSH:** Win32-OpenSSH と連携するには gpg-agent の `enable-win32-openssh-support` が必要。GnuPG のバージョンごとの対応状況を確認する。
3. **スマートカード:** 第 1 段階に含めるか。表示（カード上の鍵の識別）だけは最初から対応しておく。
4. **macOS の配布:** App Sandbox 下では `~/.gnupg` へのアクセスや gpg の起動が制限される。App Store 外で配布（Developer ID + Notarization）する前提にするか。
5. **GnuPG の同梱:** GnuPG をアプリに同梱するか、既存のインストール（Homebrew、GPG Suite、Gpg4win、ディストリのパッケージ）を使うか。
6. **最低バージョン:** 2.2 系を切って 2.4 以上に絞るか。
