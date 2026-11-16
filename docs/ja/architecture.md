# amonhen-gpgui アーキテクチャ（初版）

[English](../architecture.md)

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
│ amonhen-gpg-ffi  バインディング層 (薄い)        │
├─────────────────────────────────────────────┤
│ amonhen-gpg-core ドメインモデル / ユースケース    │
│                  gpg エンジン (プロセス実行・解析)│
└──────┬───────────────────────┬──────────────┘
       │ gpg / gpgconf          │ Assuan (gpg-connect-agent)
┌──────┴───────────────────────┴──────────────┐
│ GnuPG  (gpg, gpg-agent, pinentry, scdaemon)  │
└─────────────────────────────────────────────┘
```

### 分離のルール

- UI は core の公開 API（ユースケースとデータ型）しか知らない。gpg コマンドや colon 形式は UI に一切漏らさない。
- core は UI を知らない。表示文言・ローカライズは UI 側の責務とし、core はエラーを**種別コード＋構造化データ**で返す。
- 3 つの UI は同じ API 境界を通る。GTK4 版は Rust なので core を直接リンクできるが、その場合も `amonhen-gpg-ffi` と同じ公開 API だけを使う。
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

入力を取り消したときは `Error::Canceled`、パスフレーズが違ったときは `Error::BadPassphrase` を返す（gpg の `ERROR` 行の種類 99・11 で見分ける）。秘密鍵の書き出しの取り消しと、失効証明書を作るときの取り消し・パスフレーズ違いは gpg が `ERROR` を出さないので、`LC_ALL=C` のメッセージで見分ける。FE は取り消しを失敗として知らせなくてよい。

pinentry を出せないときは `Error::NoPinentry` を返す。設定した pinentry がない（種類 85）ときと、端末用の pinentry（`PINENTRY_LAUNCHED` の種類が `curses`・`tty`）が失敗したときで、どちらも端末のない FE からはパスフレーズを聞けない。後者は端末がないと ENOTTY か取り消しとして報告されるので、取り消しより先に見分ける（取り消しと取り違えると、FE は何も知らせずに止まる）。Homebrew の gpg は既定で pinentry-curses を使うので、FE は gpg-agent.conf の `pinentry-program` に GUI の pinentry（macOS なら pinentry-mac）を設定するよう案内する。

### 自分の鍵を失わない

自分の秘密鍵を誤って消す・管理できなくなることを最も避ける。

- 鍵は完全なフィンガープリント（40 / 64 桁）でだけ指す。短い鍵 ID・名前・メールアドレスでは指さない（別の鍵に当たり得る）。
- 削除は 2 つの操作に分ける。
  - `delete_public_key`: 公開鍵だけ。秘密鍵がある鍵は gpg が拒むので、自分の鍵はこれでは消えない（結合テストで確認済み）。
  - `delete_secret_and_public_key`: 秘密鍵ごと。元に戻せないので、FE は必ず確認し、先に秘密鍵のバックアップ（`export_secret_key`）を促す。
- 秘密鍵のバックアップ（書き出し）を第 1 段階から用意する。書き出したものは元と同じパスフレーズで守られる。
- 開発・テストは一時ディレクトリの `--homedir` だけで行い、利用者の `~/.gnupg` には触らない。
- 今後の候補:
  - 失効証明書（`openpgp-revocs.d/<FPR>.rev`）があるかを鍵ごとに表示する。
  - 期限が近い自分の鍵を知らせ、延長（`--quick-set-expire`）へ導く。
  - 秘密鍵の削除の前に、バックアップを済ませたかを FE で確かめる。

### 堅牢性のための方針

- `#![deny(unsafe_code)]`。例外は子プロセスのシグナルマスクを空にする 1 か所（`process.rs`）と FFI 層だけ。
- gpg は常に `--batch --no-tty --status-fd 2` で起動し、`LC_ALL=C` を固定する。一覧は `--with-colons --fixed-list-mode`。人間向け出力は解析しない（stderr の status 行と人間向けのメッセージは接頭辞 `[GNUPG:]` で分ける）。
- シェルを経由せず引数配列で起動する。ユーザー入力（UID・ファイル名）は検証し、オプションとの間に `--` を入れる。鍵の指定は常に完全なフィンガープリントで行う。
- 結果の判定は終了コードではなく **status 行**（`KEY_CREATED`, `IMPORT_OK`, `IMPORT_RES`, `ERROR`, `FAILURE` など）で行う。
- タイムアウトとキャンセルに対応する（pinentry 待ちは長時間になり得る）。
- GnuPG は 2.4.1 以降を求める。鍵を SSH に出す・出さないの切り替えに使う秘密鍵の属性 `Use-for-ssh` が、gpg-agent の 2.4.1 からのため。`--quick-set-ownertrust` は 2.4.6 からなので、所有者信頼を画面に出す前に、最低の版を上げるか `--edit-key` で代わりに設定するかを決める。アプリは鍵束を読むたびに版（`gpg --version`）を読み、古ければ一覧の上に警告を出す。鍵の一覧は出す（`Version::MINIMUM`）。
- テスト:
  - colon / status パーサーは単体テストとファズテスト。
  - 一時ディレクトリの `GNUPGHOME` と loopback pinentry を使い、実際の gpg に対する結合テスト。
  - パスフレーズを聞く道（gpg-agent が pinentry を起動する）は、`scripts/fake-pinentry` を `pinentry-program` にして確かめる。決まった答え・違う答え・取り消しを返せる。本物の pinentry（pinentry-mac など）の見た目は手で確かめる。

### モジュール構成

```
crates/
  core/     amonhen-gpg-core ドメインモデルと gpg・gpgconf・gpg-connect-agent の起動・解析（UI も FFI も知らない）
  ffi/      amonhen-gpg-ffi  UniFFI の窓口（Swift・C# 向け）。uniffi-bindgen もここ（feature `bindgen`）
apps/
  macos/    SwiftPM のパッケージ
              CAmonhenGpg     UniFFI が生成する C のヘッダー（systemLibrary）
              AmonhenGpgKit   生成した Swift のバインディングと、画面に依らない Swift の処理（自分の鍵の段分けなど）
              AmonhenGpg      SwiftUI のアプリ
  gtk/      GTK4 (gtk4-rs)   まだ
  windows/  WinUI 3 (C#)     まだ
scripts/    ビルド、署名と公証、インストール、画面の確認、アイコンとバナーの描画、試験の道具（development.md を参照）
.github/    CI、リリース、CodeQL、Dependabot
docs/       英語の文書。日本語版は docs/ja/
```

### バインディング

- Swift: UniFFI（`crates/ffi`）。
  - コアは UniFFI を知らない。コアの型は `amonhen-gpg-ffi` で `#[uniffi::remote]` として形を書き写す（コアの型を変えると、合わせるまでコンパイルが通らない）。パス（`PathBuf`）は文字列で渡す。
  - エラーは OS のエラーなど FFI に載らないものを持つので、`GpgError` に移す（種類と材料だけ。文言は FE）。
  - gpg を待つ呼び出し（pinentry を含む）は同期のまま出し、FE が裏のスレッドから呼ぶ。
  - `scripts/build-core.sh` が静的ライブラリをビルドし、Swift のバインディングを `apps/macos` に生成する。生成物はコミットしない。
- C#: UniFFI のサードパーティ生成器 `uniffi-bindgen-cs`。成熟度に不安があれば、cbindgen による C ABI と P/Invoke に切り替える。
- GTK4: Rust（gtk4-rs）で書けば FFI 不要。

## 鍵管理の機能範囲（第 1 段階）

画面の方針（自分の鍵が主役、他者の鍵・一時保管は別の場所）は [ui.md](ui.md) を参照。

### GPG 鍵

| 機能 | gpg での実現 |
|---|---|
| 一覧・詳細（公開鍵 / 秘密鍵、サブ鍵、UID、有効性、所有者信頼、有効期限、用途 C/S/E/A、カード上の鍵） | `--list-keys` / `--list-secret-keys --with-colons --with-keygrip` |
| 生成 | `--quick-gen-key`、サブ鍵は `--quick-add-key` |
| インポート / エクスポート（公開鍵、秘密鍵、失効証明書） | `--import` / `--export` / `--export-secret-keys` |
| 有効期限の変更 | `--quick-set-expire` |
| UID の追加・失効・主 UID の設定 | `--quick-add-uid` / `--quick-revoke-uid` / `--quick-set-primary-uid` |
| 他者の鍵への署名 | `--quick-sign-key` / `--quick-lsign-key`（UID を選べる。署名に使う鍵は `--local-user` にフィンガープリントで渡す） |
| 所有者信頼の設定 | `--quick-set-ownertrust`（2.5 で確認。古い gpg にはない） |
| 失効（鍵全体・サブ鍵） | `--edit-key` を `--command-fd` で駆動し `revkey`（`--gen-revoke` はバッチで動かない）。答え方がずれても気づけるよう、終わったあとに鍵一覧で失効を確かめる。手元の失効証明書（`openpgp-revocs.d`）は、秘密鍵を失ったときのためのもの |
| 失効証明書の作成 | `--gen-revoke` を `--batch` なしで（`--no-tty` と `--command-fd` で答える）。ない鍵には作り直して `openpgp-revocs.d/<FPR>.rev` に置く（gpg と同じく先頭に `:` を入れ、誤って取り込んでも失効しないようにする） |
| 削除 | `--delete-secret-and-public-key`（フィンガープリント指定） |
| 鍵サーバー / WKD | `--receive-keys` / `--send-keys` / `--locate-external-keys`。送ったものは取り消せないので、FE が送る鍵と送り先を確かめる。メールアドレスで探すときは WKD と鍵サーバーを分けて試す（`--auto-key-locate wkd,keyserver` とまとめると、gpg は WKD がエラーのとき（iCloud のドメインは応答が大きすぎる）鍵サーバーへ進まない）。鍵がないことは `: No data` のメッセージか、何も取り込まない成功でしか分からないので、`Error::NotFound` にする。GitHub・GitLab: `--key-origin url,<URL>` を付けて `--fetch-keys https://<ホスト>/<名前>.gpg`。鍵を登録していない利用者は空の鍵ブロックを返す（`no valid OpenPGP data found`）ので、これも `Error::NotFound` |
| パスフレーズ変更 | `--passwd`（入力は pinentry） |
| 既存の SSH 秘密鍵の取り込み | `ssh-add`（`SSH_AUTH_SOCK` を gpg-agent の SSH ソケットに）。鍵ファイルのパスフレーズは ssh-add が `SSH_ASKPASS` で聞くので、gpg-agent の `GET_PASSPHRASE`（pinentry）で聞く小さなスクリプトを一時ディレクトリに置いて渡す。パスフレーズはスクリプトから ssh-add に直に渡り、アプリは触れない。ssh-add は取り消しや間違いの理由を伝えず、間違えると何度でも聞き直すので、スクリプトが印を残し、3 回で打ち切る |

### SSH 鍵（gpg-agent 経由）

「純粋な FE」として、SSH 鍵も **gpg-agent が管理するもの**を対象にする。

| 機能 | 実現方法 |
|---|---|
| gpg-agent の SSH サポートの状態確認・有効化 | `gpgconf --list-options gpg-agent` の `enable-ssh-support` と `--list-dirs agent-ssh-socket`（SSH_AUTH_SOCK に渡す）。有効にするときは `gpgconf --change-options` のあと gpg-agent を起動し直す |
| SSH 鍵の一覧 | Assuan の `KEYINFO --list --ssh-fpr --with-ssh` と `KEYINFO --list --need-attr=Use-for-ssh`（gpg-connect-agent。`ERR` でも終了コードは 0 なので応答の行で判断する）。keygrip で GPG 鍵の主鍵・サブ鍵とつなぐ |
| GPG の認証 (A) サブ鍵を SSH 鍵として使う | `--quick-add-key <FPR> ed25519 auth` で作り、SSH に出す設定をする |
| SSH に出す・出さない | 出すときは秘密鍵の属性 `Use-for-ssh: true`（`KEYATTR`。利用者のファイルを書き換えない）。出さないときは属性を消し、`sshcontrol` で有効な行があれば `!` を付ける（属性を偽にしても `sshcontrol` が勝つ）。終わったあとに gpg-agent に聞き直して確かめる |
| SSH 公開鍵の出力（authorized_keys 用） | `gpg --export-ssh-key <FPR>!`（指した鍵そのもの）。OpenPGP の鍵でない SSH の鍵は Assuan の `READKEY --format=ssh` で、説明は `READKEY` から取る（gpg-agent は代わりに `(none)` と書く） |
| 取り込んだ SSH の鍵を消す | アプリで確かめてから Assuan の `DELETE_KEY --force`。どの OpenPGP の鍵にも属さない keygrip だけ。終わったあとに gpg-agent に聞き直して確かめる |
| 既存の SSH 秘密鍵の取り込み | `ssh-add` で gpg-agent に登録（パスフレーズは pinentry） |

## 未決事項

1. **SSH 鍵の範囲:** `~/.ssh/` の鍵ファイルや OpenSSH の ssh-agent まで扱うか、gpg-agent 管理の鍵だけにするか。本案は後者。
2. **Windows の SSH:** Win32-OpenSSH と連携するには gpg-agent の `enable-win32-openssh-support` が必要。GnuPG のバージョンごとの対応状況を確認する。
3. **スマートカード:** 第 1 段階に含めるか。表示（カード上の鍵の識別）だけは最初から対応しておく。
4. **macOS の配布:** App Sandbox 下では `~/.gnupg` へのアクセスや gpg の起動が制限される。App Store 外で配布（Developer ID + Notarization）する前提にするか。
5. **GnuPG の同梱:** GnuPG をアプリに同梱するか、既存のインストール（Homebrew、GPG Suite、Gpg4win、ディストリのパッケージ）を使うか。
