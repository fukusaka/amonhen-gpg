# git の allowed signers（設計）

[English](../allowed-signers.md)

2026-11-20 に書いた。[SSH の鍵・ホストの鍵・git の署名者](ssh-trust.md) で、git の allowed signers をこのアプリで扱うと決めたのを受ける。まだ作っていない。

## 目的

他の人が SSH の鍵で署名したコミットを、その人たちの鍵を手で集めて手入れすることなく検証できるようにする。

git は SSH の署名を、`gpg.ssh.allowedSignersFile` で指すファイルと照らし合わせる。各行は署名した人のメールアドレス、`namespaces="git"` や `valid-before="YYYYMMDD"` などの指定、公開鍵。次の 3 つが面倒で、ファイルは放置されがち。

- **集める。** 人ごとに、GitHub や GitLab から署名用の鍵を 1 つずつ写す。
- **追いかける。** 誰かが鍵を作り直しても知らせはなく、その人のコミットが検証できないと出るだけ。
- **古い鍵の扱い。** 消すと過去のコミットが検証できなくなり、残すといつまでも信じ続ける。`valid-before` で両立するが、手では誰も書かない。

ファイルはホームに書ける誰もが変えられる平文で、git はその中身をそのまま信じる。

## アプリがすること

- **人を追う。** GitHub か GitLab のアカウントと、その人が署名に使うメールアドレスで人を足す。アプリはそのアカウントの SSH の署名用の鍵を取ってくる。
- **照らし合わせてから受け入れる。** 取ってきた鍵は、GPG の鍵と同じく「受け入れ前の鍵」に入る。鍵ごとに、アカウントから取ったまま受け入れるか、持ち主とフィンガープリントを照らし合わせてから受け入れる。
- **変化を確かめる。** 求められたときに、追っているアカウントをすべて取り直し、差だけを見せる。新しい鍵は「受け入れ前の鍵」へ。アカウントから消えた鍵は、その日を `valid-before` にして退役させるよう提案する（それまでに署名したコミットは検証できたまま）。利用者なしに受け入れたり退役させたりはしない。
- **署名した記録を持つ。** どの鍵が誰のもので、どう確かめたかの記録を、自分の GPG の鍵で署名する。allowed signers のファイルは記録から書く。
- **知らないうちの変更に気づく。** 記録を開くとき、署名を検証し、allowed signers のファイルが記録と合っているかを比べる。食い違えば知らせ、黙って直さない。

## ファイル

アプリのフォルダ（macOS では `~/Library/Application Support/Amonhen GPG/`）に置く。`~/.ssh` には書かず、git の設定も変えない。

| ファイル | 中身 |
|---|---|
| `ssh-signers.json` | 記録（下） |
| `ssh-signers.json.sig` | 自分の鍵による記録の分離署名（`gpg --detach-sign`。pinentry を通す） |
| `allowed_signers` | 記録から書く、git が読むファイル |

allowed signers のファイルは一時ファイルに書いて古いファイルに rename で置き換え、git が半端な中身を読まないようにする。普通のファイルのままにする。アプリが中身を渡す名前付きパイプも git で使えるが（OpenSSH 10.3・git 2.56 で試した。検証するコミットごとに 2 回開かれる）、渡す側がいないと git が止まる。

アプリは、git にこのファイルを指させるコマンドと、git がもう指しているかを見せる。

```sh
git config --global gpg.ssh.allowedSignersFile "$HOME/Library/Application Support/Amonhen GPG/allowed_signers"
```

git が別のファイルを指していれば、そう知らせて、そのままにする。

### 記録

人ごとに 1 つ、それぞれの鍵を持つ。たとえば:

```json
{
  "version": 1,
  "people": [
    {
      "email": "alice@example.com",
      "accounts": [{ "host": "github.com", "user": "alice" }],
      "keys": [
        {
          "key": "ssh-ed25519 AAAA...",
          "fingerprint": "SHA256:...",
          "source": { "host": "github.com", "user": "alice", "fetched": "2026-11-20T10:00:00Z" },
          "checked": "account",
          "accepted": "2026-11-20T10:05:00Z",
          "valid_before": null
        }
      ]
    }
  ]
}
```

- `checked` は `account`（アカウントから取ったまま）か `fingerprint`（持ち主と照らし合わせた）。
- `valid_before` は鍵を退役させたときに入れ、allowed signers のファイルに `valid-before` として書く。
- allowed signers のファイルの各行には `namespaces="git"` を付ける。
- メールアドレスは 1 人に 1 つで足りる。git はコミットのアドレスとファイルを比べないので、どのアドレスでコミットしても検証できる。アドレスは、git が署名した人として表示するもの（OpenSSH 10.3・git 2.56 で試した）。

## 取ってくる

コアが `curl` を起動して HTTPS で取る（gpg は SSH の鍵を取れない）。gpg と同じく、TLS はアプリの外に置く。curl は macOS、たいていの Linux、Windows 10 以降に入っている。認証はせず、公開鍵だけを読む。

| ホスト | 要求 | 使う鍵 |
|---|---|---|
| GitHub | `GET https://api.github.com/users/<名前>/ssh_signing_keys?per_page=100` | すべて（署名用の鍵だけが返る） |
| GitLab | `GET https://gitlab.com/api/v4/users/<名前>/keys` | `usage_type` が `signing` か `auth_and_signing` |

`https://github.com/<名前>.keys` は使わない。これはログイン用の鍵で、署名用とは限らない。GitHub は認証なしで 1 時間に 60 回まで要求でき、チームを手で確かめるには足りる。

## 守る決まり

- 鍵は SHA256 の完全なフィンガープリントで指す。
- パスフレーズは pinentry だけ（記録の署名）。
- 子プロセス（gpg・curl と、`gpg.ssh.allowedSignersFile` を読む git）は `amonhen_gpg_core::process::command` で起動する。
- テストは一時的なフォルダとローカルの HTTP サーバーだけで行う。利用者の `~/.ssh`・git の設定・ネットワークには触らない。

## 今はしない

- リポジトリにコミットしてチームで共有する allowed signers のファイル。
- `gpg.ssh.revocationFile` と `cert-authority` の行。
- 自前の GitLab と GitHub Enterprise。
- known_hosts と、ssh-agent が持つ鍵。

## 未決事項

- 自分の鍵が複数あるとき、どれで記録に署名するか。その鍵が期限切れになったり替わったりしたときにどうするか。
- 人とその鍵を画面のどこに出すか。他者の鍵の、その人の GPG の鍵の隣か、別の一覧か。
- Linux と Windows でのフォルダ。
