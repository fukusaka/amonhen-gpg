# git の allowed signers（設計）

[English](../allowed-signers.md)

2026-11-20 に書いた。[SSH の鍵・ホストの鍵・git の署名者](ssh-trust.md) で、git の allowed signers をこのアプリで扱うと決めたのを受ける。「SSH の署名者」の場所として作った。

## 目的

他の人が SSH の鍵で署名したコミットを、その人たちの鍵を手で集めて手入れすることなく検証できるようにする。

git は SSH の署名を、`gpg.ssh.allowedSignersFile` で指すファイルと照らし合わせる。各行は署名した人のメールアドレス、`namespaces="git"` や `valid-before="YYYYMMDD"` などの指定、公開鍵。次の 3 つが面倒で、ファイルは放置されがち。

- **集める。** 人ごとに、GitHub や GitLab から署名用の鍵を 1 つずつ写す。
- **追いかける。** 誰かが鍵を作り直しても知らせはなく、その人のコミットが検証できないと出るだけ。
- **古い鍵の扱い。** 消すと過去のコミットが検証できなくなり、残すといつまでも信じ続ける。`valid-before` で両立するが、手では誰も書かない。

ファイルはホームに書ける誰もが変えられる平文で、git はその中身をそのまま信じる。

## アプリがすること

- **人を追う。** GitHub か GitLab のアカウントと、その人が署名に使うメールアドレスで人を足す。アプリはそのアカウントの SSH の署名用の鍵を取ってくる。
- **一覧に分ける。** 人は一覧（たとえばチームごと、リポジトリごと）に入れる。一覧ごとに allowed signers のファイルを 1 つ書く。同じ人が複数の一覧に入ってよく、鍵は人ごとに 1 か所で持つ。
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
| `<一覧>.allowed_signers` | 一覧ごとに記録から書く、git が読むファイル |

allowed signers のファイルは一時ファイルに書いて古いファイルに rename で置き換え、git が半端な中身を読まないようにする。一覧を除くと、そのファイルも消す。普通のファイルのままにする。アプリが中身を渡す名前付きパイプも git で使えるが（OpenSSH 10.3・git 2.56 で試した。検証するコミットごとに 2 回開かれる）、渡す側がいないと git が止まる。

git は、すべてのリポジトリにも、1 つのリポジトリにもファイルを指せる（git 2.56 で試した。リポジトリの設定が優先され、`includeIf` でフォルダごとに選ぶこともできる）。アプリは一覧のファイルを指させるコマンドを見せ、実行は利用者に任せる。

```sh
git config --global gpg.ssh.allowedSignersFile "$HOME/Library/Application Support/Amonhen GPG/work.allowed_signers"
git -C <リポジトリ> config gpg.ssh.allowedSignersFile "$HOME/Library/Application Support/Amonhen GPG/work.allowed_signers"
```

### 記録

人ごとに 1 つ、それぞれの鍵を持ち、一覧が入れる人を持つ。たとえば:

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
          "valid_before": null,
          "valid_after": null,
          "imported": null
        }
      ]
    }
  ],
  "lists": [{ "id": "work", "name": "Work", "members": ["alice@example.com"] }]
}
```

- `checked` は `account`（アカウントから取ったまま）、`fingerprint`（持ち主と照らし合わせた）、`file`（既存の allowed signers のファイルから取り込んだ。`imported` にファイル・行・日時を持つ）。
- `valid_after` は、取り込んだ行にあったときだけ持ち、`valid-after` として書く。
- `valid_before` は鍵を退役させたときに入れ、allowed signers のファイルに `valid-before` として書く。
- 一覧の `id` はファイルの名前になる（英小文字・数字・`-`）。
- allowed signers のファイルの各行には `namespaces="git"` を付ける。
- メールアドレスは 1 人に 1 つで足りる。git はコミットのアドレスとファイルを比べないので、どのアドレスでコミットしても検証できる。アドレスは、git が署名した人として表示するもの（OpenSSH 10.3・git 2.56 で試した）。

## 既存のファイルを取り込む

すでに持っている allowed signers のファイルを読み込める（「allowed signers のファイルを取り込む…」）。ファイルは変えない。

- 取り込める行は、最初の principal のメールアドレスの人の鍵として「受け入れ前の鍵」に置く。1 つずつか、まとめて受け入れ、人を入れる一覧を選ぶ。
- 取り込めない行は理由を添えて並べる。最初の principal がパターン（`*@example.com`）、principal がメールアドレスでない、`cert-authority`、`namespaces` に git がない、鍵が読めないか署名に使えない、時刻が読めない、書式が読めない。行のほかの principal は見せるだけで取り込まない。
- `valid-after` と `valid-before` は持つ。`Z` のない時刻は、このコンピュータの時刻帯で読む。
- 人に GitHub か GitLab のアカウントを付けると、「変化を確かめる」で取り込んだ鍵をアカウントと比べる。アカウントにもある鍵は、そう記録できる（入手元がそのアカウントになり、確かめ方は「ファイルから」のまま）。その人のどのアカウントにもない鍵は、そう出して「退役させる」を出す。

## 受け入れ前の鍵でアカウントを探す

受け入れ前の鍵で GitHub・GitLab の利用者を探すと、OpenPGP の鍵と一緒に、そのアカウントの SSH の署名用の鍵も取ってくる。どちらのサービスも、SSH の鍵が誰のメールアドレスのものかを示さないので、主体はアカウントから推し量った候補から利用者が選ぶ。確かなものから並べる。

- このアカウントで、すでに SSH の署名者にいる人
- GitHub では、アカウントの GPG 鍵のメールアドレスのうち、GitHub が持ち主のものと確かめたもの
- アカウントが公開している OpenPGP の鍵の UID のメールアドレス
- 公開プロフィールのメールアドレス（あれば）
- サービスがアカウントに割り当てる noreply のアドレス（`<id>+<名前>@users.noreply.github.com`、`<id>-<名前>@users.noreply.gitlab.com`）。いつでも作れる

ほかのアドレスを入れてもよい。受け入れると、人がいなければ足し、アカウントをその人に結び付け、アカウントを入手元として鍵を受け入れる。以後は「変化を確かめる」がそのアカウントを追う。git は主体を署名した人として出すだけで、コミットのメールアドレスとは突き合わせない。

## 取ってくる

コアが `curl` を起動して HTTPS で取る（gpg は SSH の鍵を取れない）。gpg と同じく、TLS はアプリの外に置く。curl は macOS、たいていの Linux、Windows 10 以降に入っている。認証はせず、公開鍵だけを読む。

| ホスト | 要求 | 使う鍵 |
|---|---|---|
| GitHub | `GET https://api.github.com/users/<名前>/ssh_signing_keys?per_page=100` | すべて（署名用の鍵だけが返る） |
| GitLab | `GET https://gitlab.com/api/v4/users/<名前>/keys` | `usage_type` が `signing` か `auth_and_signing` |

受け入れ前の鍵でアカウントを探すときは、プロフィールも読む。GitHub は `GET /users/<名前>`（`id`・`login`・`email`）と `GET /users/<名前>/gpg_keys`（`emails` と `verified`）、GitLab は `GET /users?username=<名前>`（`id`・`username`・`public_email`）。

`https://github.com/<名前>.keys` は使わない。これはログイン用の鍵で、署名用とは限らない。GitHub は認証なしで 1 時間に 60 回まで要求でき、チームを手で確かめるには足りる。

## 守る決まり

- 鍵は SHA256 の完全なフィンガープリントで指す。
- パスフレーズは pinentry だけ（記録の署名）。
- 子プロセス（gpg・curl と、`gpg.ssh.allowedSignersFile` を読む git）は `amonhen_gpg_core::process::command` で起動する。
- テストは一時的なフォルダとローカルの HTTP サーバーだけで行う。利用者の `~/.ssh`・git の設定・ネットワークには触らない。

## 今はしない

- リポジトリにコミットしてチームで共有する allowed signers のファイル（git は相対パスで読める）。
- `gpg.ssh.revocationFile` と `cert-authority` の行。
- 自前の GitLab と GitHub Enterprise。
- known_hosts と、ssh-agent が持つ鍵。

## 2026-11-21 に決めたこと

- **署名する鍵。** 他者の鍵を確認済みにするときと同じく、どの自分の鍵で記録に署名するかを選ぶ。検証は、自分の鍵（gpg が究極の信頼とみなす鍵）のどれの署名でも通す。自分の鍵を替えたら、次に変えるときに新しい鍵で署名し直すだけ。
- **画面。** 自分の鍵・他者の鍵・受け入れ前の鍵と並べて、新しい場所 **SSH の署名者** を足す。一覧、人とその鍵、鍵ごとの確かめ方、「変化を確かめる」をここにまとめる。allowed signers が扱うのは SSH で署名したコミットだけなので、SSH の名を付ける。GPG で署名したコミットは git が gpg に任せるので、その署名者は他者の鍵で確認済みにする。

## 未決事項

- Linux と Windows でのフォルダ。
