//! gpg-agent を SSH エージェントとして使うときの鍵。
//!
//! gpg-agent は次のどちらかに当てはまる鍵を SSH に出す（2.5 で確認）。
//! - 秘密鍵の属性 `Use-for-ssh` が真。
//! - `sshcontrol` に keygrip が書かれていて、`!`（無効）が付いていない。
//!
//! 使うようにするときは属性だけを付け、利用者のファイルは書き換えない。使わないようにするときは属性を消し、
//! `sshcontrol` で有効になっていればその行に `!` を付ける（属性を偽にしても `sshcontrol` の行が勝つため）。
//! 鍵は keygrip で指し、`Key::keygrip`・`Subkey::keygrip` と照らし合わせて GPG 鍵とつなぐ。
//!
//! 既存の SSH 秘密鍵（`~/.ssh/id_*`）は ssh-add で gpg-agent に渡す。鍵ファイルのパスフレーズは ssh-add が
//! `SSH_ASKPASS` で聞くので、gpg-agent の pinentry で聞く小さなスクリプトを渡す（アプリはパスフレーズに触れない）。
//! 受け取った gpg-agent は、自分の鍵束に置くためのパスフレーズを pinentry で聞き、`sshcontrol` に足す。

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use std::process::Stdio;

use crate::gpg::{check_fingerprint, percent_decode};
use crate::process::command;
use crate::{Error, Gpg, Result};

/// gpg-agent の SSH サポート。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshSupport {
    /// `enable-ssh-support` が設定されているか。
    pub enabled: bool,
    /// SSH クライアントに `SSH_AUTH_SOCK` として渡すソケット。
    pub socket: Option<PathBuf>,
}

/// `sshcontrol` での扱い。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SshControl {
    NotListed,
    Enabled,
    /// `!` が付いている。
    Disabled,
}

/// gpg-agent が持つ、SSH に使える種類の鍵。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshKey {
    pub keygrip: String,
    /// SSH の形のフィンガープリント（`SHA256:...`）。
    pub fingerprint: String,
    /// カード上の鍵なら、カードのシリアル番号。
    pub card: Option<String>,
    /// パスフレーズで守られているか（`None` は分からない）。
    pub protected: Option<bool>,
    pub sshcontrol: SshControl,
    /// 属性 `Use-for-ssh` が真か。
    pub use_for_ssh: bool,
    /// 使うたびに確認を求める（`sshcontrol` の `confirm`）。
    pub confirm: bool,
    /// 鍵の説明（ssh-keygen の `-C`。ssh-add で取り込んだ鍵だけにある）。
    pub comment: Option<String>,
}

impl SshKey {
    /// gpg-agent がこの鍵を SSH に出すか。
    pub fn enabled(&self) -> bool {
        self.use_for_ssh || self.sshcontrol == SshControl::Enabled
    }
}

impl Gpg {
    /// gpg-agent の SSH サポートが有効か、ソケットはどこか。
    pub fn ssh_support(&self) -> Result<SshSupport> {
        let options = self.run_tool("gpgconf", &["--list-options", "gpg-agent"], None)?;
        // 名前:フラグ:レベル:説明:型:別の型:引数名:既定値:引数の既定値:値（真偽は 1 か空）
        let enabled = options
            .lines()
            .filter_map(|l| l.strip_prefix("enable-ssh-support:"))
            .any(|rest| rest.split(':').nth(8) == Some("1"));
        let socket = self.run_tool("gpgconf", &["--list-dirs", "agent-ssh-socket"], None)?;
        let socket = socket.trim_end_matches(['\r', '\n']);
        Ok(SshSupport {
            enabled,
            socket: (!socket.is_empty()).then(|| PathBuf::from(percent_decode(socket))),
        })
    }

    /// gpg-agent の SSH サポートを有効にする（`gpg-agent.conf` は gpgconf が書き換える）。反映のために gpg-agent を
    /// 起動し直すので、覚えていたパスフレーズは忘れる。
    pub fn enable_ssh_support(&self) -> Result<()> {
        self.run_tool(
            "gpgconf",
            &["--change-options", "gpg-agent"],
            Some(b"enable-ssh-support:0:1\n"),
        )?;
        self.run_tool("gpgconf", &["--kill", "gpg-agent"], None)?;
        // SSH クライアントは gpg-agent を起動しないので、ソケットを用意させておく
        self.run_tool("gpgconf", &["--launch", "gpg-agent"], None)?;
        Ok(())
    }

    /// gpg-agent が持つ鍵のうち、SSH に使える種類のもの（SSH に出しているかは `SshKey::enabled`）。
    pub fn ssh_keys(&self) -> Result<Vec<SshKey>> {
        let replies = self.agent(&[
            "KEYINFO --list --ssh-fpr --with-ssh",
            "KEYINFO --list --need-attr=Use-for-ssh",
        ])?;
        let marked: Vec<&str> = replies[1]
            .iter()
            .filter_map(|l| keyinfo(l))
            .map(|f| f[0])
            .collect();
        let mut keys: Vec<SshKey> = replies[0]
            .iter()
            .filter_map(|l| parse_keyinfo(l, &marked))
            .collect();
        // 説明は鍵ごとに READKEY で読む。読めない鍵があっても一覧は出す
        let commands: Vec<String> = keys
            .iter()
            .map(|k| format!("READKEY {}", k.keygrip))
            .collect();
        if !commands.is_empty() {
            let commands: Vec<&str> = commands.iter().map(String::as_str).collect();
            if let Ok(replies) = self.agent_each(&commands) {
                for (key, reply) in keys.iter_mut().zip(replies) {
                    key.comment = reply.and_then(|lines| sexp_comment(&data(&lines)));
                }
            }
        }
        Ok(keys)
    }

    /// gpg-agent が持つ SSH の鍵の公開鍵を、`authorized_keys` に書く 1 行の形（説明があれば付ける）で返す。
    pub fn ssh_public_key(&self, keygrip: &str) -> Result<String> {
        let keygrip = check_keygrip(keygrip)?;
        let replies = self.agent(&[
            &format!("READKEY --format=ssh {keygrip}"),
            &format!("READKEY {keygrip}"),
        ])?;
        // gpg-agent は説明の代わりに `(none)` を付けるので、型と鍵だけを取る
        let ssh = String::from_utf8_lossy(&data(&replies[0])).into_owned();
        let mut fields = ssh.split_whitespace();
        let (Some(kind), Some(blob)) = (fields.next(), fields.next()) else {
            return Err(Error::Parse {
                line: 0,
                message: "gpg-agent did not return an ssh key".into(),
            });
        };
        Ok(match sexp_comment(&data(&replies[1])) {
            Some(comment) => format!("{kind} {blob} {comment}"),
            None => format!("{kind} {blob}"),
        })
    }

    /// OpenPGP の鍵でない SSH の鍵を gpg-agent から消す。元に戻せないので、FE は必ず利用者に確かめる。
    /// OpenPGP の鍵（主鍵・サブ鍵）の秘密鍵は、ここでは消さない（`delete_secret_and_public_key` で鍵ごと消す）。
    pub fn delete_ssh_key(&self, keygrip: &str) -> Result<()> {
        let keygrip = check_keygrip(keygrip)?;
        if self.belongs_to_openpgp_key(keygrip)? {
            return Err(Error::InvalidArgument {
                name: "keygrip",
                message: "the key belongs to an OpenPGP key".into(),
            });
        }
        if !self
            .ssh_keys()?
            .iter()
            .any(|k| k.keygrip.eq_ignore_ascii_case(keygrip))
        {
            return Err(Error::NotFound);
        }
        // 確かめるのは FE なので、gpg-agent には聞かせない（gpg の `--yes --delete-secret-keys` と同じ）
        self.agent(&[&format!("DELETE_KEY --force {keygrip}")])?;
        if self
            .ssh_keys()?
            .iter()
            .any(|k| k.keygrip.eq_ignore_ascii_case(keygrip))
        {
            return Err(Error::NotApplied {
                message: "gpg-agent did not delete the key".into(),
            });
        }
        Ok(())
    }

    /// keygrip が OpenPGP の鍵（主鍵・サブ鍵）のものか。
    pub(crate) fn belongs_to_openpgp_key(&self, keygrip: &str) -> Result<bool> {
        Ok(self.list_keys()?.iter().any(|k| {
            std::iter::once(&k.keygrip)
                .chain(k.subkeys.iter().map(|s| &s.keygrip))
                .any(|g| {
                    g.as_deref()
                        .is_some_and(|g| g.eq_ignore_ascii_case(keygrip))
                })
        }))
    }

    /// 鍵を SSH に出すか決める。終わったあとに gpg-agent に聞き直して確かめる。
    pub fn set_ssh_key_enabled(&self, keygrip: &str, enabled: bool) -> Result<()> {
        let keygrip = check_keygrip(keygrip)?;
        if enabled {
            self.agent(&[&format!("KEYATTR {keygrip} Use-for-ssh: true")])?;
        } else {
            self.agent(&[&format!("KEYATTR --delete {keygrip} Use-for-ssh:")])?;
            let path = self.homedir()?.join("sshcontrol");
            match std::fs::read_to_string(&path) {
                Ok(text) => {
                    if let Some(changed) = disable_in_sshcontrol(&text, keygrip) {
                        replace_file(&path, &changed)?;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => return Err(Error::Io { path, source }),
            }
        }
        let key = self
            .ssh_keys()?
            .into_iter()
            .find(|k| k.keygrip.eq_ignore_ascii_case(keygrip))
            .ok_or(Error::NotFound)?;
        if key.enabled() == enabled {
            Ok(())
        } else {
            Err(Error::NotApplied {
                message: "gpg-agent did not change whether the key is used for ssh".into(),
            })
        }
    }

    /// 鍵（主鍵またはサブ鍵のフィンガープリント）の公開鍵を、`authorized_keys` に書く 1 行の形で返す。
    /// 指した鍵そのものを使う（gpg が別の認証サブ鍵を選ばないよう `!` を付ける）。
    pub fn export_ssh_key(&self, fingerprint: &str) -> Result<String> {
        let exact = format!("{}!", check_fingerprint(fingerprint)?);
        let out = self.run(&["--export-ssh-key", "--", &exact], None)?;
        let text = String::from_utf8_lossy(&out.stdout);
        text.lines()
            .next()
            .filter(|l| !l.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| Error::Parse {
                line: 0,
                message: "gpg did not print an ssh key".into(),
            })
    }

    /// 既存の SSH 秘密鍵のファイルを gpg-agent に取り込み、SSH に出す。gpg-agent の SSH サポートが有効でなければ断る。
    /// 鍵ファイルのパスフレーズと、gpg-agent が鍵を守るパスフレーズは、どちらも pinentry が聞く。鍵ファイルは変えない。
    /// 取り消したときは `Error::Canceled`、鍵ファイルのパスフレーズを 3 回間違えたときは `Error::BadPassphrase`。
    pub fn add_ssh_key(&self, path: &Path) -> Result<()> {
        let support = self.ssh_support()?;
        let socket = match support.socket {
            Some(socket) if support.enabled => socket,
            _ => {
                return Err(Error::InvalidArgument {
                    name: "ssh",
                    message: "ssh support of gpg-agent is not enabled".into(),
                });
            }
        };
        // SSH クライアントは gpg-agent を起動しないので、ソケットを用意させておく
        self.run_tool("gpgconf", &["--launch", "gpg-agent"], None)?;
        let state = AskpassState::create()?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let mut cmd = command("ssh-add");
        cmd.arg("--")
            .arg(path)
            .env("SSH_AUTH_SOCK", &socket)
            .env("SSH_ASKPASS", state.script())
            .env("SSH_ASKPASS_REQUIRE", "force")
            // 古い ssh-add は DISPLAY がないと SSH_ASKPASS を使わない
            .env(
                "DISPLAY",
                std::env::var_os("DISPLAY").unwrap_or(":0".into()),
            )
            .env("AMONHEN_ASKPASS_STATE", state.dir())
            .env(
                "AMONHEN_CONNECT_AGENT",
                self.tool_program("gpg-connect-agent"),
            )
            .env(
                "AMONHEN_ASKPASS_DESC",
                assuan_text(&format!("Enter the passphrase of the SSH key {name}")),
            )
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        match &self.homedir {
            Some(home) => cmd.env("AMONHEN_GNUPGHOME", home),
            None => cmd.env_remove("AMONHEN_GNUPGHOME"),
        };
        let out = cmd.output().map_err(|source| Error::Spawn {
            program: "ssh-add".into(),
            source,
        })?;
        if out.status.success() {
            return Ok(());
        }
        if state.marked("canceled") {
            return Err(Error::Canceled);
        }
        if state.marked("bad-passphrase") {
            return Err(Error::BadPassphrase);
        }
        Err(Error::Tool {
            program: "ssh-add".into(),
            code: out.status.code(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }

    /// gpg-agent に Assuan のコマンドを順に送り、それぞれの応答の行（`S`・`D` の行）を返す。
    /// gpg-connect-agent は `ERR` の応答でも 0 で終わるので、応答の行で判断する。
    fn agent(&self, commands: &[&str]) -> Result<Vec<Vec<String>>> {
        let mut args = commands.to_vec();
        args.push("/bye");
        let out = self.run_tool("gpg-connect-agent", &args, None)?;
        parse_replies(&out, commands.len())
    }

    /// `agent` と同じだが、`ERR` の応答を `None` にして、ほかのコマンドの応答は返す。
    fn agent_each(&self, commands: &[&str]) -> Result<Vec<Option<Vec<String>>>> {
        let mut args = commands.to_vec();
        args.push("/bye");
        let out = self.run_tool("gpg-connect-agent", &args, None)?;
        parse_each_reply(&out, commands.len())
    }
}

/// ssh-add の `SSH_ASKPASS`。gpg-agent の pinentry（`GET_PASSPHRASE`）で鍵ファイルのパスフレーズを聞き、標準出力で
/// ssh-add に渡す。取り消し・3 回の間違いは、状態のディレクトリに印を残して知らせる（ssh-add は理由を伝えない）。
const ASKPASS: &str = r#"#!/bin/sh
state="$AMONHEN_ASKPASS_STATE"
error=X
case "$1" in
*"Bad passphrase"*)
    tries=$(cat "$state/tries" 2>/dev/null || echo 0)
    tries=$((tries + 1))
    echo "$tries" > "$state/tries"
    if [ "$tries" -ge 3 ]; then
        : > "$state/bad-passphrase"
        exit 1
    fi
    error=Bad+passphrase
    ;;
esac
if [ -n "$AMONHEN_GNUPGHOME" ]; then
    out=$("$AMONHEN_CONNECT_AGENT" --homedir "$AMONHEN_GNUPGHOME" --decode "GET_PASSPHRASE --data X $error Passphrase $AMONHEN_ASKPASS_DESC" /bye)
else
    out=$("$AMONHEN_CONNECT_AGENT" --decode "GET_PASSPHRASE --data X $error Passphrase $AMONHEN_ASKPASS_DESC" /bye)
fi
case "$out" in
"D "*) printf '%s
' "${out#D }" | head -n 1 ;;
OK*) echo ;;
*)
    : > "$state/canceled"
    exit 1
    ;;
esac
"#;

/// askpass のスクリプトと、その印を置く一時ディレクトリ（持ち主だけが入れる）。終わったら消す。
struct AskpassState {
    dir: PathBuf,
}

impl AskpassState {
    fn create() -> Result<Self> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir =
            std::env::temp_dir().join(format!("amonhen-askpass-{}-{nanos}", std::process::id()));
        let io = |path: &Path| {
            let path = path.to_owned();
            move |source| Error::Io { path, source }
        };
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&dir).map_err(io(&dir))?;
        let state = AskpassState { dir };
        let script = state.script();
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o700);
        }
        options
            .open(&script)
            .and_then(|mut f| std::io::Write::write_all(&mut f, ASKPASS.as_bytes()))
            .map_err(io(&script))?;
        Ok(state)
    }

    fn dir(&self) -> &Path {
        &self.dir
    }

    fn script(&self) -> PathBuf {
        self.dir.join("askpass")
    }

    fn marked(&self, name: &str) -> bool {
        self.dir.join(name).is_file()
    }
}

impl Drop for AskpassState {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Assuan の引数の文字（空白は `+`、`+`・`%`・制御文字は `%XX`）。
fn assuan_text(text: &str) -> String {
    let mut out = String::new();
    for b in text.bytes() {
        match b {
            b' ' => out.push('+'),
            b'+' | b'%' => out.push_str(&format!("%{b:02X}")),
            0x21..=0x7e => out.push(b as char),
            // 制御文字と、UTF-8 の多バイト文字のバイト
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn parse_replies(out: &str, expected: usize) -> Result<Vec<Vec<String>>> {
    let mut replies = Vec::new();
    let mut lines = Vec::new();
    for line in out.lines() {
        if line == "OK" || line.starts_with("OK ") {
            replies.push(std::mem::take(&mut lines));
        } else if let Some(rest) = line.strip_prefix("ERR ") {
            let (code, message) = rest.split_once(' ').unwrap_or((rest, ""));
            return Err(Error::Agent {
                code: code.parse().unwrap_or(0),
                message: message.to_owned(),
            });
        } else if line.starts_with("S ") || line.starts_with("D ") {
            lines.push(line.to_owned());
        }
    }
    if replies.len() == expected {
        Ok(replies)
    } else {
        Err(Error::Parse {
            line: 0,
            message: format!("expected {expected} replies from gpg-agent"),
        })
    }
}

fn parse_each_reply(out: &str, expected: usize) -> Result<Vec<Option<Vec<String>>>> {
    let mut replies = Vec::new();
    let mut lines = Vec::new();
    for line in out.lines() {
        if line == "OK" || line.starts_with("OK ") {
            replies.push(Some(std::mem::take(&mut lines)));
        } else if line.starts_with("ERR ") {
            lines.clear();
            replies.push(None);
        } else if line.starts_with("S ") || line.starts_with("D ") {
            lines.push(line.to_owned());
        }
    }
    if replies.len() == expected {
        Ok(replies)
    } else {
        Err(Error::Parse {
            line: 0,
            message: format!("expected {expected} replies from gpg-agent"),
        })
    }
}

/// 応答の `D` の行をつないで、Assuan のエスケープ（`%XX`）を解いたバイト列。
fn data(lines: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for line in lines {
        let Some(rest) = line.strip_prefix("D ") else {
            continue;
        };
        let bytes = rest.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let hex = bytes
                .get(i + 1..i + 3)
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok());
            match (bytes[i], hex) {
                (b'%', Some(b)) => {
                    out.push(b);
                    i += 3;
                }
                (b, _) => {
                    out.push(b);
                    i += 1;
                }
            }
        }
    }
    out
}

/// READKEY の公開鍵（canonical な S 式）の `(7:comment<長さ>:<説明>)`。制御文字は空白にし、空なら `None`。
fn sexp_comment(sexp: &[u8]) -> Option<String> {
    const TAG: &[u8] = b"(7:comment";
    let start = sexp.windows(TAG.len()).rposition(|w| w == TAG)? + TAG.len();
    let rest = &sexp[start..];
    let colon = rest.iter().position(|&b| b == b':')?;
    let len: usize = std::str::from_utf8(&rest[..colon]).ok()?.parse().ok()?;
    let value = rest.get(colon + 1..colon + 1 + len)?;
    let text: String = String::from_utf8_lossy(value)
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

/// `S KEYINFO <keygrip> <type> <serialno> <idstr> <cached> <protection> <fpr> <ttl> <flags>` の、KEYINFO より後ろ。
fn keyinfo(line: &str) -> Option<Vec<&str>> {
    let fields: Vec<&str> = line.strip_prefix("S KEYINFO ")?.split(' ').collect();
    (fields.len() >= 9).then_some(fields)
}

fn parse_keyinfo(line: &str, marked: &[&str]) -> Option<SshKey> {
    let f = keyinfo(line)?;
    let dash = |s: &str| (s != "-").then(|| s.to_owned());
    // SSH の形にできない鍵（暗号化用の cv25519 など）はフィンガープリントが `-`
    let fingerprint = dash(f[6])?;
    let flags = f[8];
    Some(SshKey {
        keygrip: f[0].to_owned(),
        fingerprint,
        card: if f[1] == "T" { dash(f[2]) } else { None },
        protected: match f[5] {
            "P" => Some(true),
            "C" => Some(false),
            _ => None,
        },
        sshcontrol: match (flags.contains('S'), flags.contains('D')) {
            (false, _) => SshControl::NotListed,
            (true, false) => SshControl::Enabled,
            (true, true) => SshControl::Disabled,
        },
        use_for_ssh: marked.contains(&f[0]),
        confirm: flags.contains('c'),
        comment: None,
    })
}

/// `sshcontrol` で keygrip の行に `!` を付けた中身（変えるところがなければ `None`）。ほかの行・コメントはそのまま。
fn disable_in_sshcontrol(text: &str, keygrip: &str) -> Option<String> {
    let mut changed = false;
    let mut out = String::with_capacity(text.len() + 1);
    for line in text.split_inclusive('\n') {
        let body = line.trim_start();
        let indent = &line[..line.len() - body.len()];
        let matches = body
            .get(..keygrip.len())
            .is_some_and(|g| g.eq_ignore_ascii_case(keygrip))
            && body[keygrip.len()..]
                .chars()
                .next()
                .is_none_or(char::is_whitespace);
        if matches {
            out.push_str(indent);
            out.push('!');
            out.push_str(body);
            changed = true;
        } else {
            out.push_str(line);
        }
    }
    changed.then_some(out)
}

/// 書きかけのファイルを gpg-agent に読ませないよう、隣に書いてから置き換える。権限は元のファイルに揃える。
fn replace_file(path: &Path, contents: &str) -> Result<()> {
    let io = |path: &Path| {
        let path = path.to_owned();
        move |source| Error::Io { path, source }
    };
    let tmp = path.with_extension("amonhen-tmp");
    let permissions = std::fs::metadata(path).map_err(io(path))?.permissions();
    std::fs::write(&tmp, contents).map_err(io(&tmp))?;
    std::fs::set_permissions(&tmp, permissions).map_err(io(&tmp))?;
    std::fs::rename(&tmp, path).map_err(io(path))
}

/// keygrip（40 桁の 16 進数）。
pub(crate) fn check_keygrip(keygrip: &str) -> Result<&str> {
    if keygrip.len() == 40 && keygrip.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(keygrip)
    } else {
        Err(Error::InvalidArgument {
            name: "keygrip",
            message: format!("`{keygrip}` is not a keygrip"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUTH: &str = "C6672EE91EB4D61374F8C32CA5CE1B743CCBD169";

    #[test]
    fn assuan_text_escapes_spaces_and_bytes() {
        assert_eq!(assuan_text("key id_ed25519"), "key+id_ed25519");
        assert_eq!(assuan_text("a+b 100%"), "a%2Bb+100%25");
        assert_eq!(assuan_text("鍵\n"), "%E9%8D%B5%0A");
    }

    #[test]
    fn parses_keyinfo_lines() {
        // gpg 2.5 の `KEYINFO --list --ssh-fpr --with-ssh` と `--need-attr=Use-for-ssh` の応答
        let out = "\
S KEYINFO D2252B9561FDDA7DBFD8F238BA882BC159AC6418 D - - - C - - -
S KEYINFO 8CB3E3EBD8B0C79B773B2277EFD52D56EDEFFB55 D - - - P SHA256:DB5ExlJk648Xq9a/F97HGJKkBFQv7OSM+4w3U8XQVKM - S
S KEYINFO C6672EE91EB4D61374F8C32CA5CE1B743CCBD169 D - - - C SHA256:vTsKSKs/SKQuJk2bmaTVierzsTANPo9BDqqpnUWnaFA - DS
S KEYINFO 1111111111111111111111111111111111111111 T D2760001240100000006012345670000 OPENPGP.3 - - SHA256:abc - c
OK
S KEYINFO C6672EE91EB4D61374F8C32CA5CE1B743CCBD169 D - - - C - - -
OK
";
        let replies = parse_replies(out, 2).unwrap();
        let marked = [AUTH];
        let keys: Vec<SshKey> = replies[0]
            .iter()
            .filter_map(|l| parse_keyinfo(l, &marked))
            .collect();
        // 暗号化用の鍵（フィンガープリントが `-`）は入らない
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0].sshcontrol, SshControl::Enabled);
        assert_eq!(keys[0].protected, Some(true));
        assert!(keys[0].enabled());
        // sshcontrol で無効でも、属性が真なら出す
        assert_eq!(keys[1].sshcontrol, SshControl::Disabled);
        assert!(keys[1].use_for_ssh && keys[1].enabled());
        assert_eq!(
            keys[2].card.as_deref(),
            Some("D2760001240100000006012345670000")
        );
        assert!(keys[2].confirm && !keys[2].enabled());
    }

    #[test]
    fn reads_comments_from_public_keys() {
        // gpg-connect-agent が出す READKEY の応答（`%` と改行はエスケープされる）
        let sexp = "D (10:public-key(3:ecc(5:curve7:Ed25519)(5:flags5:eddsa)(1:q33:@\u{1}abc(7:comment)xyz123456789012345678901234))(7:comment15:me@laptop 100%25!))";
        assert_eq!(
            sexp_comment(&data(&[sexp.to_owned()])).as_deref(),
            Some("me@laptop 100%!")
        );
        let none = "D (10:public-key(3:ecc(5:curve7:Ed25519)(1:q2:ab)))";
        assert_eq!(sexp_comment(&data(&[none.to_owned()])), None);
        let control = "D (10:public-key(7:comment5:a%0Ab%0D ))";
        assert_eq!(
            sexp_comment(&data(&[control.to_owned()])).as_deref(),
            Some("a b")
        );
        // 応答ごとに。断られた鍵は None
        let replies = parse_each_reply("D x\nOK\nERR 1 No such key\nS KEYINFO y\nOK\n", 3).unwrap();
        assert_eq!(replies[0].as_deref(), Some(&["D x".to_owned()][..]));
        assert_eq!(replies[1], None);
        assert!(replies[2].is_some());
    }

    #[test]
    fn agent_errors_and_missing_replies() {
        assert!(matches!(
            parse_replies("ERR 67141713 No such file or directory <GPG Agent>\n", 1),
            Err(Error::Agent { code: 67141713, .. })
        ));
        assert!(matches!(parse_replies("OK\n", 2), Err(Error::Parse { .. })));
    }

    #[test]
    fn disables_only_the_matching_sshcontrol_line() {
        let text = format!(
            "# List of allowed ssh keys.\n{AUTH} 0\n  {} 600 confirm\n!{} 0\n{AUTH}0 0\n",
            AUTH.to_ascii_lowercase(),
            "8CB3E3EBD8B0C79B773B2277EFD52D56EDEFFB55"
        );
        let changed = disable_in_sshcontrol(&text, AUTH).unwrap();
        assert_eq!(
            changed,
            format!(
                "# List of allowed ssh keys.\n!{AUTH} 0\n  !{} 600 confirm\n!{} 0\n{AUTH}0 0\n",
                AUTH.to_ascii_lowercase(),
                "8CB3E3EBD8B0C79B773B2277EFD52D56EDEFFB55"
            )
        );
        // 無効のものしかなければ変えない
        assert_eq!(
            disable_in_sshcontrol(
                "!8CB3E3EBD8B0C79B773B2277EFD52D56EDEFFB55 0\n",
                "8CB3E3EBD8B0C79B773B2277EFD52D56EDEFFB55"
            ),
            None
        );
        // 改行で終わらない最後の行も
        assert_eq!(
            disable_in_sshcontrol(AUTH, AUTH).as_deref(),
            Some(format!("!{AUTH}").as_str())
        );
    }

    #[test]
    fn keygrips_are_checked() {
        assert!(check_keygrip(AUTH).is_ok());
        assert!(check_keygrip(&AUTH[..39]).is_err());
        assert!(check_keygrip("C6672EE91EB4D61374F8C32CA5CE1B743CCBD16 /bye").is_err());
    }
}
