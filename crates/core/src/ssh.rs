//! gpg-agent を SSH エージェントとして使うときの鍵。
//!
//! gpg-agent は次のどちらかに当てはまる鍵を SSH に出す（2.5 で確認）。
//! - 秘密鍵の属性 `Use-for-ssh` が真。
//! - `sshcontrol` に keygrip が書かれていて、`!`（無効）が付いていない。
//!
//! 使うようにするときは属性だけを付け、利用者のファイルは書き換えない。使わないようにするときは属性を消し、
//! `sshcontrol` で有効になっていればその行に `!` を付ける（属性を偽にしても `sshcontrol` の行が勝つため）。
//! 鍵は keygrip で指し、`Key::keygrip`・`Subkey::keygrip` と照らし合わせて GPG 鍵とつなぐ。

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::gpg::{check_fingerprint, percent_decode};
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
        Ok(replies[0]
            .iter()
            .filter_map(|l| parse_keyinfo(l, &marked))
            .collect())
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

    /// gpg-agent に Assuan のコマンドを順に送り、それぞれの応答の行（`S`・`D` の行）を返す。
    /// gpg-connect-agent は `ERR` の応答でも 0 で終わるので、応答の行で判断する。
    fn agent(&self, commands: &[&str]) -> Result<Vec<Vec<String>>> {
        let mut args = commands.to_vec();
        args.push("/bye");
        let out = self.run_tool("gpg-connect-agent", &args, None)?;
        parse_replies(&out, commands.len())
    }
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
fn check_keygrip(keygrip: &str) -> Result<&str> {
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
