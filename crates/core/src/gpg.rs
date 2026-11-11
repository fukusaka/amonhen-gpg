//! gpg の起動。人間向けの出力は読まず、`--with-colons` と status（`--status-fd`）だけを見る。
//!
//! パスフレーズは扱わない。生成・秘密鍵の書き出しなどで要るときは、gpg-agent が pinentry で利用者に聞く。

use std::ffi::OsStr;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::keylist::parse_keylist;
use crate::model::{Expiry, GenerateKey, ImportResult, ImportedKey, Key};
use crate::process::command;
use crate::status::{self, Failure, Status};
use crate::{Error, Result};

/// 使う gpg と鍵の置き場所。
#[derive(Clone, Debug)]
pub struct Gpg {
    pub(crate) program: PathBuf,
    pub(crate) homedir: Option<PathBuf>,
}

impl Default for Gpg {
    fn default() -> Self {
        Gpg {
            program: "gpg".into(),
            homedir: None,
        }
    }
}

/// gpg を 1 回動かした結果。
pub(crate) struct Run {
    pub(crate) code: Option<i32>,
    pub(crate) stdout: Vec<u8>,
    pub(crate) status: Vec<Status>,
    pub(crate) messages: String,
}

impl Run {
    pub(crate) fn success(&self) -> bool {
        self.code == Some(0)
    }

    pub(crate) fn into_error(self) -> Error {
        Error::Gpg {
            code: self.code,
            failures: Failure::from_status(&self.status),
            stderr: self.messages,
        }
    }
}

impl Gpg {
    /// `PATH` の `gpg` と、既定の鍵の置き場所（`GNUPGHOME` または `~/.gnupg`）。
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_program(mut self, program: impl Into<PathBuf>) -> Self {
        self.program = program.into();
        self
    }

    /// 鍵の置き場所を `--homedir` で決める（テストや、別の鍵束を開くとき）。
    pub fn with_homedir(mut self, homedir: impl Into<PathBuf>) -> Self {
        self.homedir = Some(homedir.into());
        self
    }

    /// gpg の版。
    pub fn version(&self) -> Result<Version> {
        let out = self.run(&["--version"], None)?;
        let text = String::from_utf8_lossy(&out.stdout);
        let first = text.lines().next().unwrap_or_default();
        Version::parse(first).ok_or_else(|| Error::Parse {
            line: 1,
            message: format!("cannot read the version from `{first}`"),
        })
    }

    /// 公開鍵束のすべての鍵。秘密鍵があるかどうか（`Key::secret`）も付ける。
    pub fn list_keys(&self) -> Result<Vec<Key>> {
        let out = self.run(
            &[
                "--with-colons",
                "--fixed-list-mode",
                "--with-secret",
                "--with-keygrip",
                "--with-subkey-fingerprint",
                "--list-keys",
            ],
            None,
        )?;
        parse_keylist(&String::from_utf8_lossy(&out.stdout))
    }

    /// 鍵を作り、主鍵のフィンガープリントを返す。パスフレーズは pinentry が聞く。
    pub fn generate_key(&self, request: &GenerateKey) -> Result<String> {
        let user_id = check_user_id(&request.user_id)?;
        let algorithm = match &request.algorithm {
            Some(a) => check_token("algorithm", a)?,
            None => "default",
        };
        let usage = match request.capabilities {
            Some(caps) => caps.usage().ok_or_else(|| Error::InvalidArgument {
                name: "capabilities",
                message: "no capability selected".into(),
            })?,
            None => "default".into(),
        };
        let expire = request.expires.argument();
        let out = self.run(
            &["--quick-gen-key", "--", user_id, algorithm, &usage, &expire],
            None,
        )?;
        out.status
            .iter()
            .find(|s| s.keyword == "KEY_CREATED")
            .and_then(|s| s.arg(1))
            .map(str::to_owned)
            .ok_or_else(|| Error::Parse {
                line: 0,
                message: "gpg did not report the created key".into(),
            })
    }

    /// 鍵（公開鍵・秘密鍵・失効証明書）を取り込む。秘密鍵を含むときは pinentry がパスフレーズを聞く。
    ///
    /// 一部の鍵だけ取り込めなかったとき、gpg は失敗の終了コードを返すが、結果（`ImportResult::not_imported`）を返す。
    pub fn import(&self, data: &[u8]) -> Result<ImportResult> {
        self.run_import(&["--import"], Some(data))
    }

    /// 取り込みを伴う操作（`--import`・`--recv-keys` など）を動かし、`IMPORT_RES` から結果を作る。
    pub(crate) fn run_import(&self, args: &[&str], input: Option<&[u8]>) -> Result<ImportResult> {
        let out = self.run_raw(args, input)?;
        let Some(result) = parse_import(&out.status) else {
            return Err(out.into_error());
        };
        if result.considered == 0 {
            return Err(out.into_error());
        }
        Ok(result)
    }

    /// 公開鍵を書き出す。`armor` なら ASCII 形式。
    pub fn export_public_keys(&self, fingerprints: &[&str], armor: bool) -> Result<Vec<u8>> {
        self.export("--export", fingerprints, armor)
    }

    /// 秘密鍵を書き出す（バックアップ）。パスフレーズは pinentry が聞き、書き出したものも同じパスフレーズで守られる。
    pub fn export_secret_key(&self, fingerprint: &str, armor: bool) -> Result<Vec<u8>> {
        self.export("--export-secret-keys", &[fingerprint], armor)
    }

    /// 公開鍵だけを消す。秘密鍵がある鍵は gpg が拒む（自分の鍵を公開鍵の操作で失わないように）。
    pub fn delete_public_key(&self, fingerprint: &str) -> Result<()> {
        let fingerprint = check_fingerprint(fingerprint)?;
        self.run(&["--yes", "--delete-keys", "--", fingerprint], None)?;
        Ok(())
    }

    /// 秘密鍵ごと消す。元に戻せないので、FE は必ず利用者に確かめ、先に `export_secret_key` でのバックアップを促す。
    pub fn delete_secret_and_public_key(&self, fingerprint: &str) -> Result<()> {
        let fingerprint = check_fingerprint(fingerprint)?;
        self.run(
            &["--yes", "--delete-secret-and-public-key", "--", fingerprint],
            None,
        )?;
        Ok(())
    }

    /// 鍵のデータを、鍵束に取り込まずに読む（受け取った鍵を確かめる・一時保管の中身を見る）。
    ///
    /// `Key::secret` は、データが秘密鍵を含むか（`SecretState::None` 以外）だけを表す。gpg は、データの秘密鍵が
    /// gpg-agent にないと `#`（スタブ）と書くので、`Available` と `Stub` の違いには意味がない。
    pub fn show_keys(&self, data: &[u8]) -> Result<Vec<Key>> {
        let out = self.run(
            &[
                "--with-colons",
                "--fixed-list-mode",
                "--with-subkey-fingerprint",
                "--show-keys",
            ],
            Some(data),
        )?;
        let keys = parse_keylist(&String::from_utf8_lossy(&out.stdout))?;
        if keys.is_empty() {
            return Err(Error::NotFound);
        }
        Ok(keys)
    }

    /// 鍵の置き場所。`--homedir` で決めていなければ gpgconf に聞く（`GNUPGHOME`・Windows のレジストリも反映される）。
    pub fn homedir(&self) -> Result<PathBuf> {
        if let Some(home) = &self.homedir {
            return Ok(home.clone());
        }
        let program = self.gpgconf_program();
        let out = command(&program)
            .args(["--list-dirs", "homedir"])
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .output()
            .map_err(|source| Error::Spawn {
                program: program.display().to_string(),
                source,
            })?;
        if !out.status.success() {
            return Err(Error::Gpg {
                code: out.status.code(),
                failures: Vec::new(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            });
        }
        let line = String::from_utf8_lossy(&out.stdout);
        Ok(PathBuf::from(percent_decode(
            line.trim_end_matches(['\r', '\n']),
        )))
    }

    /// 失効証明書があるか。gpg は鍵を作るときに `openpgp-revocs.d/<フィンガープリント>.rev` を作る。
    /// 消したり別の場所に移したりしていれば `false`（手元にないことを知らせる）。
    pub fn has_revocation_certificate(&self, fingerprint: &str) -> Result<bool> {
        let fingerprint = check_fingerprint(fingerprint)?;
        let dir = self.homedir()?.join("openpgp-revocs.d");
        Ok(dir
            .join(format!("{}.rev", fingerprint.to_ascii_uppercase()))
            .is_file())
    }

    /// gpg と同じ場所の gpgconf（gpg をパスで指していなければ `PATH` で探す）。
    pub(crate) fn gpgconf_program(&self) -> PathBuf {
        let name = format!("gpgconf{}", std::env::consts::EXE_SUFFIX);
        match self.program.parent().filter(|p| p != &Path::new("")) {
            Some(dir) => dir.join(name),
            None => name.into(),
        }
    }

    fn export(&self, command: &str, fingerprints: &[&str], armor: bool) -> Result<Vec<u8>> {
        if fingerprints.is_empty() {
            return Err(Error::InvalidArgument {
                name: "fingerprints",
                message: "no key selected".into(),
            });
        }
        let mut args = vec![];
        if armor {
            args.push("--armor");
        }
        args.push(command);
        args.push("--");
        for f in fingerprints {
            args.push(check_fingerprint(f)?);
        }
        let out = self.run(&args, None)?;
        if out.stdout.is_empty() {
            return Err(Error::NotFound);
        }
        Ok(out.stdout)
    }

    /// 対話しない gpg。出力は `LC_ALL=C` にそろえ、status は stderr に混ぜて出させる（`status::split` で分ける）。
    fn command(&self) -> Command {
        let mut cmd = command(&self.program);
        cmd.args(["--batch", "--no-tty", "--status-fd", "2"])
            .env("LC_ALL", "C");
        if let Some(home) = &self.homedir {
            cmd.arg("--homedir").arg(home);
        }
        cmd
    }

    pub(crate) fn run(&self, args: &[&str], input: Option<&[u8]>) -> Result<Run> {
        let out = self.run_raw(args, input)?;
        if out.success() {
            Ok(out)
        } else {
            Err(out.into_error())
        }
    }

    /// 終了コードを見ずに結果を返す。`input` は標準入力に渡す（なければ閉じる）。
    pub(crate) fn run_raw<S: AsRef<OsStr>>(&self, args: &[S], input: Option<&[u8]>) -> Result<Run> {
        let spawn_error = |source| Error::Spawn {
            program: self.program.display().to_string(),
            source,
        };
        let mut child = self
            .command()
            .args(args)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(spawn_error)?;
        // 書き込みと読み出しを同時に進めないと、大きな入力でパイプが詰まる
        let out = std::thread::scope(|scope| {
            if let (Some(data), Some(mut stdin)) = (input, child.stdin.take()) {
                // gpg が途中で読むのをやめたときの書き込みの失敗は、gpg の結果のほうで分かる
                scope.spawn(move || {
                    let _ = stdin.write_all(data);
                });
            }
            child.wait_with_output()
        })
        .map_err(spawn_error)?;
        let (status, messages) = status::split(&String::from_utf8_lossy(&out.stderr));
        Ok(Run {
            code: out.status.code(),
            stdout: out.stdout,
            status,
            messages,
        })
    }
}

/// `IMPORT_OK` と `IMPORT_RES` から結果を作る。`IMPORT_RES` がなければ取り込みは始まっていない。
fn parse_import(status: &[Status]) -> Option<ImportResult> {
    let res = status.iter().find(|s| s.keyword == "IMPORT_RES")?;
    let n = |i: usize| res.arg(i).and_then(|a| a.parse().ok()).unwrap_or(0);
    let keys = status
        .iter()
        .filter(|s| s.keyword == "IMPORT_OK")
        .filter_map(|s| {
            let flags: u32 = s.arg(0)?.parse().ok()?;
            Some(ImportedKey {
                fingerprint: s.arg(1)?.to_owned(),
                new_key: flags & 1 != 0,
                new_user_ids: flags & 2 != 0,
                new_signatures: flags & 4 != 0,
                new_subkeys: flags & 8 != 0,
                secret: flags & 16 != 0,
            })
        })
        .collect();
    Some(ImportResult {
        considered: n(0),
        no_user_id: n(1),
        imported: n(2),
        unchanged: n(4),
        new_user_ids: n(5),
        new_subkeys: n(6),
        new_signatures: n(7),
        new_revocations: n(8),
        secret_read: n(9),
        secret_imported: n(10),
        secret_unchanged: n(11),
        not_imported: n(13),
        keys,
    })
}

/// gpgconf はパスの中の `:` などを `%3a` の形で書く。
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
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
    String::from_utf8_lossy(&out).into_owned()
}

/// 鍵はフィンガープリント（v4 は 40 桁、v5・v6 は 64 桁の 16 進）でだけ指す。短い鍵 ID や名前で指すと、
/// 別の鍵に当たることがある。
pub(crate) fn check_fingerprint(fingerprint: &str) -> Result<&str> {
    let ok =
        matches!(fingerprint.len(), 40 | 64) && fingerprint.bytes().all(|b| b.is_ascii_hexdigit());
    if ok {
        Ok(fingerprint)
    } else {
        Err(Error::InvalidArgument {
            name: "fingerprint",
            message: format!("`{fingerprint}` is not a full fingerprint"),
        })
    }
}

/// UID に改行などの制御文字があると、gpg の出力や鍵の中身が壊れる。
pub(crate) fn check_user_id(user_id: &str) -> Result<&str> {
    if user_id.trim().is_empty() || user_id.chars().any(char::is_control) {
        return Err(Error::InvalidArgument {
            name: "user_id",
            message: "empty or contains control characters".into(),
        });
    }
    Ok(user_id)
}

/// アルゴリズム名（`ed25519`・`rsa4096`・`future-default` など）。
pub(crate) fn check_token<'a>(name: &'static str, value: &'a str) -> Result<&'a str> {
    let ok = !value.is_empty()
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_+/".contains(&b));
    if ok {
        Ok(value)
    } else {
        Err(Error::InvalidArgument {
            name,
            message: format!("`{value}` is not a valid value"),
        })
    }
}

impl Expiry {
    pub(crate) fn argument(&self) -> String {
        match self {
            Expiry::Never => "never".into(),
            Expiry::Days(d) => format!("{d}d"),
        }
    }
}

/// gpg の版（`gpg (GnuPG) 2.5.24` の数字）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl Version {
    /// `gpg --version` の 1 行目を読む。最後の語が版（`2.5.24`、`2.4.0-beta3` のような後ろの部分は無視する）。
    pub fn parse(line: &str) -> Option<Self> {
        let word = line.split_whitespace().last()?;
        let mut parts = word
            .split(|c: char| !c.is_ascii_digit())
            .map(|p| p.parse::<u32>());
        Some(Version {
            major: parts.next()?.ok()?,
            minor: parts.next()?.ok()?,
            patch: parts.next().and_then(|p| p.ok()).unwrap_or(0),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_from_first_line() {
        let v = Version::parse("gpg (GnuPG) 2.5.24").unwrap();
        assert_eq!((v.major, v.minor, v.patch), (2, 5, 24));
        let v = Version::parse("gpg (GnuPG/MacGPG2) 2.2.41").unwrap();
        assert_eq!((v.major, v.minor, v.patch), (2, 2, 41));
        let v = Version::parse("gpg (GnuPG) 2.4.0-beta3").unwrap();
        assert_eq!((v.major, v.minor, v.patch), (2, 4, 0));
        assert!(Version::parse("gpg (GnuPG)").is_none());
        assert!(Version::parse("").is_none());
    }

    #[test]
    fn gpgconf_paths_are_decoded() {
        assert_eq!(
            percent_decode(r"C%3a\Users\a\AppData\Roaming\gnupg"),
            r"C:\Users\a\AppData\Roaming\gnupg"
        );
        assert_eq!(percent_decode("/home/a/.gnupg"), "/home/a/.gnupg");
        assert_eq!(percent_decode("50%"), "50%");
        assert_eq!(percent_decode("%zz"), "%zz");
    }

    #[test]
    fn gpgconf_sits_next_to_gpg() {
        let exe = std::env::consts::EXE_SUFFIX;
        assert_eq!(
            Gpg::new().gpgconf_program(),
            PathBuf::from(format!("gpgconf{exe}"))
        );
        assert_eq!(
            Gpg::new()
                .with_program("/opt/gnupg/bin/gpg")
                .gpgconf_program(),
            PathBuf::from(format!("/opt/gnupg/bin/gpgconf{exe}"))
        );
    }

    #[test]
    fn only_full_fingerprints_are_accepted() {
        assert!(check_fingerprint("AAAABBBBCCCCDDDDEEEEFFFF1111222233334444").is_ok());
        assert!(check_fingerprint(&"a".repeat(64)).is_ok());
        assert!(check_fingerprint("1111222233334444").is_err());
        assert!(check_fingerprint("--delete-secret-keys---------------------").is_err());
        assert!(check_fingerprint("alice@example.com").is_err());
    }

    #[test]
    fn user_ids_and_tokens_are_checked() {
        assert!(check_user_id("Alice <alice@example.com>").is_ok());
        assert!(check_user_id("-x").is_ok());
        assert!(check_user_id("Alice\n<a@example.com>").is_err());
        assert!(check_user_id("  ").is_err());
        assert!(check_token("algorithm", "future-default").is_ok());
        assert!(check_token("algorithm", "--yes").is_err());
        assert!(check_token("algorithm", "rsa 4096").is_err());
    }

    #[test]
    fn import_counts_and_keys() {
        let (status, _) = status::split(
            "\
[GNUPG:] IMPORT_OK 17 AAAABBBBCCCCDDDDEEEEFFFF1111222233334444
[GNUPG:] IMPORT_OK 0 0000111122223333444455556666DDDDEEEEFFFF0000
[GNUPG:] IMPORT_RES 2 0 1 0 1 0 0 0 0 1 1 0 0 0 0 0
",
        );
        let r = parse_import(&status).unwrap();
        assert_eq!((r.considered, r.imported, r.unchanged), (2, 1, 1));
        assert_eq!((r.secret_read, r.secret_imported), (1, 1));
        assert_eq!(r.keys.len(), 2);
        assert!(r.keys[0].new_key && r.keys[0].secret);
        assert!(!r.keys[1].new_key && !r.keys[1].secret);
        assert!(parse_import(&[]).is_none());
    }
}
