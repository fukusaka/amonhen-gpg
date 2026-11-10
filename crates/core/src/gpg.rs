//! gpg の起動。人間向けの出力は読まず、`--with-colons` と終了コードだけを見る。

use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use crate::keylist::parse_keylist;
use crate::model::Key;
use crate::process::command;
use crate::{Error, Result};

/// 使う gpg と鍵の置き場所。
#[derive(Clone, Debug)]
pub struct Gpg {
    program: PathBuf,
    homedir: Option<PathBuf>,
}

impl Default for Gpg {
    fn default() -> Self {
        Gpg {
            program: "gpg".into(),
            homedir: None,
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
        let out = self.run(["--version"])?;
        let text = String::from_utf8_lossy(&out.stdout);
        let first = text.lines().next().unwrap_or_default();
        Version::parse(first).ok_or_else(|| Error::Parse {
            line: 1,
            message: format!("cannot read the version from `{first}`"),
        })
    }

    /// 公開鍵束のすべての鍵。秘密鍵があるかどうか（`Key::secret`）も付ける。
    pub fn list_keys(&self) -> Result<Vec<Key>> {
        let out = self.run([
            "--with-colons",
            "--fixed-list-mode",
            "--with-secret",
            "--with-keygrip",
            "--with-subkey-fingerprint",
            "--list-keys",
        ])?;
        parse_keylist(&String::from_utf8_lossy(&out.stdout))
    }

    /// 対話しない gpg。出力は `LC_ALL=C` にそろえ、標準入力は閉じる（パスフレーズは pinentry が聞く）。
    fn command(&self) -> Command {
        let mut cmd = command(&self.program);
        cmd.args(["--batch", "--no-tty"])
            .env("LC_ALL", "C")
            .stdin(Stdio::null());
        if let Some(home) = &self.homedir {
            cmd.arg("--homedir").arg(home);
        }
        cmd
    }

    fn run<I, S>(&self, args: I) -> Result<Output>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let out = self
            .command()
            .args(args)
            .output()
            .map_err(|source| Error::Spawn {
                program: self.program.display().to_string(),
                source,
            })?;
        if !out.status.success() {
            return Err(Error::Gpg {
                code: out.status.code(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            });
        }
        Ok(out)
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
}
