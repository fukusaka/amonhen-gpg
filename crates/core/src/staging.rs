//! 一時保管の鍵束と、鍵サーバー・WKD とのやり取り（取得と公開）。画面の方針は `docs/ui.md` の「一時保管」。
//!
//! gpg には「一時的な鍵」がないので、アプリが管理する別の `--homedir` を一時保管にする。取ってきた鍵は
//! まずそこに入れ、利用者が確かめてから本来の鍵束に公開鍵だけを移す。本来の鍵束は散らからない。

use std::path::{Path, PathBuf};

use crate::gpg::check_fingerprint;
use crate::model::ImportResult;
use crate::process::command;
use crate::{Error, Gpg, Result};

/// 一時保管の印。これがあるディレクトリだけを `discard_staging` が消す（利用者の鍵束を誤って消さないように）。
const MARKER: &str = ".amonhen-staging";

impl Gpg {
    /// `dir` を一時保管の鍵束として使う gpg（同じ gpg の実行ファイル）。なければ作る。中身のあるディレクトリで、
    /// 一時保管の印がなければ拒む（利用者の鍵束を一時保管として扱わないように）。
    pub fn staging(&self, dir: impl Into<PathBuf>) -> Result<Gpg> {
        let dir = dir.into();
        let marker = dir.join(MARKER);
        if !marker.is_file() {
            let empty = match std::fs::read_dir(&dir) {
                Ok(mut entries) => entries.next().is_none(),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
                Err(e) => return Err(io_error(&dir, e)),
            };
            if !empty {
                return Err(Error::InvalidArgument {
                    name: "dir",
                    message: format!("{} is not an empty directory", dir.display()),
                });
            }
            create_private_dir(&dir)?;
            std::fs::write(&marker, b"").map_err(|e| io_error(&marker, e))?;
        }
        Ok(self.clone().with_homedir(dir))
    }

    /// 一時保管の鍵束を捨てる（gpg-agent・dirmngr を止めてからディレクトリごと消す）。一時保管の印がない
    /// ディレクトリ（利用者の鍵束など）や、`--homedir` を決めていない gpg では何もせずにエラーにする。
    pub fn discard_staging(self) -> Result<()> {
        let Some(dir) = self.homedir.clone() else {
            return Err(Error::InvalidArgument {
                name: "homedir",
                message: "not a staging keyring".into(),
            });
        };
        if !dir.join(MARKER).is_file() {
            return Err(Error::InvalidArgument {
                name: "homedir",
                message: format!("{} is not a staging keyring", dir.display()),
            });
        }
        // 止まらなくても消すことはできる（Windows では使用中のファイルが残ることがあるので、消す側の失敗で分かる）
        let _ = command(self.gpgconf_program())
            .arg("--homedir")
            .arg(&dir)
            .args(["--kill", "all"])
            .status();
        std::fs::remove_dir_all(&dir).map_err(|e| io_error(&dir, e))
    }

    /// 鍵の公開鍵を、ほかの鍵束（一時保管から本来の鍵束へ）に移す。秘密鍵は移さない。
    pub fn copy_public_keys_to(&self, dest: &Gpg, fingerprints: &[&str]) -> Result<ImportResult> {
        let data = self.export_public_keys(fingerprints, false)?;
        dest.import(&data)
    }

    /// 鍵サーバーから、フィンガープリントで鍵を取ってくる。`keyserver` を決めなければ dirmngr の設定を使う
    /// （設定がない鍵束では gpg が「No keyserver available」で失敗する。一時保管の鍵束では FE が決めて渡す）。
    pub fn receive_keys(
        &self,
        fingerprints: &[&str],
        keyserver: Option<&str>,
    ) -> Result<ImportResult> {
        if fingerprints.is_empty() {
            return Err(Error::InvalidArgument {
                name: "fingerprints",
                message: "no key selected".into(),
            });
        }
        let mut args = Vec::new();
        if let Some(server) = keyserver {
            args.extend(["--keyserver", check_keyserver(server)?]);
        }
        args.extend(["--recv-keys", "--"]);
        for f in fingerprints {
            args.push(check_fingerprint(f)?);
        }
        self.run_import(&args, None)
    }

    /// 鍵の公開鍵を鍵サーバーに送る（失効させた自分の鍵を知らせる、署名した他者の鍵を返すなど）。秘密鍵は送らない。
    /// **送ったものは取り消せない**（鍵サーバーは公開鍵を消さないものが多い）ので、FE は送る鍵と送り先を確かめる。
    /// keys.openpgp.org は、UID のメールアドレスを持ち主が確かめるまで UID を公開しない。
    pub fn send_keys(&self, fingerprints: &[&str], keyserver: Option<&str>) -> Result<()> {
        if fingerprints.is_empty() {
            return Err(Error::InvalidArgument {
                name: "fingerprints",
                message: "no key selected".into(),
            });
        }
        let mut args = Vec::new();
        if let Some(server) = keyserver {
            args.extend(["--keyserver", check_keyserver(server)?]);
        }
        args.extend(["--send-keys", "--"]);
        for f in fingerprints {
            args.push(check_fingerprint(f)?);
        }
        self.run(&args, None)?;
        Ok(())
    }

    /// メールアドレスで鍵を探して取ってくる。WKD（そのドメインが自分で公開している鍵）を先に、なければ鍵サーバー。
    pub fn locate_external_key(&self, email: &str) -> Result<ImportResult> {
        let email = check_email(email)?;
        self.run_import(
            &[
                "--auto-key-locate",
                "clear,nodefault,wkd,keyserver",
                "--locate-external-keys",
                "--",
                email,
            ],
            None,
        )
    }
}

/// gpg は鍵束のディレクトリの権限が緩いと警告するので、自分だけが読めるように作る。
fn create_private_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).map_err(|e| io_error(dir, e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| io_error(dir, e))?;
    }
    Ok(())
}

fn io_error(path: &Path, source: std::io::Error) -> Error {
    Error::Io {
        path: path.to_owned(),
        source,
    }
}

fn check_keyserver(server: &str) -> Result<&str> {
    let schemes = [
        "hkps://", "hkp://", "https://", "http://", "ldaps://", "ldap://",
    ];
    let ok = schemes.iter().any(|s| server.starts_with(s))
        && !server.chars().any(|c| c.is_whitespace() || c.is_control());
    if ok {
        Ok(server)
    } else {
        Err(Error::InvalidArgument {
            name: "keyserver",
            message: format!("`{server}` is not a keyserver URL"),
        })
    }
}

fn check_email(email: &str) -> Result<&str> {
    let ok = email
        .split_once('@')
        .is_some_and(|(local, domain)| !local.is_empty() && domain.contains('.'))
        && !email.starts_with('-')
        && !email.chars().any(|c| c.is_whitespace() || c.is_control());
    if ok {
        Ok(email)
    } else {
        Err(Error::InvalidArgument {
            name: "email",
            message: format!("`{email}` is not an email address"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyservers_and_emails_are_checked() {
        assert!(check_keyserver("hkps://keys.openpgp.org").is_ok());
        assert!(check_keyserver("keys.openpgp.org").is_err());
        assert!(check_keyserver("hkps://a b").is_err());
        assert!(check_keyserver("--no-auto-key-retrieve").is_err());
        assert!(check_email("alice@example.com").is_ok());
        assert!(check_email("alice").is_err());
        assert!(check_email("@example.com").is_err());
        assert!(check_email("-x@example.com").is_err());
        assert!(check_email("a b@example.com").is_err());
    }
}
