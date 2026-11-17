//! 自分の鍵の編集（有効期限・UID・サブ鍵・失効・パスフレーズ・所有者信頼）と、失効証明書の作成。
//!
//! どれも主鍵の秘密鍵で署名し直すので、パスフレーズは pinentry が聞く。`--quick-*` があるものはそれを使い、
//! ない操作（失効）だけ `--edit-key` を `--command-fd` で動かし、gpg の問いに順に答える（失効証明書は `--gen-revoke`）。答え方がずれると別の結果になり得るので、
//! そうした操作は終わったあとに鍵一覧で結果を確かめる。

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::gpg::{check_fingerprint, check_token, check_user_id};
use crate::model::{Capabilities, Expiry, Validity};
use crate::{Error, Gpg, Result};

/// 失効の理由（OpenPGP の Reason for Revocation）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevocationReason {
    /// 理由を示さない。
    Unspecified,
    /// 秘密鍵が漏れた（またはその恐れがある）。
    Compromised,
    /// 新しい鍵に置き換えた。
    Superseded,
    /// もう使わない。
    Retired,
}

impl RevocationReason {
    /// gpg の問い（`ask_revocation_reason.code`）への答え。
    fn code(self) -> &'static str {
        match self {
            RevocationReason::Unspecified => "0",
            RevocationReason::Compromised => "1",
            RevocationReason::Superseded => "2",
            RevocationReason::Retired => "3",
        }
    }
}

/// 所有者信頼（自分の鍵は `Ultimate`）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OwnerTrust {
    Unknown,
    Never,
    Marginal,
    Full,
    Ultimate,
}

impl OwnerTrust {
    fn argument(self) -> &'static str {
        match self {
            OwnerTrust::Unknown => "undefined",
            OwnerTrust::Never => "never",
            OwnerTrust::Marginal => "marginal",
            OwnerTrust::Full => "full",
            OwnerTrust::Ultimate => "ultimate",
        }
    }
}

impl Gpg {
    /// 主鍵の有効期限を変える。期限切れの鍵も、延長すれば使えるようになる。
    pub fn set_expiry(&self, fingerprint: &str, expires: Expiry) -> Result<()> {
        let fingerprint = check_fingerprint(fingerprint)?;
        let expire = expires.argument();
        self.run(&["--quick-set-expire", "--", fingerprint, &expire], None)?;
        Ok(())
    }

    /// サブ鍵の有効期限を変える。
    pub fn set_subkey_expiry(
        &self,
        fingerprint: &str,
        subkeys: &[&str],
        expires: Expiry,
    ) -> Result<()> {
        let fingerprint = check_fingerprint(fingerprint)?;
        if subkeys.is_empty() {
            return Err(Error::InvalidArgument {
                name: "subkeys",
                message: "no subkey selected".into(),
            });
        }
        let expire = expires.argument();
        let mut args = vec!["--quick-set-expire", "--", fingerprint, &expire];
        for s in subkeys {
            args.push(check_fingerprint(s)?);
        }
        self.run(&args, None)?;
        Ok(())
    }

    /// UID を加える。
    pub fn add_user_id(&self, fingerprint: &str, user_id: &str) -> Result<()> {
        let fingerprint = check_fingerprint(fingerprint)?;
        let user_id = check_user_id(user_id)?;
        self.run(&["--quick-add-uid", "--", fingerprint, user_id], None)?;
        Ok(())
    }

    /// UID を失効させる（`user_id` は鍵一覧の `UserId::text` と同じ文字列）。最後の有効な UID は gpg が拒む。
    pub fn revoke_user_id(&self, fingerprint: &str, user_id: &str) -> Result<()> {
        let fingerprint = check_fingerprint(fingerprint)?;
        let user_id = check_user_id(user_id)?;
        self.run(&["--quick-revoke-uid", "--", fingerprint, user_id], None)?;
        Ok(())
    }

    /// 主たる UID（一覧で名前として出るもの）を決める。
    pub fn set_primary_user_id(&self, fingerprint: &str, user_id: &str) -> Result<()> {
        let fingerprint = check_fingerprint(fingerprint)?;
        let user_id = check_user_id(user_id)?;
        self.run(
            &["--quick-set-primary-uid", "--", fingerprint, user_id],
            None,
        )?;
        Ok(())
    }

    /// サブ鍵を加え、そのフィンガープリントを返す。`algorithm` が `None` なら gpg の既定（用途に合うもの）。
    pub fn add_subkey(
        &self,
        fingerprint: &str,
        algorithm: Option<&str>,
        capabilities: Capabilities,
        expires: Expiry,
    ) -> Result<String> {
        let fingerprint = check_fingerprint(fingerprint)?;
        let algorithm = match algorithm {
            Some(a) => check_token("algorithm", a)?,
            None => "default",
        };
        let usage = capabilities.usage().ok_or_else(|| Error::InvalidArgument {
            name: "capabilities",
            message: "no capability selected".into(),
        })?;
        let expire = expires.argument();
        let out = self.run(
            &[
                "--quick-add-key",
                "--",
                fingerprint,
                algorithm,
                &usage,
                &expire,
            ],
            None,
        )?;
        out.status
            .iter()
            .find(|s| s.keyword == "KEY_CREATED")
            .and_then(|s| s.arg(1))
            .map(str::to_owned)
            .ok_or_else(|| Error::Parse {
                line: 0,
                message: "gpg did not report the created subkey".into(),
            })
    }

    /// パスフレーズを変える。今のものと新しいものは pinentry が聞く。
    /// 今のものを取り消すと、gpg は `ERROR keyedit.passwd` を出すだけで 0 で終わるので、ERROR があれば失敗にする
    /// （変わっていないのに変わったと知らせないように）。
    pub fn change_passphrase(&self, fingerprint: &str) -> Result<()> {
        let fingerprint = check_fingerprint(fingerprint)?;
        let run = self.run_raw(&["--passwd", "--", fingerprint], None)?;
        if !run.success() || run.status.iter().any(|s| s.keyword == "ERROR") {
            return Err(run.into_error());
        }
        Ok(())
    }

    /// 所有者信頼を決める。別の PC から取り込んだ自分の鍵を「自分の鍵」にするときは `Ultimate`。
    /// `--quick-set-ownertrust` は gpg 2.4.6 から（`Version::MINIMUM`）。
    pub fn set_owner_trust(&self, fingerprint: &str, trust: OwnerTrust) -> Result<()> {
        let fingerprint = check_fingerprint(fingerprint)?;
        self.run(
            &[
                "--quick-set-ownertrust",
                "--",
                fingerprint,
                trust.argument(),
            ],
            None,
        )?;
        Ok(())
    }

    /// 鍵全体を失効させる。**元に戻せない。** FE は必ず確かめ、失効させた鍵を鍵サーバーなどで公開するよう促す。
    /// `description` は 1 行の説明（空でもよい）。
    pub fn revoke_key(
        &self,
        fingerprint: &str,
        reason: RevocationReason,
        description: &str,
    ) -> Result<()> {
        let fingerprint = check_fingerprint(fingerprint)?;
        let answers = revocation_answers(reason, description)?;
        // `--gen-revoke` はバッチでは動かないので `--edit-key` の revkey を使う。サブ鍵を選ばずに revkey すると
        // 鍵全体の失効になる: revkey → 鍵全体を失効させるか → 理由 → 説明 → okay → save
        let input = format!("revkey\ny\n{answers}save\n");
        self.run(
            &["--command-fd", "0", "--edit-key", "--", fingerprint],
            Some(input.as_bytes()),
        )?;
        self.expect(fingerprint, |key| key.validity == Validity::Revoked)
    }

    /// サブ鍵を失効させる（漏れた・使わなくなった暗号化用や認証用のサブ鍵）。**元に戻せない。**
    pub fn revoke_subkey(
        &self,
        fingerprint: &str,
        subkey: &str,
        reason: RevocationReason,
        description: &str,
    ) -> Result<()> {
        let fingerprint = check_fingerprint(fingerprint)?;
        let subkey = check_fingerprint(subkey)?;
        let answers = revocation_answers(reason, description)?;
        // key <指紋> で選び、revkey → keyedit.revoke.subkey.okay → 理由 → 説明 → okay → save
        let input = format!("key {subkey}\nrevkey\ny\n{answers}save\n");
        self.run(
            &["--command-fd", "0", "--edit-key", "--", fingerprint],
            Some(input.as_bytes()),
        )?;
        self.expect(fingerprint, |key| {
            key.subkeys.iter().any(|s| {
                s.fingerprint.eq_ignore_ascii_case(subkey) && s.validity == Validity::Revoked
            })
        })
    }

    /// 失効証明書を作る（鍵は失効させない）。ASCII 形式の証明書を返す。取り込むと鍵が失効するので、扱いに注意する。
    /// 主鍵の秘密鍵で署名するので、パスフレーズは pinentry が聞く。
    pub fn generate_revocation_certificate(
        &self,
        fingerprint: &str,
        reason: RevocationReason,
        description: &str,
    ) -> Result<Vec<u8>> {
        let fingerprint = check_fingerprint(fingerprint)?;
        let answers = revocation_answers(reason, description)?;
        // `--gen-revoke` はバッチでは断るので、`--batch` を外して問いに答える:
        // 作るか（gen_revoke.okay）→ 理由 → 説明 → okay
        let input = format!("y\n{answers}");
        let out = self.run_unbatched(
            &[
                "--command-fd",
                "0",
                "--armor",
                "--output",
                "-",
                "--gen-revoke",
                "--",
                fingerprint,
            ],
            input.as_bytes(),
        )?;
        if out.stdout.is_empty() {
            return Err(Error::NotApplied {
                message: "gpg made no revocation certificate".into(),
            });
        }
        Ok(out.stdout)
    }

    /// 失効証明書がなければ作り、gpg が鍵を作るときと同じ場所（`openpgp-revocs.d/<フィンガープリント>.rev`）に置く。
    /// あれば何もしない。誤って取り込んでも失効しないよう、gpg と同じく先頭の `-----BEGIN` の前に `:` を入れる。
    /// 置いた場所を返す。
    pub fn save_revocation_certificate(&self, fingerprint: &str) -> Result<PathBuf> {
        let fingerprint = check_fingerprint(fingerprint)?.to_ascii_uppercase();
        let dir = self.homedir()?.join("openpgp-revocs.d");
        let path = dir.join(format!("{fingerprint}.rev"));
        if path.is_file() {
            return Ok(path);
        }
        let certificate =
            self.generate_revocation_certificate(&fingerprint, RevocationReason::Unspecified, "")?;
        let certificate = String::from_utf8_lossy(&certificate);
        let contents = format!(
            "This is a revocation certificate for the OpenPGP key\n\
             {fingerprint}\n\
             \n\
             Importing it revokes the key for good. Use it if the secret key is lost or\n\
             leaked. To avoid using it by accident, a colon was inserted before the\n\
             first five dashes below. Remove it before importing.\n\
             \n\
             :{certificate}"
        );
        write_private_file(&dir, &path, contents.as_bytes())?;
        Ok(path)
    }

    /// 対話で答えた操作が、思ったとおりに鍵に反映されたか。
    fn expect(&self, fingerprint: &str, applied: impl Fn(&crate::Key) -> bool) -> Result<()> {
        let keys = self.list_keys()?;
        let key = keys
            .iter()
            .find(|k| k.fingerprint.eq_ignore_ascii_case(fingerprint))
            .ok_or(Error::NotFound)?;
        if applied(key) {
            Ok(())
        } else {
            Err(Error::NotApplied {
                message: "gpg finished but the key did not change as expected".into(),
            })
        }
    }
}

/// 持ち主だけが読めるファイルを `dir`（なければ作る。持ち主だけが入れる）に書く。書きかけを残さないよう、隣に書いてから置き換える。
fn write_private_file(dir: &Path, path: &Path, contents: &[u8]) -> Result<()> {
    let io = |path: &Path| {
        let path = path.to_owned();
        move |source| Error::Io { path, source }
    };
    if !dir.is_dir() {
        std::fs::create_dir_all(dir).map_err(io(dir))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .map_err(io(dir))?;
        }
    }
    let tmp = path.with_extension("amonhen-tmp");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let written = options
        .open(&tmp)
        .and_then(|mut file| file.write_all(contents));
    if let Err(source) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(Error::Io { path: tmp, source });
    }
    std::fs::rename(&tmp, path).map_err(io(path))
}

/// 失効の理由と説明への答え（理由のコード、説明の 1 行、終わりの空行、確認の y）。
fn revocation_answers(reason: RevocationReason, description: &str) -> Result<String> {
    if description.chars().any(char::is_control) {
        return Err(Error::InvalidArgument {
            name: "description",
            message: "must be a single line".into(),
        });
    }
    let description = description.trim();
    let mut answers = format!("{}\n", reason.code());
    if !description.is_empty() {
        answers.push_str(description);
        answers.push('\n');
    }
    answers.push_str("\ny\n");
    Ok(answers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revocation_answers_are_line_based() {
        assert_eq!(
            revocation_answers(RevocationReason::Superseded, " new key ").unwrap(),
            "2\nnew key\n\ny\n"
        );
        assert_eq!(
            revocation_answers(RevocationReason::Compromised, "").unwrap(),
            "1\n\ny\n"
        );
        // 説明の改行で、続く問いへの答えを差し込めないように
        assert!(revocation_answers(RevocationReason::Retired, "a\ny\nsave").is_err());
    }
}
