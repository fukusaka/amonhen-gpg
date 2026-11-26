//! 他者の鍵への署名（鍵の持ち主と UID を確かめたことを、自分の鍵で示す）。信頼の輪の材料になる。

use serde::{Deserialize, Serialize};

use crate::colons::{Record, unescape};
use crate::gpg::{check_fingerprint, check_user_id};
use crate::{Error, Gpg, Result};

/// UID に付いた、ほかの鍵による署名（証明）。持ち主自身の署名（自己署名）は含めない。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Certification {
    /// 署名された UID（鍵一覧の `UserId::text` と同じ文字列）。
    pub user_id: String,
    /// 署名した鍵のフィンガープリント。古い署名には入っていないことがある。
    pub signer_fingerprint: Option<String>,
    /// 署名した鍵の鍵 ID（16 桁）。
    pub signer_key_id: String,
    /// 署名した鍵の主な UID。その鍵が鍵束になければ `None`。
    pub signer_user_id: Option<String>,
    pub created: Option<u64>,
    pub expires: Option<u64>,
    /// 鍵と一緒に書き出される署名か。`false` は書き出さない署名（`--quick-lsign-key`）。
    pub exportable: bool,
    pub check: SignatureCheck,
    /// 署名した人が、あとで署名を取り消した（失効させた）か。
    pub revoked: bool,
}

/// 署名を確かめた結果（`--check-signatures` の Field 2）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureCheck {
    /// `!`: 正しい。
    Good,
    /// `-`: 正しくない（偽物か壊れている）。
    Bad,
    /// `?`: 署名した鍵が鍵束にないので確かめられない。
    MissingKey,
    /// `%` など: 確かめられなかった。
    Error,
}

impl Gpg {
    /// 鍵の UID に自分の鍵で署名する。`user_ids` が空なら有効な UID すべて（鍵一覧の `UserId::text` と同じ文字列で選ぶ）。
    /// `signer` は署名に使う自分の鍵のフィンガープリント（`None` なら gpg の既定の鍵）。`local` なら書き出さない署名
    /// （`--quick-lsign-key`）にし、自分の鍵束の中で有効性を決めるだけで、鍵サーバーには載らない。
    /// 署名済みの UID はそのままにする。FE は署名の前に、フィンガープリントを持ち主と照らし合わせるよう促す。
    pub fn sign_key(
        &self,
        fingerprint: &str,
        user_ids: &[&str],
        signer: Option<&str>,
        local: bool,
    ) -> Result<()> {
        let fingerprint = check_fingerprint(fingerprint)?;
        let mut args = Vec::new();
        if let Some(signer) = signer {
            let signer = check_fingerprint(signer)?;
            // ローカル署名用の鍵は人に渡さないので、その署名を書き出しても誰も確かめられない
            if !local
                && self
                    .list_keys()?
                    .iter()
                    .any(|k| k.fingerprint.eq_ignore_ascii_case(signer) && k.is_local_certifier())
            {
                return Err(Error::InvalidArgument {
                    name: "signer",
                    message: "a key for local signatures signs only locally".into(),
                });
            }
            args.extend(["--local-user", signer]);
        }
        args.push(if local {
            "--quick-lsign-key"
        } else {
            "--quick-sign-key"
        });
        args.extend(["--", fingerprint]);
        for u in user_ids {
            args.push(check_user_id(u)?);
        }
        self.run(&args, None)?;
        Ok(())
    }

    /// 鍵に付けた自分の署名（`signer` の証明）を取り消す。書き出さない署名（ローカル署名）は消す。公開していないので
    /// 消せば済み、秘密鍵も要らない。書き出す署名は失効させる（`--quick-revoke-sig`。主鍵の秘密鍵が要り、パスフレーズは
    /// pinentry が聞く）。失効を他の人に知らせるには、FE がこの鍵を送り直すよう勧める。終わったら、`signer` の取り消して
    /// いない署名が残っていないことを確かめる。
    pub fn withdraw_certifications(
        &self,
        fingerprint: &str,
        signer: &str,
    ) -> Result<WithdrawnCertifications> {
        let fingerprint = check_fingerprint(fingerprint)?;
        let signer = check_fingerprint(signer)?;
        let by_signer = |c: &Certification| {
            c.signer_fingerprint
                .as_deref()
                .is_some_and(|f| f.eq_ignore_ascii_case(signer))
                || signer
                    .to_ascii_uppercase()
                    .ends_with(&c.signer_key_id.to_ascii_uppercase())
        };
        let mine = |c: &Certification| by_signer(c) && !c.revoked;
        let before = self.certifications(fingerprint)?;
        let withdrawn = WithdrawnCertifications {
            deleted: before.iter().filter(|c| mine(c) && !c.exportable).count() as u32,
            revoked: before.iter().filter(|c| mine(c) && c.exportable).count() as u32,
        };
        if withdrawn.deleted > 0 {
            let out = self.run(
                &[
                    "--with-colons",
                    "--fixed-list-mode",
                    "--list-signatures",
                    "--",
                    fingerprint,
                ],
                None,
            )?;
            let answers =
                delsig_answers(&String::from_utf8_lossy(&out.stdout), fingerprint, signer);
            // すべての UID を選んで delsig。gpg は UID の署名を鍵束の並びに 1 つずつ聞くので、一覧と同じ並びで答える
            let input = format!("uid *\ndelsig\n{answers}save\n");
            self.run(
                &["--command-fd", "0", "--edit-key", "--", fingerprint],
                Some(input.as_bytes()),
            )?;
        }
        if withdrawn.revoked > 0 {
            self.run(&["--quick-revoke-sig", "--", fingerprint, signer], None)?;
        }
        // 有効性は trustdb に覚えてあるので、署名が変わったら計算し直させる
        self.run(&["--check-trustdb"], None)?;
        let after = self.certifications(fingerprint)?;
        // 答えがずれて他人の署名を消していないか、自分の署名が残っていないかを確かめる
        let others = |cs: &[Certification]| cs.iter().filter(|c| !by_signer(c)).count();
        if after.iter().any(mine) || others(&after) != others(&before) {
            return Err(crate::Error::Parse {
                line: 0,
                message: "the signatures were not withdrawn as expected".into(),
            });
        }
        Ok(withdrawn)
    }

    /// 自分の鍵がローカル署名した他者の鍵を、ローカル署名ごと書き出す。主鍵のある Mac で署名し、主鍵のない Mac へ
    /// 運ぶため（ローカル署名はふつうの書き出しでは落ちる）。署名は主鍵がしたものなので、運ぶ途中で書き換えられれば
    /// 取り込む側の gpg がはねる。`only` が空でなければ、そのうちの鍵だけ（署名の依頼への返事）。ローカル署名した鍵が
    /// なければ `Error::NotFound`。
    pub fn export_local_signatures(&self, only: &[&str], armor: bool) -> Result<LocalSignatures> {
        for f in only {
            check_fingerprint(f)?;
        }
        let own: Vec<String> = self
            .list_keys()?
            .into_iter()
            .filter(|k| k.secret != crate::SecretState::None)
            .map(|k| k.fingerprint)
            .collect();
        let out = self.run(
            &["--with-colons", "--fixed-list-mode", "--list-signatures"],
            None,
        )?;
        let mut keys = locally_signed_keys(&String::from_utf8_lossy(&out.stdout), &own);
        if !only.is_empty() {
            keys.retain(|k| only.iter().any(|f| f.eq_ignore_ascii_case(k)));
        }
        if keys.is_empty() {
            return Err(crate::Error::NotFound);
        }
        let mut args = vec!["--export-options", "export-local"];
        if armor {
            args.push("--armor");
        }
        args.extend(["--export", "--"]);
        args.extend(keys.iter().map(String::as_str));
        let out = self.run(&args, None)?;
        Ok(LocalSignatures {
            data: out.stdout,
            keys,
        })
    }

    /// 書き出したローカル署名（`export_local_signatures`）を取り込む。鍵束にある鍵にだけ署名を加え
    /// （`merge-only`）、ない鍵は飛ばす（確かめていない鍵が紛れ込まないように。先に受け入れる）。
    pub fn import_local_signatures(&self, data: &[u8]) -> Result<ImportedLocalSignatures> {
        let present: Vec<String> = self
            .list_keys()?
            .into_iter()
            .map(|k| k.fingerprint)
            .collect();
        let in_file = self.show_keys(data)?;
        let mut result = ImportedLocalSignatures::default();
        for key in &in_file {
            if !present
                .iter()
                .any(|f| f.eq_ignore_ascii_case(&key.fingerprint))
            {
                result.missing.push(key.fingerprint.clone());
            }
        }
        // 飛ばす鍵しかなければ、gpg は何も読まなかったと言うので、取り込まない
        if result.missing.len() == in_file.len() {
            return Ok(result);
        }
        let imported = self.run_import(
            &["--import-options", "import-local,merge-only", "--import"],
            Some(data),
        )?;
        for key in imported.keys {
            if result
                .missing
                .iter()
                .any(|f| f.eq_ignore_ascii_case(&key.fingerprint))
            {
                continue;
            }
            if key.new_signatures {
                result.signed.push(key.fingerprint);
            } else {
                result.unchanged.push(key.fingerprint);
            }
        }
        // 有効性は trustdb に覚えてあるので、署名が変わったら計算し直させる
        if !result.signed.is_empty() {
            self.run(&["--check-trustdb"], None)?;
        }
        Ok(result)
    }

    /// 鍵の UID に付いた、ほかの鍵による署名を、確かめたうえで返す（`--check-signatures`）。
    pub fn certifications(&self, fingerprint: &str) -> Result<Vec<Certification>> {
        let fingerprint = check_fingerprint(fingerprint)?;
        let out = self.run(
            &[
                "--with-colons",
                "--fixed-list-mode",
                "--check-signatures",
                "--",
                fingerprint,
            ],
            None,
        )?;
        Ok(parse_certifications(
            &String::from_utf8_lossy(&out.stdout),
            fingerprint,
        ))
    }
}

/// 書き出したローカル署名（`Gpg::export_local_signatures`）。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSignatures {
    /// ローカル署名を含めた公開鍵（`--export-options export-local`）。
    pub data: Vec<u8>,
    /// 書き出した鍵のフィンガープリント。
    pub keys: Vec<String>,
}

/// ローカル署名を取り込んだ結果（`Gpg::import_local_signatures`）。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedLocalSignatures {
    /// 新しい署名が付いた鍵。
    pub signed: Vec<String>,
    /// すでに同じ署名が付いていた鍵。
    pub unchanged: Vec<String>,
    /// 鍵束にないので飛ばした鍵（先に受け入れる）。
    pub missing: Vec<String>,
}

/// 自分の署名を取り消した数。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawnCertifications {
    /// 消したローカル署名。
    pub deleted: u32,
    /// 失効させた、書き出す署名。
    pub revoked: u32,
}

/// `--edit-key` の delsig への答え（1 行ずつ `y` か `n`）。gpg は選んだ UID（写真も）の署名と取り消しを、鍵束の並びに
/// 聞く（自己署名も聞くが消さない）。`signer` のローカル署名（`10l`〜`13l`）にだけ `y` と答える。サブ鍵の署名は聞かない。
fn delsig_answers(output: &str, fingerprint: &str, signer: &str) -> String {
    let mut answers = String::new();
    let mut key_matches = false;
    let mut in_uid = false;
    for line in output.lines() {
        let r = Record::parse(line);
        match r.kind() {
            "pub" => {
                key_matches = false;
                in_uid = false;
            }
            "fpr" if !in_uid && !key_matches => {
                key_matches = r
                    .field(10)
                    .is_some_and(|f| f.eq_ignore_ascii_case(fingerprint));
            }
            "uid" | "uat" => in_uid = key_matches,
            "sub" => in_uid = false,
            "sig" | "rev" if in_uid => {
                let class = r.field(11).unwrap_or_default();
                let local = r.kind() == "sig"
                    && class.len() == 3
                    && ["10", "11", "12", "13"].contains(&&class[..2])
                    && class.ends_with('l');
                let by_signer = r.field(13).is_some_and(|f| f.eq_ignore_ascii_case(signer))
                    || r.field(5).is_some_and(|k| {
                        !k.is_empty()
                            && signer
                                .to_ascii_uppercase()
                                .ends_with(&k.to_ascii_uppercase())
                    });
                answers.push_str(if local && by_signer { "y\n" } else { "n\n" });
            }
            _ => {}
        }
    }
    answers
}

/// `--list-signatures --with-colons` の出力から、`signers`（自分の鍵）のどれかがローカル署名（`10l`〜`13l`）した
/// 鍵を並びのまま返す。`signers` 自身の鍵は入れない（自分の鍵どうしの署名は運ばなくてよい）。
fn locally_signed_keys(output: &str, signers: &[String]) -> Vec<String> {
    let mut keys: Vec<String> = Vec::new();
    let mut current: Option<String> = None;
    let mut want_fpr = false;
    let mut in_uid = false;
    let is_signer = |fpr: Option<&str>, key_id: Option<&str>| {
        signers.iter().any(|s| {
            fpr.is_some_and(|f| f.eq_ignore_ascii_case(s))
                || key_id.is_some_and(|k| {
                    !k.is_empty() && s.to_ascii_uppercase().ends_with(&k.to_ascii_uppercase())
                })
        })
    };
    for line in output.lines() {
        let r = Record::parse(line);
        match r.kind() {
            "pub" => {
                current = None;
                want_fpr = true;
                in_uid = false;
            }
            "fpr" if want_fpr => {
                want_fpr = false;
                current = r
                    .field(10)
                    .map(str::to_owned)
                    .filter(|f| !signers.iter().any(|s| s.eq_ignore_ascii_case(f)));
            }
            "uid" | "uat" => in_uid = true,
            "sub" => in_uid = false,
            "sig" if in_uid => {
                let Some(key) = &current else { continue };
                let class = r.field(11).unwrap_or_default();
                let local = class.len() == 3
                    && ["10", "11", "12", "13"].contains(&&class[..2])
                    && class.ends_with('l');
                if local && is_signer(r.field(13), r.field(5)) && !keys.contains(key) {
                    keys.push(key.clone());
                }
            }
            _ => {}
        }
    }
    keys
}

/// `--check-signatures --with-colons` の出力から、`fingerprint` の鍵の UID に付いた、ほかの鍵の署名を取り出す。
/// `sig` は直前の `uid` のもの（`pub`・`sub` の直後は鍵そのものへの署名なので見ない）。`rev` は署名の取り消しで、
/// 同じ人が同じ UID にした、それより前の署名を取り消したものとして扱う。
pub fn parse_certifications(output: &str, fingerprint: &str) -> Vec<Certification> {
    let mut found: Vec<Certification> = Vec::new();
    let mut key_matches = false;
    let mut user_id: Option<String> = None;
    let mut key_id = String::new();
    let mut revocations: Vec<(String, String, Option<u64>)> = Vec::new();
    for line in output.lines() {
        let r = Record::parse(line);
        match r.kind() {
            "pub" => {
                key_id = r.field(5).unwrap_or_default().to_owned();
                key_matches = false;
                user_id = None;
            }
            "fpr" if user_id.is_none() && !key_matches => {
                key_matches = r
                    .field(10)
                    .is_some_and(|f| f.eq_ignore_ascii_case(fingerprint));
            }
            "uid" => user_id = Some(r.field(10).map(unescape).unwrap_or_default()),
            "uat" | "sub" => user_id = None,
            "sig" | "rev" if key_matches => {
                let Some(uid) = &user_id else { continue };
                let signer_key_id = r.field(5).unwrap_or_default().to_owned();
                let signer_fingerprint = r.field(13).map(str::to_owned);
                // 自己署名
                if signer_key_id.eq_ignore_ascii_case(&key_id)
                    || signer_fingerprint
                        .as_deref()
                        .is_some_and(|f| f.eq_ignore_ascii_case(fingerprint))
                {
                    continue;
                }
                let created = r.field(6).and_then(|t| t.parse().ok());
                if r.kind() == "rev" {
                    // gpg は取り消しを、取り消した署名より前に並べることがある（`--quick-revoke-sig` のあと）ので、終わりに当てる。
                    // 同じ秒の署名は gpg も取り消されたと見なさない（新しい署名が取り消しに勝つ）ので、それより前の署名だけ
                    revocations.push((uid.clone(), signer_key_id, created));
                    continue;
                }
                let class = r.field(11).unwrap_or_default();
                found.push(Certification {
                    user_id: uid.clone(),
                    signer_fingerprint,
                    signer_key_id,
                    signer_user_id: r.field(10).map(unescape),
                    created,
                    expires: r.field(7).and_then(|t| t.parse().ok()),
                    exportable: !class.ends_with('l'),
                    check: match r.field(2) {
                        Some("!") => SignatureCheck::Good,
                        Some("-") => SignatureCheck::Bad,
                        Some("?") => SignatureCheck::MissingKey,
                        _ => SignatureCheck::Error,
                    },
                    revoked: false,
                });
            }
            _ => {}
        }
    }
    for (uid, signer, created) in revocations {
        for c in found.iter_mut().filter(|c| {
            c.user_id == uid && c.signer_key_id.eq_ignore_ascii_case(&signer) && c.created < created
        }) {
            c.revoked = true;
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOB: &str = "2BFEB4F107E714F45918402013E0390F0F502517";

    #[test]
    fn reads_certifications_and_skips_self_signatures() {
        let out = "\
tru:o:1:1794576437:1:3:1:5
pub:u:255:22:13E0390F0F502517:1794576436:::u:::scSC:::::ed25519:::0:
fpr:::::::::2BFEB4F107E714F45918402013E0390F0F502517:
uid:u::::1794576437::1E6B::Bob <bob@work.example>::::::::::0:
sig:!::22:13E0390F0F502517:1794576437::::Bob <bob@work.example>:13x::2BFEB4F107E714F45918402013E0390F0F502517:::10:
sig:?::22:D8A03462583A69C3:1794576437:::::10x::D927C57B1814F12165C68886D8A03462583A69C3:::10:
uid:u::::1794576436::2B04::Bob <b@example.com>::::::::::0:
sig:!::22:13E0390F0F502517:1794576436::::Bob <bob@work.example>:13x::2BFEB4F107E714F45918402013E0390F0F502517:::10:
sig:!::22:4B01540BB451A080:1794576437::::Alice \\x3a A <a@example.com>:10l::1B0DF3FC12DD4880A376042C4B01540BB451A080:::10:
sig:-::22:D8A03462583A69C3:1794576437:1800000000:::Carol <c@example.com>:10x::D927C57B1814F12165C68886D8A03462583A69C3:::10:
rev:!::22:D8A03462583A69C3:1794576500::::Carol <c@example.com>:30x::D927C57B1814F12165C68886D8A03462583A69C3:::10:
sub:u:255:18:AAAA:1794576436::::::e:::::cv25519::
sig:!::22:4B01540BB451A080:1794576437::::Alice:18x::1B0DF3FC12DD4880A376042C4B01540BB451A080:::10:
";
        let c = parse_certifications(out, BOB);
        assert_eq!(c.len(), 3);
        assert_eq!(c[0].user_id, "Bob <bob@work.example>");
        assert_eq!(c[0].check, SignatureCheck::MissingKey);
        assert_eq!(c[0].signer_user_id, None);
        assert_eq!(c[0].signer_key_id, "D8A03462583A69C3");
        assert!(c[0].exportable && !c[0].revoked);
        assert_eq!(c[1].user_id, "Bob <b@example.com>");
        assert_eq!(
            c[1].signer_user_id.as_deref(),
            Some("Alice : A <a@example.com>")
        );
        assert_eq!(
            c[1].signer_fingerprint.as_deref(),
            Some("1B0DF3FC12DD4880A376042C4B01540BB451A080")
        );
        assert_eq!(c[1].created, Some(1794576437));
        assert!(!c[1].exportable);
        assert_eq!(c[2].check, SignatureCheck::Bad);
        assert_eq!(c[2].expires, Some(1800000000));
        assert!(c[2].revoked);
    }

    #[test]
    fn applies_a_revocation_listed_before_its_signature() {
        let out = "\
pub:u:255:22:13E0390F0F502517:1794576436:::u:::scSC:::::ed25519:::0:
fpr:::::::::2BFEB4F107E714F45918402013E0390F0F502517:
uid:u::::1794576437::1E6B::Bob <bob@work.example>::::::::::0:
rev:!::22:4B01540BB451A080:1794576500::::Alice:30x,00::1B0DF3FC12DD4880A376042C4B01540BB451A080:::10:
sig:!::22:13E0390F0F502517:1794576437::::Bob:13x::2BFEB4F107E714F45918402013E0390F0F502517:::10:
sig:!::22:4B01540BB451A080:1794576437::::Alice:10x::1B0DF3FC12DD4880A376042C4B01540BB451A080:::10:
";
        let c = parse_certifications(out, BOB);
        assert_eq!(c.len(), 1);
        assert!(c[0].revoked);
    }

    #[test]
    fn answers_delsig_for_local_signatures_by_the_signer() {
        let out = "\
pub:u:255:22:13E0390F0F502517:1794576436:::u:::scSC:::::ed25519:::0:
fpr:::::::::2BFEB4F107E714F45918402013E0390F0F502517:
uid:u::::1794576437::1E6B::Bob <bob@work.example>::::::::::0:
sig:::22:13E0390F0F502517:1794576437::::Bob:13x::2BFEB4F107E714F45918402013E0390F0F502517:::10:
sig:::22:4B01540BB451A080:1794576437::::Alice:10l::1B0DF3FC12DD4880A376042C4B01540BB451A080:::10:
sig:::22:4B01540BB451A080:1794576437::::Alice:10x::1B0DF3FC12DD4880A376042C4B01540BB451A080:::10:
sig:::22:D8A03462583A69C3:1794576437::::Carol:10l::D927C57B1814F12165C68886D8A03462583A69C3:::10:
uid:u::::1794576436::2B04::Bob <b@example.com>::::::::::0:
rev:::22:4B01540BB451A080:1794576500::::Alice:30x::1B0DF3FC12DD4880A376042C4B01540BB451A080:::10:
sig:::22:4B01540BB451A080:1794576437::::Alice:13l:::::10:
sub:u:255:18:AAAA:1794576436::::::e:::::cv25519::
sig:::22:13E0390F0F502517:1794576437::::Bob:18x::2BFEB4F107E714F45918402013E0390F0F502517:::10:
";
        let alice = "1B0DF3FC12DD4880A376042C4B01540BB451A080";
        // 自己署名・書き出す署名・他人のローカル署名・取り消しには n、サブ鍵の署名は聞かれない
        assert_eq!(delsig_answers(out, BOB, alice), "n\ny\nn\nn\nn\ny\n");
        assert_eq!(
            delsig_answers(out, "1111111111111111111111111111111111111111", alice),
            ""
        );
    }

    #[test]
    fn ignores_other_keys() {
        let out = "\
pub:u:255:22:1111111111111111:1:::u:::scSC::::::::0:
fpr:::::::::1111111111111111111111111111111111111111:
uid:u::::1::AA::X <x@example.com>::::::::::0:
sig:!::22:2222222222222222:1::::Y:10x::2222222222222222222222222222222222222222:::10:
";
        assert!(parse_certifications(out, BOB).is_empty());
    }

    #[test]
    fn finds_keys_with_own_local_signatures() {
        let alice = "1B0DF3FC12DD4880A376042C4B01540BB451A080".to_owned();
        // Bob: Alice のローカル署名あり。Carol: Alice の書き出す署名だけ。Dave: 他人のローカル署名と、Alice の
        // サブ鍵への署名だけ。Erin: フィンガープリントのない古い署名（鍵 ID で見る）。Alice 自身は入れない
        let out = "\
pub:u:255:22:4B01540BB451A080:1::::::cSC:::::ed25519:::0:
fpr:::::::::1B0DF3FC12DD4880A376042C4B01540BB451A080:
uid:u::::1::1::Alice <a@example.com>::::::::::0:
sig:!::22:4B01540BB451A080:1::::Alice:13x::1B0DF3FC12DD4880A376042C4B01540BB451A080:::10:
sig:!::22:4B01540BB451A080:1::::Alice:10l::1B0DF3FC12DD4880A376042C4B01540BB451A080:::10:
pub:f:255:22:13E0390F0F502517:1::::::scSC:::::ed25519:::0:
fpr:::::::::2BFEB4F107E714F45918402013E0390F0F502517:
uid:f::::1::2::Bob <b@example.com>::::::::::0:
sig:!::22:13E0390F0F502517:1::::Bob:13x::2BFEB4F107E714F45918402013E0390F0F502517:::10:
sig:!::22:4B01540BB451A080:2::::Alice:10l::1B0DF3FC12DD4880A376042C4B01540BB451A080:::10:
uid:f::::1::3::Bob Work <b@work.example>::::::::::0:
sig:!::22:4B01540BB451A080:2::::Alice:10l::1B0DF3FC12DD4880A376042C4B01540BB451A080:::10:
pub:f:255:22:3333333333333333:1::::::scSC:::::ed25519:::0:
fpr:::::::::3333333333333333333333333333333333333333:
uid:f::::1::4::Carol <c@example.com>::::::::::0:
sig:!::22:4B01540BB451A080:2::::Alice:10x::1B0DF3FC12DD4880A376042C4B01540BB451A080:::10:
pub:-:255:22:4444444444444444:1::::::scSC:::::ed25519:::0:
fpr:::::::::4444444444444444444444444444444444444444:
uid:-::::1::5::Dave <d@example.com>::::::::::0:
sig:!::22:5555555555555555:2::::Eve:10l::5555555555555555555555555555555555555555:::10:
sub:-:255:18:6666666666666666:1::::::e:::::cv25519::
fpr:::::::::6666666666666666666666666666666666666666:
sig:!::22:4B01540BB451A080:2::::Alice:18l::1B0DF3FC12DD4880A376042C4B01540BB451A080:::10:
pub:f:255:22:7777777777777777:1::::::scSC:::::ed25519:::0:
fpr:::::::::7777777777777777777777777777777777777777:
uid:f::::1::6::Erin <e@example.com>::::::::::0:
sig:!::17:4B01540BB451A080:2::::Alice:12l:::::2:
";
        assert_eq!(
            locally_signed_keys(out, &[alice]),
            [
                "2BFEB4F107E714F45918402013E0390F0F502517",
                "7777777777777777777777777777777777777777"
            ]
        );
        assert!(locally_signed_keys(out, &[]).is_empty());
    }
}
