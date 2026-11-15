//! 鍵・サブ鍵・UID がなぜ失効したか（持ち主自身の失効の署名にある理由と説明）。

use serde::{Deserialize, Serialize};

use crate::colons::{Record, unescape};
use crate::gpg::check_fingerprint;
use crate::{Gpg, Result};

/// 失効の理由（失効の署名の理由のコード、RFC 9580 の Reason for Revocation）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevocationCause {
    /// 理由を示していない（知らないコードも含む）。
    Unspecified,
    /// 新しい鍵に置き換えた。
    Superseded,
    /// 秘密鍵が漏れた（またはその恐れがある）。
    Compromised,
    /// もう使わない。
    Retired,
    /// UID がもう正しくない（UID の失効）。
    UserIdInvalid,
}

impl RevocationCause {
    fn from_code(code: &str) -> Self {
        match code {
            "01" => RevocationCause::Superseded,
            "02" => RevocationCause::Compromised,
            "03" => RevocationCause::Retired,
            "32" => RevocationCause::UserIdInvalid,
            _ => RevocationCause::Unspecified,
        }
    }
}

/// 1 つの失効。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revocation {
    pub cause: RevocationCause,
    /// 失効させた人が書いた説明。書いていなければ `None`。
    pub comment: Option<String>,
    pub created: Option<u64>,
}

/// サブ鍵の失効。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubkeyRevocation {
    pub fingerprint: String,
    pub revocation: Revocation,
}

/// UID の失効。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserIdRevocation {
    /// 鍵一覧の `UserId::text` と同じ文字列。
    pub user_id: String,
    pub revocation: Revocation,
}

/// 鍵に付いた、持ち主自身の失効。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revocations {
    pub key: Option<Revocation>,
    pub subkeys: Vec<SubkeyRevocation>,
    pub user_ids: Vec<UserIdRevocation>,
}

impl Gpg {
    /// 鍵・サブ鍵・UID の失効の理由と説明。署名を確かめ（`--check-signatures`）、正しい自己署名の失効だけを読む。
    pub fn revocations(&self, fingerprint: &str) -> Result<Revocations> {
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
        Ok(parse_revocations(
            &String::from_utf8_lossy(&out.stdout),
            fingerprint,
        ))
    }
}

/// 今どの部分の署名を読んでいるか。
enum Part {
    Key,
    Subkey(String),
    UserId(String),
    /// 写真などの属性（`uat`）や、ほかの鍵。
    Other,
}

/// `--check-signatures --with-colons` の出力から、`fingerprint` の鍵の、持ち主自身の失効（`rev`）を取り出す。
/// `rev` の Field 11 は `20x,01` の形（署名の種類と、コンマの後に理由のコード）、Field 21 は説明。
/// 同じものに失効がいくつかあれば、新しいものを使う。
pub fn parse_revocations(output: &str, fingerprint: &str) -> Revocations {
    let mut result = Revocations::default();
    let mut key_matches = false;
    let mut key_id = String::new();
    let mut part = Part::Other;
    // `sub` の直後の `fpr` がサブ鍵のフィンガープリント
    let mut awaiting_subkey_fpr = false;
    for line in output.lines() {
        let r = Record::parse(line);
        match r.kind() {
            "pub" => {
                key_id = r.field(5).unwrap_or_default().to_owned();
                key_matches = false;
                part = Part::Key;
                awaiting_subkey_fpr = false;
            }
            "fpr" if awaiting_subkey_fpr => {
                part = Part::Subkey(r.field(10).unwrap_or_default().to_owned());
                awaiting_subkey_fpr = false;
            }
            "fpr" if matches!(part, Part::Key) && !key_matches => {
                key_matches = r
                    .field(10)
                    .is_some_and(|f| f.eq_ignore_ascii_case(fingerprint));
            }
            "uid" => part = Part::UserId(r.field(10).map(unescape).unwrap_or_default()),
            "uat" => part = Part::Other,
            "sub" => {
                part = Part::Other;
                awaiting_subkey_fpr = true;
            }
            "rev" if key_matches && r.field(2) == Some("!") => {
                let by_owner = r.field(5).is_some_and(|k| k.eq_ignore_ascii_case(&key_id))
                    || r.field(13)
                        .is_some_and(|f| f.eq_ignore_ascii_case(fingerprint));
                if !by_owner {
                    continue;
                }
                let class = r.field(11).unwrap_or_default();
                let revocation = Revocation {
                    cause: class
                        .split_once(',')
                        .map_or(RevocationCause::Unspecified, |(_, code)| {
                            RevocationCause::from_code(code)
                        }),
                    // 説明の改行は `\n` の 2 文字で書かれる
                    comment: r
                        .field(21)
                        .map(|c| unescape(c).replace("\\n", "\n").trim().to_owned())
                        .filter(|c| !c.is_empty()),
                    created: r.field(6).and_then(|t| t.parse().ok()),
                };
                match &part {
                    Part::Key => keep_newer(&mut result.key, revocation),
                    Part::Subkey(fpr) => {
                        match result.subkeys.iter_mut().find(|s| &s.fingerprint == fpr) {
                            Some(s) => replace_if_newer(&mut s.revocation, revocation),
                            None => result.subkeys.push(SubkeyRevocation {
                                fingerprint: fpr.clone(),
                                revocation,
                            }),
                        }
                    }
                    Part::UserId(uid) => {
                        match result.user_ids.iter_mut().find(|u| &u.user_id == uid) {
                            Some(u) => replace_if_newer(&mut u.revocation, revocation),
                            None => result.user_ids.push(UserIdRevocation {
                                user_id: uid.clone(),
                                revocation,
                            }),
                        }
                    }
                    Part::Other => {}
                }
            }
            _ => {}
        }
    }
    result
}

fn keep_newer(slot: &mut Option<Revocation>, new: Revocation) {
    match slot {
        Some(old) => replace_if_newer(old, new),
        None => *slot = Some(new),
    }
}

fn replace_if_newer(old: &mut Revocation, new: Revocation) {
    if new.created >= old.created {
        *old = new;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: &str = "D9E7BDBCA6567E6002B7E37F18603347D2540952";

    #[test]
    fn reads_reasons_and_comments_of_own_revocations() {
        let out = "\
pub:r:255:22:18603347D2540952:1794740275:::u:::sc:::::ed25519:::0:Key is superseded.\\n:
fpr:::::::::D9E7BDBCA6567E6002B7E37F18603347D2540952:
rev:!::22:18603347D2540952:1794740275::::Alice:20x,01::D9E7BDBCA6567E6002B7E37F18603347D2540952:::10:
rev:!::22:18603347D2540952:1794740300::::Alice:20x,02::D9E7BDBCA6567E6002B7E37F18603347D2540952:::10:::::lost laptop\\x3a stolen\\n:
uid:r::::1794740275::6375::Alice Work <alice@work.example>::::::::::0:
sig:!::22:18603347D2540952:1794740275::::Alice:13x::D9E7BDBCA6567E6002B7E37F18603347D2540952:::10:
rev:!::22:18603347D2540952:1794740280::::Alice:30x,32::D9E7BDBCA6567E6002B7E37F18603347D2540952:::10:
uid:u::::1794740275::7777::Alice <alice@example.com>::::::::::0:
rev:!::22:4B01540BB451A080:1794740290::::Bob:30x,00::1B0DF3FC12DD4880A376042C4B01540BB451A080:::10:
rev:-::22:18603347D2540952:1794740290::::Alice:30x,32::D9E7BDBCA6567E6002B7E37F18603347D2540952:::10:
sub:r:255:18:AAAABBBBCCCCDDDD:1794740275::::::e:::::cv25519::
fpr:::::::::1111222233334444555566667777AAAABBBBCCCCDDDD:
rev:!::22:18603347D2540952:1794740285::::Alice:28x,03::D9E7BDBCA6567E6002B7E37F18603347D2540952:::10:::::no longer used:
";
        let r = parse_revocations(out, ALICE);
        // 鍵の失効は新しいほう。説明のエスケープを解き、末尾の改行を落とす
        let key = r.key.unwrap();
        assert_eq!(key.cause, RevocationCause::Compromised);
        assert_eq!(key.comment.as_deref(), Some("lost laptop: stolen"));
        assert_eq!(key.created, Some(1794740300));
        // UID の失効。ほかの人の取り消し（Bob）と、確かめられなかったものは読まない
        assert_eq!(r.user_ids.len(), 1);
        assert_eq!(r.user_ids[0].user_id, "Alice Work <alice@work.example>");
        assert_eq!(
            r.user_ids[0].revocation.cause,
            RevocationCause::UserIdInvalid
        );
        assert_eq!(r.user_ids[0].revocation.comment, None);
        // サブ鍵の失効は、そのサブ鍵のフィンガープリントで
        assert_eq!(r.subkeys.len(), 1);
        assert_eq!(
            r.subkeys[0].fingerprint,
            "1111222233334444555566667777AAAABBBBCCCCDDDD"
        );
        assert_eq!(r.subkeys[0].revocation.cause, RevocationCause::Retired);
        assert_eq!(
            r.subkeys[0].revocation.comment.as_deref(),
            Some("no longer used")
        );
    }

    #[test]
    fn ignores_other_keys() {
        let out = "\
pub:r:255:22:1111111111111111:1:::u:::sc::::::::0:
fpr:::::::::1111111111111111111111111111111111111111:
rev:!::22:1111111111111111:1::::X:20x,02::1111111111111111111111111111111111111111:::10:
";
        assert_eq!(parse_revocations(out, ALICE), Revocations::default());
    }
}
