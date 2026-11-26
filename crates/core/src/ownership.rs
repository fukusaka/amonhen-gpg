//! 自分の鍵の判定と、主画面の段（使える／この PC では使えない／使えた鍵）。画面の方針は `docs/ui.md`。

use serde::{Deserialize, Serialize};

use crate::model::{Key, SecretState, Validity};

/// 主画面での段。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tier {
    /// 有効で、署名・復号・認証のどれかの秘密鍵がこの PC かカードにある。
    Usable,
    /// 有効だが、秘密鍵がこの PC にない（公開鍵だけ、またはスタブだけ）。
    NotOnThisDevice,
    /// 期限切れ・失効した、使えた鍵。
    History,
}

/// ある用途に、どこで使えるか。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Availability {
    /// この PC（gpg-agent）にある秘密鍵で使える。
    ThisDevice,
    /// スマートカードの秘密鍵で使える。カードのシリアル番号。
    Card(String),
    /// その用途の鍵はあるが、秘密鍵がここにない。
    Elsewhere,
    /// その用途の有効な鍵がない。
    None,
}

impl Availability {
    pub fn is_usable(&self) -> bool {
        matches!(self, Availability::ThisDevice | Availability::Card(_))
    }

    /// 良いほうを選ぶ（この PC > カード > ほかの場所 > ない）。
    fn rank(&self) -> u8 {
        match self {
            Availability::ThisDevice => 3,
            Availability::Card(_) => 2,
            Availability::Elsewhere => 1,
            Availability::None => 0,
        }
    }
}

/// 自分の鍵の状態。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyStatus {
    pub tier: Tier,
    /// 証明（有効期限の延長・UID やサブ鍵の追加・他人の鍵への署名）。主鍵の秘密鍵が要る。
    pub certify: Availability,
    pub sign: Availability,
    /// 復号（暗号化の用途の鍵の秘密鍵）。
    pub decrypt: Availability,
    /// 認証（SSH）。
    pub authenticate: Availability,
}

impl Key {
    /// 自分の鍵か。所有者信頼が絶対的か、秘密鍵（スタブ・カード上を含む）がある鍵。秘密鍵の有無だけで決めると、
    /// 秘密鍵が別の PC にある自分の鍵が漏れる。
    pub fn is_mine(&self) -> bool {
        self.owner_trust == Validity::Ultimate
            || self.secret != SecretState::None
            || self.subkeys.iter().any(|s| s.secret != SecretState::None)
    }

    /// ローカル署名用の鍵か（主鍵のない Mac で、他者の鍵をその Mac の中だけで有効にするために作る鍵）。
    /// 名前ではなく形で見分ける: 主鍵が証明だけの鍵で、サブ鍵がなく、どの UID にもメールアドレスがない。
    /// ふつうの鍵はデータの署名か暗号化の鍵を持ち、人に渡すのでメールアドレスを付ける。
    pub fn is_local_certifier(&self) -> bool {
        let caps = self.capabilities;
        caps.certify
            && !caps.sign
            && !caps.encrypt
            && !caps.authenticate
            && self.subkeys.is_empty()
            && self
                .user_ids
                .iter()
                .all(|u| u.attribute || !u.text.contains('@'))
    }

    /// 主画面での段と、用途ごとにどこで使えるか。`now` は UNIX 時刻（秒）。
    pub fn status(&self, now: u64) -> KeyStatus {
        let primary_alive = alive(self.validity, self.expires, now);
        let primary = [(
            primary_alive && !self.disabled,
            self.capabilities,
            &self.secret,
        )];
        let parts = primary.into_iter().chain(self.subkeys.iter().map(|s| {
            (
                primary_alive && alive(s.validity, s.expires, now),
                s.capabilities,
                &s.secret,
            )
        }));

        let mut status = KeyStatus {
            tier: Tier::History,
            certify: Availability::None,
            sign: Availability::None,
            decrypt: Availability::None,
            authenticate: Availability::None,
        };
        for (ok, caps, secret) in parts {
            if !ok {
                continue;
            }
            let here = match secret {
                SecretState::Available => Availability::ThisDevice,
                SecretState::OnCard(serial) => Availability::Card(serial.clone()),
                SecretState::Stub | SecretState::None => Availability::Elsewhere,
            };
            for (has, slot) in [
                (caps.certify, &mut status.certify),
                (caps.sign, &mut status.sign),
                (caps.encrypt, &mut status.decrypt),
                (caps.authenticate, &mut status.authenticate),
            ] {
                if has && here.rank() > slot.rank() {
                    *slot = here.clone();
                }
            }
        }

        status.tier = if !primary_alive {
            Tier::History
        } else if [&status.sign, &status.decrypt, &status.authenticate]
            .iter()
            .any(|a| a.is_usable())
            // ローカル署名用の鍵は、証明にしか使わない
            || (self.is_local_certifier() && status.certify.is_usable())
        {
            Tier::Usable
        } else {
            Tier::NotOnThisDevice
        };
        status
    }
}

/// 失効・期限切れでない。gpg の有効性は一覧を取った時点のものなので、期限も `now` で確かめる。
fn alive(validity: Validity, expires: Option<u64>, now: u64) -> bool {
    !matches!(
        validity,
        Validity::Revoked | Validity::Expired | Validity::Invalid
    ) && !expires.is_some_and(|t| t <= now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Capabilities, Subkey};

    const NOW: u64 = 1_750_000_000;

    fn caps(flags: &str) -> Capabilities {
        Capabilities::from_flags(Some(flags), false)
    }

    fn key(owner_trust: Validity, secret: SecretState, subkeys: Vec<Subkey>) -> Key {
        Key {
            fingerprint: "A".repeat(40),
            key_id: "A".repeat(16),
            keygrip: None,
            validity: Validity::Ultimate,
            owner_trust,
            algorithm: 22,
            length: 255,
            curve: Some("ed25519".into()),
            created: Some(1_700_000_000),
            expires: None,
            capabilities: caps("sc"),
            usable: Capabilities::default(),
            disabled: false,
            secret,
            subkeys,
            user_ids: Vec::new(),
            origin: crate::KeyOrigin::Generated,
            origin_url: None,
            last_update: None,
        }
    }

    fn sub(flags: &str, secret: SecretState, expires: Option<u64>) -> Subkey {
        Subkey {
            fingerprint: "B".repeat(40),
            key_id: "B".repeat(16),
            keygrip: None,
            validity: Validity::Ultimate,
            algorithm: 18,
            length: 255,
            curve: Some("cv25519".into()),
            created: Some(1_700_000_000),
            expires,
            capabilities: caps(flags),
            secret,
        }
    }

    #[test]
    fn key_with_secret_here_is_usable() {
        let k = key(
            Validity::Ultimate,
            SecretState::Available,
            vec![
                sub("e", SecretState::Available, None),
                sub("a", SecretState::OnCard("D276".into()), None),
            ],
        );
        assert!(k.is_mine());
        let s = k.status(NOW);
        assert_eq!(s.tier, Tier::Usable);
        assert_eq!(s.certify, Availability::ThisDevice);
        assert_eq!(s.sign, Availability::ThisDevice);
        assert_eq!(s.decrypt, Availability::ThisDevice);
        assert_eq!(s.authenticate, Availability::Card("D276".into()));
    }

    #[test]
    fn own_key_with_secret_elsewhere_is_not_on_this_device() {
        let k = key(
            Validity::Ultimate,
            SecretState::None,
            vec![sub("e", SecretState::None, None)],
        );
        assert!(k.is_mine());
        let s = k.status(NOW);
        assert_eq!(s.tier, Tier::NotOnThisDevice);
        assert_eq!(s.sign, Availability::Elsewhere);
        assert_eq!(s.authenticate, Availability::None);
    }

    #[test]
    fn offline_primary_still_usable_through_subkeys() {
        let k = key(
            Validity::Ultimate,
            SecretState::Stub,
            vec![sub("e", SecretState::Available, None)],
        );
        let s = k.status(NOW);
        assert_eq!(s.tier, Tier::Usable);
        assert_eq!(s.certify, Availability::Elsewhere);
        assert_eq!(s.decrypt, Availability::ThisDevice);
    }

    #[test]
    fn expired_subkeys_do_not_count() {
        let k = key(
            Validity::Ultimate,
            SecretState::Stub,
            vec![sub("e", SecretState::Available, Some(NOW - 1))],
        );
        let s = k.status(NOW);
        assert_eq!(s.decrypt, Availability::None);
        assert_eq!(s.tier, Tier::NotOnThisDevice);
    }

    #[test]
    fn expired_or_revoked_primary_is_history() {
        let mut k = key(Validity::Ultimate, SecretState::Available, vec![]);
        k.expires = Some(NOW);
        assert_eq!(k.status(NOW).tier, Tier::History);
        assert_eq!(k.status(NOW).sign, Availability::None);

        let mut k = key(Validity::Ultimate, SecretState::Available, vec![]);
        k.validity = Validity::Revoked;
        assert_eq!(k.status(NOW).tier, Tier::History);
    }

    #[test]
    fn local_certifier_is_usable_for_certifying() {
        let mut k = key(Validity::Ultimate, SecretState::Available, vec![]);
        k.capabilities = caps("c");
        k.user_ids = vec![crate::model::UserId {
            text: "Local certifications (Studio)".into(),
            validity: Validity::Ultimate,
            created: None,
            expires: None,
            hash: None,
            attribute: false,
        }];
        assert!(k.is_local_certifier());
        let s = k.status(NOW);
        assert_eq!(s.tier, Tier::Usable);
        assert_eq!(s.certify, Availability::ThisDevice);

        // メールアドレスがあるか、サブ鍵があれば、ふつうの鍵
        let mut with_email = k.clone();
        with_email.user_ids[0].text = "Alice <alice@example.com>".into();
        assert!(!with_email.is_local_certifier());
        let mut with_subkey = k.clone();
        with_subkey.subkeys = vec![sub("e", SecretState::Available, None)];
        assert!(!with_subkey.is_local_certifier());
        // 署名もできる主鍵は違う
        let mut signing = k;
        signing.capabilities = caps("sc");
        assert!(!signing.is_local_certifier());
        assert_eq!(signing.status(NOW).tier, Tier::Usable);
    }

    #[test]
    fn others_keys_are_not_mine() {
        let k = key(Validity::Full, SecretState::None, vec![]);
        assert!(!k.is_mine());
        let k = key(Validity::Unknown, SecretState::None, vec![]);
        assert!(!k.is_mine());
    }
}
