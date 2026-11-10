//! FE に渡す鍵の型。gpg の出力の形（colon 形式）はここに出さない。

use serde::{Deserialize, Serialize};

/// 主鍵と、そのサブ鍵・UID。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Key {
    pub fingerprint: String,
    pub key_id: String,
    pub keygrip: Option<String>,
    pub validity: Validity,
    /// 所有者信頼（`--edit-key` の `trust` で決めるもの）。
    pub owner_trust: Validity,
    /// OpenPGP のアルゴリズム番号（RFC 9580。1 = RSA、22 = EdDSA など）。
    pub algorithm: u32,
    pub length: u32,
    /// ECC の曲線の名前（`ed25519` など）。
    pub curve: Option<String>,
    /// UNIX 時刻（秒）。
    pub created: Option<u64>,
    pub expires: Option<u64>,
    /// この鍵自身ができること。
    pub capabilities: Capabilities,
    /// 鍵全体として今使えること（サブ鍵を含む。失効・期限切れのものは除く）。
    pub usable: Capabilities,
    pub disabled: bool,
    pub secret: SecretState,
    pub subkeys: Vec<Subkey>,
    pub user_ids: Vec<UserId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subkey {
    pub fingerprint: String,
    pub key_id: String,
    pub keygrip: Option<String>,
    pub validity: Validity,
    pub algorithm: u32,
    pub length: u32,
    pub curve: Option<String>,
    pub created: Option<u64>,
    pub expires: Option<u64>,
    pub capabilities: Capabilities,
    pub secret: SecretState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserId {
    /// `Name (Comment) <email>` の形の文字列。写真などの属性（`uat`）のときは gpg の要約。
    pub text: String,
    pub validity: Validity,
    pub created: Option<u64>,
    pub expires: Option<u64>,
    /// gpg が UID ごとに付けるハッシュ（`--quick-revoke-uid` などで UID を指すのには使わないが、同じ UID かを見分けられる）。
    pub hash: Option<String>,
    /// 写真などの属性（`uat`）。
    pub attribute: bool,
}

/// 有効性・信頼の度合い（`doc/DETAILS` の Field 2）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Validity {
    /// `o`: まだ計算していない。
    New,
    /// `i`: 不正（自己署名がないなど）。
    Invalid,
    /// `d`: 無効にしてある。
    Disabled,
    /// `r`: 失効している。
    Revoked,
    /// `e`: 期限切れ。
    Expired,
    /// `-`・`q`・空: 分からない。
    Unknown,
    /// `n`: 信頼しない。
    Never,
    /// `m`: 少し信頼する。
    Marginal,
    /// `f`: 十分に信頼する。
    Full,
    /// `u`: 絶対的に信頼する（自分の鍵）。
    Ultimate,
    /// `w`: よく知られた秘密鍵。
    WellKnown,
    /// `s`: 特別な有効性（S/MIME の鍵など）。
    Special,
}

impl Validity {
    pub fn from_flag(flag: Option<&str>) -> Self {
        match flag.and_then(|f| f.chars().next()) {
            Some('o') => Validity::New,
            Some('i') => Validity::Invalid,
            Some('d') => Validity::Disabled,
            Some('r') => Validity::Revoked,
            Some('e') => Validity::Expired,
            Some('n') => Validity::Never,
            Some('m') => Validity::Marginal,
            Some('f') => Validity::Full,
            Some('u') => Validity::Ultimate,
            Some('w') => Validity::WellKnown,
            Some('s') => Validity::Special,
            _ => Validity::Unknown,
        }
    }
}

/// 鍵の用途（`doc/DETAILS` の Field 12）。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    pub certify: bool,
    pub sign: bool,
    pub encrypt: bool,
    /// 認証。SSH 鍵として使えるのはこれを持つ鍵。
    pub authenticate: bool,
}

impl Capabilities {
    /// 小文字（この鍵自身）か大文字（鍵全体）の一方だけを読む。
    pub fn from_flags(flags: Option<&str>, uppercase: bool) -> Self {
        let mut caps = Capabilities::default();
        for c in flags.unwrap_or("").chars() {
            if c.is_ascii_uppercase() != uppercase {
                continue;
            }
            match c.to_ascii_lowercase() {
                'c' => caps.certify = true,
                's' => caps.sign = true,
                'e' => caps.encrypt = true,
                'a' => caps.authenticate = true,
                _ => {}
            }
        }
        caps
    }
}

/// 秘密鍵がどこにあるか（`--with-secret` のときの Field 15）。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretState {
    /// 秘密鍵はない（公開鍵だけ）。
    None,
    /// gpg-agent が持っている（`+`）。
    Available,
    /// スタブだけ（`#`）。秘密鍵は別の場所に移してある。
    Stub,
    /// スマートカードにある。カードのシリアル番号。
    OnCard(String),
}

impl SecretState {
    pub fn from_field(field: Option<&str>) -> Self {
        match field {
            None => SecretState::None,
            Some("+") => SecretState::Available,
            Some("#") => SecretState::Stub,
            Some(serial) => SecretState::OnCard(serial.to_owned()),
        }
    }
}
