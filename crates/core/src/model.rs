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
    /// どこから取り込んだか（gpg が最初に取り込んだときに記録する）。
    pub origin: KeyOrigin,
    /// 取り込んだ先の URL（鍵サーバー・WKD・URL から取り込んだとき）。
    pub origin_url: Option<String>,
    /// 鍵サーバーや WKD から最後に取り直した日時。
    pub last_update: Option<u64>,
}

/// 鍵をどこから取り込んだか（`--with-key-origin` の Field 20。`--key-origin` で渡す名前と対応する）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyOrigin {
    Unknown,
    /// 鍵サーバー（`ks`）。
    Keyserver,
    /// 鍵が指定した、好みの鍵サーバー（`ks-pref`）。
    PreferredKeyserver,
    /// DNS（DANE、`dane`）。
    Dane,
    /// メールアドレスのドメインが公開している鍵（WKD、`wkd`）。
    Wkd,
    /// URL（`url`）。
    Url,
    /// ファイル（`file`）。
    File,
    /// この鍵束で作った鍵（`self`）。
    Generated,
}

impl KeyOrigin {
    /// Field 20 の数（`doc/DETAILS` の KEYORG_*）。知らない数は `Unknown`。
    pub(crate) fn from_number(n: Option<&str>) -> Self {
        match n {
            Some("1") => KeyOrigin::Keyserver,
            Some("2") => KeyOrigin::PreferredKeyserver,
            Some("3") => KeyOrigin::Dane,
            Some("4") => KeyOrigin::Wkd,
            Some("5") => KeyOrigin::Url,
            Some("6") => KeyOrigin::File,
            Some("7") => KeyOrigin::Generated,
            _ => KeyOrigin::Unknown,
        }
    }

    /// `--key-origin` に渡す名前。`Unknown` は渡さない。
    pub(crate) fn option_name(self) -> Option<&'static str> {
        match self {
            KeyOrigin::Unknown => None,
            KeyOrigin::Keyserver => Some("ks"),
            KeyOrigin::PreferredKeyserver => Some("ks-pref"),
            KeyOrigin::Dane => Some("dane"),
            KeyOrigin::Wkd => Some("wkd"),
            KeyOrigin::Url => Some("url"),
            KeyOrigin::File => Some("file"),
            KeyOrigin::Generated => Some("self"),
        }
    }
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

    /// `--quick-gen-key`・`--quick-add-key` の用途の引数（`cert,sign` など）。何もなければ `None`。
    pub fn usage(&self) -> Option<String> {
        let names = [
            (self.certify, "cert"),
            (self.sign, "sign"),
            (self.encrypt, "encr"),
            (self.authenticate, "auth"),
        ];
        let usage: Vec<_> = names
            .iter()
            .filter(|(on, _)| *on)
            .map(|(_, n)| *n)
            .collect();
        (!usage.is_empty()).then(|| usage.join(","))
    }
}

/// 鍵を作るときの指定。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerateKey {
    /// `Name <email>` の形。
    pub user_id: String,
    /// `ed25519`・`rsa4096` など。`None` なら gpg の既定。
    pub algorithm: Option<String>,
    /// 主鍵の用途。`None` なら gpg の既定（既定のアルゴリズムでは暗号化用のサブ鍵も作る）。
    pub capabilities: Option<Capabilities>,
    pub expires: Expiry,
}

/// 有効期限の指定。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Expiry {
    Never,
    /// 今日から何日後か。
    Days(u32),
}

/// 取り込みの結果（`IMPORT_RES` と `IMPORT_OK`）。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportResult {
    /// 読んだ鍵の数。
    pub considered: u32,
    pub no_user_id: u32,
    /// 新しく加えた鍵。
    pub imported: u32,
    /// すでにあって、変わらなかった鍵。
    pub unchanged: u32,
    pub new_user_ids: u32,
    pub new_subkeys: u32,
    pub new_signatures: u32,
    pub new_revocations: u32,
    pub secret_read: u32,
    pub secret_imported: u32,
    pub secret_unchanged: u32,
    /// 取り込めなかった鍵。
    pub not_imported: u32,
    pub keys: Vec<ImportedKey>,
}

impl ImportResult {
    /// 何回かに分けて取り込んだ結果を足し合わせる。
    pub(crate) fn add(&mut self, other: ImportResult) {
        self.considered += other.considered;
        self.no_user_id += other.no_user_id;
        self.imported += other.imported;
        self.unchanged += other.unchanged;
        self.new_user_ids += other.new_user_ids;
        self.new_subkeys += other.new_subkeys;
        self.new_signatures += other.new_signatures;
        self.new_revocations += other.new_revocations;
        self.secret_read += other.secret_read;
        self.secret_imported += other.secret_imported;
        self.secret_unchanged += other.secret_unchanged;
        self.not_imported += other.not_imported;
        self.keys.extend(other.keys);
    }
}

/// 取り込んだ（または変わらなかった）1 つの鍵。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedKey {
    pub fingerprint: String,
    pub new_key: bool,
    pub new_user_ids: bool,
    pub new_signatures: bool,
    pub new_subkeys: bool,
    /// 秘密鍵を含んでいた。
    pub secret: bool,
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
