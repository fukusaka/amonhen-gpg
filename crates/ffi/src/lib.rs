//! FE（Swift・C#）向けの窓口。UniFFI でコアの公開 API をそのまま出す。
//!
//! コアは FFI を知らないので、コアの型はここで `#[uniffi::remote]` として形を書き写す（コアの型を変えたら、ここも
//! 合わせないとコンパイルが通らない）。エラーだけは、OS のエラーなど FFI に載らないものを持つので、ここの型に移す。
//! gpg を待つ呼び出し（pinentry を含む）は時間がかかるので、FE は裏のスレッドから呼ぶ。

#![deny(unsafe_code)]

use std::path::PathBuf;
use std::sync::Arc;

use amonhen_core::status::Failure;
use amonhen_core::{
    Availability, Capabilities, Card, Expiry, GenerateKey, ImportResult, ImportedKey, Key,
    KeyStatus, OwnerTrust, RevocationReason, SecretState, SshControl, SshKey, SshSupport, Subkey,
    Tier, UserId, Validity, Version,
};

uniffi::setup_scaffolding!();

// パスは文字列で渡す（FE の多くはパスを文字列で持つ）
uniffi::custom_type!(PathBuf, String, {
    remote,
    lower: |path| path.to_string_lossy().into_owned(),
    try_lift: |text| Ok(PathBuf::from(text)),
});

#[uniffi::remote(Record)]
pub struct Key {
    pub fingerprint: String,
    pub key_id: String,
    pub keygrip: Option<String>,
    pub validity: Validity,
    pub owner_trust: Validity,
    pub algorithm: u32,
    pub length: u32,
    pub curve: Option<String>,
    pub created: Option<u64>,
    pub expires: Option<u64>,
    pub capabilities: Capabilities,
    pub usable: Capabilities,
    pub disabled: bool,
    pub secret: SecretState,
    pub subkeys: Vec<Subkey>,
    pub user_ids: Vec<UserId>,
}

#[uniffi::remote(Record)]
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

#[uniffi::remote(Record)]
pub struct UserId {
    pub text: String,
    pub validity: Validity,
    pub created: Option<u64>,
    pub expires: Option<u64>,
    pub hash: Option<String>,
    pub attribute: bool,
}

#[uniffi::remote(Enum)]
pub enum Validity {
    New,
    Invalid,
    Disabled,
    Revoked,
    Expired,
    Unknown,
    Never,
    Marginal,
    Full,
    Ultimate,
    WellKnown,
    Special,
}

#[uniffi::remote(Record)]
pub struct Capabilities {
    pub certify: bool,
    pub sign: bool,
    pub encrypt: bool,
    pub authenticate: bool,
}

#[uniffi::remote(Enum)]
pub enum SecretState {
    None,
    Available,
    Stub,
    OnCard(String),
}

#[uniffi::remote(Record)]
pub struct GenerateKey {
    pub user_id: String,
    pub algorithm: Option<String>,
    pub capabilities: Option<Capabilities>,
    pub expires: Expiry,
}

#[uniffi::remote(Enum)]
pub enum Expiry {
    Never,
    Days(u32),
}

#[uniffi::remote(Record)]
pub struct ImportResult {
    pub considered: u32,
    pub no_user_id: u32,
    pub imported: u32,
    pub unchanged: u32,
    pub new_user_ids: u32,
    pub new_subkeys: u32,
    pub new_signatures: u32,
    pub new_revocations: u32,
    pub secret_read: u32,
    pub secret_imported: u32,
    pub secret_unchanged: u32,
    pub not_imported: u32,
    pub keys: Vec<ImportedKey>,
}

#[uniffi::remote(Record)]
pub struct ImportedKey {
    pub fingerprint: String,
    pub new_key: bool,
    pub new_user_ids: bool,
    pub new_signatures: bool,
    pub new_subkeys: bool,
    pub secret: bool,
}

#[uniffi::remote(Record)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

#[uniffi::remote(Enum)]
pub enum Tier {
    Usable,
    NotOnThisDevice,
    History,
}

#[uniffi::remote(Enum)]
pub enum Availability {
    ThisDevice,
    Card(String),
    Elsewhere,
    None,
}

#[uniffi::remote(Record)]
pub struct KeyStatus {
    pub tier: Tier,
    pub certify: Availability,
    pub sign: Availability,
    pub decrypt: Availability,
    pub authenticate: Availability,
}

#[uniffi::remote(Record)]
pub struct Card {
    pub aid: String,
    pub reader: Option<String>,
    pub vendor: Option<String>,
    pub serial: Option<String>,
    pub signature_count: Option<u32>,
    pub signing_key: Option<String>,
    pub encryption_key: Option<String>,
    pub authentication_key: Option<String>,
    pub pin_retries: Vec<u32>,
}

#[uniffi::remote(Enum)]
pub enum OwnerTrust {
    Unknown,
    Never,
    Marginal,
    Full,
    Ultimate,
}

#[uniffi::remote(Enum)]
pub enum RevocationReason {
    Unspecified,
    Compromised,
    Superseded,
    Retired,
}

#[uniffi::remote(Record)]
pub struct SshSupport {
    pub enabled: bool,
    pub socket: Option<PathBuf>,
}

#[uniffi::remote(Enum)]
pub enum SshControl {
    NotListed,
    Enabled,
    Disabled,
}

#[uniffi::remote(Record)]
pub struct SshKey {
    pub keygrip: String,
    pub fingerprint: String,
    pub card: Option<String>,
    pub protected: Option<bool>,
    pub sshcontrol: SshControl,
    pub use_for_ssh: bool,
    pub confirm: bool,
}

#[uniffi::remote(Record)]
pub struct Failure {
    pub location: String,
    pub code: u32,
}

/// コアのエラー（`amonhen_core::Error`）。文言は FE が決めるので、種類と材料だけを渡す。
#[derive(Debug, uniffi::Error)]
pub enum GpgError {
    /// gpg などを起動できなかった。
    Spawn { program: String, message: String },
    /// gpg が失敗した。`failures` の `code` の下位 16 ビットが gpg-error の種類。
    Gpg {
        code: Option<i32>,
        failures: Vec<Failure>,
        stderr: String,
    },
    /// 利用者がパスフレーズの入力を取り消した。
    Canceled,
    /// パスフレーズが違った。
    BadPassphrase,
    /// パスフレーズを聞く画面（pinentry）を出せなかった。`flavor` は端末用の pinentry の種類（`curses`・`tty`）。
    NoPinentry { flavor: Option<String> },
    /// gpg-agent が要求を断った。
    Agent { code: u32, message: String },
    /// gpg の出力を解釈できなかった。
    Parse { line: u64, message: String },
    /// 引数が正しくない。
    InvalidArgument { name: String, message: String },
    /// 指した鍵がない。
    NotFound,
    /// gpg は成功を返したが、鍵が思ったとおりに変わらなかった。
    NotApplied { message: String },
    /// ファイルの操作に失敗した。
    Io { path: String, message: String },
}

impl std::fmt::Display for GpgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for GpgError {}

impl From<amonhen_core::Error> for GpgError {
    fn from(error: amonhen_core::Error) -> Self {
        use amonhen_core::Error as E;
        match error {
            E::Spawn { program, source } => GpgError::Spawn {
                program,
                message: source.to_string(),
            },
            E::Gpg {
                code,
                failures,
                stderr,
            } => GpgError::Gpg {
                code,
                failures,
                stderr,
            },
            E::Canceled => GpgError::Canceled,
            E::BadPassphrase => GpgError::BadPassphrase,
            E::NoPinentry { flavor } => GpgError::NoPinentry { flavor },
            E::Agent { code, message } => GpgError::Agent { code, message },
            E::Parse { line, message } => GpgError::Parse {
                line: line as u64,
                message,
            },
            E::InvalidArgument { name, message } => GpgError::InvalidArgument {
                name: name.into(),
                message,
            },
            E::NotFound => GpgError::NotFound,
            E::NotApplied { message } => GpgError::NotApplied { message },
            E::Io { path, source } => GpgError::Io {
                path: path.to_string_lossy().into_owned(),
                message: source.to_string(),
            },
        }
    }
}

type Result<T> = std::result::Result<T, GpgError>;

fn strs(items: &[String]) -> Vec<&str> {
    items.iter().map(String::as_str).collect()
}

/// 自分の鍵か（所有者信頼が絶対的か、秘密鍵がある）。
#[uniffi::export]
pub fn key_is_mine(key: &Key) -> bool {
    key.is_mine()
}

/// 自分の鍵の段と、用途ごとにどこで使えるか。`now` は UNIX 時刻（秒）。
#[uniffi::export]
pub fn key_status(key: &Key, now: u64) -> KeyStatus {
    key.status(now)
}

/// gpg-agent がこの鍵を SSH に出すか。
#[uniffi::export]
pub fn ssh_key_enabled(key: &SshKey) -> bool {
    key.enabled()
}

/// 使う gpg と鍵の置き場所。
#[derive(uniffi::Object)]
pub struct Gpg {
    inner: amonhen_core::Gpg,
}

impl Gpg {
    fn wrap(inner: amonhen_core::Gpg) -> Arc<Self> {
        Arc::new(Gpg { inner })
    }
}

#[uniffi::export]
impl Gpg {
    /// `program` は gpg の実行ファイル（`None` なら `PATH` の gpg）、`homedir` は鍵の置き場所（`None` なら既定）。
    #[uniffi::constructor]
    pub fn new(program: Option<String>, homedir: Option<String>) -> Arc<Self> {
        let mut gpg = amonhen_core::Gpg::new();
        if let Some(program) = program {
            gpg = gpg.with_program(program);
        }
        if let Some(homedir) = homedir {
            gpg = gpg.with_homedir(homedir);
        }
        Gpg::wrap(gpg)
    }

    pub fn version(&self) -> Result<Version> {
        Ok(self.inner.version()?)
    }

    pub fn homedir(&self) -> Result<PathBuf> {
        Ok(self.inner.homedir()?)
    }

    pub fn list_keys(&self) -> Result<Vec<Key>> {
        Ok(self.inner.list_keys()?)
    }

    pub fn show_keys(&self, data: Vec<u8>) -> Result<Vec<Key>> {
        Ok(self.inner.show_keys(&data)?)
    }

    pub fn generate_key(&self, request: GenerateKey) -> Result<String> {
        Ok(self.inner.generate_key(&request)?)
    }

    pub fn import(&self, data: Vec<u8>) -> Result<ImportResult> {
        Ok(self.inner.import(&data)?)
    }

    pub fn export_public_keys(&self, fingerprints: Vec<String>, armor: bool) -> Result<Vec<u8>> {
        Ok(self.inner.export_public_keys(&strs(&fingerprints), armor)?)
    }

    pub fn export_secret_key(&self, fingerprint: String, armor: bool) -> Result<Vec<u8>> {
        Ok(self.inner.export_secret_key(&fingerprint, armor)?)
    }

    pub fn delete_public_key(&self, fingerprint: String) -> Result<()> {
        Ok(self.inner.delete_public_key(&fingerprint)?)
    }

    pub fn delete_secret_and_public_key(&self, fingerprint: String) -> Result<()> {
        Ok(self.inner.delete_secret_and_public_key(&fingerprint)?)
    }

    pub fn has_revocation_certificate(&self, fingerprint: String) -> Result<bool> {
        Ok(self.inner.has_revocation_certificate(&fingerprint)?)
    }

    pub fn generate_revocation_certificate(
        &self,
        fingerprint: String,
        reason: RevocationReason,
        description: String,
    ) -> Result<Vec<u8>> {
        Ok(self
            .inner
            .generate_revocation_certificate(&fingerprint, reason, &description)?)
    }

    pub fn save_revocation_certificate(&self, fingerprint: String) -> Result<PathBuf> {
        Ok(self.inner.save_revocation_certificate(&fingerprint)?)
    }

    pub fn card_status(&self) -> Result<Option<Card>> {
        Ok(self.inner.card_status()?)
    }

    // 一時保管と鍵サーバー

    pub fn staging(&self, dir: String) -> Result<Arc<Gpg>> {
        Ok(Gpg::wrap(self.inner.staging(dir)?))
    }

    pub fn discard_staging(&self) -> Result<()> {
        Ok(self.inner.clone().discard_staging()?)
    }

    pub fn copy_public_keys_to(
        &self,
        dest: Arc<Gpg>,
        fingerprints: Vec<String>,
    ) -> Result<ImportResult> {
        Ok(self
            .inner
            .copy_public_keys_to(&dest.inner, &strs(&fingerprints))?)
    }

    pub fn receive_keys(
        &self,
        fingerprints: Vec<String>,
        keyserver: Option<String>,
    ) -> Result<ImportResult> {
        Ok(self
            .inner
            .receive_keys(&strs(&fingerprints), keyserver.as_deref())?)
    }

    pub fn send_keys(&self, fingerprints: Vec<String>, keyserver: Option<String>) -> Result<()> {
        Ok(self
            .inner
            .send_keys(&strs(&fingerprints), keyserver.as_deref())?)
    }

    pub fn locate_external_key(&self, email: String) -> Result<ImportResult> {
        Ok(self.inner.locate_external_key(&email)?)
    }

    // 自分の鍵の編集

    pub fn set_expiry(&self, fingerprint: String, expires: Expiry) -> Result<()> {
        Ok(self.inner.set_expiry(&fingerprint, expires)?)
    }

    pub fn set_subkey_expiry(
        &self,
        fingerprint: String,
        subkeys: Vec<String>,
        expires: Expiry,
    ) -> Result<()> {
        Ok(self
            .inner
            .set_subkey_expiry(&fingerprint, &strs(&subkeys), expires)?)
    }

    pub fn add_user_id(&self, fingerprint: String, user_id: String) -> Result<()> {
        Ok(self.inner.add_user_id(&fingerprint, &user_id)?)
    }

    pub fn revoke_user_id(&self, fingerprint: String, user_id: String) -> Result<()> {
        Ok(self.inner.revoke_user_id(&fingerprint, &user_id)?)
    }

    pub fn set_primary_user_id(&self, fingerprint: String, user_id: String) -> Result<()> {
        Ok(self.inner.set_primary_user_id(&fingerprint, &user_id)?)
    }

    pub fn add_subkey(
        &self,
        fingerprint: String,
        algorithm: Option<String>,
        capabilities: Capabilities,
        expires: Expiry,
    ) -> Result<String> {
        Ok(self
            .inner
            .add_subkey(&fingerprint, algorithm.as_deref(), capabilities, expires)?)
    }

    pub fn change_passphrase(&self, fingerprint: String) -> Result<()> {
        Ok(self.inner.change_passphrase(&fingerprint)?)
    }

    pub fn set_owner_trust(&self, fingerprint: String, trust: OwnerTrust) -> Result<()> {
        Ok(self.inner.set_owner_trust(&fingerprint, trust)?)
    }

    pub fn revoke_key(
        &self,
        fingerprint: String,
        reason: RevocationReason,
        description: String,
    ) -> Result<()> {
        Ok(self.inner.revoke_key(&fingerprint, reason, &description)?)
    }

    pub fn revoke_subkey(
        &self,
        fingerprint: String,
        subkey: String,
        reason: RevocationReason,
        description: String,
    ) -> Result<()> {
        Ok(self
            .inner
            .revoke_subkey(&fingerprint, &subkey, reason, &description)?)
    }

    // 他者の鍵

    pub fn sign_key(
        &self,
        fingerprint: String,
        user_ids: Vec<String>,
        signer: Option<String>,
        local: bool,
    ) -> Result<()> {
        Ok(self
            .inner
            .sign_key(&fingerprint, &strs(&user_ids), signer.as_deref(), local)?)
    }

    // SSH

    pub fn ssh_support(&self) -> Result<SshSupport> {
        Ok(self.inner.ssh_support()?)
    }

    pub fn enable_ssh_support(&self) -> Result<()> {
        Ok(self.inner.enable_ssh_support()?)
    }

    pub fn ssh_keys(&self) -> Result<Vec<SshKey>> {
        Ok(self.inner.ssh_keys()?)
    }

    pub fn set_ssh_key_enabled(&self, keygrip: String, enabled: bool) -> Result<()> {
        Ok(self.inner.set_ssh_key_enabled(&keygrip, enabled)?)
    }

    pub fn export_ssh_key(&self, fingerprint: String) -> Result<String> {
        Ok(self.inner.export_ssh_key(&fingerprint)?)
    }
}
