//! amonhen-gpgui のコア。GnuPG（`gpg`・`gpg-agent`）を起動して結果を解析し、FE に渡す型にする。
//! FE のことを知らず、暗号の処理は自分でしない（例外は、gpg-agent との鍵の受け渡しの包み（`ssh_backup`）だけ）。
//! パスフレーズは gpg-agent の pinentry が扱い、ここは触らない。

#![deny(unsafe_code)]

mod card;
mod certify;
pub mod colons;
mod edit;
mod error;
mod gpg;
mod keylist;
mod model;
mod ownership;
pub mod process;
mod request;
mod revocation;
mod signer_fetch;
mod signers;
mod signers_import;
mod ssh;
mod ssh_backup;
mod staging;
pub mod status;

pub use card::Card;
pub use certify::{
    Certification, ImportedLocalSignatures, LocalSignatures, SignatureCheck,
    WithdrawnCertifications, parse_certifications,
};
pub use edit::{OwnerTrust, RevocationReason};
pub use error::{Error, Result};
pub use gpg::{Gpg, Version};
pub use keylist::parse_keylist;
pub use model::{
    Capabilities, Expiry, GenerateKey, ImportResult, ImportedKey, Key, KeyOrigin, SecretState,
    Subkey, UserId, Validity,
};
pub use ownership::{Availability, KeyStatus, Tier};
pub use request::SigningRequest;
pub use revocation::{
    Revocation, RevocationCause, Revocations, SubkeyRevocation, UserIdRevocation, parse_revocations,
};
pub use signer_fetch::{
    AccountProfile, CandidateSource, FetchedKey, PrincipalCandidate, SignerChanges,
    fetch_account_profile, fetch_account_profile_from, fetch_signing_keys, fetch_signing_keys_from,
};
pub use signers::{
    Account, Checked, FileState, ImportedFrom, KeySource, LoadedSigners, RECORD_FILE,
    RecordSignature, SIGNATURE_FILE, SIGNERS_FILE_SUFFIX, Signer, SignerKey, SignerList,
    SignerRecord, SignersFile, normalize_key, signers_file, ssh_fingerprint,
};
pub use signers_import::{
    ParsedEntry, ParsedSigners, SkipReason, SkippedLine, parse_allowed_signers,
};
pub use ssh::{SshControl, SshKey, SshSupport};
pub use ssh_backup::SSH_RESTORE_MINIMUM;
pub use staging::{CodeHost, is_keyserver_url};
