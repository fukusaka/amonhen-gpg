//! amonhen-gpgui のコア。GnuPG（`gpg`・`gpg-agent`）を起動して結果を解析し、FE に渡す型にする。
//! FE のことを知らず、暗号の処理は自分でしない。パスフレーズは gpg-agent の pinentry が扱い、ここは触らない。

#![deny(unsafe_code)]

pub mod colons;
mod error;
mod gpg;
mod keylist;
mod model;
pub mod process;
pub mod status;

pub use error::{Error, Result};
pub use gpg::{Gpg, Version};
pub use keylist::parse_keylist;
pub use model::{
    Capabilities, Expiry, GenerateKey, ImportResult, ImportedKey, Key, SecretState, Subkey, UserId,
    Validity,
};
