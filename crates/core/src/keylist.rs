//! 鍵一覧（`gpg --list-keys --with-colons --with-secret`・`--show-keys`）の出力を `Key` にまとめる。
//!
//! `pub` が鍵の始まりで、続く `fpr`・`grp` は直前の `pub`／`sub` のもの、`uid`・`uat`・`sub` はその鍵のもの。
//! 秘密鍵を含むデータを `--show-keys` で見ると、`pub`・`sub` の代わりに `sec`・`ssb` になる。
//! `tru`（trustdb の情報）や知らない種類は読み飛ばす。

use crate::colons::{Record, unescape};
use crate::model::{Capabilities, Key, SecretState, Subkey, UserId, Validity};
use crate::{Error, Result};

pub fn parse_keylist(output: &str) -> Result<Vec<Key>> {
    let mut keys: Vec<Key> = Vec::new();
    // 直前の `pub`／`sub` に `fpr`・`grp` を付けるため、どちらを見ているかを覚える
    let mut in_subkey = false;

    for (index, line) in output.lines().enumerate() {
        let line_no = index + 1;
        if line.is_empty() {
            continue;
        }
        let r = Record::parse(line);
        match r.kind() {
            "pub" | "sec" => {
                keys.push(primary(&r));
                in_subkey = false;
            }
            "sub" | "ssb" => {
                current(&mut keys, &r, line_no)?.subkeys.push(subkey(&r));
                in_subkey = true;
            }
            "uid" | "uat" => current(&mut keys, &r, line_no)?.user_ids.push(user_id(&r)),
            "fpr" | "grp" => {
                let key = current(&mut keys, &r, line_no)?;
                let value = r.field(10).map(str::to_owned);
                let (fingerprint, keygrip) = match key.subkeys.last_mut() {
                    Some(s) if in_subkey => (&mut s.fingerprint, &mut s.keygrip),
                    _ => (&mut key.fingerprint, &mut key.keygrip),
                };
                if r.kind() == "fpr" {
                    *fingerprint = value.ok_or_else(|| Error::Parse {
                        line: line_no,
                        message: "`fpr` record without a fingerprint".into(),
                    })?;
                } else {
                    *keygrip = value;
                }
            }
            _ => {}
        }
    }

    if let Some(k) = keys
        .iter()
        .find(|k| k.fingerprint.is_empty() || k.subkeys.iter().any(|s| s.fingerprint.is_empty()))
    {
        return Err(Error::Parse {
            line: 0,
            message: format!("key {} has no fingerprint", k.key_id),
        });
    }
    Ok(keys)
}

/// 今読んでいる鍵（最後の `pub`）。`pub` より前の `sub`・`uid` などは壊れた出力。
fn current<'k>(keys: &'k mut [Key], r: &Record, line: usize) -> Result<&'k mut Key> {
    keys.last_mut().ok_or_else(|| Error::Parse {
        line,
        message: format!("`{}` record before any `pub`", r.kind()),
    })
}

fn primary(r: &Record) -> Key {
    let flags = r.field(12);
    Key {
        fingerprint: String::new(),
        key_id: r.field(5).unwrap_or_default().to_owned(),
        keygrip: None,
        validity: Validity::from_flag(r.field(2)),
        owner_trust: Validity::from_flag(r.field(9)),
        algorithm: number(r.field(4)),
        length: number(r.field(3)),
        curve: r.field(17).map(str::to_owned),
        created: timestamp(r.field(6)),
        expires: timestamp(r.field(7)),
        capabilities: Capabilities::from_flags(flags, false),
        usable: Capabilities::from_flags(flags, true),
        disabled: flags.is_some_and(|f| f.contains('D')),
        secret: secret(r),
        subkeys: Vec::new(),
        user_ids: Vec::new(),
    }
}

fn subkey(r: &Record) -> Subkey {
    Subkey {
        fingerprint: String::new(),
        key_id: r.field(5).unwrap_or_default().to_owned(),
        keygrip: None,
        validity: Validity::from_flag(r.field(2)),
        algorithm: number(r.field(4)),
        length: number(r.field(3)),
        curve: r.field(17).map(str::to_owned),
        created: timestamp(r.field(6)),
        expires: timestamp(r.field(7)),
        capabilities: Capabilities::from_flags(r.field(12), false),
        secret: secret(r),
    }
}

/// `pub`・`sub` では `--with-secret` の印（`+`・`#`・カードのシリアル番号）。`sec`・`ssb` は秘密鍵そのものの
/// レコードなので、印がなければ秘密鍵がある。
fn secret(r: &Record) -> SecretState {
    match (r.kind(), r.field(15)) {
        ("sec" | "ssb", None) => SecretState::Available,
        (_, field) => SecretState::from_field(field),
    }
}

fn user_id(r: &Record) -> UserId {
    UserId {
        text: r.field(10).map(unescape).unwrap_or_default(),
        validity: Validity::from_flag(r.field(2)),
        created: timestamp(r.field(6)),
        expires: timestamp(r.field(7)),
        hash: r.field(8).map(str::to_owned),
        attribute: r.kind() == "uat",
    }
}

fn number(field: Option<&str>) -> u32 {
    field.and_then(|f| f.parse().ok()).unwrap_or(0)
}

/// `--fixed-list-mode` では UNIX 時刻（秒）。それ以外の形（ISO 8601）は扱わない。
fn timestamp(field: Option<&str>) -> Option<u64> {
    field.and_then(|f| f.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    // gpg 2.5 の `--list-keys --with-colons --with-secret --with-keygrip --with-subkey-fingerprint` の形
    const LISTING: &str = "\
tru::1:1700000000:0:3:1:5
pub:u:255:22:1111222233334444:1700000000:1800000000::u:::scESCA:::+::ed25519:::0:
fpr:::::::::AAAABBBBCCCCDDDDEEEEFFFF1111222233334444:
grp:::::::::0123456789ABCDEF0123456789ABCDEF01234567:
uid:u::::1700000000::HASH1::Alice \\x3a Ops <alice@example.com>::::::::::0:
uat:u::::1700000100::HASH2::1 3456::::::::::0:
sub:u:255:18:5555666677778888:1700000000::::::e:::+::cv25519::
fpr:::::::::99990000AAAABBBBCCCCDDDD5555666677778888:
grp:::::::::FEDCBA9876543210FEDCBA9876543210FEDCBA98:
sub:e:255:22:9999AAAABBBBCCCC:1600000000:1650000000:::::a:::D2760001240100000006123456780000::ed25519::
fpr:::::::::12341234123412341234123412349999AAAABBBBCCCC:
pub:f:4096:1:DDDDEEEEFFFF0000:1500000000:::-:::scESC:::::::::0:
fpr:::::::::0000111122223333444455556666DDDDEEEEFFFF0000:
uid:f::::1500000000::HASH3::Bob <bob@example.org>::::::::::0:
";

    #[test]
    fn parses_primary_subkeys_and_uids() {
        let keys = parse_keylist(LISTING).unwrap();
        assert_eq!(keys.len(), 2);

        let alice = &keys[0];
        assert_eq!(
            alice.fingerprint,
            "AAAABBBBCCCCDDDDEEEEFFFF1111222233334444"
        );
        assert_eq!(
            alice.keygrip.as_deref(),
            Some("0123456789ABCDEF0123456789ABCDEF01234567")
        );
        assert_eq!(alice.validity, Validity::Ultimate);
        assert_eq!(alice.owner_trust, Validity::Ultimate);
        assert_eq!(alice.algorithm, 22);
        assert_eq!(alice.curve.as_deref(), Some("ed25519"));
        assert_eq!(alice.created, Some(1_700_000_000));
        assert_eq!(alice.expires, Some(1_800_000_000));
        assert!(alice.capabilities.certify && alice.capabilities.sign);
        assert!(!alice.capabilities.encrypt);
        assert!(alice.usable.encrypt && alice.usable.authenticate);
        assert_eq!(alice.secret, SecretState::Available);

        assert_eq!(alice.user_ids.len(), 2);
        assert_eq!(alice.user_ids[0].text, "Alice : Ops <alice@example.com>");
        assert!(!alice.user_ids[0].attribute);
        assert!(alice.user_ids[1].attribute);

        assert_eq!(alice.subkeys.len(), 2);
        let enc = &alice.subkeys[0];
        assert_eq!(enc.fingerprint, "99990000AAAABBBBCCCCDDDD5555666677778888");
        assert_eq!(
            enc.keygrip.as_deref(),
            Some("FEDCBA9876543210FEDCBA9876543210FEDCBA98")
        );
        assert!(enc.capabilities.encrypt);
        let auth = &alice.subkeys[1];
        assert_eq!(auth.validity, Validity::Expired);
        assert!(auth.capabilities.authenticate);
        assert_eq!(
            auth.secret,
            SecretState::OnCard("D2760001240100000006123456780000".into())
        );
        assert_eq!(auth.keygrip, None);

        let bob = &keys[1];
        assert_eq!(bob.owner_trust, Validity::Unknown);
        assert_eq!(bob.expires, None);
        assert_eq!(bob.secret, SecretState::None);
        assert!(bob.subkeys.is_empty());
    }

    #[test]
    fn secret_records_from_show_keys() {
        let listing = "\
sec:-:255:22:1111222233334444:1700000000:::-:::scSC:::::ed25519:::0:
fpr:::::::::AAAABBBBCCCCDDDDEEEEFFFF1111222233334444:
uid:-::::1700000000::HASH1::Alice <alice@example.com>::::::::::0:
ssb:-:255:18:5555666677778888:1700000000::::::e:::#::cv25519::
fpr:::::::::99990000AAAABBBBCCCCDDDD5555666677778888:
";
        let keys = parse_keylist(listing).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].secret, SecretState::Available);
        assert_eq!(keys[0].subkeys[0].secret, SecretState::Stub);
        assert_eq!(
            keys[0].subkeys[0].fingerprint,
            "99990000AAAABBBBCCCCDDDD5555666677778888"
        );
    }

    #[test]
    fn empty_listing_has_no_keys() {
        assert!(parse_keylist("").unwrap().is_empty());
        assert!(
            parse_keylist("tru::1:1700000000:0:3:1:5\n")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn records_before_pub_are_rejected() {
        let err = parse_keylist("uid:u::::1::H::x::\n").unwrap_err();
        assert!(matches!(err, Error::Parse { line: 1, .. }));
    }

    #[test]
    fn key_without_fingerprint_is_rejected() {
        let err = parse_keylist("pub:u:255:22:1111222233334444:1::::::scSC:\n").unwrap_err();
        assert!(matches!(err, Error::Parse { .. }));
    }
}
