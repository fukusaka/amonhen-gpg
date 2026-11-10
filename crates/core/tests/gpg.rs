//! 本物の gpg で鍵の操作を確かめる。一時ディレクトリを `--homedir` にし、終わったら gpg-agent を止める。
//! 利用者の鍵束（`~/.gnupg`）には触らない。gpg がない環境では何もしない。

use std::path::Path;
use std::process::Stdio;

use amonhen_core::process::command;
use amonhen_core::{Capabilities, Error, Expiry, GenerateKey, Gpg, SecretState, Validity};

struct Home {
    dir: tempfile::TempDir,
}

impl Home {
    /// テストではパスフレーズを空にして pinentry を出さない（`gpg.conf` で loopback と空のパスフレーズの
    /// ファイルを指す）。アプリのコアはパスフレーズを扱わないので、ここで決める。
    fn new() -> Option<Self> {
        let found = command("gpg")
            .arg("--version")
            .stdout(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if !found {
            return None;
        }
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty-passphrase");
        std::fs::write(&empty, "").unwrap();
        std::fs::write(
            dir.path().join("gpg.conf"),
            format!(
                "pinentry-mode loopback\npassphrase-file {}\n",
                empty.display()
            ),
        )
        .unwrap();
        Some(Home { dir })
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn gpg(&self, args: &[&str]) {
        let status = command("gpg")
            .arg("--homedir")
            .arg(self.path())
            .args(["--batch", "--no-tty"])
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "gpg {args:?} failed");
    }
}

impl Drop for Home {
    /// テストが途中で失敗しても、gpg-agent・dirmngr を残さない（一時保管の鍵束も含めて）。
    fn drop(&mut self) {
        for dir in [self.path().to_owned(), self.path().join("staging")] {
            if dir.exists() {
                let _ = command("gpgconf")
                    .arg("--homedir")
                    .arg(&dir)
                    .args(["--kill", "all"])
                    .status();
            }
        }
    }
}

fn alice() -> GenerateKey {
    GenerateKey {
        user_id: "Alice <alice@example.com>".into(),
        algorithm: Some("ed25519".into()),
        capabilities: Some(Capabilities {
            certify: true,
            sign: true,
            ..Capabilities::default()
        }),
        expires: Expiry::Never,
    }
}

#[test]
fn lists_generated_keys() {
    let Some(home) = Home::new() else {
        eprintln!("gpg not found; skipped");
        return;
    };
    let gpg = Gpg::new().with_homedir(home.path());
    assert!(gpg.version().unwrap().major >= 2);
    assert!(gpg.list_keys().unwrap().is_empty());

    let fpr = gpg.generate_key(&alice()).unwrap();
    home.gpg(&["--quick-add-key", &fpr, "cv25519", "encr", "1y"]);
    home.gpg(&["--quick-add-key", &fpr, "ed25519", "auth", "never"]);

    let keys = gpg.list_keys().unwrap();
    assert_eq!(keys.len(), 1);
    let key = &keys[0];
    assert_eq!(key.fingerprint, fpr);
    assert_eq!(key.fingerprint.len(), 40);
    assert_eq!(key.validity, Validity::Ultimate);
    assert_eq!(key.secret, SecretState::Available);
    assert!(key.keygrip.is_some());
    assert!(key.capabilities.certify && key.capabilities.sign);
    assert!(key.usable.encrypt && key.usable.authenticate);
    assert_eq!(key.curve.as_deref(), Some("ed25519"));
    assert_eq!(key.expires, None);
    assert_eq!(key.user_ids.len(), 1);
    assert_eq!(key.user_ids[0].text, "Alice <alice@example.com>");

    assert_eq!(key.subkeys.len(), 2);
    let enc = &key.subkeys[0];
    assert!(enc.capabilities.encrypt);
    assert!(enc.expires.is_some());
    assert_eq!(enc.secret, SecretState::Available);
    let auth = &key.subkeys[1];
    assert!(auth.capabilities.authenticate);
    assert_eq!(auth.fingerprint.len(), 40);
    assert!(auth.keygrip.is_some());
}

#[test]
fn export_delete_and_import_round_trip() {
    let Some(home) = Home::new() else {
        eprintln!("gpg not found; skipped");
        return;
    };
    let gpg = Gpg::new().with_homedir(home.path());
    let fpr = gpg.generate_key(&alice()).unwrap();

    let public = gpg.export_public_keys(&[&fpr], true).unwrap();
    assert!(public.starts_with(b"-----BEGIN PGP PUBLIC KEY BLOCK-----"));
    let secret = gpg.export_secret_key(&fpr, false).unwrap();
    assert!(!secret.is_empty());

    // 秘密鍵のある鍵は、公開鍵の削除では消えない
    assert!(matches!(
        gpg.delete_public_key(&fpr),
        Err(Error::Gpg { .. })
    ));
    assert_eq!(gpg.list_keys().unwrap().len(), 1);

    gpg.delete_secret_and_public_key(&fpr).unwrap();
    assert!(gpg.list_keys().unwrap().is_empty());

    let r = gpg.import(&public).unwrap();
    assert_eq!((r.considered, r.imported, r.secret_imported), (1, 1, 0));
    assert_eq!(r.keys[0].fingerprint, fpr);
    assert!(r.keys[0].new_key && !r.keys[0].secret);
    assert_eq!(gpg.list_keys().unwrap()[0].secret, SecretState::None);

    // 公開鍵だけになったので、公開鍵の削除で消せる
    gpg.delete_public_key(&fpr).unwrap();
    assert!(gpg.list_keys().unwrap().is_empty());

    let r = gpg.import(&secret).unwrap();
    assert_eq!((r.secret_read, r.secret_imported), (1, 1));
    assert!(r.keys.iter().any(|k| k.fingerprint == fpr && k.secret));
    assert_eq!(gpg.list_keys().unwrap()[0].secret, SecretState::Available);
}

#[test]
fn bad_requests_are_rejected() {
    let Some(home) = Home::new() else {
        eprintln!("gpg not found; skipped");
        return;
    };
    let gpg = Gpg::new().with_homedir(home.path());
    let unknown = "0123456789ABCDEF0123456789ABCDEF01234567";
    assert!(matches!(
        gpg.export_public_keys(&[unknown], true),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        gpg.delete_secret_and_public_key("alice@example.com"),
        Err(Error::InvalidArgument { .. })
    ));
    assert!(matches!(gpg.import(b"not a key"), Err(Error::Gpg { .. })));
    let mut bad = alice();
    bad.user_id = "Alice\n<alice@example.com>".into();
    assert!(matches!(
        gpg.generate_key(&bad),
        Err(Error::InvalidArgument { .. })
    ));
}

#[test]
fn own_keys_show_keys_and_revocation_certificates() {
    use amonhen_core::{Availability, Tier};

    let Some(home) = Home::new() else {
        eprintln!("gpg not found; skipped");
        return;
    };
    let gpg = Gpg::new().with_homedir(home.path());
    let fpr = gpg.generate_key(&alice()).unwrap();
    home.gpg(&["--quick-add-key", &fpr, "cv25519", "encr", "1y"]);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let key = &gpg.list_keys().unwrap()[0];
    assert!(key.is_mine());
    let status = key.status(now);
    assert_eq!(status.tier, Tier::Usable);
    assert_eq!(status.sign, Availability::ThisDevice);
    assert_eq!(status.decrypt, Availability::ThisDevice);
    assert_eq!(status.authenticate, Availability::None);

    // gpg は鍵を作るときに失効証明書を残す
    assert!(gpg.has_revocation_certificate(&fpr).unwrap());
    assert!(
        !gpg.has_revocation_certificate("0123456789ABCDEF0123456789ABCDEF01234567")
            .unwrap()
    );

    // 取り込まずに中身を見る。秘密鍵を含むデータは `sec` として読める
    let public = gpg.export_public_keys(&[&fpr], true).unwrap();
    let secret = gpg.export_secret_key(&fpr, false).unwrap();
    gpg.delete_secret_and_public_key(&fpr).unwrap();
    let shown = gpg.show_keys(&public).unwrap();
    assert_eq!(shown.len(), 1);
    assert_eq!(shown[0].fingerprint, fpr);
    assert_eq!(shown[0].secret, SecretState::None);
    assert_eq!(shown[0].user_ids[0].text, "Alice <alice@example.com>");
    let shown = gpg.show_keys(&secret).unwrap();
    assert_ne!(shown[0].secret, SecretState::None);
    assert_eq!(shown[0].subkeys.len(), 1);
    assert!(
        gpg.list_keys().unwrap().is_empty(),
        "show_keys must not import"
    );
    assert!(gpg.show_keys(b"not a key").is_err());
}

#[test]
fn missing_program_is_a_spawn_error() {
    let err = Gpg::new()
        .with_program("amonhen-no-such-gpg")
        .list_keys()
        .unwrap_err();
    assert!(matches!(err, Error::Spawn { .. }));
}

#[test]
fn staging_keeps_fetched_keys_apart() {
    let (Some(remote), Some(home)) = (Home::new(), Home::new()) else {
        eprintln!("gpg not found; skipped");
        return;
    };
    // 相手の鍵（別の鍵束で作る）
    let bob = Gpg::new().with_homedir(remote.path());
    let mut request = alice();
    request.user_id = "Bob <bob@example.org>".into();
    let fpr = bob.generate_key(&request).unwrap();
    let data = bob.export_public_keys(&[&fpr], false).unwrap();

    let main = Gpg::new().with_homedir(home.path());
    let dir = home.path().join("staging");
    let staging = main.staging(&dir).unwrap();
    let r = staging.import(&data).unwrap();
    assert_eq!(r.imported, 1);
    assert!(
        main.list_keys().unwrap().is_empty(),
        "staging must stay apart"
    );
    // 作り直しても同じ一時保管を開く
    assert_eq!(main.staging(&dir).unwrap().list_keys().unwrap().len(), 1);

    let r = staging.copy_public_keys_to(&main, &[&fpr]).unwrap();
    assert_eq!(r.imported, 1);
    let keys = main.list_keys().unwrap();
    assert_eq!(keys[0].fingerprint, fpr);
    assert!(!keys[0].is_mine());

    staging.discard_staging().unwrap();
    assert!(!dir.exists());
    // 一時保管ではない鍵束は消さない
    assert!(matches!(
        main.clone().discard_staging(),
        Err(Error::InvalidArgument { .. })
    ));
    assert!(matches!(
        Gpg::new().discard_staging(),
        Err(Error::InvalidArgument { .. })
    ));
    assert!(home.path().join("pubring.kbx").exists());
    // 中身のあるディレクトリは一時保管にしない
    assert!(matches!(
        main.staging(home.path()),
        Err(Error::InvalidArgument { .. })
    ));
}

#[test]
fn card_status_without_a_card() {
    let Some(home) = Home::new() else {
        eprintln!("gpg not found; skipped");
        return;
    };
    let gpg = Gpg::new().with_homedir(home.path());
    // カードが挿さっている機械では、カードの情報が返る
    match gpg.card_status().unwrap() {
        None => {}
        Some(card) => assert!(!card.aid.is_empty()),
    }
}

/// ネットワークを使う（`cargo test -- --ignored`）。
#[test]
#[ignore]
fn locate_external_key_through_wkd() {
    let Some(home) = Home::new() else {
        eprintln!("gpg not found; skipped");
        return;
    };
    let staging = Gpg::new()
        .with_homedir(home.path())
        .staging(home.path().join("staging"))
        .unwrap();
    let r = staging.locate_external_key("torvalds@kernel.org").unwrap();
    assert!(r.considered >= 1);
    let keys = staging.list_keys().unwrap();
    assert!(keys.iter().any(|k| {
        k.user_ids
            .iter()
            .any(|u| u.text.contains("torvalds@kernel.org"))
    }));
    let fpr = keys[0].fingerprint.clone();
    let r = staging
        .receive_keys(&[&fpr], Some("hkps://keys.openpgp.org"))
        .unwrap();
    assert!(r.considered >= 1);
    staging.discard_staging().unwrap();
}
