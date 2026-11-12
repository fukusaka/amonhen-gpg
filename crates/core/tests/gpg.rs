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

    /// パスフレーズを本物と同じ道（gpg-agent が pinentry を起動する）で聞く鍵束。pinentry は
    /// `scripts/fake-pinentry` で、`answer` を答える（`None` なら取り消す）。
    fn with_pinentry(answer: Option<&str>) -> Option<Self> {
        let home = Self::new()?;
        std::fs::remove_file(home.path().join("gpg.conf")).unwrap();
        let pinentry = home.path().join("pinentry");
        std::fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/fake-pinentry"),
            &pinentry,
        )
        .unwrap();
        std::fs::write(
            home.path().join("gpg-agent.conf"),
            format!("pinentry-program {}\n", pinentry.display()),
        )
        .unwrap();
        home.answer(answer);
        Some(home)
    }

    /// pinentry の答えを変え、gpg-agent が覚えたパスフレーズを忘れさせる。
    fn answer(&self, answer: Option<&str>) {
        let file = self.path().join("pinentry-answer");
        match answer {
            Some(a) => std::fs::write(&file, a).unwrap(),
            None => {
                let _ = std::fs::remove_file(&file);
            }
        }
        let _ = command("gpgconf")
            .arg("--homedir")
            .arg(self.path())
            .args(["--reload", "gpg-agent"])
            .status();
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
fn reports_an_unusable_pinentry() {
    // 設定した pinentry がない
    let Some(home) = Home::with_pinentry(Some("passphrase")) else {
        return;
    };
    std::fs::write(
        home.path().join("gpg-agent.conf"),
        "pinentry-program /nonexistent/pinentry\n",
    )
    .unwrap();
    home.answer(Some("passphrase"));
    let gpg = Gpg::new().with_homedir(home.path());
    assert!(matches!(
        gpg.generate_key(&alice()),
        Err(Error::NoPinentry { flavor: None })
    ));

    // 端末用の pinentry は、端末がないと取り消しとして報告する（pinentry-tty）。取り消しと取り違えない
    let Some(home) = Home::with_pinentry(None) else {
        return;
    };
    std::fs::write(home.path().join("pinentry-flavor"), "tty").unwrap();
    let gpg = Gpg::new().with_homedir(home.path());
    match gpg.generate_key(&alice()) {
        Err(Error::NoPinentry { flavor }) => assert_eq!(flavor.as_deref(), Some("tty")),
        other => panic!("expected NoPinentry, got {other:?}"),
    }
}

#[test]
fn saves_a_missing_revocation_certificate() {
    let Some(home) = Home::new() else {
        return;
    };
    let gpg = Gpg::new().with_homedir(home.path());
    let fpr = gpg.generate_key(&alice()).unwrap();
    let path = home
        .path()
        .join("openpgp-revocs.d")
        .join(format!("{fpr}.rev"));
    std::fs::remove_file(&path).unwrap();
    assert!(!gpg.has_revocation_certificate(&fpr).unwrap());

    assert_eq!(gpg.save_revocation_certificate(&fpr).unwrap(), path);
    assert!(gpg.has_revocation_certificate(&fpr).unwrap());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // 作っただけでは失効しない。そのまま取り込んでも、先頭の `:` のおかげで失効しない
    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(contents.contains(&fpr));
    assert!(contents.contains("\n:-----BEGIN PGP PUBLIC KEY BLOCK-----"));
    assert!(gpg.import(contents.as_bytes()).is_err());
    assert_ne!(gpg.list_keys().unwrap()[0].validity, Validity::Revoked);

    // あればそのまま（パスフレーズも聞かない）
    let before = std::fs::read(&path).unwrap();
    gpg.save_revocation_certificate(&fpr).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), before);

    // `:` を外して取り込むと失効する
    let armored = contents.replace("\n:-----BEGIN", "\n-----BEGIN");
    let result = gpg.import(armored.as_bytes()).unwrap();
    assert_eq!(result.new_revocations, 1);
    assert_eq!(gpg.list_keys().unwrap()[0].validity, Validity::Revoked);
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

#[test]
fn edit_own_key() {
    use amonhen_core::{OwnerTrust, RevocationReason, Tier};

    let Some(home) = Home::new() else {
        eprintln!("gpg not found; skipped");
        return;
    };
    let gpg = Gpg::new().with_homedir(home.path());
    let fpr = gpg.generate_key(&alice()).unwrap();
    let key = |gpg: &Gpg| gpg.list_keys().unwrap().remove(0);

    // 有効期限: 付けて、外す
    gpg.set_expiry(&fpr, Expiry::Days(30)).unwrap();
    assert!(key(&gpg).expires.is_some());
    gpg.set_expiry(&fpr, Expiry::Never).unwrap();
    assert_eq!(key(&gpg).expires, None);

    // サブ鍵を加え、その期限を変える
    let enc = gpg
        .add_subkey(
            &fpr,
            Some("cv25519"),
            Capabilities {
                encrypt: true,
                ..Capabilities::default()
            },
            Expiry::Never,
        )
        .unwrap();
    let auth = gpg
        .add_subkey(
            &fpr,
            None,
            Capabilities {
                authenticate: true,
                ..Capabilities::default()
            },
            Expiry::Days(365),
        )
        .unwrap();
    let k = key(&gpg);
    assert_eq!(k.subkeys.len(), 2);
    assert_eq!(k.subkeys[0].fingerprint, enc);
    assert!(k.subkeys[1].capabilities.authenticate);
    gpg.set_subkey_expiry(&fpr, &[&enc], Expiry::Days(10))
        .unwrap();
    assert!(key(&gpg).subkeys[0].expires.is_some());

    // UID: 加える、主にする、失効させる
    gpg.add_user_id(&fpr, "Alice Work <alice@work.example>")
        .unwrap();
    gpg.set_primary_user_id(&fpr, "Alice Work <alice@work.example>")
        .unwrap();
    assert_eq!(key(&gpg).user_ids.len(), 2);
    gpg.revoke_user_id(&fpr, "Alice <alice@example.com>")
        .unwrap();
    let k = key(&gpg);
    let old = k
        .user_ids
        .iter()
        .find(|u| u.text == "Alice <alice@example.com>")
        .unwrap();
    assert_eq!(old.validity, Validity::Revoked);

    // サブ鍵の失効
    gpg.revoke_subkey(&fpr, &auth, RevocationReason::Retired, "no longer used")
        .unwrap();
    let k = key(&gpg);
    assert_eq!(k.subkeys[1].validity, Validity::Revoked);
    assert_eq!(k.subkeys[0].validity, Validity::Ultimate);

    gpg.change_passphrase(&fpr).unwrap();
    gpg.set_owner_trust(&fpr, OwnerTrust::Full).unwrap();
    assert_eq!(key(&gpg).owner_trust, Validity::Full);
    gpg.set_owner_trust(&fpr, OwnerTrust::Ultimate).unwrap();

    // 鍵全体の失効。履歴の段に移る
    gpg.revoke_key(&fpr, RevocationReason::Superseded, "")
        .unwrap();
    let k = key(&gpg);
    assert_eq!(k.validity, Validity::Revoked);
    assert_eq!(k.status(0).tier, Tier::History);

    assert!(matches!(
        gpg.revoke_subkey(&fpr, &fpr[..16], RevocationReason::Retired, ""),
        Err(Error::InvalidArgument { .. })
    ));
}

#[test]
fn sign_others_key() {
    let (Some(home), Some(other)) = (Home::new(), Home::new()) else {
        eprintln!("gpg not found; skipped");
        return;
    };
    let gpg = Gpg::new().with_homedir(home.path());
    let me = gpg.generate_key(&alice()).unwrap();

    // Bob は別の鍵束で作り、公開鍵だけを受け取る
    let bob_gpg = Gpg::new().with_homedir(other.path());
    let bob = bob_gpg
        .generate_key(&GenerateKey {
            user_id: "Bob <bob@example.com>".into(),
            ..alice()
        })
        .unwrap();
    bob_gpg
        .add_user_id(&bob, "Bob Work <bob@work.example>")
        .unwrap();
    gpg.import(&bob_gpg.export_public_keys(&[&bob], false).unwrap())
        .unwrap();

    let uid = |text: &str| {
        let keys = gpg.list_keys().unwrap();
        let key = keys.iter().find(|k| k.fingerprint == bob).unwrap();
        key.user_ids
            .iter()
            .find(|u| u.text == text)
            .unwrap()
            .validity
    };
    assert_ne!(uid("Bob <bob@example.com>"), Validity::Full);

    // 1 つの UID にだけ署名する。自分の鍵（絶対的な信頼）の署名で確認済みになる
    gpg.sign_key(&bob, &["Bob <bob@example.com>"], Some(&me), false)
        .unwrap();
    assert_eq!(uid("Bob <bob@example.com>"), Validity::Full);
    assert_ne!(uid("Bob Work <bob@work.example>"), Validity::Full);

    // 書き出さない署名で残りの UID にも。署名済みの UID はそのまま
    gpg.sign_key(&bob, &[], None, true).unwrap();
    assert_eq!(uid("Bob Work <bob@work.example>"), Validity::Full);

    assert!(
        gpg.sign_key(&bob, &["Nobody <x@example.com>"], None, false)
            .is_err()
    );
    assert!(matches!(
        gpg.sign_key(&bob, &[], Some("Alice"), false),
        Err(Error::InvalidArgument { .. })
    ));
}

#[test]
fn send_keys_to_a_keyserver() {
    let Some(home) = Home::new() else {
        eprintln!("gpg not found; skipped");
        return;
    };
    let gpg = Gpg::new().with_homedir(home.path());
    let me = gpg.generate_key(&alice()).unwrap();

    // 本物の鍵サーバーには送らない（届かない宛先で失敗を確かめる）
    assert!(matches!(
        gpg.send_keys(&[], None),
        Err(Error::InvalidArgument { .. })
    ));
    assert!(matches!(
        gpg.send_keys(&[&me], Some("keys.openpgp.org")),
        Err(Error::InvalidArgument { .. })
    ));
    assert!(matches!(
        gpg.send_keys(&[&me], Some("hkp://127.0.0.1:1")),
        Err(Error::Gpg { .. })
    ));
}

#[test]
fn ssh_keys_through_gpg_agent() {
    use amonhen_core::SshControl;

    let Some(home) = Home::new() else {
        eprintln!("gpg not found; skipped");
        return;
    };
    let gpg = Gpg::new().with_homedir(home.path());
    let support = gpg.ssh_support().unwrap();
    assert!(!support.enabled);
    let socket = support.socket.unwrap();
    assert!(socket.starts_with(home.path()));

    let fpr = gpg.generate_key(&alice()).unwrap();
    let auth = gpg
        .add_subkey(
            &fpr,
            Some("ed25519"),
            Capabilities {
                authenticate: true,
                ..Capabilities::default()
            },
            Expiry::Never,
        )
        .unwrap();
    let enc = gpg
        .add_subkey(
            &fpr,
            Some("cv25519"),
            Capabilities {
                encrypt: true,
                ..Capabilities::default()
            },
            Expiry::Never,
        )
        .unwrap();
    let key = gpg.list_keys().unwrap().remove(0);
    let grip = |f: &str| {
        key.subkeys
            .iter()
            .find(|s| s.fingerprint == f)
            .and_then(|s| s.keygrip.clone())
            .unwrap()
    };
    let (auth_grip, enc_grip) = (grip(&auth), grip(&enc));
    let ssh_key = |g: &str| gpg.ssh_keys().unwrap().into_iter().find(|k| k.keygrip == g);

    // 暗号化用の鍵は SSH に使えないので出てこない。認証用は最初は使っていない
    assert!(ssh_key(&enc_grip).is_none());
    let k = ssh_key(&auth_grip).unwrap();
    assert!(k.fingerprint.starts_with("SHA256:"));
    assert!(!k.enabled());

    gpg.set_ssh_key_enabled(&auth_grip, true).unwrap();
    assert!(ssh_key(&auth_grip).unwrap().use_for_ssh);
    gpg.set_ssh_key_enabled(&auth_grip, false).unwrap();
    assert!(!ssh_key(&auth_grip).unwrap().enabled());

    // sshcontrol で有効にしてある鍵は、その行に `!` を付けて止める。ほかの行は変えない
    let sshcontrol = home.path().join("sshcontrol");
    std::fs::write(&sshcontrol, format!("# mine\n{auth_grip} 0\n")).unwrap();
    assert_eq!(ssh_key(&auth_grip).unwrap().sshcontrol, SshControl::Enabled);
    gpg.set_ssh_key_enabled(&auth_grip, false).unwrap();
    assert_eq!(
        std::fs::read_to_string(&sshcontrol).unwrap(),
        format!("# mine\n!{auth_grip} 0\n")
    );
    assert_eq!(
        ssh_key(&auth_grip).unwrap().sshcontrol,
        SshControl::Disabled
    );
    gpg.set_ssh_key_enabled(&auth_grip, true).unwrap();
    assert!(ssh_key(&auth_grip).unwrap().enabled());

    assert!(matches!(
        gpg.set_ssh_key_enabled(&"0".repeat(40), true),
        Err(Error::Agent { .. })
    ));

    // authorized_keys の 1 行
    let line = gpg.export_ssh_key(&auth).unwrap();
    assert!(line.starts_with("ssh-ed25519 "), "{line}");
    assert!(matches!(gpg.export_ssh_key(&enc), Err(Error::Gpg { .. })));

    // SSH サポートを有効にすると、ssh-add から鍵が見える
    gpg.enable_ssh_support().unwrap();
    assert!(gpg.ssh_support().unwrap().enabled);
    let listed = command("ssh-add")
        .arg("-L")
        .env("SSH_AUTH_SOCK", &socket)
        .output();
    if let Ok(out) = listed {
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            text.contains(line.split(' ').nth(1).unwrap()),
            "ssh-add -L: {text}"
        );
    }
}

#[test]
fn passphrases_through_pinentry() {
    const PASSPHRASE: &str = "correct horse battery staple";
    let Some(home) = Home::with_pinentry(None) else {
        return;
    };
    let gpg = Gpg::new().with_homedir(home.path());

    // 鍵の作成でパスフレーズを決めるのを取り消す
    assert!(matches!(gpg.generate_key(&alice()), Err(Error::Canceled)));
    home.answer(Some(PASSPHRASE));
    let fpr = gpg.generate_key(&alice()).unwrap();

    // 主鍵で署名し直す操作（期限）
    home.answer(None);
    assert!(matches!(
        gpg.set_expiry(&fpr, Expiry::Days(365)),
        Err(Error::Canceled)
    ));
    home.answer(Some("wrong"));
    assert!(matches!(
        gpg.set_expiry(&fpr, Expiry::Days(365)),
        Err(Error::BadPassphrase)
    ));
    home.answer(Some(PASSPHRASE));
    gpg.set_expiry(&fpr, Expiry::Days(365)).unwrap();

    // 秘密鍵の書き出し（取り消したときだけ gpg は ERROR を出さない）
    home.answer(None);
    assert!(matches!(
        gpg.export_secret_key(&fpr, true),
        Err(Error::Canceled)
    ));
    home.answer(Some("wrong"));
    assert!(matches!(
        gpg.export_secret_key(&fpr, true),
        Err(Error::BadPassphrase)
    ));
    home.answer(Some(PASSPHRASE));
    let backup = gpg.export_secret_key(&fpr, true).unwrap();

    // 失効証明書（`--batch` を外して動かす）
    use amonhen_core::RevocationReason::Unspecified;
    home.answer(None);
    assert!(matches!(
        gpg.generate_revocation_certificate(&fpr, Unspecified, ""),
        Err(Error::Canceled)
    ));
    home.answer(Some("wrong"));
    assert!(matches!(
        gpg.generate_revocation_certificate(&fpr, Unspecified, ""),
        Err(Error::BadPassphrase)
    ));
    home.answer(Some(PASSPHRASE));
    let certificate = gpg
        .generate_revocation_certificate(&fpr, Unspecified, "")
        .unwrap();
    assert!(certificate.starts_with(b"-----BEGIN PGP PUBLIC KEY BLOCK-----"));

    // 秘密鍵は守られたまま入るので、取り込みではパスフレーズを聞かない
    let Some(other) = Home::with_pinentry(None) else {
        return;
    };
    let result = Gpg::new()
        .with_homedir(other.path())
        .import(&backup)
        .unwrap();
    assert_eq!(result.secret_imported, 1);
}

/// 既存の SSH 秘密鍵を ssh-add で gpg-agent に取り込む。鍵ファイルのパスフレーズも gpg-agent が守るパスフレーズも、
/// fake の pinentry が答える。ssh-keygen・ssh-add がなければ何もしない。
#[test]
fn adds_existing_ssh_keys() {
    const PASSPHRASE: &str = "correct horse battery staple";
    let found = ["ssh-keygen", "ssh-add"].iter().all(|p| {
        command("sh")
            .args(["-c", &format!("command -v {p}")])
            .stdout(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    });
    if !found {
        eprintln!("ssh-keygen or ssh-add not found; skipped");
        return;
    }
    let Some(home) = Home::with_pinentry(Some(PASSPHRASE)) else {
        return;
    };
    let gpg = Gpg::new().with_homedir(home.path());
    let keys = tempfile::tempdir().unwrap();
    let keygen = |name: &str, passphrase: &str| {
        let path = keys.path().join(name);
        let status = command("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-C", name, "-N", passphrase, "-f"])
            .arg(&path)
            .status()
            .unwrap();
        assert!(status.success());
        path
    };
    let plain = keygen("id_plain", "");

    // SSH サポートが有効でなければ断る
    assert!(matches!(
        gpg.add_ssh_key(&plain),
        Err(Error::InvalidArgument { name: "ssh", .. })
    ));
    gpg.enable_ssh_support().unwrap();

    gpg.add_ssh_key(&plain).unwrap();
    let encrypted = keygen("id_encrypted", PASSPHRASE);
    gpg.add_ssh_key(&encrypted).unwrap();
    let keys_in_agent = gpg.ssh_keys().unwrap();
    assert_eq!(keys_in_agent.len(), 2);
    assert!(keys_in_agent.iter().all(|k| k.enabled()));

    // 鍵ファイルのパスフレーズを聞かれて取り消す
    let other = keygen("id_other", "other passphrase");
    home.answer(None);
    assert!(matches!(gpg.add_ssh_key(&other), Err(Error::Canceled)));
    // 3 回間違える（ssh-add は何度でも聞き直すので、askpass が打ち切る）
    home.answer(Some("wrong"));
    assert!(matches!(gpg.add_ssh_key(&other), Err(Error::BadPassphrase)));
    // 鍵ファイルでないもの
    std::fs::write(keys.path().join("not-a-key"), "hello").unwrap();
    assert!(matches!(
        gpg.add_ssh_key(&keys.path().join("not-a-key")),
        Err(Error::Tool { .. })
    ));
    assert_eq!(gpg.ssh_keys().unwrap().len(), 2);
}
