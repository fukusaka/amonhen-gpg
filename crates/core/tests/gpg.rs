//! 本物の gpg で鍵の操作を確かめる。一時ディレクトリを `--homedir` にし、終わったら gpg-agent を止める。
//! 利用者の鍵束（`~/.gnupg`）には触らない。gpg がない環境では何もしない。

use std::path::Path;
use std::process::Stdio;

use amonhen_gpg_core::process::command;
use amonhen_gpg_core::{
    Capabilities, CodeHost, Error, Expiry, GenerateKey, Gpg, KeyOrigin, SecretState, Validity,
};

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
    use amonhen_gpg_core::{Availability, Tier};

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
    let r = staging.import_from_file(&data).unwrap();
    assert_eq!(r.imported, 1);
    assert_eq!(staging.list_keys().unwrap()[0].origin, KeyOrigin::File);
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
    // 書き出して取り込み直しても、一時保管での入手元を引き継ぐ
    assert_eq!(keys[0].origin, KeyOrigin::File);

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
    // どこにもない鍵は NotFound（WKD も鍵サーバーも探したうえで）
    std::fs::write(
        home.path().join("staging/dirmngr.conf"),
        "keyserver hkps://keys.openpgp.org\n",
    )
    .unwrap();
    let _ = command("gpgconf")
        .arg("--homedir")
        .arg(home.path().join("staging"))
        .args(["--reload", "dirmngr"])
        .status();
    let r = staging.locate_external_key("nobody-amonhen-test@example.com");
    assert!(matches!(r, Err(Error::NotFound)), "{r:?}");
    assert!(matches!(
        staging.receive_keys(
            &["0123456789ABCDEF0123456789ABCDEF01234567"],
            Some("hkps://keys.openpgp.org")
        ),
        Err(Error::NotFound)
    ));
    staging.discard_staging().unwrap();
}

/// ネットワークを使う（`cargo test -- --ignored`）。GitHub が公開している web-flow（Web 上のコミットに署名する鍵）で試す。
#[test]
#[ignore]
fn fetch_keys_from_github() {
    let Some(home) = Home::new() else {
        eprintln!("gpg not found; skipped");
        return;
    };
    let staging = Gpg::new()
        .with_homedir(home.path())
        .staging(home.path().join("staging"))
        .unwrap();
    let r = staging
        .fetch_from_code_host(CodeHost::GitHub, "web-flow")
        .unwrap();
    assert!(r.considered >= 1);
    // 入手元は、取ってきた URL
    let keys = staging.list_keys().unwrap();
    assert!(!keys.is_empty());
    for key in &keys {
        assert_eq!(key.origin, KeyOrigin::Url);
        assert_eq!(
            key.origin_url.as_deref(),
            Some("https://github.com/web-flow.gpg")
        );
    }
    // いない利用者と、鍵を登録していない利用者（octocat）は NotFound
    for user in ["amonhen-no-such-user-zz9q", "octocat"] {
        let r = staging.fetch_from_code_host(CodeHost::GitHub, user);
        assert!(matches!(r, Err(Error::NotFound)), "{user}: {r:?}");
    }
    staging.discard_staging().unwrap();
}

/// 試験用の鍵サーバー（`scripts/test-keyserver.sh up`）を使う。
/// `AMONHEN_TEST_KEYSERVER=hkp://127.0.0.1:11371 cargo test -- --ignored test_keyserver`
#[test]
#[ignore]
fn test_keyserver_sends_and_receives() {
    let Ok(server) = std::env::var("AMONHEN_TEST_KEYSERVER") else {
        eprintln!("AMONHEN_TEST_KEYSERVER not set; skipped");
        return;
    };
    let Some(home) = Home::new() else {
        eprintln!("gpg not found; skipped");
        return;
    };
    let gpg = Gpg::new().with_homedir(home.path());
    // 試験のたびに新しい鍵なので、前の試験で送った鍵と混ざらない
    let fpr = gpg.generate_key(&alice()).unwrap();
    gpg.send_keys(&[&fpr], Some(&server)).unwrap();

    let staging = gpg.staging(home.path().join("staging")).unwrap();
    let r = staging.receive_keys(&[&fpr], Some(&server)).unwrap();
    assert!(r.considered >= 1);
    let keys = staging.list_keys().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].fingerprint, fpr);
    assert_eq!(keys[0].secret, SecretState::None);
    assert!(
        keys[0]
            .user_ids
            .iter()
            .any(|u| u.text.contains("alice@example.com"))
    );

    // メールアドレスで探す（WKD は example.com にないので、鍵サーバーで見つかる）
    staging.delete_public_key(&fpr).unwrap();
    std::fs::write(
        home.path().join("staging/dirmngr.conf"),
        format!("keyserver {server}\n"),
    )
    .unwrap();
    let _ = command("gpgconf")
        .arg("--homedir")
        .arg(home.path().join("staging"))
        .args(["--reload", "dirmngr"])
        .status();
    staging.locate_external_key("alice@example.com").unwrap();
    assert!(
        staging
            .list_keys()
            .unwrap()
            .iter()
            .any(|k| k.fingerprint == fpr)
    );

    // 鍵サーバーにない鍵は NotFound
    assert!(matches!(
        staging.receive_keys(&["0123456789ABCDEF0123456789ABCDEF01234567"], Some(&server)),
        Err(Error::NotFound)
    ));
    staging.discard_staging().unwrap();
}

#[test]
fn edit_own_key() {
    use amonhen_gpg_core::{OwnerTrust, RevocationCause, RevocationReason, Tier};

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
    let r = gpg.revocations(&fpr).unwrap();
    assert_eq!(r.subkeys.len(), 1);
    assert_eq!(r.subkeys[0].fingerprint, auth);
    assert_eq!(r.subkeys[0].revocation.cause, RevocationCause::Retired);
    assert_eq!(
        r.subkeys[0].revocation.comment.as_deref(),
        Some("no longer used")
    );
    assert_eq!(r.user_ids[0].user_id, "Alice <alice@example.com>");
    assert!(r.key.is_none());

    gpg.change_passphrase(&fpr).unwrap();
    gpg.set_owner_trust(&fpr, OwnerTrust::Full).unwrap();
    assert_eq!(key(&gpg).owner_trust, Validity::Full);
    gpg.set_owner_trust(&fpr, OwnerTrust::Ultimate).unwrap();

    // 鍵全体の失効。履歴の段に移る
    gpg.revoke_key(&fpr, RevocationReason::Superseded, "moved to a new key")
        .unwrap();
    let k = key(&gpg);
    assert_eq!(k.validity, Validity::Revoked);
    let revoked = gpg.revocations(&fpr).unwrap().key.unwrap();
    assert_eq!(revoked.cause, RevocationCause::Superseded);
    assert_eq!(revoked.comment.as_deref(), Some("moved to a new key"));
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

    // 誰がどの UID に署名したか（Bob 自身の署名は入らない）
    let certs = gpg.certifications(&bob).unwrap();
    assert_eq!(certs.len(), 2);
    for c in &certs {
        assert_eq!(c.signer_fingerprint.as_deref(), Some(me.as_str()));
        assert_eq!(c.check, amonhen_gpg_core::SignatureCheck::Good);
        assert!(
            c.signer_user_id
                .as_deref()
                .unwrap()
                .contains("alice@example.com")
        );
    }
    let exportable = |u: &str| certs.iter().find(|c| c.user_id == u).unwrap().exportable;
    assert!(exportable("Bob <bob@example.com>"));
    assert!(!exportable("Bob Work <bob@work.example>"));

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
    use amonhen_gpg_core::SshControl;

    let Some(home) = Home::new() else {
        eprintln!("gpg not found; skipped");
        return;
    };
    let gpg = Gpg::new().with_homedir(home.path());
    let support = gpg.ssh_support().unwrap();
    assert!(!support.enabled);
    let socket = support.socket.unwrap();
    // ふだんの鍵束のソケットではないこと。macOS は homedir の中、Linux は /run/user/<uid>/gnupg/d.<homedir のハッシュ>/ に置く。
    let hashed = socket
        .parent()
        .and_then(|dir| dir.file_name())
        .is_some_and(|name| name.to_string_lossy().starts_with("d."));
    assert!(socket.starts_with(home.path()) || hashed, "{socket:?}");

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
    // OpenPGP の鍵の秘密鍵は、SSH の鍵としては消さない
    assert!(matches!(
        gpg.delete_ssh_key(&auth_grip),
        Err(Error::InvalidArgument {
            name: "keygrip",
            ..
        })
    ));

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
    use amonhen_gpg_core::RevocationReason::Unspecified;
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

    // パスフレーズの変更: 今のものを取り消す・間違える、正しければ新しいものに変わる
    home.answer(None);
    assert!(matches!(gpg.change_passphrase(&fpr), Err(Error::Canceled)));
    home.answer(Some("wrong"));
    assert!(matches!(
        gpg.change_passphrase(&fpr),
        Err(Error::BadPassphrase)
    ));
    const NEW: &str = "another horse battery staple";
    std::fs::write(home.path().join("pinentry-new"), NEW).unwrap();
    home.answer(Some(PASSPHRASE));
    gpg.change_passphrase(&fpr).unwrap();
    std::fs::remove_file(home.path().join("pinentry-new")).unwrap();
    // 古いパスフレーズでは使えず、新しいもので使える
    home.answer(Some(PASSPHRASE));
    assert!(matches!(
        gpg.generate_revocation_certificate(&fpr, Unspecified, ""),
        Err(Error::BadPassphrase)
    ));
    home.answer(Some(NEW));
    gpg.generate_revocation_certificate(&fpr, Unspecified, "")
        .unwrap();

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
    // 説明（ssh-keygen の -C）と公開鍵は、鍵ファイルの .pub と同じ
    let pub_line = |name: &str| {
        std::fs::read_to_string(keys.path().join(format!("{name}.pub")))
            .unwrap()
            .trim()
            .to_owned()
    };
    for name in ["id_plain", "id_encrypted"] {
        let key = keys_in_agent
            .iter()
            .find(|k| k.comment.as_deref() == Some(name))
            .unwrap();
        assert_eq!(gpg.ssh_public_key(&key.keygrip).unwrap(), pub_line(name));
    }

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

    // gpg-agent から消す。鍵ファイルは残る
    let plain_grip = gpg
        .ssh_keys()
        .unwrap()
        .into_iter()
        .find(|k| k.comment.as_deref() == Some("id_plain"))
        .unwrap()
        .keygrip;
    gpg.delete_ssh_key(&plain_grip).unwrap();
    assert_eq!(gpg.ssh_keys().unwrap().len(), 1);
    assert!(plain.is_file());
    assert!(matches!(
        gpg.delete_ssh_key(&plain_grip),
        Err(Error::NotFound)
    ));
}

/// 取り込んだ SSH の鍵を、gpg-agent が守ったままの形で書き出し、別の鍵束に戻す。パスフレーズは聞かない
/// （戻す側の pinentry は取り消すようにしておく）。gpg-agent で戻すのは 2.5.14 から。それより古ければ、ファイルを
/// `private-keys-v1.d/<keygrip>.key` に置いて戻せることを確かめる。
#[test]
fn backs_up_and_restores_ssh_keys() {
    use amonhen_gpg_core::SSH_RESTORE_MINIMUM;

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
    gpg.enable_ssh_support().unwrap();
    let keys = tempfile::tempdir().unwrap();
    let keygen = |name: &str| {
        let path = keys.path().join(name);
        let status = command("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-C", name, "-N", "", "-f"])
            .arg(&path)
            .status()
            .unwrap();
        assert!(status.success());
        path
    };
    let find = |gpg: &Gpg, name: &str| {
        gpg.ssh_keys()
            .unwrap()
            .into_iter()
            .find(|k| k.comment.as_deref() == Some(name))
    };
    // gpg-agent はパスフレーズ（pinentry の答え）で守って置く
    gpg.add_ssh_key(&keygen("id_kept")).unwrap();
    let kept = find(&gpg, "id_kept").unwrap();
    assert_eq!(kept.protected, Some(true));
    let public = gpg.ssh_public_key(&kept.keygrip).unwrap();

    home.answer(None);
    let backup = gpg.export_ssh_key_backup(&kept.keygrip).unwrap();
    assert!(backup.starts_with(b"(21:protected-private-key"));
    // 中身はパスフレーズで守られている（秘密の値 `d` は平文で入っていない）
    assert!(!backup.windows(4).any(|w| w == b"1:d3"));

    // パスフレーズを空にすると守られずに置かれる。それは書き出さない
    home.answer(Some(""));
    gpg.add_ssh_key(&keygen("id_open")).unwrap();
    let open = find(&gpg, "id_open").unwrap();
    assert_eq!(open.protected, Some(false));
    assert!(matches!(
        gpg.export_ssh_key_backup(&open.keygrip),
        Err(Error::InvalidArgument {
            name: "keygrip",
            ..
        })
    ));
    assert!(matches!(
        gpg.export_ssh_key_backup(&"0".repeat(40)),
        Err(Error::NotFound)
    ));

    // 戻す側
    let Some(other) = Home::with_pinentry(None) else {
        return;
    };
    let restored = Gpg::new().with_homedir(other.path());
    if restored.version().unwrap() < SSH_RESTORE_MINIMUM {
        assert!(matches!(
            restored.import_ssh_key_backup(&backup),
            Err(Error::InvalidArgument { name: "gpg", .. })
        ));
        // 2.4 系: ファイルを置けば gpg-agent が読む
        let dir = other.path().join("private-keys-v1.d");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{}.key", kept.keygrip)), &backup).unwrap();
        let key = find(&restored, "id_kept").unwrap();
        assert_eq!(key.keygrip, kept.keygrip);
        assert_eq!(key.protected, Some(true));
        assert_eq!(restored.ssh_public_key(&key.keygrip).unwrap(), public);
        return;
    }
    // SSH サポートが有効でなければ断る
    assert!(matches!(
        restored.import_ssh_key_backup(&backup),
        Err(Error::InvalidArgument { name: "ssh", .. })
    ));
    restored.enable_ssh_support().unwrap();
    assert!(matches!(
        restored.import_ssh_key_backup(b"(11:private-key(1:a))"),
        Err(Error::InvalidArgument { name: "backup", .. })
    ));
    assert!(matches!(
        restored.import_ssh_key_backup(b"hello"),
        Err(Error::InvalidArgument { name: "backup", .. })
    ));
    let grip = restored.import_ssh_key_backup(&backup).unwrap();
    assert_eq!(grip, kept.keygrip);
    let key = find(&restored, "id_kept").unwrap();
    assert!(key.enabled());
    assert_eq!(key.protected, Some(true));
    assert_eq!(restored.ssh_public_key(&grip).unwrap(), public);
    // 同じ鍵はもうある
    assert!(matches!(
        restored.import_ssh_key_backup(&backup),
        Err(Error::Agent { .. })
    ));
}

/// SSH の鍵を一時ディレクトリに作り、公開鍵の行と、秘密鍵のファイルを返す。ssh-keygen がなければ `None`。
fn ssh_key(dir: &Path, name: &str) -> Option<(String, std::path::PathBuf)> {
    let path = dir.join(name);
    let ok = command("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", name, "-f"])
        .arg(&path)
        .stdout(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    ok.then(|| {
        let line = std::fs::read_to_string(path.with_extension("pub")).unwrap();
        (line.trim().to_owned(), path)
    })
}

#[test]
fn keeps_allowed_signers() {
    use amonhen_gpg_core::{
        Account, Checked, FileState, KeySource, RECORD_FILE, RecordSignature, SIGNATURE_FILE,
        SignerRecord, signers_file,
    };
    let Some(home) = Home::new() else {
        eprintln!("gpg not found; skipped");
        return;
    };
    let keys = tempfile::tempdir().unwrap();
    let Some((alice_ssh, alice_secret)) = ssh_key(keys.path(), "alice") else {
        eprintln!("ssh-keygen not found; skipped");
        return;
    };
    let gpg = Gpg::new().with_homedir(home.path());
    let me = gpg.generate_key(&alice()).unwrap();
    let dir = home.path().join("signers");

    // 記録がなければ空
    let loaded = gpg.load_signers(&dir).unwrap();
    assert_eq!(loaded.signature, RecordSignature::NoRecord);
    assert!(loaded.files.is_empty());
    assert!(loaded.record.people.is_empty());

    let mut record = SignerRecord::new();
    let account = Account {
        host: CodeHost::GitHub,
        user: "alice".into(),
    };
    record
        .add_person("alice@example.com", Some(account))
        .unwrap();
    let source = KeySource {
        host: CodeHost::GitHub,
        user: "alice".into(),
        fetched: "2026-11-21T00:00:00Z".into(),
    };
    record
        .accept_key(
            "alice@example.com",
            &alice_ssh,
            Some(source),
            Checked::Account,
        )
        .unwrap();
    // 同じ鍵をもう一度受け入れると、照らし合わせたほうを残す
    record
        .accept_key("alice@example.com", &alice_ssh, None, Checked::Fingerprint)
        .unwrap();
    record
        .accept_key("alice@example.com", &alice_ssh, None, Checked::Account)
        .unwrap();
    let key = &record.people[0].keys;
    assert_eq!(key.len(), 1);
    assert_eq!(key[0].checked, Checked::Fingerprint);
    assert!(key[0].fingerprint.starts_with("SHA256:"));
    assert!(key[0].source.is_some());
    assert!(!key[0].key.ends_with("alice"), "comment is dropped");
    assert!(matches!(
        record.accept_key("nobody@example.com", &alice_ssh, None, Checked::Account),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        record.accept_key(
            "alice@example.com",
            "ssh-ed25519 AAAAnotakeyatallAAAA",
            None,
            Checked::Account
        ),
        Err(Error::Tool { .. })
    ));

    // 一覧に入れた人だけを書く
    record.add_person("bob@example.com", None).unwrap();
    let (bob_ssh, _) = ssh_key(keys.path(), "bob").unwrap();
    record
        .accept_key("bob@example.com", &bob_ssh, None, Checked::Account)
        .unwrap();
    record.add_list("work", "Work").unwrap();
    record.add_member("work", "alice@example.com").unwrap();
    record.add_list("old", "Old").unwrap();
    record.add_member("old", "bob@example.com").unwrap();
    let work = signers_file(&dir, "work");

    gpg.save_signers(&dir, &record, &me).unwrap();
    let text = std::fs::read_to_string(&work).unwrap();
    assert!(
        text.contains("alice@example.com namespaces=\"git\" ssh-ed25519 "),
        "{text}"
    );
    assert!(!text.contains("bob@example.com"), "{text}");
    // 一覧を除くと、そのファイルも消える
    record.remove_list("old").unwrap();
    gpg.save_signers(&dir, &record, &me).unwrap();
    assert!(!signers_file(&dir, "old").exists());
    let loaded = gpg.load_signers(&dir).unwrap();
    assert_eq!(loaded.record, record);
    assert_eq!(
        loaded.signature,
        RecordSignature::Valid { signer: me.clone() }
    );
    assert_eq!(loaded.files.len(), 1);
    assert_eq!(loaded.files[0].list, "work");
    assert_eq!(loaded.files[0].path, work);
    assert_eq!(loaded.files[0].state, FileState::Matches);
    // 一時ファイルを残さない
    let mut names: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, [RECORD_FILE, SIGNATURE_FILE, "work.allowed_signers"]);

    // git がこのファイルで署名を検証できる（git がなければ飛ばす）
    let repo = keys.path().join("repo");
    let git = |args: &[&str]| {
        command("git")
            .arg("-C")
            .arg(&repo)
            .args(args)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
    };
    std::fs::create_dir(&repo).unwrap();
    if git(&["init", "-q"]).is_ok_and(|o| o.status.success()) {
        let config = [
            ("user.name", "Alice".to_owned()),
            ("user.email", "alice@example.com".to_owned()),
            ("gpg.format", "ssh".to_owned()),
            ("user.signingkey", alice_secret.display().to_string()),
            ("gpg.ssh.allowedSignersFile", work.display().to_string()),
        ];
        for (k, v) in &config {
            assert!(git(&["config", k, v]).unwrap().status.success());
        }
        assert!(
            git(&["commit", "-q", "-S", "--allow-empty", "-m", "one"])
                .unwrap()
                .status
                .success()
        );
        let out = git(&["log", "-1", "--format=%G? %GS"]).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            "G alice@example.com"
        );

        // 退役させると、それより後の署名は検証しない（git はコミットの時刻で比べる）
        let fingerprint = record.people[0].keys[0].fingerprint.clone();
        record
            .retire_key("alice@example.com", &fingerprint)
            .unwrap();
        gpg.save_signers(&dir, &record, &me).unwrap();
        let text = std::fs::read_to_string(&work).unwrap();
        assert!(text.contains(",valid-before=\""), "{text}");
        std::thread::sleep(std::time::Duration::from_secs(2));
        assert!(
            git(&["commit", "-q", "-S", "--allow-empty", "-m", "two"])
                .unwrap()
                .status
                .success()
        );
        let out = git(&["log", "-2", "--format=%G?"]).unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "U\nG");
    } else {
        eprintln!("git not found; skipped the git check");
    }

    // 知らないうちの変更に気づく
    std::fs::write(&work, "x@example.com ssh-ed25519 AAAA\n").unwrap();
    assert_eq!(
        gpg.load_signers(&dir).unwrap().files[0].state,
        FileState::Differs
    );
    let json = std::fs::read_to_string(dir.join(RECORD_FILE)).unwrap();
    std::fs::write(
        dir.join(RECORD_FILE),
        json.replace("alice@example.com", "mallory@example.com"),
    )
    .unwrap();
    assert_eq!(
        gpg.load_signers(&dir).unwrap().signature,
        RecordSignature::Invalid
    );
    std::fs::remove_file(dir.join(SIGNATURE_FILE)).unwrap();
    assert_eq!(
        gpg.load_signers(&dir).unwrap().signature,
        RecordSignature::Missing
    );

    // 自分の鍵でない鍵の署名は通さない（他者の鍵として取り込み、秘密鍵を消す）
    gpg.save_signers(&dir, &record, &me).unwrap();
    let mut bob = alice();
    bob.user_id = "Bob <bob@example.com>".into();
    let bob = gpg.generate_key(&bob).unwrap();
    gpg.save_signers(&dir, &record, &bob).unwrap();
    let public = gpg.export_public_keys(&[&bob], false).unwrap();
    gpg.delete_secret_and_public_key(&bob).unwrap();
    gpg.import(&public).unwrap();
    assert_eq!(
        gpg.load_signers(&dir).unwrap().signature,
        RecordSignature::Invalid
    );

    // 壊れた記録と読めない版は読まない
    std::fs::write(dir.join(RECORD_FILE), "{").unwrap();
    assert!(matches!(gpg.load_signers(&dir), Err(Error::Parse { .. })));
    std::fs::write(dir.join(RECORD_FILE), r#"{"version":2,"people":[]}"#).unwrap();
    assert!(matches!(gpg.load_signers(&dir), Err(Error::Parse { .. })));
    // 書けない署名者なら、どのファイルも変えない
    let before = std::fs::read(dir.join(RECORD_FILE)).unwrap();
    assert!(gpg.save_signers(&dir, &record, &bob).is_err());
    assert_eq!(std::fs::read(dir.join(RECORD_FILE)).unwrap(), before);
}

/// 決まった応答を返す HTTP サーバー（127.0.0.1 の空いたポート）。`routes` は（パス、状態、本体）。
fn serve(routes: Vec<(String, u16, String)>) -> String {
    use std::io::{BufRead, BufReader, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut line = String::new();
            BufReader::new(&stream).read_line(&mut line).unwrap();
            let path = line.split(' ').nth(1).unwrap_or("").to_owned();
            let (status, body) = routes
                .iter()
                .find(|(p, _, _)| *p == path)
                .map(|(_, s, b)| (*s, b.clone()))
                .unwrap_or((404, "{\"message\":\"Not Found\"}".into()));
            let _ = write!(
                stream,
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    format!("http://{addr}")
}

#[test]
fn fetches_ssh_signing_keys() {
    use amonhen_gpg_core::{Checked, KeySource, SignerRecord, fetch_signing_keys_from};
    let dir = tempfile::tempdir().unwrap();
    let (Some((a, _)), Some((b, _)), Some((c, _))) = (
        ssh_key(dir.path(), "a"),
        ssh_key(dir.path(), "b"),
        ssh_key(dir.path(), "c"),
    ) else {
        eprintln!("ssh-keygen not found; skipped");
        return;
    };
    let found = command("curl")
        .arg("--version")
        .stdout(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !found {
        eprintln!("curl not found; skipped");
        return;
    }
    let json = |s: &str| serde_json_escape(s);
    let api = serve(vec![
        (
            "/users/alice/ssh_signing_keys?per_page=100".into(),
            200,
            format!(
                r#"[{{"id":1,"key":"{}","title":"laptop"}},{{"id":2,"key":"{}","title":""}},{{"id":3,"key":"{}"}}]"#,
                json(&a),
                json(&b),
                json(&a)
            ),
        ),
        (
            "/users/bob/keys?per_page=100".into(),
            200,
            format!(
                r#"[{{"key":"{}","usage_type":"auth"}},{{"key":"{}","usage_type":"signing"}},{{"key":"{}","usage_type":"auth_and_signing"}}]"#,
                json(&a),
                json(&b),
                json(&c)
            ),
        ),
        (
            "/users/limited/ssh_signing_keys?per_page=100".into(),
            403,
            "{\"message\":\"rate limit\"}".into(),
        ),
    ]);

    let keys = fetch_signing_keys_from(&api, CodeHost::GitHub, "alice").unwrap();
    assert_eq!(keys.len(), 2, "duplicates are dropped");
    assert_eq!(keys[0].title.as_deref(), Some("laptop"));
    assert_eq!(keys[1].title, None);
    assert!(!keys[0].key.ends_with(" a"), "comment is dropped");
    let gitlab = fetch_signing_keys_from(&api, CodeHost::GitLab, "bob").unwrap();
    assert_eq!(gitlab.len(), 2, "auth-only keys are skipped");
    assert_eq!(gitlab[0].fingerprint, keys[1].fingerprint);
    assert!(matches!(
        fetch_signing_keys_from(&api, CodeHost::GitHub, "ghost"),
        Err(Error::NotFound)
    ));
    match fetch_signing_keys_from(&api, CodeHost::GitHub, "limited") {
        Err(Error::Tool { stderr, .. }) => assert!(stderr.contains("HTTP 403"), "{stderr}"),
        other => panic!("{other:?}"),
    }

    // 記録との差: 受け入れていない鍵は新しく、アカウントから消えた鍵は消えたとする
    let mut record = SignerRecord::new();
    record.add_person("alice@example.com", None).unwrap();
    let source = KeySource {
        host: CodeHost::GitHub,
        user: "alice".into(),
        fetched: "2026-11-21T00:00:00Z".into(),
    };
    for key in [&a, &c] {
        record
            .accept_key(
                "alice@example.com",
                key,
                Some(source.clone()),
                Checked::Account,
            )
            .unwrap();
    }
    let changes = record
        .changes("alice@example.com", CodeHost::GitHub, "alice", &keys)
        .unwrap();
    assert_eq!(changes.new, [keys[1].clone()]);
    let c_fingerprint = record.people[0].keys[1].fingerprint.clone();
    assert_eq!(changes.gone, std::slice::from_ref(&c_fingerprint));
    // 退役させた鍵は消えたとしない。ほかのアカウントの鍵とも比べない
    record
        .retire_key("alice@example.com", &c_fingerprint)
        .unwrap();
    let changes = record
        .changes("alice@example.com", CodeHost::GitHub, "alice", &keys)
        .unwrap();
    assert!(changes.gone.is_empty());
    let changes = record
        .changes("alice@example.com", CodeHost::GitLab, "alice", &[])
        .unwrap();
    assert!(changes.gone.is_empty());
}

/// JSON の文字列の中に入れられる形にする（鍵の行には `"` と `\` は出ないが、念のため）。
fn serde_json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[test]
fn imports_allowed_signers_files() {
    use amonhen_gpg_core::{
        Checked, FetchedKey, SignerRecord, SkipReason, parse_allowed_signers, ssh_fingerprint,
    };
    let dir = tempfile::tempdir().unwrap();
    let (Some((a, _)), Some((b, _))) = (ssh_key(dir.path(), "a"), ssh_key(dir.path(), "b")) else {
        eprintln!("ssh-keygen not found; skipped");
        return;
    };
    let text = format!(
        "# team\n\
         alice@example.com,alice@work.example namespaces=\"git\",valid-after=\"20260101Z\" {a}\n\
         \n\
         bob@example.com {b}\n\
         *@example.com {a}\n\
         ca@example.com cert-authority {a}\n\
         carol@example.com namespaces=\"file\" {b}\n\
         dave@example.com ssh-ed25519 AAAAbrokenbrokenbrokenAAAA\n"
    );
    let parsed = parse_allowed_signers(&text).unwrap();
    let lines: Vec<_> = parsed
        .entries
        .iter()
        .map(|e| (e.line, e.email.as_str()))
        .collect();
    assert_eq!(lines, [(2, "alice@example.com"), (4, "bob@example.com")]);
    assert_eq!(parsed.entries[0].other_principals, ["alice@work.example"]);
    assert_eq!(
        parsed.entries[0].valid_after.as_deref(),
        Some("2026-01-01T00:00:00Z")
    );
    assert_eq!(parsed.entries[0].fingerprint, ssh_fingerprint(&a).unwrap());
    let skipped: Vec<_> = parsed.skipped.iter().map(|s| (s.line, s.reason)).collect();
    assert_eq!(
        skipped,
        [
            (5, SkipReason::Pattern),
            (6, SkipReason::CertAuthority),
            (7, SkipReason::NotForGit),
            (8, SkipReason::Key)
        ]
    );

    // 記録に取り込む: 確かめ方は「ファイルから」、期限はファイルのまま
    let mut record = SignerRecord::new();
    for e in &parsed.entries {
        record.add_person(&e.email, None).unwrap();
        record
            .import_key(&e.email, e, "/team/allowed_signers")
            .unwrap();
    }
    record.add_list("team", "Team").unwrap();
    record.add_member("team", "alice@example.com").unwrap();
    let key = &record.people[0].keys[0];
    assert_eq!(key.checked, Checked::File);
    assert_eq!(
        key.imported.as_ref().map(|i| (i.path.as_str(), i.line)),
        Some(("/team/allowed_signers", 2))
    );
    let text = record.allowed_signers("team").unwrap();
    assert!(
        text.contains("namespaces=\"git\",valid-after=\"20260101000000Z\" ssh-ed25519 "),
        "{text}"
    );
    // 同じ鍵をもう一度取り込んでも増えない
    record
        .import_key("alice@example.com", &parsed.entries[0], "/other")
        .unwrap();
    assert_eq!(record.people[0].keys.len(), 1);
    assert_eq!(
        record.people[0].keys[0].imported.as_ref().unwrap().path,
        "/team/allowed_signers"
    );

    // アカウントと比べる: ファイルの鍵がアカウントにもあれば also、なければ absent
    let fetched = |k: &str| FetchedKey {
        key: k.to_owned(),
        fingerprint: ssh_fingerprint(k).unwrap(),
        title: None,
    };
    let alice = record
        .changes(
            "alice@example.com",
            CodeHost::GitHub,
            "alice",
            &[fetched(&a), fetched(&b)],
        )
        .unwrap();
    assert_eq!(alice.also, [ssh_fingerprint(&a).unwrap()]);
    assert!(alice.absent.is_empty() && alice.gone.is_empty());
    assert_eq!(alice.new.len(), 1, "b is new for alice");
    let bob = record
        .changes("bob@example.com", CodeHost::GitHub, "bob", &[])
        .unwrap();
    assert_eq!(bob.absent, [ssh_fingerprint(&b).unwrap()]);
    assert!(bob.also.is_empty());
}
