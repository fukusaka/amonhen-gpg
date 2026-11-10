//! 本物の gpg で鍵一覧を確かめる。一時ディレクトリを `--homedir` にし、終わったら gpg-agent を止める。
//! gpg がない環境では何もしない。

use std::path::Path;
use std::process::Stdio;

use amonhen_core::process::command;
use amonhen_core::{Gpg, SecretState, Validity};

struct Home {
    dir: tempfile::TempDir,
}

impl Home {
    fn new() -> Option<Self> {
        let found = command("gpg")
            .arg("--version")
            .stdout(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        found.then(|| Home {
            dir: tempfile::tempdir().unwrap(),
        })
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    /// テストの準備だけはパスフレーズなし・loopback で鍵を作る（アプリは pinentry に任せる）。
    fn gpg(&self, args: &[&str]) {
        let status = command("gpg")
            .arg("--homedir")
            .arg(self.path())
            .args([
                "--batch",
                "--no-tty",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
            ])
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "gpg {args:?} failed");
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = command("gpgconf")
            .arg("--homedir")
            .arg(self.path())
            .args(["--kill", "all"])
            .status();
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

    home.gpg(&[
        "--quick-gen-key",
        "Alice <alice@example.com>",
        "ed25519",
        "cert,sign",
        "never",
    ]);
    let fpr = gpg.list_keys().unwrap()[0].fingerprint.clone();
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
fn missing_program_is_a_spawn_error() {
    let err = Gpg::new()
        .with_program("amonhen-no-such-gpg")
        .list_keys()
        .unwrap_err();
    assert!(matches!(err, amonhen_core::Error::Spawn { .. }));
}
