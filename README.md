<h1><img src="docs/images/banner.png" alt="Amonhen GPG"></h1>

[![CI](https://github.com/fukusaka/amonhen-gpg/actions/workflows/ci.yml/badge.svg)](https://github.com/fukusaka/amonhen-gpg/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

[日本語](README.ja.md)

A front end for GnuPG that keeps your own keys usable and safe. It shows which of your keys you can sign, decrypt
and log in with, and where (this Mac or a smart card), and warns before a key expires or is lost for good.

![My Keys in Amonhen GPG: a usable key that expires in 19 days and has no backup, a key whose secret key is on another machine, and keys used before](docs/images/my-keys.png)

## Features

- **Your keys first** — Your keys are grouped into usable, not usable on this Mac, and used before. Each shows
  whether it can sign, decrypt and authenticate, and where.
- **Don't lose them** — Warnings for keys without a backup or a revocation certificate, and for keys about to
  expire. Extend the expiry of a key and its subkeys at once. Deleting a secret key asks for a backup first and for the
  last digits of its fingerprint.
- **Your names and addresses** — Add, make primary or revoke the names and email addresses of a key. Change its
  passphrase. Revoke a key and tell others by sending it to a keyserver.
- **Others' keys** — Mark a key as verified only after comparing its fingerprint with its owner, and see who verified
  it. Keys found by email address (WKD or keys.openpgp.org) or by fingerprint wait in a staging keyring until you
  import them.
- **SSH** — Use an authentication subkey for SSH through gpg-agent, turn SSH support on, add existing SSH keys and copy
  the public key for `authorized_keys`.
- **A pure front end** — GnuPG does all the cryptography. Passphrases go to pinentry and never through the app.

> [!WARNING]
> This is a work in progress. Features may change without notice, and it comes with no warranty. Keep backups of your
> secret keys.

## Installation

On a Mac (macOS 14.4 or later, Apple silicon), with GnuPG 2.2 or later (2.4 or later recommended) from
[Homebrew](https://brew.sh) (`brew install gnupg pinentry-mac`), [GPG Suite](https://gpgtools.org) or MacGPG2:

1. Download `Amonhen-GPG-Snapshot-<version>.zip` from the
   [snapshot](https://github.com/fukusaka/amonhen-gpg/releases/tag/snapshot) pre-release. It is the latest `main`,
   signed but not notarized yet.
2. Unzip it and move `Amonhen GPG Snapshot.app` into `/Applications`.
3. Open it. Downloaded in a browser, macOS stops it the first time; allow it under System Settings > Privacy &
   Security.

The app finds `gpg` on the `PATH`, in Homebrew and in GPG Suite, and opens your usual keyring (`~/.gnupg`). If no
passphrase dialog can be shown, it tells you how to set `pinentry-program` to pinentry-mac.

To build it yourself, see [Development](#development).

## Documents

- [Screen policy](docs/ui.md): what each place shows, and what the app can do
- [Architecture](docs/architecture.md): the Rust core, the bindings and how gpg is driven
- [Survey of GPG GUIs](docs/gpg-gui-survey.md)

## Development

```bash
cargo test --workspace                      # Rust; integration tests run gpg in a temporary --homedir
scripts/build-core.sh && (cd apps/macos && swift test)
scripts/build-app.sh snapshot               # dist/Amonhen GPG Snapshot.app and its zip
scripts/snapshots.sh                        # capture every screen from a sample keyring into dist/snapshots
```

Tests and screenshots never touch `~/.gnupg`: they use temporary keyrings (`scripts/sample-keyring.sh`).

## License

[MIT](LICENSE-MIT) or [Apache License 2.0](LICENSE-APACHE), at your option.
