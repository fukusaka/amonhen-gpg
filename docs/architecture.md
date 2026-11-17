# amonhen-gpgui architecture (first draft)

[日本語](ja/architecture.md)

## Requirements

- A **pure frontend** for GnuPG. GnuPG does the cryptography and stores the keys; the app implements no cryptography of its own.
- The first scope is limited to **key management**. Encryption, decryption, signing and verification come later.
- **Separate the UI and the BE (core) completely.**
- The core is written in Rust and made robust.
- The UIs are SwiftUI (macOS) / GTK4 (Linux) / WinUI 3 (Windows).
- Handle **GPG keys and SSH keys**.

## Overall structure

```
┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│  SwiftUI    │ │   GTK4      │ │  WinUI 3    │   UI: display and input only
│  (Swift)    │ │  (Rust)     │ │  (C#)       │
└──────┬──────┘ └──────┬──────┘ └──────┬──────┘
       │ UniFFI        │ Rust API      │ UniFFI (C#)
┌──────┴───────────────┴───────────────┴──────┐
│ amonhen-gpg-ffi  binding layer (thin)       │
├─────────────────────────────────────────────┤
│ amonhen-gpg-core domain model / use cases   │
│                  gpg engine (run and parse) │
└──────┬───────────────────────┬──────────────┘
       │ gpg / gpgconf         │ Assuan (gpg-connect-agent)
┌──────┴───────────────────────┴──────────────┐
│ GnuPG  (gpg, gpg-agent, pinentry, scdaemon) │
└─────────────────────────────────────────────┘
```

### Separation rules

- The UI knows only the core's public API (use cases and data types). gpg commands and the colon format never leak into the UI.
- The core does not know the UI. Display text and localization are the UI's job; the core returns errors as **a kind code plus structured data**.
- All three UIs go through the same API boundary. The GTK4 version is Rust and can link the core directly, but even then it uses only the same public API as `amonhen-gpg-ffi`.
- The API takes the form "command → result", and all data types are serializable. If we later want to move the core into a separate process (IPC), it can move without changing the API.

## Core design

### How to talk to GnuPG (decided: drive the gpg CLI directly)

| Approach | Pros | Cons |
|---|---|---|
| **gpg CLI + `--with-colons` / `--status-fd`** (chosen) | Depends only on GnuPG itself. Can be written in Rust alone and is easy to build on all 3 OSes. GPGME itself calls gpg internally | We have to own the output parsing |
| GPGME (`gpgme` crate) | Official high-level API | Depends on a C library. Building and distributing is heavy, especially on Windows. Key editing ends up as an edit-key dialog anyway |
| `gpgme-json` | Operated through JSON | A Native Messaging server for browser extensions. Its operations are only keylist / createkey / import / export / delete and crypto operations; it cannot handle expiry, UIDs, subkeys, signatures, trust, revocation, keyservers or SSH |
| Sequoia / rPGP etc. | Pure Rust | No longer a GnuPG FE (outside the requirements) |

gpg itself has no JSON / XML output, and the GnuPG project treats `--with-colons` and the status lines as its machine interface. Driving the CLI directly is the most natural way to get both "a pure FE" and "robust in Rust". The part that calls gpg is kept replaceable inside the core, so a move to GPGME can be considered later when extending to crypto operations or S/MIME.

### Do not handle passphrases

Passphrase entry is left to **pinentry**, which gpg-agent launches. The app's process never touches passphrases or secret key material. This is the biggest benefit of being "a pure FE", and it is also a security boundary.

When the user cancels the entry, return `Error::Canceled`; when the passphrase is wrong, return `Error::BadPassphrase` (told apart by the kind 99 and 11 in gpg's `ERROR` line). gpg prints no `ERROR` when exporting a secret key is canceled, or when creating a revocation certificate is canceled or gets a wrong passphrase, so these are told apart by the `LC_ALL=C` messages. The FE does not need to report a cancel as a failure.

When pinentry cannot be shown, return `Error::NoPinentry`. This covers the case where the configured pinentry does not exist (kind 85) and the case where a terminal pinentry (`PINENTRY_LAUNCHED` with kind `curses` or `tty`) fails; in both, an FE without a terminal cannot ask for the passphrase. Without a terminal, the latter is reported as ENOTTY or as a cancel, so it is told apart before the cancel (if mistaken for a cancel, the FE stops without telling the user anything). Homebrew's gpg uses pinentry-curses by default, so the FE guides the user to set a GUI pinentry (pinentry-mac on macOS) as `pinentry-program` in gpg-agent.conf.

### Do not lose your own keys

The thing to avoid most is deleting your own secret key by mistake, or losing the ability to manage it.

- Keys are referred to only by their full fingerprint (40 / 64 digits). Never by short key ID, name or email address (these can match another key).
- Deletion is split into 2 operations.
  - `delete_public_key`: the public key only. gpg refuses keys that have a secret key, so your own keys are not deleted by this (confirmed by integration tests).
  - `delete_secret_and_public_key`: including the secret key. This cannot be undone, so the FE always confirms and first prompts for a backup of the secret key (`export_secret_key`).
- Secret key backup (export) is provided from stage 1. The exported key is protected by the same passphrase as the original.
- Development and tests use only a `--homedir` in a temporary directory and never touch the user's `~/.gnupg`.
- Future candidates:
  - Show for each key whether a revocation certificate (`openpgp-revocs.d/<FPR>.rev`) exists.
  - Notify about your own keys that expire soon, and lead to extending them (`--quick-set-expire`).
  - Before deleting a secret key, check in the FE that a backup has been made.

### Robustness policy

- `#![deny(unsafe_code)]`. The exceptions are the one place that clears the child process's signal mask (`process.rs`) and the FFI layer.
- gpg is always launched with `--batch --no-tty --status-fd 2`, with `LC_ALL=C` fixed. Listings use `--with-colons --fixed-list-mode`. Human-readable output is not parsed (status lines and human-readable messages on stderr are separated by the `[GNUPG:]` prefix).
- Launch with an argument array, not through a shell. User input (UIDs, file names) is validated, and `--` is placed between it and the options. Keys are always specified by full fingerprint.
- Results are judged by **status lines** (`KEY_CREATED`, `IMPORT_OK`, `IMPORT_RES`, `ERROR`, `FAILURE` etc.), not by the exit code.
- Support timeouts and cancellation (waiting for pinentry can take a long time).
- Require GnuPG 2.4.6 or later: setting owner trust uses `--quick-set-ownertrust`, which gpg has since 2.4.6 (turning SSH on and off for a key uses the private-key attribute `Use-for-ssh`, which gpg-agent has since 2.4.1). The app reads the version (`gpg --version`) whenever it reads the keyring, and shows a warning above the lists when gpg is older; the keys are still listed (`Version::MINIMUM`).
- Tests:
  - Unit tests and fuzz tests for the colon / status parsers.
  - Integration tests against the real gpg, using a `GNUPGHOME` in a temporary directory and loopback pinentry.
  - The path that asks for a passphrase (gpg-agent launches pinentry) is checked with `scripts/fake-pinentry` as `pinentry-program`. It can return a fixed answer, a wrong answer or a cancel. The look of a real pinentry (pinentry-mac etc.) is checked by hand.

### Module layout

```
crates/
  core/     amonhen-gpg-core Domain model, and launching and parsing gpg, gpgconf and gpg-connect-agent (knows neither the UI nor FFI)
  ffi/      amonhen-gpg-ffi  UniFFI entry point (for Swift and C#). uniffi-bindgen also lives here (feature `bindgen`)
apps/
  macos/    SwiftPM package
              CAmonhenGpg     C header generated by UniFFI (systemLibrary)
              AmonhenGpgKit   Generated Swift bindings, and Swift logic that does not depend on screens (grouping your own keys into sections etc.)
              AmonhenGpg      SwiftUI app
  gtk/      GTK4 (gtk4-rs)   not yet
  windows/  WinUI 3 (C#)     not yet
scripts/    building, signing and notarizing, installing, checking the screens, drawing the icon and banner, test helpers
            (see development.md)
.github/    CI, releases, CodeQL and Dependabot
docs/       documents in English; the Japanese versions are in docs/ja/
```

### Bindings

- Swift: UniFFI (`crates/ffi`).
  - The core does not know UniFFI. The core's types are copied in shape in `amonhen-gpg-ffi` as `#[uniffi::remote]` (if a core type changes, compilation fails until they match). Paths (`PathBuf`) are passed as strings.
  - Errors carry things that cannot cross FFI, such as OS errors, so they are moved into `GpgError` (kind and data only; the text belongs to the FE).
  - Calls that wait on gpg (including pinentry) are exposed as synchronous, and the FE calls them from a background thread.
  - `scripts/build-core.sh` builds the static library and generates the Swift bindings into `apps/macos`. The generated files are not committed.
- C#: `uniffi-bindgen-cs`, a third-party UniFFI generator. If its maturity is a concern, switch to a C ABI with cbindgen and P/Invoke.
- GTK4: written in Rust (gtk4-rs), so no FFI is needed.

## Key management scope (stage 1)

For the screen policy (your own keys are the main focus; other people's keys and staging are in separate places), see [ui.md](ui.md).

### GPG keys

| Feature | How gpg does it |
|---|---|
| List and details (public / secret keys, subkeys, UIDs, validity, owner trust, expiry, usage C/S/E/A, keys on a card) | `--list-keys` / `--list-secret-keys --with-colons --with-keygrip` |
| Generate | `--quick-gen-key`, subkeys with `--quick-add-key` |
| Import / export (public keys, secret keys, revocation certificates) | `--import` / `--export` / `--export-secret-keys` |
| Change expiry | `--quick-set-expire` |
| Add and revoke UIDs, set the primary UID | `--quick-add-uid` / `--quick-revoke-uid` / `--quick-set-primary-uid` |
| Sign other people's keys | `--quick-sign-key` / `--quick-lsign-key` (UIDs can be chosen. The signing key is passed to `--local-user` by fingerprint) |
| Set owner trust | `--quick-set-ownertrust` (since 2.4.6) |
| Revoke (whole key, subkeys) | Drive `--edit-key` with `--command-fd` and use `revkey` (`--gen-revoke` does not work in batch mode). So that a mismatch in the answers is noticed, check the revocation in the key list afterwards. The local revocation certificate (`openpgp-revocs.d`) is for when the secret key is lost |
| Create a revocation certificate | `--gen-revoke` without `--batch` (answered with `--no-tty` and `--command-fd`). For keys that have none, recreate it and place it at `openpgp-revocs.d/<FPR>.rev` (like gpg, put a `:` at the start so that importing it by mistake does not revoke the key) |
| Delete | `--delete-secret-and-public-key` (specified by fingerprint) |
| Keyserver / WKD | `--receive-keys` / `--send-keys` / `--locate-external-keys`. What has been sent cannot be taken back, so the FE confirms the keys to send and the destination. When searching by email address, try WKD and the keyserver separately (if combined as `--auto-key-locate wkd,keyserver`, gpg does not go on to the keyserver when WKD errors (iCloud domains return responses that are too large)). A missing key is only visible as a `: No data` message or as a success that imports nothing, so it becomes `Error::NotFound`. GitHub and GitLab: `--fetch-keys https://<host>/<name>.gpg` with `--key-origin url,<URL>`; a user without keys returns an empty key block (`no valid OpenPGP data found`), which is also `Error::NotFound` |
| Change passphrase | `--passwd` (input through pinentry) |
| Import an existing SSH secret key | `ssh-add` (with `SSH_AUTH_SOCK` set to gpg-agent's SSH socket). ssh-add asks for the key file's passphrase through `SSH_ASKPASS`, so a small script that asks through gpg-agent's `GET_PASSPHRASE` (pinentry) is placed in a temporary directory and passed. The passphrase goes directly from the script to ssh-add, and the app never touches it. ssh-add does not report the reason for a cancel or a mistake, and asks again any number of times after a wrong one, so the script leaves a marker and gives up after 3 tries |

### SSH keys (through gpg-agent)

As "a pure FE", the SSH keys handled are also **the ones gpg-agent manages**.

| Feature | How it is done |
|---|---|
| Check and enable gpg-agent's SSH support | `enable-ssh-support` in `gpgconf --list-options gpg-agent`, and `--list-dirs agent-ssh-socket` (passed to SSH_AUTH_SOCK). To enable it, run `gpgconf --change-options`, then restart gpg-agent |
| List SSH keys | Assuan `KEYINFO --list --ssh-fpr --with-ssh` and `KEYINFO --list --need-attr=Use-for-ssh` (gpg-connect-agent. The exit code is 0 even on `ERR`, so judge by the response lines). Linked to the primary key and subkeys of GPG keys by keygrip |
| Use a GPG authentication (A) subkey as an SSH key | Create it with `--quick-add-key <FPR> ed25519 auth` and configure it to be offered to SSH |
| Offer or stop offering to SSH | To offer, set the secret key attribute `Use-for-ssh: true` (`KEYATTR`. Does not rewrite the user's files). To stop, remove the attribute, and if `sshcontrol` has an enabled line, add `!` to it (`sshcontrol` wins even when the attribute is false). Afterwards, ask gpg-agent again to confirm |
| Output the SSH public key (for authorized_keys) | `gpg --export-ssh-key <FPR>!` (the key pointed to, exactly). For SSH keys that are not OpenPGP keys, Assuan `READKEY --format=ssh`, with the comment taken from `READKEY` (gpg-agent writes `(none)` in its place) |
| Remove an imported SSH key | Assuan `DELETE_KEY --force` after the app's own confirmation, only for keygrips that belong to no OpenPGP key; afterwards, ask gpg-agent again to confirm |
| Import an existing SSH secret key | Register it in gpg-agent with `ssh-add` (passphrase through pinentry) |

## Open questions

1. **Scope of SSH keys:** Whether to handle key files in `~/.ssh/` and OpenSSH's ssh-agent, or only keys managed by gpg-agent. This proposal takes the latter.
2. **SSH on Windows:** Working with Win32-OpenSSH needs gpg-agent's `enable-win32-openssh-support`. Check support across GnuPG versions.
3. **Smart cards:** Whether to include them in stage 1. Display (identifying keys on a card) is supported from the start.
4. **macOS distribution:** Under App Sandbox, access to `~/.gnupg` and launching gpg are restricted. Whether to assume distribution outside the App Store (Developer ID + Notarization).
5. **Bundling GnuPG:** Whether to bundle GnuPG with the app, or use an existing installation (Homebrew, GPG Suite, Gpg4win, distribution packages).
