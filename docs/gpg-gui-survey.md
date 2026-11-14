# GPG GUI survey

[日本語](ja/gpg-gui-survey.md)

Surveyed on 2026-11-11. Compiled from each tool's official site and documentation.
Not read: the Kleopatra / KGpg handbooks, GpgFrontend's detailed guides (key generation, smart cards, revocation etc.), and the article bodies of the GPG Keychain FAQ. For this reason some items remain "unknown".

## Overall comparison

| | GPG Suite (Keychain) | Kleopatra | GpgFrontend | Seahorse | KGpg | gpg-tui |
|---|---|---|---|---|---|---|
| Supported OS | macOS | Windows (Gpg4win), Linux | Win / Mac / Linux | Linux (GNOME) | Linux (KDE) | Terminal |
| Latest version | Stable version number unknown | 26.08.3 (2026-11-05), Gpg4win 5.1.1 (2026-09-23) | v2.2.x series | Unknown | 26.08.3 (2026-11-05) | Unknown |
| Scope | Key management and OS / mail integration | Key management, crypto operations, smart cards | Key management, crypto operations, mail | Central management of keys and passwords | Key management | Key management only |
| Internals | MacGPG (GnuPG) | GnuPG | Can switch between GnuPG and Rust rPGP. C++/Qt | GNOME Keyring | GnuPG | Rust and GPGME, gpg CLI for missing operations |
| File and text encryption | From the Services menu | File operations and Notepad | File Panel and Text Editor | Unknown | Unknown | Not supported |
| Smart cards | FAQ articles only | Very extensive (OpenPGP / PIV, YubiKey) | Can move secret keys to a card | Unknown | Unknown | Unknown |
| Price | GPG Mail is paid (moving to an annual subscription) | Free | Free (GPLv3) | Free | Free | Free (MIT) |

## By tool

### GPG Suite / GPG Keychain (macOS)

- **Screen:** A simple layout with just one key list. The toolbar has New, Import, Export and Search, and there is a "show secret keys only" checkbox.
- **Key generation:** A key can be made by entering just a name and email address. Key length, expiry and algorithm are set in the advanced view. Uploading to a keyserver can also be chosen at generation time.
- **Context menu:** Send to keyserver, update the key, manage key details.
- **Encryption:** The app itself has no encryption screen. It uses the macOS Services menu (GPG Services) to encrypt and sign text, files and folders in any app.
- **GPG Mail:** An Apple Mail extension. Encrypt and sign buttons are added to the compose window, and a "Security:" header is shown on received mail. Paid, and moving to an annual subscription.
- **Strengths:** Good defaults and the ease of getting things done in a few clicks.
- **Weaknesses:** No description was found of support for showing trust and validity, signing keys, or WKD.

### Kleopatra (KDE / Gpg4win)

- **What it handles:** Both OpenPGP and S/MIME (X.509).
- **Getting and publishing keys:** Search and upload with keyservers, LDAP and WKD.
- **Key trust and expiry:** Both can be set.
- **Smart cards (OpenPGP / PIV):**
  - Changing the PIN and PUK
  - Changing the cardholder information
  - Generating keys on the card
  - Copying existing secret keys to the card
  - Creating keys for SSH authentication
  - YubiKey / Gnuk work without additional drivers
- **Text:** The Notepad screen can encrypt, decrypt and verify text.
- **File manager integration:** Files can be encrypted directly from Dolphin or Explorer.
- **Assessment:** The most comprehensive feature set; the typical "everything included" tool.

### GpgFrontend (cross-platform)

Its UI layout is the most clearly documented.

```
┌ Toolbar (File / Operations / Keys) ───────────────┐
│ Workspace (tabs)              │ Key ToolBox       │
│  - File Panel (batch)         │  Type/Usage/Email │
│  - Text Editor                │  /Status/Expiry   │
│  - Mail Editor (EML)          │                   │
├ Status panel (operation result report) ───────────┤
└ Status bar ───────────────────────────────────────┘
```

- **Key list display:**
  - Type: `pub`, `pub/sec`, `pub/sec^` (key on a card), `group`
  - Usage: C/E/S/A
  - Status: OK / expiring soon / expired / revoked / disabled
- **Context menu:** Set owner trust, add to a category, show key details.
- **Key generation:** Quick generation by right-clicking or long-pressing the New Keypair button.
- **Keyservers:** Publishing and updating through the KeyServerSync module.
- **Operation results:** Each time, shown together as a "SECURITY OPERATION REPORT".
- **Text Editor:** UTF-8 plain text, with a limit of 4 MB.
- **Other features:** Portable mode for carrying on USB, profiles, multiple key databases, post-quantum cryptography (ML-KEM / ML-DSA / SLH-DSA), extension through modules.

### Seahorse (GNOME)

- **What it handles:** Manages PGP keys, SSH keys and passwords together.
- **Main features:** Keyserver sync, signing and publishing keys, passphrase caching, backup, adding photo IDs.
- **Status:** The old wiki has been shut down, and no coherent up-to-date documentation was found.

### KGpg (KDE)

- **What it handles:** Key management, import and export, checking signatures, trust and expiry.
- **Positioning:** A lightweight tool that puts "simple" up front.

### gpg-tui (terminal)

- **Operation:** vim-style single-letter keys. `g` generate, `i` import, `x` export, `s` sign, `e` edit, `f` receive, `u` send, `d` delete.
- **Display:** Trust as `[q] [n] [m] [f] [u] [?]`, revocation as `[rev]`, expiry as `(Y-m-d)`.
- **Shell integration:** `--select` can output the chosen key ID. Example: `gpg -e -r $(gpg-tui --select key-id)`
- **Scope:** Specialized in key management, and states clearly that it does not aim to cover all of gpg's features.

## Implications for building a new GPG GUI

1. **The key list becomes the home screen.** Every tool does this. GpgFrontend's "type, usage, status" columns are dense with information and a clear example.
2. **How trust and validity are shown is where tools differ most.** GPG Suite is too sparse, and gpg-tui is all symbols and hard for beginners to read, so there is room for improvement.
3. **There are 3 entry points for encryption.** OS integration (GPG Suite), a dedicated workspace (GpgFrontend, Kleopatra), and the clipboard. For macOS, Services integration is a must.
4. **Kleopatra has the most mature smart card support.** Many people use YubiKeys, so it is worth learning from.
5. **Reporting operation results together in one place**, as GpgFrontend does, suits conveying information that is easy to misread, such as verification results.

## Sources

- [KDE Apps: Kleopatra](https://apps.kde.org/kleopatra/)
- [Gpg4win](https://www.gpg4win.org/)
- [GPGTools](https://gpgtools.org/)
- [GPG Keychain FAQ](https://gpgtools.tenderapp.com/kb/gpg-keychain-faq)
- [GpgFrontend](https://www.gpgfrontend.bktus.com/)
- [GpgFrontend: Understand Interface](https://www.gpgfrontend.bktus.com/guides/understand-interface/)
- [GpgFrontend GitHub](https://github.com/saturneric/GpgFrontend)
- [Seahorse wiki (archive)](https://wiki.gnome.org/Apps/Seahorse)
- [Seahorse GitLab](https://gitlab.gnome.org/GNOME/seahorse)
- [KDE Apps: KGpg](https://apps.kde.org/kgpg/)
- [gpg-tui GitHub](https://github.com/orhun/gpg-tui)
- [Help Net Security: GUI frontends for GnuPG](https://www.helpnetsecurity.com/2025/01/24/gnupg-gui-frontends/)
