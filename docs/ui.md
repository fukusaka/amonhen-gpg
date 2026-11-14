# amonhen-gpgui screen policy (proposal)

[日本語](ja/ui.md)

Instead of managing keys as one flat list, manage mainly **the keys you can use and the keys you used to be able to use**. Other people's keys, and keys fetched temporarily from a keyserver or elsewhere, are handled in separate places.

## 3 places

| Place | Contents | Role |
|---|---|---|
| **My Keys** (main screen) | Keys you can use, keys you used to be able to use | Keep your own keys usable (expiry, backup, card, SSH) |
| **Others' Keys** | Keys used as encryption recipients or to verify signatures | Keep the ones you need |
| **Staging** | Keys fetched from a keyserver or WKD, keys received as files | Check the contents, then import into "Others' Keys" or discard |

## Main screen: My Keys

Split keys into 3 sections by "whether they can be used".

```
My Keys                                          [+ Create] [Import]
─────────────────────────────────────────────────────────────────
Usable
  🔑 Alice <alice@example.com>                    ⚠ Expires in 30 days [Extend]
     Sign ✓ This PC   Decrypt ✓ This PC   SSH ✓ This PC
  💳 Work <a@corp.example>
     Sign ✓ YubiKey   Decrypt ✓ YubiKey   SSH ✓ YubiKey  ("Insert the card" if the card is not connected)

Not usable on this PC
  🖥 Alice (for home PC) <alice@home.example>
     Secret key is not on this PC · public key only    [Import secret key…]

Used before (history)                                  ▸ 3 keys
  ⌛ Alice 2019 — expired 2024-03   [Extend] [Revoke…]
  ⛔ Old <old@example.com> — revoked 2021
```

- **For each key, show what it can do, by usage.** For signing, decryption and SSH (authentication), show "whether it can" and "where it can (this PC, YubiKey)" side by side. The difference between the primary key and subkeys is not shown until the details screen.
- **What counts as "my key":** a key with ultimate owner trust (`u`), or a key that has a secret key (including stubs and keys on a card). Deciding by the secret key alone would miss "my own key whose secret key is on another PC".
- **How the sections are split:**
  - Usable: valid, and the secret key for at least one usage is on this PC or on a card.
  - Not usable on this PC: valid, but the secret key is not on this PC (public key only, or only a stub).
  - Used before (history): expired or revoked. Collapsed by default. An expired key can be brought back by extending it; revoking it settles it as history. The secret key is assumed to be kept, to decrypt things encrypted to old keys.
- **Warnings are shown only for your own keys:** expiry is near, no backup has been made, no revocation certificate (`openpgp-revocs.d`).
- **Dangerous operations** (deleting including the secret key) are kept apart, deep in the details screen, and prompt for a backup first ("Do not lose your own keys" in [architecture.md](architecture.md)).

## Others' Keys

- Keys kept as encryption recipients and for verifying signatures.
- Validity is shown in words, not symbols ("Verified", "Not verified" etc.).
- The "verify" operation signs the key (`Gpg::sign_key`). It first prompts the user to compare the fingerprint with the owner. The default is a non-exportable signature (it only marks the key as verified inside your own keyring); a signature that appears on keyservers is made only when chosen.
- Deletion only deletes the public key (gpg refuses keys that have a secret key).

## Staging

gpg itself has no notion of a "temporary key", so **use a separate keyring (a temporary `--homedir` managed by the app).**

1. Searching a keyserver or WKD puts the results into the staging keyring. A key received as a file can be inspected without importing it, with `gpg --show-keys`.
2. After checking the fingerprint, UIDs and signatures, press "Import". The key is exported from staging and imported into the real keyring.
3. Keys you do not use are simply discarded, so the real keyring does not get cluttered.

Signature verification in git and mail looks only at the real keyring, so keys used for those purposes need to be imported.

## Web of trust

Not shown on the main screen. Few people use it, so it comes later, and if shown at all, it is kept low-key.

- On the details screen of another person's key, show in one line "whose signature made it verified".
- For your own keys, just show the number of signatures received.
- Do not draw it as a graph.

## What the core is missing

Done:

- Deciding "my key" and the section (usable / not usable on this PC / history) from owner trust and where the secret key is (`Key::is_mine`, `Key::status`). It also returns, for each usage (certify, sign, decrypt, authenticate), where it can be used: this PC, a card, or elsewhere.
- Support for `--show-keys` (inspect the contents without importing) (`Gpg::show_keys`).
- Checking whether a revocation certificate exists (`Gpg::has_revocation_certificate`), and recreating it when it does not (`Gpg::save_revocation_certificate`).
- The staging keyring (`Gpg::staging`, `discard_staging`), and moving only the public keys into the real keyring (`copy_public_keys_to`). `discard_staging` deletes only a directory that has the staging marker (`.amonhen-staging`).
- Fetching from a keyserver (`receive_keys`; fetched by fingerprint) and WKD (`locate_external_key`; searched by email address, falling back to the keyserver). The dirmngr of a new keyring has no keyserver configured, so for staging the FE chooses the keyserver and passes it.
- Card status (`Gpg::card_status`; `Card::holds` matches it against `SecretState::OnCard` in the key list). The behavior with no card is confirmed, but parsing the output with a real card has not been checked yet.
- Editing your own keys (expiry, UIDs, subkeys, passphrase, owner trust, revocation).
- Signing other people's keys (`Gpg::sign_key`).
- Listing signatures by other keys on a key's UIDs (`Gpg::certifications`; checked with `--check-signatures`, self-signatures excluded).
- Sending to a keyserver (`Gpg::send_keys`; used to announce your own revoked key).
- gpg-agent's SSH keys (`Gpg::ssh_support`, `enable_ssh_support`, `ssh_keys`, `set_ssh_key_enabled`, `export_ssh_key`), and importing an existing SSH secret key (`Gpg::add_ssh_key`). "SSH ✓ This PC" on the main screen is shown by matching the authentication subkey's keygrip against `SshKey`.

Not yet:

- Searching a keyserver by name (`--search-keys`). After checking the shape of its output in batch mode.

## What the macOS app (SwiftUI) can do

- The list of your own keys (3 sections) and the list of other people's keys.
- Extending expiry ("Extend…" on keys whose expiry is near and on expired keys, and in the row menu). The primary key and the subkeys that have an expiry and are not revoked are all set to the same expiry (extending only the primary key is not enough: once the subkeys expire, the key cannot sign or decrypt). Only keys that are not revoked and whose primary secret key is on this PC or on a card can be extended.
- Names and email addresses ("Names and Email Addresses…" in the row menu). Add a UID, make it primary, revoke it. UIDs are never deleted (once given out, they do not disappear from the other person's copy, so revoke them to announce they are not used). The last one cannot be revoked. When a UID is added to a key that has no primary mark, gpg makes it the primary, so after adding, the primary is set again, and the added one becomes primary only when chosen. After a change, the app suggests sending the updated public key to a keyserver or exporting it. Only keys that are not revoked and whose primary secret key is on this PC or on a card.
- Changing the passphrase ("Change Passphrase…" in the row menu). pinentry asks for the current and the new one; the app never touches them. Existing backups stay protected by the old passphrase, so the app says so when confirming, and suggests making a new backup after the change. Only keys whose secret key is on this PC (keys on a card are protected by the PIN). gpg exits with 0 even when entering the current passphrase is canceled, so the failure is told apart by the `ERROR` status line.
- Backing up the secret key (row menu). The user chooses where to save, and the key is exported in ASCII format. It stays protected by the passphrase, and the file is readable only by the owner (0600). Keys on a card cannot be exported, so only keys whose secret key is on this PC.
- Creating a key ("+" in the toolbar, and the screen shown when there are no keys). Asks only for name, email and expiry (2 years by default), and leaves the algorithm and usage to gpg's defaults. Suggests a backup right after creating it.
- Importing keys (toolbar, and the screen shown when there are no keys). The user chooses files with public keys, secret key backups or revocation certificates; they are imported one by one and the results are reported together. Even if some files cannot be read, the rest are imported. They go directly into the real keyring without going through staging (because the user chose the files).
- Your own keys with no backup record (those whose secret key is on this PC; including keys used before, since they are needed to decrypt old things) get the warning "No backup" and lead to "Back Up…". gpg keeps no record, so the app remembers the time of export per key fingerprint (UserDefaults). A backup made some other way is recorded after confirmation through "Mark as Backed Up…" in the row menu.
- Your own keys with no revocation certificate get the warning "No revocation certificate", and "Create…" recreates one (only keys that are not revoked and whose primary secret key is on this PC or on a card). It is placed in the same `openpgp-revocs.d` that gpg uses when it creates a key, and the app prompts the user to keep a copy somewhere other than this Mac too.
- Revoking a key ("Revoke Key…" in the row menu). The user chooses a reason (no longer used, superseded, compromised, not given) and a one-line description, and the app confirms once more that it cannot be undone before revoking. If there is no backup record, it prompts for a backup on the spot (even after revoking, the secret key is needed to decrypt old things). Only keys whose primary secret key is on this PC or on a card can be revoked.
- Giving out the public key (row menu). Export it to a file, or send it to a keyserver (keys.openpgp.org; the app chooses the destination and passes it). What has been sent cannot be taken back, so the app confirms that anyone will be able to fetch it before sending. After revoking, this is how other people find out, so the app suggests it right away.
- Giving out the SSH public key ("Copy SSH Public Key" and "Export SSH Public Key…" in the row menu). Of the authentication subkeys that are not revoked or expired, the newest one is output as the one line written to `authorized_keys` (the file is 0644). If gpg-agent does not offer this key to SSH yet, the app notes that.
- Staging. Search by email address (WKD, falling back to keys.openpgp.org) or fingerprint (keys.openpgp.org), or add from a file (even from a file that contains secret keys, only the public keys are added). Look at the UIDs, fingerprint, creation date and expiry, then "Import" (move only the public key into the real keyring) or "Discard". Never search by short key ID or name. The staging keyring is created in a temporary directory at each launch and discarded when the app quits. Its name includes the ID of the process that created it, and ones left behind by a crashed app are discarded at the next launch (ones whose process is still running, and ones without the staging marker, are not touched).
- Marking other people's keys as verified ("Verify…" on unverified keys, and in the row menu). The fingerprint is shown large, and signing is not possible until the user answers that they compared it with the owner. Only the UIDs that were checked are chosen and signed (even if UIDs are added later, unchecked ones are not signed). The user chooses which of their own keys to sign with. The default is a non-exportable signature; a signature published with the key is made only when chosen.
- Key details ("Details…" in the row menu, or double-clicking a row). Validity per UID, and the algorithm, usage, creation date and expiry of the primary key and subkeys. For each UID, shows when it was verified with your own keys (the signing key, the date, whether the signature is published, whether it was withdrawn). Signatures by other people are not proof of authenticity when the signers are unknown, so only the count is shown as "N others", and the names appear on mouse hover.
- Deleting another person's public key (row menu). Deleted after confirmation. The app says that the signatures that marked it as verified are deleted too.
- The SSH section of the My Keys screen. If gpg-agent's SSH support is disabled, the app says so and enables it after confirmation (adds it to gpg-agent.conf and restarts gpg-agent). Lists SSH keys that are not OpenPGP keys (keys imported with ssh-add) and switches whether each is used for SSH. Imports existing SSH secret key files (`~/.ssh`). Shows the location of the socket to point `SSH_AUTH_SOCK` at.
- Deleting including the secret key (at the very bottom of the row menu). If the secret key is on this PC, deletion is not allowed until there is a backup record (a backup can be made on the spot). If the key is not revoked, the app says that other people will keep encrypting to it, and leads to revocation. The user types the last 4 characters of the fingerprint, and the app confirms once more at the end. gpg-agent does not confirm with pinentry when deleting a secret key, so the app's confirmation is all there is.
- Passphrases are asked for by gpg-agent's pinentry. When the entry is canceled, the app returns to the previous screen without any message; when the passphrase is wrong, it says so. When pinentry cannot be shown (a terminal pinentry such as pinentry-curses is in use), the app shows the `pinentry-program` line to add to gpg-agent.conf (with the location of the installed pinentry-mac). The app does not rewrite the configuration.

## Open questions

- Mapping to each OS's UI components (SwiftUI / GTK4 / WinUI).
