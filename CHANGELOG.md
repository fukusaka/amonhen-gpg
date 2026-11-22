# Changelog

User-visible changes, by release (`v*` tags). Changes not released yet go under `Unreleased`; on release, that
heading becomes `## [x.y.z] - YYYY-MM-DD`, followed by a short summary paragraph that becomes the GitHub Release
notes.

## Unreleased

### Added

- Fetch Again on others' keys (in the row menu and the key window) fetches the key again from where it came from (WKD or a GitHub or GitLab account) or from the keyserver, to get a new expiry or a revocation. The copy waits in Keys to Accept, marked In your keyring with the expiry of your copy, and Update merges it into your keyring.

### Changed

- Keys to Accept is now last in the sidebar, after SSH Signers.
- Keys to Accept has a pop-up menu to choose what to search by: email address, fingerprint, GitHub or GitLab. For GitHub and GitLab, the user name is enough. Pasting an email address, a fingerprint, `github:name` or a profile URL still works and picks the kind.
- When empty, Keys to Accept and SSH Signers show a diagram of where keys come from and where they go. The empty Keys to Accept is centered instead of sitting at the top left.

## [0.4.0] - 2026-11-22

SSH signers for git. Keep the SSH keys others sign commits with as git's allowed signers: fetch them from a GitHub or
GitLab account, or import an existing allowed signers file, accept each one in Keys to Accept (formerly Staging), and
write a file per list for `gpg.ssh.allowedSignersFile`. Imported SSH keys can also be backed up.

### Added

- Back up imported SSH keys from their menu (Back Up…). The backup keeps the passphrase protection gpg-agent gave the key, so no passphrase is asked; keys gpg-agent holds without a passphrase are not backed up. Restore it with Add SSH Key… (needs GnuPG 2.5.14 or later).
- SSH Signers, a new place that keeps git's allowed signers for commits others sign with SSH keys. Add people with their GitHub or GitLab account; their SSH signing keys are fetched with curl and wait in Keys to Accept until you accept each one, as taken from the account or after comparing the fingerprint. Check for Changes fetches them again; retire keys that are gone or no longer trusted, so older commits stay verified. People go into lists, each written as its own allowed signers file to point `gpg.ssh.allowedSignersFile` at; the app never changes git's settings. The record is signed with your own key, and changes made outside the app are reported.
- Import an existing allowed signers file into SSH Signers (Import Allowed Signers File…). Its lines wait in Keys to Accept to be accepted one by one or all at once into a list, keeping `valid-after` and `valid-before`; lines that cannot be imported are listed with the reason. Check for Changes then compares the imported keys with the person's GitHub or GitLab account.

### Changed

- Staging is now called Keys to Accept, which says what it is for: fetched keys wait there until you check and accept them.

## [0.3.0] - 2026-11-18

The web of trust. Set how far you trust the owners of others' keys, and keys they signed count as verified; the key
window shows whose signatures made a key verified. A key whose secret key is on another computer can be marked as
your own. Needs GnuPG 2.4.6 or later.

### Added

- Key details show whose signatures made another person's key verified (your own keys, and keys whose owner you trust), and, for your own keys, how many keys signed them.
- "Mark as My Key…" for a key in Others' Keys that is your own, with its secret key on another computer; it moves to My Keys. "Not My Key…" moves it back.
- Owner trust for others' keys: choose how far you rely on a key's owner to check other keys (not set, not at all, marginally, fully) from the row menu or the key details. Keys signed by people you trust then count as verified.

### Changed

- Requires GnuPG 2.4.6 or later (was 2.4.1), the first version that can set owner trust without the interactive editor. With an older gpg, the app warns above the lists.

## [0.2.0] - 2026-11-17

Finding and comparing keys, and more of SSH. Search your keys, see others' keys in a sortable table, and open any key
in its own window with its signatures, origin and revocation reasons. Staging fetches keys from GitHub and GitLab.
Your own keys can now be turned on for SSH, get a subkey for SSH, and imported SSH keys can be copied and removed.
Settings let you choose the gpg to use, and warnings are quieter.

### Added

- Search My Keys and Others' Keys by name, email address or fingerprint.
- Others' Keys is a table: sort by any column, choose and reorder the columns, and filter by verification from the
  toolbar; the sidebar counts the keys. The columns, sort order and filter are remembered.
- Key details open in a window of their own (double-click, Details…, or Key > Show Details ⌘I), so keys can be
  compared side by side. Tabs show an overview (key ID, algorithm and, for your own keys, where the secret key is, its
  backup, its revocation certificate and SSH use), the names and addresses, and each subkey's fingerprint and keygrip.
- A Signatures tab in the key window lists every signature on the key. Signatures from your own keys and from keys
  you verified come first; the rest are dimmed, since they are no proof that the key is genuine.
- The key window shows where a key came from (keyserver, WKD or file) and when it was last refreshed, why a key,
  subkey or name was revoked, and the SSH fingerprint of authentication subkeys. Keys moved out of staging keep their
  origin. Staging shows where each key came from too.
- Staging fetches the keys a GitHub or GitLab user publishes: search for `github:name`, `gitlab:name` or the profile
  URL.
- Press the space bar on others' keys to quick-look the selected key's fingerprint, validity and expiry.
- A warning above the lists when gpg is older than 2.4.1, which the app needs.
- Settings (⌘,) shows the gpg in use and its version, and lets you choose another gpg or go back to finding it
  automatically.
- Turn your own key on or off for SSH from its menu (Use for SSH, Stop Using for SSH).
- Add a subkey for SSH to a key that has none: it expires with the key and is offered to SSH right away.
- Imported SSH keys show their comment, and their menu copies or exports the public key and removes the key from
  gpg-agent.

### Changed

- Warnings on your own keys are quieter: only expiry within 14 days stays orange; a missing backup or revocation
  certificate, expiry further away and SSH support being off are shown in gray.
- My Keys lists usable keys and keys not usable on this Mac by expiry, soonest first, so the key that needs extending
  is at the top.

### Fixed

- Your own keys can be selected in My Keys, so double-clicking one opens its details and Key > Show Details ⌘I
  works for it too.

## [0.1.0] - 2026-11-14

The first release: a GnuPG front end for macOS that keeps your own keys usable and safe. It shows which of your keys
can sign, decrypt and log in over SSH, and where; warns about keys without a backup or a revocation certificate and
about keys about to expire; and checks fingerprints before you trust someone else's key.

### Added

- My Keys groups your keys into usable, not usable on this Mac, and used before, and shows for each whether it can
  sign, decrypt and authenticate, on this Mac or on a smart card.
- Create a key, extend its expiry (with its subkeys), change its passphrase, back up its secret key, and add, make
  primary or revoke its names and email addresses.
- Warnings for keys without a recorded backup or a revocation certificate, and for keys about to expire; a missing
  revocation certificate can be created again.
- Revoke a key and send it to a keyserver or export it so others learn of it. Deleting a secret key asks for a backup
  first and for the last digits of its fingerprint.
- Others' Keys: mark a key as verified after comparing its fingerprint with its owner, see who verified it, and delete
  public keys.
- Staging: find keys by email address (WKD, then keys.openpgp.org) or fingerprint, or open a key file, and look at them
  before importing them into your keyring.
- SSH through gpg-agent: turn SSH support on, use an authentication subkey for SSH, add existing SSH keys, and copy or
  export the public key for `authorized_keys`.
- Passphrases are always asked by pinentry; the app never sees them, and tells you how to set up pinentry-mac when no
  dialog can be shown.
- Requires macOS 14.4 or later on Apple silicon and GnuPG 2.4.1 or later. English and Japanese.
