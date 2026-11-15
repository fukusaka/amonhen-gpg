# Changelog

User-visible changes, by release (`v*` tags). Changes not released yet go under `Unreleased`; on release, that
heading becomes `## [x.y.z] - YYYY-MM-DD`, followed by a short summary paragraph that becomes the GitHub Release
notes.

## Unreleased

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
  origin.
- Press the space bar on others' keys to quick-look the selected key's fingerprint, validity and expiry.

### Changed

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
