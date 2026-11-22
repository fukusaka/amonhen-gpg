# amonhen-gpgui screen policy (proposal)

[日本語](ja/ui.md)

Instead of managing keys as one flat list, manage mainly **the keys you can use and the keys you used to be able to use**. Other people's keys, and keys fetched temporarily from a keyserver or elsewhere, are handled in separate places.

## 4 places

| Place | Contents | Role |
|---|---|---|
| **My Keys** (main screen) | Keys you can use, keys you used to be able to use | Keep your own keys usable (expiry, backup, card, SSH) |
| **Others' Keys** | Keys used as encryption recipients or to verify signatures | Keep the ones you need |
| **SSH Signers** | People whose SSH-signed git commits you verify, their accepted keys, and lists | Keep git's allowed signers files ([allowed-signers.md](allowed-signers.md)) |
| **Keys to Accept** | Keys fetched from a keyserver, WKD, GitHub or GitLab, keys received as files; SSH signing keys fetched for SSH Signers | Check the contents, then import into "Others' Keys" (or accept into SSH Signers) or discard |

If gpg is older than 2.4.6, a warning above every place says so and suggests updating GnuPG or choosing a newer gpg in Settings. The keys are still listed, but some actions (such as turning SSH on or off) may fail.

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
- **Order within a section:** usable keys and keys not usable on this PC come in order of expiry, soonest first and keys that never expire last, so a key that needs extending is at the top. Keys used before come newest first. There is no sort menu: you have only a few keys of your own.
- **Warnings are shown only for your own keys:** expiry is near, no backup has been made, no revocation certificate (`openpgp-revocs.d`).
- **Dangerous operations** (deleting including the secret key) are kept apart, deep in the details screen, and prompt for a backup first ("Do not lose your own keys" in [architecture.md](architecture.md)).

## Others' Keys

- Keys kept as encryption recipients and for verifying signatures.
- Validity is shown in words, not symbols ("Verified", "Not verified" etc.).
- The "verify" operation signs the key (`Gpg::sign_key`). It first prompts the user to compare the fingerprint with the owner. The default is a non-exportable signature (it only marks the key as verified inside your own keyring); a signature that appears on keyservers is made only when chosen.
- Owner trust (how far you rely on the owner to check other keys before signing them) is chosen in the row menu (Owner Trust) or on the Overview of the key details: not set, not at all, marginally or fully (`Gpg::set_owner_trust`). Ultimate is left out: it belongs to your own keys, and setting it would turn the key into one of yours. A short note says what it does (with gpg's defaults, one signature from a key you trust fully, or three you trust marginally, makes a key verified).
- "Mark as My Key…" in the row menu is for your own key whose secret key is on another computer: after a confirmation that asks you to compare the fingerprint with that computer, it sets ultimate owner trust and the key moves to My Keys (not usable on this Mac). Such a key, mine only by owner trust, has "Not My Key…" in its menu, which sets the owner trust back to not set and moves it to Others' Keys. Keys with a secret key are always your own and do not have it.
- Deletion only deletes the public key (gpg refuses keys that have a secret key).

## Keys to Accept

Formerly called Staging. gpg itself has no notion of a "temporary key", so **use a separate keyring (a temporary `--homedir` managed by the app),** called the staging keyring below and in the code.

1. Searching a keyserver, WKD, GitHub or GitLab puts the results into the staging keyring. A key received as a file can be inspected without importing it, with `gpg --show-keys`.
2. After checking the fingerprint, UIDs and signatures, press "Import". The key is exported from the staging keyring and imported into the real keyring, keeping where it came from (keyserver, WKD, web address or file).
3. Keys you do not use are simply discarded, so the real keyring does not get cluttered.

Signature verification in git and mail looks only at the real keyring, so keys used for those purposes need to be imported.

SSH signing keys fetched for SSH Signers wait here too, in their own section, until they are accepted (as taken from the account, or after comparing the fingerprint with the owner, shown in a monospaced font). They are kept in memory only, like the staging keyring.

## Web of trust

Not shown on the main screen; kept low-key in the key details.

- On the details of another person's key that is verified or partly verified, "Verified by" lists whose signatures it rests on: your own keys, and verified keys whose owner you trust fully or marginally (`Keyring.introducers`; good, unwithdrawn signatures only, as in gpg's pgp trust model).
- For your own keys, the details show only the number of keys that signed them (`Keyring.signerCount`); who signed is on the Signatures tab.
- Do not draw it as a graph.

## What the core is missing

Done:

- Deciding "my key" and the section (usable / not usable on this PC / history) from owner trust and where the secret key is (`Key::is_mine`, `Key::status`). It also returns, for each usage (certify, sign, decrypt, authenticate), where it can be used: this PC, a card, or elsewhere.
- Support for `--show-keys` (inspect the contents without importing) (`Gpg::show_keys`).
- Checking whether a revocation certificate exists (`Gpg::has_revocation_certificate`), and recreating it when it does not (`Gpg::save_revocation_certificate`).
- The staging keyring (`Gpg::staging`, `discard_staging`), and moving only the public keys into the real keyring (`copy_public_keys_to`). `discard_staging` deletes only a directory that has the staging marker (`.amonhen-staging`).
- Fetching from a keyserver (`receive_keys`; fetched by fingerprint) and WKD (`locate_external_key`; searched by email address, falling back to the keyserver). The dirmngr of a new keyring has no keyserver configured, so for staging the FE chooses the keyserver and passes it. GitHub and GitLab (`fetch_from_code_host`; `https://github.com/<name>.gpg` with `--fetch-keys`): the core builds the URL from a user name it has checked, and records the URL as the origin with `--key-origin` (`--fetch-keys` alone records none).
- Card status (`Gpg::card_status`; `Card::holds` matches it against `SecretState::OnCard` in the key list). The behavior with no card is confirmed, but parsing the output with a real card has not been checked yet.
- Editing your own keys (expiry, UIDs, subkeys, passphrase, owner trust, revocation).
- Signing other people's keys (`Gpg::sign_key`).
- Listing signatures by other keys on a key's UIDs (`Gpg::certifications`; checked with `--check-signatures`, self-signatures excluded).
- Sending to a keyserver (`Gpg::send_keys`; used to announce your own revoked key).
- gpg-agent's SSH keys (`Gpg::ssh_support`, `enable_ssh_support`, `ssh_keys`, `set_ssh_key_enabled`, `export_ssh_key`, `ssh_public_key`, `delete_ssh_key`), importing an existing SSH secret key (`Gpg::add_ssh_key`), and backing up and restoring an imported one (`export_ssh_key_backup`, `import_ssh_key_backup`). "SSH ✓ This PC" on the main screen is shown by matching the authentication subkey's keygrip against `SshKey`.

Left out on purpose:

- Searching a keyserver by name (`--search-keys`). keys.openpgp.org, the default, finds keys only by exact email
  address or fingerprint. Keyservers that do search names (such as keyserver.ubuntu.com) return many keys that anyone
  uploaded under someone else's name, and a name proves nothing about a key. Keys to Accept finds keys by email address
  (WKD first), fingerprint, or a GitHub or GitLab user instead.

## What the macOS app (SwiftUI) can do

- The list of your own keys (3 sections) and the list of other people's keys.
- Other people's keys are a table: name (with the number of other user IDs, listed on hover), email address, verification (with Verify… for unverified keys), key ID, created, expires and algorithm. Any column sorts; verified keys come first and revoked keys last, and keys that never expire after all others. A double-click opens the details, the space bar shows a quick look (the fingerprint, validity, expiry and algorithm; it follows the selection, and space again closes it), the context menu holds the row's actions (Fetch Again fetches the key again, from where it came from or from the keyserver, to get a new expiry or a revocation; the copy waits in Keys to Accept, marked In your keyring with the expiry of your copy, and Update merges it; the search field there shows what it looked up first: the email address for WKD, the account for GitHub and GitLab, otherwise the fingerprint), and expired or revoked keys are dimmed. Right-clicking a header shows or hides columns (the name always stays) and headers can be dragged to reorder them; the columns, their order and widths, and the sort order are remembered. A filter menu in the toolbar shows all keys, the verified ones, the ones not verified yet (partly verified keys included) or the expired and revoked ones; it is remembered, and when nothing matches the table says so with a button to show all.
- The sidebar shows how many keys of your own and of other people there are.
- Searching both lists from the toolbar. Every word must match a name or email address (any user ID, ignoring case) or, for hex words of four characters or more, a fingerprint of the primary key or a subkey; a fingerprint pasted with its spaces matches whole. While searching, My Keys hides the SSH section and opens Used Before. Keys to Accept keeps its own field, which searches keyservers.
- Extending expiry ("Extend…" on keys whose expiry is near and on expired keys, and in the row menu). The primary key and the subkeys that have an expiry and are not revoked are all set to the same expiry (extending only the primary key is not enough: once the subkeys expire, the key cannot sign or decrypt). Only keys that are not revoked and whose primary secret key is on this PC or on a card can be extended.
- Names and email addresses ("Names and Email Addresses…" in the row menu). Add a UID, make it primary, revoke it. UIDs are never deleted (once given out, they do not disappear from the other person's copy, so revoke them to announce they are not used). The last one cannot be revoked. When a UID is added to a key that has no primary mark, gpg makes it the primary, so after adding, the primary is set again, and the added one becomes primary only when chosen. After a change, the app suggests sending the updated public key to a keyserver or exporting it. Only keys that are not revoked and whose primary secret key is on this PC or on a card.
- Changing the passphrase ("Change Passphrase…" in the row menu). pinentry asks for the current and the new one; the app never touches them. Existing backups stay protected by the old passphrase, so the app says so when confirming, and suggests making a new backup after the change. Only keys whose secret key is on this PC (keys on a card are protected by the PIN). gpg exits with 0 even when entering the current passphrase is canceled, so the failure is told apart by the `ERROR` status line.
- Backing up the secret key (row menu). The user chooses where to save, and the key is exported in ASCII format. It stays protected by the passphrase, and the file is readable only by the owner (0600). Keys on a card cannot be exported, so only keys whose secret key is on this PC.
- Creating a key ("+" in the toolbar, and the screen shown when there are no keys). Asks only for name, email and expiry (2 years by default), and leaves the algorithm and usage to gpg's defaults. Suggests a backup right after creating it.
- Importing keys (toolbar, and the screen shown when there are no keys). The user chooses files with public keys, secret key backups or revocation certificates; they are imported one by one and the results are reported together. Even if some files cannot be read, the rest are imported. They go directly into the real keyring without going through staging (because the user chose the files).
- Your own keys with no backup record (those whose secret key is on this PC; including keys used before, since they are needed to decrypt old things) get the warning "No backup" and lead to "Back Up…". gpg keeps no record, so the app remembers the time of export per key fingerprint (UserDefaults). A backup made some other way is recorded after confirmation through "Mark as Backed Up…" in the row menu.
- Your own keys with no revocation certificate get the warning "No revocation certificate", and "Create…" recreates one (only keys that are not revoked and whose primary secret key is on this PC or on a card). It is placed in the same `openpgp-revocs.d` that gpg uses when it creates a key, and the app prompts the user to keep a copy somewhere other than this Mac too.
- Only what is urgent stands out in orange on the rows of your own keys: expiry within 14 days. Expiry within 60 days, "No backup", "No revocation certificate" and, in the SSH section, SSH support being off are shown in gray, with their buttons.
- Revoking a key ("Revoke Key…" in the row menu). The user chooses a reason (no longer used, superseded, compromised, not given) and a one-line description, and the app confirms once more that it cannot be undone before revoking. If there is no backup record, it prompts for a backup on the spot (even after revoking, the secret key is needed to decrypt old things). Only keys whose primary secret key is on this PC or on a card can be revoked.
- Giving out the public key (row menu). Export it to a file, or send it to a keyserver (keys.openpgp.org; the app chooses the destination and passes it). What has been sent cannot be taken back, so the app confirms that anyone will be able to fetch it before sending. After revoking, this is how other people find out, so the app suggests it right away.
- Giving out the SSH public key ("Copy SSH Public Key" and "Export SSH Public Key…" in the row menu). Of the authentication subkeys that are not revoked or expired, the newest one is output as the one line written to `authorized_keys` (the file is 0644). If gpg-agent does not offer this key to SSH yet, the app notes that.
- Turning your own key on or off for SSH ("Use for SSH" and "Stop Using for SSH" in the row menu). Turning on offers the newest usable authentication subkey whose secret key gpg-agent holds; turning off stops every part of the key that gpg-agent offers. If SSH support is off, the app says the key cannot be used until it is turned on.
- Adding a subkey for SSH ("Add Subkey for SSH…" in the row menu, for usable keys without a usable authentication subkey whose primary secret key is on this PC or a card). After confirmation, gpg adds an authentication subkey with its default algorithm that expires with the key, and the app offers it to SSH. The app then offers to copy the SSH public key and to make a new backup, since earlier backups lack the subkey.
- Keys to Accept. Choose what to search by in a pop-up menu next to the field: email address (WKD, falling back to keys.openpgp.org), fingerprint (keys.openpgp.org), or GitHub or GitLab to fetch the keys a user publishes (the user name; `github:name`, `gitlab:name` or the profile URL also work, and pasting one of these, an email address or a fingerprint picks the kind; they only show that the account registered the key, so the fingerprint still has to be compared with its owner; the account's SSH signing keys come along, to accept into SSH Signers under an email address chosen from guesses, see [allowed-signers.md](allowed-signers.md)), or add from a file (even from a file that contains secret keys, only the public keys are added). Look at the UIDs, fingerprint, where the key came from (the keyserver's host, the email domain's WKD, the web address such as github.com, or a file), creation date and expiry, then "Import" (move only the public key into the real keyring) or "Discard". Never search by short key ID or name. The staging keyring is created in a temporary directory at each launch and discarded when the app quits. Its name includes the ID of the process that created it, and ones left behind by a crashed app are discarded at the next launch (ones whose process is still running, and ones without the staging marker, are not touched).
- Marking other people's keys as verified ("Verify…" on unverified keys, and in the row menu). The fingerprint is shown large, and signing is not possible until the user answers that they compared it with the owner. Only the UIDs that were checked are chosen and signed (even if UIDs are added later, unchecked ones are not signed). The user chooses which of their own keys to sign with. The default is a non-exportable signature; a signature published with the key is made only when chosen.
- Key details ("Details…" in the row menu, double-clicking a row, or Key > Show Details ⌘I). Each key opens in a window of its own (opening it again brings the same window forward), so keys can be compared side by side; if the key leaves the keyring, the window says so. The name and the fingerprint are at the top (with Fetch Again for others' keys), and the rest is in tabs. Overview: the key ID, validity, owner trust (for others' keys, with a menu to change it), whose signatures made it verified (for others' keys), creation date, expiry, the reason and description of a revocation (an exposed secret key stands out), the algorithm, and where the key came from (a keyserver, the email domain's WKD, a file, with the host and the date it was last refreshed; for your own keys only when known), and for your own keys where the secret key is (this PC, a smart card, stored elsewhere), the backup record, the revocation certificate, the number of keys that signed it, and whether it is set for SSH with its SSH fingerprint. Names: validity per UID, and the reason for a revoked one. Keys: the usage, creation date, expiry, revocation reason, secret key location, fingerprint and keygrip of the primary key and each subkey, and the SSH fingerprint (`SHA256:…`) of authentication subkeys whose secret key gpg-agent holds. Signatures: every signature on the key's UIDs, with the signer (the name if the key is in the keyring, otherwise only the key ID), the UID, the result of checking it (good, does not check out, cannot check because the signer's key is missing, withdrawn), the date and whether it is published with the key. Signatures from your own keys and from keys you verified come first. Signatures by other people are not proof of authenticity when the signers are unknown, so the rest come below, dimmed, under a note that says so.
- Deleting another person's public key (row menu). Deleted after confirmation. The app says that the signatures that marked it as verified are deleted too.
- The SSH section of the My Keys screen. If gpg-agent's SSH support is disabled, the app says so and enables it after confirmation (adds it to gpg-agent.conf and restarts gpg-agent). Lists SSH keys that are not OpenPGP keys (keys imported with ssh-add) by their comment, and switches whether each is used for SSH. Each one's menu copies or exports its public key as the line for `authorized_keys`, backs it up ("Back Up…": the key as gpg-agent stores it, still protected by the passphrase given when it was added, in a file only you can read named `<keygrip>.key`; no passphrase is asked, and a key gpg-agent keeps without a passphrase is not backed up, with a note on how to protect it), and removes it from gpg-agent after confirmation (the key file it came from is not touched). Imports existing SSH secret key files (`~/.ssh`) and restores backups through the same "Add SSH Key…" (gpg 2.5.14 or later; with an older gpg, the app explains how to restore by copying the file into `private-keys-v1.d`). Shows the location of the socket to point `SSH_AUTH_SOCK` at.
- SSH Signers ([allowed-signers.md](allowed-signers.md)). Lists (one allowed signers file each, with commands to copy for `git config`), people with their GitHub or GitLab account and accepted keys (how each was checked, retired keys with the time), Check for Changes (fetched keys go to Keys to Accept; keys gone from the account get Retire), per key Retire… and Remove Key…, and Import Allowed Signers File… (lines wait in Keys to Accept with a list to put the people in, Accept All, and the lines that cannot be imported with the reason; imported keys are compared with the person's accounts on Check for Changes). The record is signed with a key of yours that can sign (chosen in the toolbar when there are several); a record not signed by your own key, or a file changed outside the app, is reported, and Write the Files Again rewrites the files from the record. git's settings are never changed.
- Settings (⌘,). Shows the gpg program in use and its version. "Choose…" picks another gpg (hidden folders such as /opt are shown, and a symlink is kept as is, so a Homebrew upgrade keeps working); it is used only if its version can be read. "Find Automatically" goes back to the first gpg in `PATH`, /opt/homebrew/bin, /usr/local/bin or /usr/local/MacGPG2/bin. The choice is remembered (UserDefaults), and changing it reads the keyring again and starts staging over empty (its keyring was made by the previous gpg). The `--gpg` launch option comes first, and Settings then only shows it.
- Deleting including the secret key (at the very bottom of the row menu). If the secret key is on this PC, deletion is not allowed until there is a backup record (a backup can be made on the spot). If the key is not revoked, the app says that other people will keep encrypting to it, and leads to revocation. The user types the last 4 characters of the fingerprint, and the app confirms once more at the end. gpg-agent does not confirm with pinentry when deleting a secret key, so the app's confirmation is all there is.
- Passphrases are asked for by gpg-agent's pinentry. When the entry is canceled, the app returns to the previous screen without any message; when the passphrase is wrong, it says so. When pinentry cannot be shown (a terminal pinentry such as pinentry-curses is in use), the app shows the `pinentry-program` line to add to gpg-agent.conf (with the location of the installed pinentry-mac). The app does not rewrite the configuration.

## Open questions

- Mapping to each OS's UI components (SwiftUI / GTK4 / WinUI).
