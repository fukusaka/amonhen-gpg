# SSH keys, host keys and git signers (design memo)

[日本語](ja/ssh-trust.md)

Written on 2026-11-16 to think the problem through. On 2026-11-20 it was decided to handle git's allowed signers in
this app (see [Decision](#decision-2026-11-20)); the rest is still open.

## The problem

Keys used with SSH and git, and the trust placed in them, are scattered, and nothing shows the whole picture.

| | Where it lives | What goes wrong |
|---|---|---|
| SSH secret keys | Files in `~/.ssh`, ssh-agent, the macOS Keychain, gpg-agent, smart cards, password managers | Hard to tell which key is where, and which keys the agent behind `SSH_AUTH_SOCK` offers |
| SSH public keys | `authorized_keys` on servers, keys registered on GitHub and GitLab | Hard to trace which secret key a public key belongs to, and where it was registered |
| Host keys | `~/.ssh/known_hosts` (often hashed) | The first connection is usually accepted without comparing the fingerprint (trust on first use); old lines stay after a host key changes |
| git's allowed signers | A hand-written file named by `gpg.ssh.allowedSignersFile` | No tool for it, and no record of whose key was checked how |

## What the app does today

Everything goes through gpg-agent; the app never writes to `~/.ssh`.

- My Keys shows "SSH ✓ This Mac" when an authentication subkey of your own key is offered to SSH by gpg-agent.
- The row menu copies or exports the authentication subkey's public key as the line for `authorized_keys`.
- The SSH section turns on gpg-agent's SSH support, lists SSH keys that are not OpenPGP keys, switches whether each
  is offered to SSH, and imports an existing secret key file (from `~/.ssh`) into gpg-agent with `ssh-add`. The file is
  left as it is.

Gaps inside gpg-agent, which fit the current definition (all filled after this memo; restoring a backup needs gpg 2.5.14):

1. Your own key cannot be turned on for SSH from the app (only imported SSH keys can). The core already has
   `set_ssh_key_enabled` (`Use-for-ssh`).
2. An authentication subkey cannot be added to your own key. The core already has `add_subkey` (`--quick-add-key`).
3. For imported SSH keys: no public key to copy or export, no comment shown, no way to remove them from gpg-agent and
   no backup.

## How others handle it

Surveyed on 2026-11-16, from each project's documentation where a source is given; the rest is from memory and not
checked.

- **Seahorse** (GNOME "Passwords and Keys") creates, imports and backs up SSH keys in `~/.ssh` alongside GPG keys. No
  sign of known_hosts handling. ([opensource.com](https://opensource.com/article/19/4/ssh-keys-seahorse),
  [GNOME Wiki](https://wiki.gnome.org/Apps/Seahorse))
- **Kleopatra, GPG Keychain**: GPG (and S/MIME) only. Not checked.
- **Secretive, KeePassXC, 1Password**: hold the secret keys themselves and act as the SSH agent. Not checked, except
  that 1Password documents setting up git commit signing with SSH
  ([1Password](https://developer.1password.com/docs/ssh/git-commit-signing)).
- **Host keys**: no GUI found; people use `ssh-keyscan`, `ssh-keygen -F` and `ssh-keygen -R` by hand. GitHub publishes
  its host keys and fingerprints in `api.github.com/meta` (`ssh_keys`, `ssh_key_fingerprints`) and in its docs, and
  the check is `ssh-keyscan` piped to `ssh-keygen -lf -`
  ([GitHub Changelog](https://github.blog/changelog/2022-01-18-githubs-ssh-host-keys-are-now-published-in-the-api/),
  [GitHub Docs](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints)).
  GitHub replaced its RSA host key in 2023 and old fingerprints are still quoted on the web, so fingerprints must be
  fetched, not hard-coded ([GitHub Blog](https://github.blog/2023-03-23-we-updated-our-rsa-ssh-host-key/)).
  SSH certificates (`@cert-authority` in known_hosts; step-ca, Teleport) avoid per-host keys altogether. Not checked.
- **Allowed signers**: no tool and no fixed location; `~/.ssh`, inside the repository, or committed and shared are all
  conventions. Each line is the email address, `namespaces="git"` and the public key
  ([GitLab Docs](https://docs.gitlab.com/user/project/repository/signed_commits/ssh),
  [DEV](https://dev.to/calebhearth/signing-git-commits-with-your-ssh-key-2p4l)). `https://github.com/<name>.keys` is
  used to collect keys, but it lists authentication keys, which are not necessarily signing keys. sigstore's gitsign
  avoids a key list by signing without long-lived keys. Not checked.

In short, secret keys are split by who holds them, and host keys and allowed signers have almost no tools for
checking trust.

## Mapping to the app's model

The app's three places and its rule "compare the fingerprint, then import" fit the same problem.

| Place | GPG today | SSH and git |
|---|---|---|
| My Keys | Your keys, by whether they can be used | Your SSH secret keys: where each one is, whether it is offered to SSH, where its public key is registered |
| Others' Keys | Keys you verified | People's SSH signing keys with their email address (allowed signers); host keys (known_hosts) |
| Staging | Keys fetched from a keyserver, WKD, GitHub, GitLab or a file | Host keys from `ssh-keyscan`, compared with `api.github.com/meta` or SSHFP in DNS; people's keys fetched from GitHub or GitLab, compared with their owner |

## Options

1. **Stay with GnuPG.** Fill the gpg-agent gaps above and nothing more.
2. **Widen to "your keys and the trust in them".** Also handle SSH keys outside gpg-agent, known_hosts and allowed
   signers, starting read-only.
3. **Option 1 here, and treat SSH and git trust as a separate tool.**

Option 1 stands on its own and is needed in every case.

### One app or a separate front end

For a separate front end (option 3):

- The definition stays clear. This app drives gpg and nothing else; the other drives ssh, ssh-keygen and git, and
  reads and writes files.
- The trust models differ. GPG has validity and signatures; known_hosts and allowed signers are flat lists with no
  record of how an entry was checked, so the separate tool has to keep that record itself.
- The failure modes differ. Breaking known_hosts or the allowed signers file locks the user out of servers or turns
  signatures unverified, which needs its own care.

For one app (option 2):

- Your own keys are one list. An SSH key held by gpg-agent would otherwise appear in both apps.
- Staging and fingerprint comparison would be built twice.

A middle way: design the SSH and git side as its own front end, but share the Rust code (a separate crate in this
repository, using `amonhen_gpg_core::process::command` and the same staging idea), and read gpg-agent's SSH keys
from this app's core rather than managing them twice. Whether it ships as a second app or as a section of this one
can then be decided later.

## If the scope widens

- **Read before writing.** First show where each key is, old or duplicate lines in known_hosts, and the contents of
  the allowed signers file.
- **Do not rewrite the user's files directly.** Prefer files the app owns, pointed at by the user
  (`git config gpg.ssh.allowedSignersFile`, ssh's `UserKnownHostsFile`), and leave edits of the user's files to the
  tools (`ssh-keygen -R`).
- **Do not handle ssh-agent's or a password manager's keys.** Show them at most; they belong to the tool that holds
  them.
- **Keep the same rules as for GPG.** Keys are named by full fingerprint, passphrases only through the tool's own
  prompt, child processes through `amonhen_gpg_core::process::command`, and tests use temporary directories only (never
  the user's `~/.ssh`).

## Decision (2026-11-20)

Thought through from one user's setup: SSH through macOS's ssh-agent (not gpg-agent), git commits signed with GPG,
known_hosts left untidy but not a problem, and teammates who sign with SSH keys whose keys are too tedious to collect.

- Option 1 is done.
- git's allowed signers are handled **in this app** (option 2, limited to allowed signers), because collecting,
  following and retiring signing keys is the real burden, and it fits Staging and the rule "compare the fingerprint,
  then import". Design: [allowed-signers.md](allowed-signers.md).
- What is kept per key is how it was checked (taken from the account, or compared with the owner), not a trust level:
  teammates' keys need no chain of introductions.
- The allowed signers file is plain text that anyone with access to your home folder can change. The app keeps a
  record signed with your own GPG key and notices when the file no longer matches it. This does not stop someone who
  can also change `~/.gitconfig`; ssh trusts files in your home folder in the same way.
- known_hosts (showing old and duplicate lines) comes next if anything does. Keys held by ssh-agent are not handled.

## Open questions

- If the app widens beyond allowed signers: which other files it owns, where they live, and how the user points ssh at
  them.
- Whether hashed known_hosts lines can be shown usefully (only matched against a host name the user types).
