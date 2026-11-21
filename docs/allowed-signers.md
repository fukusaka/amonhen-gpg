# git's allowed signers (design)

[日本語](ja/allowed-signers.md)

Written on 2026-11-20. Follows [SSH keys, host keys and git signers](ssh-trust.md), which decided to handle git's
allowed signers in this app. Not built yet.

## Goal

Verify commits that others sign with SSH keys, without collecting and maintaining their keys by hand.

git checks an SSH signature against the file named by `gpg.ssh.allowedSignersFile`. Each line holds the signer's
email address, options such as `namespaces="git"` and `valid-before="YYYYMMDD"`, and the public key. Three things
make it tedious, so the file is often left alone:

- **Collecting.** Each person's signing keys have to be copied from GitHub or GitLab one by one.
- **Following.** Nothing tells you when someone makes a new key; their commits just show as unverified.
- **Retiring.** Deleting an old key makes their past commits unverifiable, and keeping it trusts it forever.
  `valid-before` solves this, but nobody writes it by hand.

The file is plain text that anyone with access to your home folder can change, and git trusts whatever it says.

## What the app does

- **Follow people.** You add a person as an account on GitHub or GitLab together with the email address they sign
  with. The app fetches that account's SSH signing keys.
- **Keep lists.** People go into lists, for example one per team or per repository. Each list becomes its own
  allowed signers file. A person can be in several lists; their keys are kept once.
- **Compare before accepting.** Fetched keys go to Staging, as GPG keys do. You accept each key, either as fetched
  from the account, or after comparing its fingerprint with the owner.
- **Check for changes.** On request, the app fetches every followed account again and shows only the difference: new
  keys go to Staging; keys no longer on the account are proposed for retirement with `valid-before` set to that day,
  so commits signed before stay verified. Nothing is accepted or retired without you.
- **Keep a signed record.** The record of who each key belongs to and how it was checked is signed with your own GPG
  key. The allowed signers file is written from the record.
- **Notice changes made behind its back.** When the app opens the record, it verifies the signature and compares the
  allowed signers file with what the record says. A mismatch is shown, not silently repaired.

## Files

In the app's own folder (`~/Library/Application Support/Amonhen GPG/` on macOS). The app never writes `~/.ssh` and
never changes git's configuration.

| File | Contents |
|---|---|
| `ssh-signers.json` | The record (below) |
| `ssh-signers.json.sig` | Detached signature of the record by your own key (`gpg --detach-sign`, through pinentry) |
| `<list>.allowed_signers` | One per list, written from the record, for git to read |

Each allowed signers file is written to a temporary file and renamed over the old one, so git never reads half a file.
Removing a list removes its file.
It stays a regular file: a named pipe served by the app also works with git (tried with OpenSSH 10.3 and git 2.56,
two opens per verified commit), but git hangs when nothing serves it.

git can point at a file for all repositories or for one (tried with git 2.56; a repository's own setting wins, and
`includeIf` can choose by folder). The app shows the commands for a list's file, and leaves running them to you:

```sh
git config --global gpg.ssh.allowedSignersFile "$HOME/Library/Application Support/Amonhen GPG/work.allowed_signers"
git -C <repository> config gpg.ssh.allowedSignersFile "$HOME/Library/Application Support/Amonhen GPG/work.allowed_signers"
```

### The record

One entry per person, each with their keys, and the lists naming their members. A sketch:

```json
{
  "version": 1,
  "people": [
    {
      "email": "alice@example.com",
      "accounts": [{ "host": "github.com", "user": "alice" }],
      "keys": [
        {
          "key": "ssh-ed25519 AAAA...",
          "fingerprint": "SHA256:...",
          "source": { "host": "github.com", "user": "alice", "fetched": "2026-11-20T10:00:00Z" },
          "checked": "account",
          "accepted": "2026-11-20T10:05:00Z",
          "valid_before": null
        }
      ]
    }
  ],
  "lists": [{ "id": "work", "name": "Work", "members": ["alice@example.com"] }]
}
```

- `checked` is `account` (taken from the account as it was) or `fingerprint` (compared with the owner).
- `valid_before` is set when a key is retired, and is written as `valid-before` in the allowed signers file.
- A list's `id` names its file (lowercase letters, digits and `-`).
- Every line of the allowed signers file has `namespaces="git"`.
- One email address per person is enough. git does not compare the committer's address with the file, so their
  commits verify whichever address they use; the address is only what git shows as the signer (tried with OpenSSH
  10.3 and git 2.56).

## Fetching

The core runs `curl` to fetch over HTTPS (gpg cannot fetch SSH keys), so TLS stays outside the app as it does for gpg.
curl comes with macOS, most Linux distributions and Windows 10 or later. No authentication; only public keys are
read.

| Host | Request | Keys used |
|---|---|---|
| GitHub | `GET https://api.github.com/users/<user>/ssh_signing_keys?per_page=100` | All (signing keys only) |
| GitLab | `GET https://gitlab.com/api/v4/users/<user>/keys` | `usage_type` is `signing` or `auth_and_signing` |

`https://github.com/<user>.keys` is not used: it lists authentication keys, which are not necessarily signing keys.
GitHub allows 60 unauthenticated requests per hour, enough for checking a team by hand.

## Rules kept

- Keys are named by their full SHA256 fingerprint.
- Passphrases only through pinentry (signing the record).
- Child processes (gpg, curl, and git for reading `gpg.ssh.allowedSignersFile`) through
  `amonhen_gpg_core::process::command`.
- Tests use temporary folders and a local HTTP server only; never the user's `~/.ssh`, git configuration or the
  network.

## Not now

- An allowed signers file committed in a repository and shared by a team (git reads one by a relative path).
- `gpg.ssh.revocationFile`, and `cert-authority` lines.
- Self-hosted GitLab and GitHub Enterprise.
- known_hosts, and keys held by ssh-agent.

## Decided on 2026-11-21

- **Signing key.** You choose which of your keys signs the record, as when you verify someone's key. A signature by
  any of your own keys (ones gpg trusts ultimately) is accepted, so after replacing your key the record is simply
  signed again with the new one on the next change.
- **Screen.** A new place, **git Signers**, next to My Keys, Others' Keys and Staging: lists, people and their keys,
  how each key was checked, and Check for Changes.

## Open questions

- The folder on Linux and Windows.
