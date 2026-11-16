# Installation

[日本語](ja/install.md)

Everything is on the [Releases](https://github.com/fukusaka/amonhen-gpg/releases) page. There are two kinds of
release:

- **Stable** releases, tagged `v<version>`. The latest is marked Latest.
- **Snapshot**: the latest development build, updated whenever the code passes its tests.

> [!NOTE]
> Stable releases are notarized and open without a security warning on macOS. Snapshots are signed but not notarized:
> install them with the script below, or allow them once in System Settings > Privacy & Security after downloading.

## GnuPG

The app is a front end and needs GnuPG 2.4.1 or later, with a pinentry that can show a
dialog (with an older gpg, the app warns above the lists). With [Homebrew](https://brew.sh):

```sh
brew install gnupg pinentry-mac
```

[GPG Suite](https://gpgtools.org) and MacGPG2 work too. The app finds `gpg` on the `PATH`, in Homebrew and in GPG
Suite, and opens your usual keyring (`~/.gnupg`). If no passphrase dialog can be shown, it tells you which
`pinentry-program` line to add to `gpg-agent.conf`.

## App (macOS)

1. Download `Amonhen-GPG-<version>.zip` (the snapshot is `Amonhen-GPG-Snapshot-<version>.zip`).
2. Unzip it and move `Amonhen GPG.app` into `/Applications`. The snapshot is called `Amonhen GPG Snapshot.app`, so you
   can keep both.
3. Open it.

## Install or update in one line

This script finds the latest release, downloads it and installs it (or replaces the one you have). It only needs
`curl`:

```sh
curl -fsSL https://raw.githubusercontent.com/fukusaka/amonhen-gpg/main/scripts/install-app.sh | sh -s -- stable
```

Replace `stable` with `snapshot` for the latest development build. Run the same line again to update. If the
app is open while you update it, the script tells you, and the new version is used the next time you open the app.
Downloaded this way, the app carries no quarantine flag, so macOS opens it without asking.

The app goes into `/Applications`. Add `--user` (`sh -s -- --user stable`) to put it in your own Applications folder
(`~/Applications`) instead, `--system` for `/Applications`, or `--dir <folder>` for any folder (created if missing).
Without any of them, an update replaces the app where it is already installed.

From a clone of the repository, run `scripts/install-app.sh` directly.

## Checking a download

Every file on a Release carries a build provenance attestation, which proves it was built by this repository's CI
from a given commit. With the [GitHub CLI](https://cli.github.com/):

```sh
gh attestation verify <file> --repo fukusaka/amonhen-gpg
```

## Requirements

- macOS 14.4 or later on Apple silicon.
- GnuPG 2.4.1 or later, and a pinentry that shows a dialog (pinentry-mac).
