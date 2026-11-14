# Development

[日本語](ja/development.md)

Building, testing, and checking the screens. For the design see [architecture.md](architecture.md) and
[ui.md](ui.md).

Tests and screenshots never touch `~/.gnupg`: they use temporary keyrings. Never point the app or the tests at your
own keyring.

## Build and test

```sh
cargo test --workspace                      # Rust; integration tests run gpg in a temporary --homedir
cargo clippy --workspace --all-targets -- -D warnings
scripts/build-core.sh && (cd apps/macos && swift test)
scripts/build-app.sh snapshot               # dist/Amonhen GPG Snapshot.app and its zip
```

After changing a workflow in `.github/workflows`, check it with
[actionlint](https://github.com/rhysd/actionlint) and [zizmor](https://docs.zizmor.sh)
(`brew install actionlint zizmor`):

```sh
actionlint && zizmor --persona=pedantic .
```

- `scripts/build-core.sh` builds the Rust core as a static library and generates the Swift bindings (not committed).
- `scripts/swift-build.sh` runs `swift build` in `apps/macos` so that the app records the real SDK version (Swift 6.4
  otherwise records the deployment target, and macOS shows the app with the old look).
- `scripts/build-app.sh [stable|snapshot]` signs with `AMONHEN_SIGN_IDENTITY` if set (ad hoc otherwise), and notarizes
  when the App Store Connect API keys are given (`scripts/notarize.sh`).
- The integration tests skip when `gpg` is missing. A test against a keyserver runs only with
  `AMONHEN_TEST_KEYSERVER=hkp://127.0.0.1:11371` and a local keyserver from `scripts/test-keyserver.sh up` (Podman).

## Checking the screens

```sh
scripts/snapshots.sh [dist/snapshots] [light|dark]
```

It builds the debug app, makes a sample keyring (`scripts/sample-keyring.sh`), captures the three places and every
sheet, and stops the keyring's gpg-agent afterwards. It opens the real window and captures it with `screencapture`,
so the app that runs the script needs Screen Recording permission the first time.

One screen at a time:

```sh
"$(scripts/swift-build.sh --show-bin-path)/AmonhenGpg" --homedir "$(scripts/sample-keyring.sh)" --snapshot out.png --place mine
```

Launch options: `--homedir <dir>`, `--gpg <path>`, `--keyserver <url>`, `--snapshot <file.png>` (capture the window
and exit), `--place mine|others|staging`, `--sheet extend|create|revoke|certify|details|otherdetails|delete|userids`,
`--stage <file>` (put a key file into staging first), `--appearance light|dark`.

## Icon and banner

Both are drawn in code. Edit the script and run it again:

```sh
swift scripts/make-icon.swift      # apps/macos/Icons (and AppIcon-sizes.png to check 16, 32 and 64 px)
swift scripts/make-banner.swift    # docs/images/banner.png
```

## Releases

CI (`.github/workflows/ci.yml`) runs the tests on every push and pull request. On `main`, when they pass, it builds a
signed snapshot and replaces the `snapshot` pre-release. A `v<version>` tag that matches `Cargo.toml` and has passed
CI is built, notarized and released (`release.yml`). The signing and notarization secrets live in the `release`
environment.

User-visible changes go under `Unreleased` in `CHANGELOG.md` (English only), grouped per release rather than per
commit. To release:

1. In `CHANGELOG.md`, change `## Unreleased` to `## [x.y.z] - YYYY-MM-DD` and make sure a short summary paragraph
   follows it: it becomes the Release notes (`scripts/changelog-notes.sh x.y.z`), and the release stops without it.
2. Set `version` in `Cargo.toml` to `x.y.z`, merge to `main` and wait for CI.
3. Tag that commit `vx.y.z` and push the tag.
