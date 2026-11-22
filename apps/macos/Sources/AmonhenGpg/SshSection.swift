import AmonhenGpgKit
import AppKit
import SwiftUI

/// 自分の鍵の画面の SSH の段。gpg-agent の SSH サポートの状態と、OpenPGP の鍵でない SSH の鍵（ssh-add で取り込んだ鍵）。
/// OpenPGP の鍵の認証サブ鍵は、各行の「SSH ✓」で示す。
struct SshSection: View {
    let model: KeyringModel
    var notify: (Notice) -> Void = { _ in }
    @State private var enabling = false
    /// gpg-agent から消すか確かめている鍵。
    @State private var removing: SshKey?
    /// パスフレーズがないのでバックアップできないと知らせている鍵。
    @State private var unprotected: SshKey?

    var body: some View {
        let support = model.keyring.sshSupport
        Section {
            if support?.enabled == false {
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    Label(L("SSH support of gpg-agent is off, so SSH cannot use these keys."), systemImage: "info.circle")
                        .foregroundStyle(.secondary)
                    Button(L("Turn On…")) { enabling = true }
                        .controlSize(.small)
                }
                .font(.callout)
            }
            ForEach(model.keyring.sshOnly, id: \.keygrip) { key in
                let actions = SshKeyActions(
                    setEnabled: { setEnabled(key, $0) }, copy: { copy(key) }, export: { export(key) },
                    backUp: { key.canBackUp ? backUp(key) : (unprotected = key) }, remove: { removing = key })
                SshKeyRow(key: key, actions: actions)
                    .contextMenu { SshKeyMenuItems(key: key, actions: actions) }
                    // 一覧で選べるのは自分の鍵だけ（選んだ鍵の詳細を開くため）
                    .selectionDisabled()
            }
            HStack {
                Button(L("Add SSH Key…"), action: addKey)
                    .disabled(support?.enabled != true)
                Spacer()
            }
            if support?.enabled == true, let socket = support?.socket {
                Text(L("To use gpg-agent from ssh, set SSH_AUTH_SOCK to %@.", socket))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
        } header: {
            Text("SSH")
        }
        .alert(L("Turn on SSH support?"), isPresented: $enabling) {
            Button(L("Turn On")) { enable() }
            Button(L("Cancel"), role: .cancel) {}
        } message: {
            Text(L("This adds enable-ssh-support to gpg-agent.conf and restarts gpg-agent, which forgets the passphrases it remembered."))
        }
        .alert(
            L("Remove the SSH key from gpg-agent?"),
            isPresented: Binding(get: { removing != nil }, set: { if !$0 { removing = nil } }),
            presenting: removing
        ) { key in
            Button(L("Remove"), role: .destructive) { remove(key) }
            Button(L("Cancel"), role: .cancel) {}
        } message: { key in
            Text(L("gpg-agent deletes its copy of the secret key %@. This cannot be undone. The key file you added it from is not changed; without that file, the key is lost.", key.displayName))
        }
        .alert(
            L("Cannot back up %@", unprotected?.displayName ?? ""),
            isPresented: Binding(get: { unprotected != nil }, set: { if !$0 { unprotected = nil } })
        ) {
            Button(L("OK"), role: .cancel) {}
        } message: {
            Text(L("gpg-agent keeps this key without a passphrase, so a backup would hold the secret key unprotected. To protect it, remove it from gpg-agent and add it again from its key file, entering a passphrase when gpg-agent asks."))
        }
    }

    private func setEnabled(_ key: SshKey, _ enabled: Bool) {
        let keygrip = key.keygrip
        Task {
            if case let .failure(error) = await model.perform({ try $0.setSshKeyEnabled(keygrip: keygrip, enabled: enabled) }) {
                notify(Notice(title: L("Cannot change the SSH key"), message: describe(error)))
            }
        }
    }

    /// 公開鍵を、`authorized_keys` に貼る 1 行としてコピーする。
    private func copy(_ key: SshKey) {
        let keygrip = key.keygrip
        Task {
            switch await model.perform({ try $0.sshPublicKey(keygrip: keygrip) }) {
            case let .success(line):
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(line, forType: .string)
                notify(Notice(title: L("Copied"), message: L("Copied the SSH public key. Paste it as one line into ~/.ssh/authorized_keys on the server.")))
            case let .failure(error):
                notify(Notice(title: L("Cannot copy the SSH public key"), message: describe(error)))
            }
        }
    }

    /// 公開鍵を、`authorized_keys` の 1 行の形でファイルに書き出す。
    private func export(_ key: SshKey) {
        let panel = NSSavePanel()
        panel.title = L("Export SSH Public Key")
        panel.nameFieldStringValue = key.publicKeyFileName
        guard panel.runModal() == .OK, let url = panel.url else { return }
        Task {
            switch await model.perform({ try $0.exportSshPublicKey(key, to: url) }) {
            case .success:
                notify(Notice(title: L("Exported"), message: L("Saved the SSH public key to %@.", url.path)))
            case let .failure(error):
                notify(Notice(title: L("Cannot export the SSH public key"), message: describe(error)))
            }
        }
    }

    /// gpg-agent がパスフレーズで守ったままの形で書き出す。パスフレーズは聞かない。
    private func backUp(_ key: SshKey) {
        let panel = NSSavePanel()
        panel.title = L("Back Up SSH Key")
        panel.message = L("The backup stays protected by the passphrase gpg-agent asked for when the key was added. Keep that passphrase too.")
        panel.nameFieldStringValue = key.backupFileName
        guard panel.runModal() == .OK, let url = panel.url else { return }
        Task {
            switch await model.perform({ try $0.exportSshKeyBackup(key, to: url) }) {
            case .success:
                notify(Notice(title: L("Backed up"), message: L("Saved %@ to %@. To restore it, choose Add SSH Key… and pick this file.", key.displayName, url.path)))
            case let .failure(error):
                notify(Notice(title: L("Cannot back up the SSH key"), message: describe(error)))
            }
        }
    }

    private func remove(_ key: SshKey) {
        let keygrip = key.keygrip
        Task {
            switch await model.perform({ try $0.deleteSshKey(keygrip: keygrip) }) {
            case .success:
                notify(Notice(title: L("SSH key removed"), message: L("gpg-agent no longer has %@.", key.displayName)))
            case let .failure(error):
                notify(Notice(title: L("Cannot remove the SSH key"), message: describe(error)))
            }
        }
    }

    private func enable() {
        Task {
            if case let .failure(error) = await model.perform({ try $0.enableSshSupport() }) {
                notify(Notice(title: L("Cannot turn on SSH support"), message: describe(error)))
            }
        }
    }

    /// 既存の SSH 秘密鍵のファイルか、バックアップを選ばせ、gpg-agent に取り込む。鍵ファイルのパスフレーズは pinentry が聞く。
    /// バックアップは守られたまま戻す（パスフレーズは聞かない）。選んだファイルは変えない。
    private func addKey() {
        let panel = NSOpenPanel()
        panel.title = L("Add SSH Key")
        panel.message = L("Choose a private key file, such as id_ed25519, or a backup made with Back Up…. gpg-agent keeps its own copy; the file is not changed.")
        panel.directoryURL = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh")
        panel.showsHiddenFiles = true
        panel.canChooseDirectories = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        if let data = try? Data(contentsOf: url), Gpg.isSshKeyBackup(data) {
            restore(data, from: url)
            return
        }
        Task {
            switch await model.perform({ try $0.addSshKey(path: url.path) }) {
            case .success:
                notify(Notice(title: L("SSH key added"), message: L("gpg-agent now offers %@ to ssh.", url.lastPathComponent)))
            case let .failure(error) where isCanceled(error): break
            case let .failure(error):
                notify(Notice(title: L("Cannot add the SSH key"), message: describe(error)))
            }
        }
    }
}

extension SshSection {
    /// バックアップを gpg-agent に戻す（gpg 2.5.14 から）。それより古い gpg では、ファイルを置いて戻す方法を知らせる。
    private func restore(_ data: Data, from url: URL) {
        guard model.keyring.canRestoreSshKeyBackup else {
            notify(Notice(
                title: L("Cannot restore the SSH key"),
                message: L("Restoring a backup needs gpg %@ or later. With this gpg, quit gpg-agent (gpgconf --kill gpg-agent) and copy the file into the private-keys-v1.d folder of the GnuPG home, named after its keygrip as when it was saved (keygrip.key).",
                           sshRestoreMinimumVersion().description)))
            return
        }
        Task {
            switch await model.perform({ try $0.importSshKeyBackup(backup: data) }) {
            case .success:
                notify(Notice(title: L("SSH key restored"), message: L("gpg-agent now offers the key from %@ to ssh. It is protected by the passphrase it had when it was backed up.", url.lastPathComponent)))
            case let .failure(GpgError.Agent(code, _)) where code & 0xFFFF == 32803:
                // GPG_ERR_EEXIST
                notify(Notice(title: L("Cannot restore the SSH key"), message: L("gpg-agent already has this key.")))
            case let .failure(error):
                notify(Notice(title: L("Cannot restore the SSH key"), message: describe(error)))
            }
        }
    }
}

/// SSH の鍵ごとの操作。
struct SshKeyActions {
    var setEnabled: (Bool) -> Void = { _ in }
    var copy: () -> Void = {}
    var export: () -> Void = {}
    var backUp: () -> Void = {}
    var remove: () -> Void = {}
}

/// SSH の鍵の操作（行の ⋯ と、右クリックのメニュー）。
struct SshKeyMenuItems: View {
    let key: SshKey
    let actions: SshKeyActions

    var body: some View {
        Button(L("Copy SSH Public Key"), action: actions.copy)
        Button(L("Export SSH Public Key…"), action: actions.export)
        Button(L("Back Up…"), action: actions.backUp)
            .disabled(key.card != nil)
        Divider()
        Button(L("Remove from gpg-agent…"), role: .destructive, action: actions.remove)
    }
}

/// OpenPGP の鍵でない SSH の鍵ひとつ。説明（ssh-keygen の -C）と、SSH の形のフィンガープリントで示す。
struct SshKeyRow: View {
    let key: SshKey
    var actions = SshKeyActions()

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: key.card == nil ? "terminal" : "creditcard")
                .font(.title2)
                .frame(width: 28)
            VStack(alignment: .leading, spacing: 4) {
                Text(key.displayName).font(.headline)
                Text(key.fingerprint)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
            Spacer()
            Toggle(L("Use for SSH"), isOn: Binding(get: { sshKeyEnabled(key: key) }, set: { actions.setEnabled($0) }))
                .toggleStyle(.switch)
                .controlSize(.small)
                .fixedSize()
            Menu {
                SshKeyMenuItems(key: key, actions: actions)
            } label: {
                Image(systemName: "ellipsis.circle")
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .fixedSize()
        }
        .padding(.vertical, 4)
        .listRowSeparator(.hidden)
    }
}

extension SshKey {
    /// 一覧での名前。説明（ssh-keygen の -C）がなければ、種類で。
    var displayName: String {
        comment ?? card.map { L("SSH key on card %@", $0) } ?? L("SSH key")
    }
}
