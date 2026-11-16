import AmonhenGpgKit
import AppKit
import SwiftUI

/// 自分の鍵の画面の SSH の段。gpg-agent の SSH サポートの状態と、OpenPGP の鍵でない SSH の鍵（ssh-add で取り込んだ鍵）。
/// OpenPGP の鍵の認証サブ鍵は、各行の「SSH ✓」で示す。
struct SshSection: View {
    let model: KeyringModel
    var notify: (Notice) -> Void = { _ in }
    @State private var enabling = false

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
                SshKeyRow(key: key) { enabled in
                    let keygrip = key.keygrip
                    Task {
                        if case let .failure(error) = await model.perform({ try $0.setSshKeyEnabled(keygrip: keygrip, enabled: enabled) }) {
                            notify(Notice(title: L("Cannot change the SSH key"), message: describe(error)))
                        }
                    }
                }
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
    }

    private func enable() {
        Task {
            if case let .failure(error) = await model.perform({ try $0.enableSshSupport() }) {
                notify(Notice(title: L("Cannot turn on SSH support"), message: describe(error)))
            }
        }
    }

    /// 既存の SSH 秘密鍵のファイルを選ばせ、gpg-agent に取り込む。パスフレーズは pinentry が聞く。鍵ファイルは変えない。
    private func addKey() {
        let panel = NSOpenPanel()
        panel.title = L("Add SSH Key")
        panel.message = L("Choose a private key file, such as id_ed25519. gpg-agent keeps its own copy; the file is not changed.")
        panel.directoryURL = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh")
        panel.showsHiddenFiles = true
        panel.canChooseDirectories = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
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

/// OpenPGP の鍵でない SSH の鍵ひとつ。gpg-agent は鍵のコメントを返さないので、SSH の形のフィンガープリントで示す。
struct SshKeyRow: View {
    let key: SshKey
    let setEnabled: (Bool) -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: key.card == nil ? "terminal" : "creditcard")
                .font(.title2)
                .frame(width: 28)
            VStack(alignment: .leading, spacing: 4) {
                Text(key.card.map { L("SSH key on card %@", $0) } ?? L("SSH key")).font(.headline)
                Text(key.fingerprint)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
            Spacer()
            Toggle(L("Use for SSH"), isOn: Binding(get: { sshKeyEnabled(key: key) }, set: setEnabled))
                .toggleStyle(.switch)
                .controlSize(.small)
                .fixedSize()
        }
        .padding(.vertical, 4)
        .listRowSeparator(.hidden)
    }
}
