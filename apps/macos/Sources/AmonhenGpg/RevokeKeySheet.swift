import AmonhenGpgKit
import SwiftUI

extension RevocationReason {
    /// 選ぶ順。よくある「もう使わない」を先に。
    static let choices: [RevocationReason] = [.retired, .superseded, .compromised, .unspecified]

    var title: String {
        switch self {
        case .retired: L("I no longer use it")
        case .superseded: L("I replaced it with a new key")
        case .compromised: L("The secret key leaked, or may have")
        case .unspecified: L("No reason given")
        }
    }
}

/// 鍵全体を失効させる。**元に戻せない**ので、理由を選ばせたうえで、もう一度確かめる。
/// 先にバックアップを促す（失効させても、昔のものの復号に秘密鍵が要る）。
struct RevokeKeySheet: View {
    let model: KeyringModel
    let own: OwnKey
    var backUp: (OwnKey) -> Void = { _ in }
    /// 失効させたら、読み直した鍵で呼ぶ（シートは閉じる）。
    var onRevoked: (OwnKey) -> Void = { _ in }
    @Environment(\.dismiss) private var dismiss
    @State private var reason = RevocationReason.retired
    @State private var description = ""
    @State private var confirming = false
    @State private var working = false
    @State private var failure: String?

    var body: some View {
        let name = own.key.primaryUserId.map { UserIdParts($0.text).name } ?? own.key.fingerprint
        VStack(alignment: .leading, spacing: 16) {
            Text(L("Revoke Key")).font(.title2.bold())
            VStack(alignment: .leading, spacing: 4) {
                Text(own.key.primaryUserId?.text ?? own.key.fingerprint).font(.headline)
                Text(Fingerprint.grouped(own.key.fingerprint))
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }
            Text(L("Once revoked, others stop encrypting to this key and its signatures count as from a revoked key. This cannot be undone. The secret key stays, so you can still decrypt old messages."))
                .fixedSize(horizontal: false, vertical: true)
            Form {
                Picker(L("Reason"), selection: $reason) {
                    ForEach(RevocationReason.choices, id: \.self) { reason in
                        Text(reason.title).tag(reason)
                    }
                }
                .pickerStyle(.radioGroup)
                TextField(L("Note (optional)"), text: $description, prompt: Text(L("e.g. Replaced by key 1234 5678")))
            }
            .formStyle(.columns)
            if reason == .compromised {
                Text(L("Revoke it now, then tell the people you exchange messages with. A leaked key can still be used to decrypt what was sent to it."))
                    .font(.callout)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if own.needsBackup {
                Warning(text: L("No backup"), action: L("Back Up…")) { backUp(own) }
            }
            Text(L("gpg will ask for the passphrase of this key."))
                .font(.callout)
                .foregroundStyle(.secondary)
            if let failure {
                Text(failure)
                    .foregroundStyle(.red)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                if working {
                    ProgressView().controlSize(.small)
                }
                Spacer()
                Button(L("Cancel"), role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button(L("Revoke…"), role: .destructive) { confirming = true }
            }
            .disabled(working)
        }
        .padding(20)
        .frame(width: 480)
        .alert(L("Revoke “%@”?", name), isPresented: $confirming) {
            Button(L("Revoke"), role: .destructive) { revoke() }
            Button(L("Cancel"), role: .cancel) {}
        } message: {
            Text(L("This cannot be undone."))
        }
    }

    private func revoke() {
        working = true
        failure = nil
        let fingerprint = own.key.fingerprint
        let reason = reason
        let description = description.replacingOccurrences(of: "\n", with: " ")
        Task {
            let result = await model.perform {
                try $0.revokeKey(fingerprint: fingerprint, reason: reason, description: description)
            }
            working = false
            switch result {
            case .success:
                dismiss()
                if let revoked = model.keyring.own(fingerprint) {
                    onRevoked(revoked)
                }
            case let .failure(error) where isCanceled(error): break
            case let .failure(error): failure = describe(error)
            }
        }
    }
}
