import AmonhenGpgKit
import SwiftUI

/// 自分の鍵を秘密鍵ごと消す。いちばん危ない操作なので、何重にも確かめる（docs/architecture.md の「自分の鍵を失わない」）。
/// - 秘密鍵がこの PC にあるなら、バックアップの記録があるまで消させない。
/// - 失効させていなければ、ほかの人がこの鍵に暗号化し続けることを伝え、失効へ導く。
/// - フィンガープリントの最後の 4 文字を打ってもらい、最後にもう一度確かめる。
/// gpg-agent は秘密鍵を消すときに pinentry で確かめないので、ここでの確認がすべて。
struct DeleteKeySheet: View {
    let model: KeyringModel
    let own: OwnKey
    var backUp: (OwnKey) -> Void = { _ in }
    /// 失効させる（このシートを閉じてから、失効のシートを出す）。
    var revoke: (OwnKey) -> Void = { _ in }
    /// 消したら、消した鍵の名前で呼ぶ（シートは閉じる）。
    var onDeleted: (String) -> Void = { _ in }
    @Environment(\.dismiss) private var dismiss
    @State private var typed = ""
    @State private var confirming = false
    @State private var working = false
    @State private var failure: String?

    var body: some View {
        // バックアップを取ると読み直されるので、いまの鍵束から引き直す
        let own = model.keyring.own(own.key.fingerprint) ?? own
        let name = own.key.primaryUserId?.text ?? own.key.fingerprint
        let tail = String(own.key.fingerprint.suffix(4))
        VStack(alignment: .leading, spacing: 16) {
            Text(L("Delete Key with Secret Key")).font(.title2.bold())
            VStack(alignment: .leading, spacing: 4) {
                Text(name).font(.headline)
                Text(Fingerprint.grouped(own.key.fingerprint))
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }
            Text(L("This removes the secret and public key from this Mac. It cannot be undone. Without a backup, anything encrypted to this key can never be decrypted again."))
            VStack(alignment: .leading, spacing: 8) {
                if own.canBackUp {
                    if let date = own.backedUp {
                        Label(L("Backed up on %@", date.formatted(date: .long, time: .omitted)), systemImage: "checkmark.circle.fill")
                            .foregroundStyle(.green)
                    } else {
                        Warning(text: L("No backup. Back it up before deleting."), action: L("Back Up…")) { backUp(own) }
                    }
                }
                if case .onCard = own.key.secret {
                    Label(L("The secret key on the card stays on the card."), systemImage: "creditcard")
                        .foregroundStyle(.secondary)
                }
                if own.key.validity != .revoked {
                    Warning(text: L("Not revoked. Others will keep encrypting to it."), action: L("Revoke…")) {
                        dismiss()
                        revoke(own)
                    }
                    .disabled(!own.canRevoke)
                }
            }
            .font(.callout)
            Form {
                TextField(L("Type the last 4 characters of the fingerprint (%@)", tail), text: $typed, prompt: Text(verbatim: "····"))
            }
            .formStyle(.columns)
            .disabled(!own.canDelete)
            if let failure {
                Text(failure)
                    .foregroundStyle(.red)
                    .textSelection(.enabled)
            }
            HStack {
                if working {
                    ProgressView().controlSize(.small)
                }
                Spacer()
                Button(L("Cancel"), role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button(L("Delete…"), role: .destructive) { confirming = true }
                    .disabled(!own.canDelete || typed.trimmingCharacters(in: .whitespaces).uppercased() != tail)
            }
            .disabled(working)
        }
        .padding(20)
        .frame(width: 500)
        .alert(L("Delete “%@” for good?", name), isPresented: $confirming) {
            Button(L("Delete"), role: .destructive) { delete(own, name: name) }
            Button(L("Cancel"), role: .cancel) {}
        } message: {
            Text(L("This cannot be undone."))
        }
    }

    private func delete(_ own: OwnKey, name: String) {
        working = true
        failure = nil
        let fingerprint = own.key.fingerprint
        Task {
            let result = await model.perform { try $0.deleteSecretAndPublicKey(fingerprint: fingerprint) }
            working = false
            switch result {
            case .success:
                dismiss()
                onDeleted(name)
            case let .failure(error): failure = describe(error)
            }
        }
    }
}
