import AmonhenGpgKit
import SwiftUI

/// 他者の鍵に付けた自分の署名を取り消す。ローカル署名は消し（公開していないので消せば済む）、公開した署名は失効させる
/// （主鍵の秘密鍵が要る。ほかの人に知らせるには鍵を送り直す）。取り消すと、ほかの人の署名で有効でない限り、鍵は有効でなくなる。
struct WithdrawSignaturesSheet: View {
    let model: KeyringModel
    let key: Key
    /// 取り消したら、知らせる文で呼ぶ（シートは閉じる）。
    var onWithdrawn: (String) -> Void = { _ in }
    @Environment(\.dismiss) private var dismiss
    @State private var mine: [Certification]?
    @State private var working = false
    @State private var failure: String?

    var body: some View {
        let name = key.primaryUserId?.text ?? key.fingerprint
        let local = (mine ?? []).filter { !$0.exportable }
        let published = (mine ?? []).filter(\.exportable)
        // 公開した署名の失効には、署名した自分の鍵の主鍵の秘密鍵が要る
        let cannotRevoke = published.contains { !canCertify($0.signerFingerprint) }
        VStack(alignment: .leading, spacing: 16) {
            Text(L("Withdraw Your Signatures")).font(.title2.bold())
            Text(name).font(.headline)
            if let mine {
                if mine.isEmpty {
                    Text(L("You have not signed this key."))
                } else {
                    VStack(alignment: .leading, spacing: 8) {
                        if !local.isEmpty {
                            Label(L("Local signatures: %@. They are deleted; they were never published.", "\(local.count)"),
                                  systemImage: "trash")
                        }
                        if !published.isEmpty {
                            Label(L("Published signatures: %@. They are revoked. Others learn about it only when you send this key again, for example to a keyserver.", "\(published.count)"),
                                  systemImage: "xmark.seal")
                            if cannotRevoke {
                                Text(L("Revoking needs your primary key's secret, which is not on this Mac."))
                                    .foregroundStyle(.orange)
                            }
                        }
                    }
                    .fixedSize(horizontal: false, vertical: true)
                    Text(L("Unless others' signatures make it valid, the key is no longer valid in your keyring."))
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } else {
                ProgressView().controlSize(.small)
            }
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
                Button(L("Withdraw"), role: .destructive) { withdraw(name: name) }
                    .disabled(mine?.isEmpty ?? true || cannotRevoke)
            }
            .disabled(working)
        }
        .padding(20)
        .frame(width: 500)
        .task { await load() }
    }

    /// 自分の鍵（どの段にあっても）がした、まだ取り消していない署名。
    private func load() async {
        let gpg = model.gpg
        let fingerprint = key.fingerprint
        let all = await Task.detached { try? gpg.certifications(fingerprint: fingerprint) }.value ?? []
        mine = all.filter { c in !c.revoked && c.signerFingerprint.map { model.keyring.own($0) != nil } == true }
    }

    private func canCertify(_ signer: String?) -> Bool {
        guard let signer, let own = model.keyring.own(signer) else { return false }
        switch own.status.certify {
        case .thisDevice, .card: return true
        case .elsewhere, .none: return false
        }
    }

    private func withdraw(name: String) {
        let signers = Array(Set((mine ?? []).compactMap(\.signerFingerprint)))
        let fingerprint = key.fingerprint
        working = true
        failure = nil
        Task {
            let result = await model.perform { gpg in
                var total = WithdrawnCertifications(deleted: 0, revoked: 0)
                for signer in signers {
                    let done = try gpg.withdrawCertifications(fingerprint: fingerprint, signer: signer)
                    total.deleted += done.deleted
                    total.revoked += done.revoked
                }
                return total
            }
            working = false
            switch result {
            case let .success(total):
                dismiss()
                onWithdrawn(total.revoked > 0
                    ? L("Your signatures on %@ are withdrawn. Send the key again to tell others about the revoked ones.", name)
                    : L("Your signatures on %@ are withdrawn.", name))
            case let .failure(error) where isCanceled(error):
                break
            case let .failure(error):
                failure = describe(error)
            }
        }
    }
}
