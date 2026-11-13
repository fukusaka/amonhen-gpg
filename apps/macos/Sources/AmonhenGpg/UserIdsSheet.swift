import AmonhenGpgKit
import SwiftUI

/// 自分の鍵の名前とメールアドレス（UID）。足す・主にする・失効させる。
/// 消すことはしない（公開したあとでは消しても相手の手元から消えないので、失効させて使わないと知らせる）。
/// 変えたことがほかの人に届くのは、更新した公開鍵を渡してからなので、終わりにそれを知らせる。
struct UserIdsSheet: View {
    let model: KeyringModel
    let own: OwnKey
    /// 変えたら呼ぶ（公開鍵を渡すよう勧めるため。シートは閉じる）。
    var onChanged: (OwnKey) -> Void = { _ in }
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var email = ""
    @State private var makePrimary = false
    @State private var revoking: UserId?
    @State private var changed = false
    @State private var working = false
    @State private var failure: String?

    var body: some View {
        // 変えるたびに読み直されるので、いまの鍵束から引き直す
        let own = model.keyring.own(own.key.fingerprint) ?? own
        let key = own.key
        let parts = UserIdParts(name: name, comment: nil, email: email)
        VStack(alignment: .leading, spacing: 16) {
            Text(L("Names and Email Addresses")).font(.title2.bold())
            Text(Fingerprint.grouped(key.fingerprint))
                .font(.callout.monospaced())
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
            VStack(alignment: .leading, spacing: 0) {
                ForEach(Array(key.namedUserIds.enumerated()), id: \.offset) { index, uid in
                    if index > 0 { Divider() }
                    row(uid, in: key)
                }
            }
            .padding(.horizontal, 10)
            .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 8))
            Text(L("Add a Name and Email Address")).font(.headline)
            Form {
                TextField(L("Name"), text: $name)
                TextField(L("Email"), text: $email, prompt: Text(verbatim: "alice@example.com"))
                Toggle(L("Use as the primary name"), isOn: $makePrimary)
            }
            .formStyle(.columns)
            .disabled(working)
            if key.hasActiveUserId(parts.text) {
                Text(L("This key already has this name and email address."))
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            Text(L("Others see the change only after they get the updated public key. A name and email address cannot be deleted once others have it; revoke it instead. gpg will ask for the passphrase of this key."))
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
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
                Button(changed ? L("Done") : L("Cancel")) { close(own) }
                    .keyboardShortcut(.cancelAction)
                Button(L("Add")) { add(parts.text, to: key) }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!parts.isValidForNewKey || key.hasActiveUserId(parts.text))
            }
            .disabled(working)
        }
        .padding(20)
        .frame(width: 520)
        .onAppear {
            name = key.primaryUserId.map { UserIdParts($0.text).name } ?? ""
        }
        .alert(
            L("Revoke “%@”?", revoking?.text ?? ""),
            isPresented: Binding(get: { revoking != nil }, set: { if !$0 { revoking = nil } }),
            presenting: revoking
        ) { uid in
            Button(L("Revoke"), role: .destructive) {
                let fingerprint = key.fingerprint
                perform { try $0.revokeUserId(fingerprint: fingerprint, userId: uid.text) }
            }
            Button(L("Cancel"), role: .cancel) {}
        } message: { _ in
            Text(L("Others who get the updated public key see that you no longer use it. This cannot be undone."))
        }
    }

    private func row(_ uid: UserId, in key: Key) -> some View {
        let revoked = uid.validity == .revoked
        return HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 2) {
                Text(uid.text)
                    .foregroundStyle(revoked ? .secondary : .primary)
                    .strikethrough(revoked)
                    .textSelection(.enabled)
                if uid == key.primaryUserId, !revoked {
                    Text(L("Primary")).font(.caption).foregroundStyle(.secondary)
                } else if revoked {
                    Text(L("Revoked")).font(.caption).foregroundStyle(.secondary)
                }
            }
            Spacer()
            if key.canMakePrimary(uid) {
                Button(L("Make Primary")) {
                    let fingerprint = key.fingerprint
                    perform { try $0.setPrimaryUserId(fingerprint: fingerprint, userId: uid.text) }
                }
                .controlSize(.small)
            }
            if key.canRevoke(uid) {
                Button(L("Revoke…")) { revoking = uid }
                    .controlSize(.small)
            }
        }
        .padding(.vertical, 8)
        .disabled(working)
    }

    private func add(_ text: String, to key: Key) {
        let makePrimary = makePrimary
        perform { try $0.addUserId(text, to: key, makePrimary: makePrimary) } then: {
            name = UserIdParts(text).name
            email = ""
            self.makePrimary = false
        }
    }

    /// 裏で変え、鍵束を読み直す。パスフレーズを取り消したときは何も言わない。
    private func perform(_ work: @escaping @Sendable (Gpg) throws -> Void, then: @escaping () -> Void = {}) {
        working = true
        failure = nil
        Task {
            let result = await model.perform(work)
            working = false
            switch result {
            case .success:
                changed = true
                then()
            case let .failure(error) where isCanceled(error): break
            case let .failure(error): failure = describe(error)
            }
        }
    }

    private func close(_ own: OwnKey) {
        dismiss()
        if changed { onChanged(own) }
    }
}
