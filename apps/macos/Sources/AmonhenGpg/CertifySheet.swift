import AmonhenGpgKit
import SwiftUI

/// 他者の鍵を確認済みにする（自分の鍵で UID に署名する）。先にフィンガープリントを持ち主と照らし合わせてもらう。
/// 既定は書き出さない署名（自分の鍵束の中で確認済みにするだけで、鍵サーバーには載らない）。
struct CertifySheet: View {
    let model: KeyringModel
    let key: Key
    /// 署名できたら、読み直した鍵束で呼ぶ（シートは閉じる）。
    var onCertified: () -> Void = {}
    @Environment(\.dismiss) private var dismiss
    @State private var selected: Set<String>
    @State private var signer: String?
    @State private var compared = false
    @State private var exportable = false
    @State private var working = false
    @State private var failure: String?

    init(model: KeyringModel, key: Key, onCertified: @escaping () -> Void = {}) {
        self.model = model
        self.key = key
        self.onCertified = onCertified
        _selected = State(initialValue: Set(key.certifiableUserIds.map(\.text)))
        _signer = State(initialValue: model.keyring.signers.first?.key.fingerprint)
    }

    var body: some View {
        let signers = model.keyring.signers
        VStack(alignment: .leading, spacing: 16) {
            Text(L("Mark as Verified")).font(.title2.bold())
            Text(L("Ask the owner to read out their fingerprint by another channel, in person or on the phone, and compare it with this one, group by group."))
            // 声に出して照らし合わせやすいよう、大きく 2 行に分ける（gpg の表示と同じ切れ目）
            Text(Fingerprint.lines(key.fingerprint))
                .font(.system(size: 24, weight: .medium, design: .monospaced))
                .multilineTextAlignment(.center)
                .lineSpacing(4)
                .textSelection(.enabled)
                .padding(10)
                .frame(maxWidth: .infinity)
                .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))
            Toggle(L("The fingerprint matches the one the owner gave me"), isOn: $compared)
            VStack(alignment: .leading, spacing: 6) {
                Text(L("Names and addresses you checked")).font(.headline)
                ForEach(key.certifiableUserIds, id: \.text) { uid in
                    Toggle(uid.text, isOn: Binding(
                        get: { selected.contains(uid.text) },
                        set: { if $0 { selected.insert(uid.text) } else { selected.remove(uid.text) } }))
                }
            }
            if signers.isEmpty {
                Text(L("You have no key of your own that can sign on this Mac."))
                    .foregroundStyle(.orange)
            } else {
                Picker(L("Sign with"), selection: $signer) {
                    ForEach(signers) { own in
                        Text(own.key.primaryUserId?.text ?? own.key.fingerprint).tag(Optional(own.key.fingerprint))
                    }
                }
            }
            Toggle(L("Let others see it (publish the signature with the key)"), isOn: $exportable)
            Text(exportable
                ? L("The signature goes wherever this key is sent, including keyservers, and shows that you know the owner.")
                : L("The key is verified only in your keyring. Nothing is published."))
                .font(.callout)
                .foregroundStyle(.secondary)
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
                Button(L("Mark as Verified")) { certify() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!compared || selected.isEmpty || signer == nil)
            }
            .disabled(working)
        }
        .padding(20)
        .frame(width: 520)
    }

    private func certify() {
        guard let signer else { return }
        working = true
        failure = nil
        let fingerprint = key.fingerprint
        // 全部を選んだときも UID を並べて渡す（あとで UID が増えても、確かめていないものに署名しない）
        let userIds = key.certifiableUserIds.map(\.text).filter(selected.contains)
        let local = !exportable
        Task {
            let result = await model.perform {
                try $0.signKey(fingerprint: fingerprint, userIds: userIds, signer: signer, local: local)
            }
            working = false
            switch result {
            case .success:
                dismiss()
                onCertified()
            case let .failure(error) where isCanceled(error): break
            case let .failure(error): failure = describe(error)
            }
        }
    }
}
