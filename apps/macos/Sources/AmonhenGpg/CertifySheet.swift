import AmonhenGpgKit
import AppKit
import SwiftUI

/// 他者の鍵に署名する（自分の鍵で UID を証明する。信頼の輪）。先にフィンガープリントを持ち主と照らし合わせてもらう。
/// 既定は書き出さない署名（ローカル署名。自分の鍵束の中で有効にするだけで、鍵サーバーには載らない）。
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
    @State private var creatingLocalCertifier = false

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
            Text(L("Sign Key")).font(.title2.bold())
            Text(L("Web of Trust: signing this key with your own key makes it valid in your keyring."))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Text(L("Ask the owner to read out their fingerprint by another channel, in person or on the phone, and compare it with this one, group by group."))
            FingerprintView(fingerprint: key.fingerprint)
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
                withoutPrimaryKey
            } else {
                Picker(L("Sign with"), selection: $signer) {
                    ForEach(signers) { own in
                        Text(own.key.primaryUserId?.text ?? own.key.fingerprint).tag(Optional(own.key.fingerprint))
                    }
                }
                if signsLocallyOnly {
                    // ローカル署名用の鍵の署名は、人に渡しても確かめられない
                    Text(L("The signature stays on this Mac (a local signature). Keys signed with this key are valid on this Mac only."))
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                } else {
                    Toggle(L("Let others see it (publish the signature with the key)"), isOn: $exportable)
                    Text(exportable
                        ? L("The signature goes wherever this key is sent, including keyservers, and shows that you know the owner.")
                        : L("The signature stays in your keyring (a local signature) and is not published."))
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
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
                Button(L("Sign")) { certify() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!compared || selected.isEmpty || signer == nil)
            }
            .disabled(working)
        }
        .padding(20)
        .frame(width: 520)
        .sheet(isPresented: $creatingLocalCertifier) {
            LocalCertifierSheet(model: model) { signer = $0 }
        }
    }

    /// 選んだ鍵がローカル署名用の鍵で、書き出す署名はできない。
    private var signsLocallyOnly: Bool {
        signer.flatMap(model.keyring.own)?.isLocalCertifier ?? false
    }

    /// 署名できる鍵がこの Mac にないとき。主鍵のある Mac に頼むか、この Mac 用の鍵を作るかを選ばせる。
    @ViewBuilder private var withoutPrimaryKey: some View {
        if model.keyring.canCreateLocalCertifier {
            VStack(alignment: .leading, spacing: 8) {
                Text(L("Your primary key is not on this Mac. Ask the Mac with your primary key to sign, or create a key that signs locally on this Mac only."))
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
                HStack {
                    Button(L("Save a Signing Request…"), action: saveRequest)
                        .disabled(!compared || model.keyring.dataSigners.isEmpty)
                        .help(L("Open the request on the Mac with your primary key, then import the local signatures here."))
                    Button(L("Create a Key for This Mac…")) { creatingLocalCertifier = true }
                }
            }
        } else {
            Text(L("You have no key of your own that can sign on this Mac."))
                .foregroundStyle(.orange)
        }
    }

    /// この鍵だけの署名の依頼を保存する（`RequestSignaturesSheet` と同じもの）。
    private func saveRequest() {
        guard let requester = model.keyring.dataSigners.first?.key.fingerprint else { return }
        let panel = NSSavePanel()
        panel.title = L("Save Signing Request")
        panel.nameFieldStringValue = ExportNames.signingRequest
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let fingerprint = key.fingerprint
        working = true
        failure = nil
        Task {
            let result = await model.perform { try $0.createSigningRequest([fingerprint], signer: requester, to: url) }
            working = false
            switch result {
            case .success: dismiss()
            case let .failure(error) where isCanceled(error): break
            case let .failure(error): failure = describe(error)
            }
        }
    }

    private func certify() {
        guard let signer else { return }
        working = true
        failure = nil
        let fingerprint = key.fingerprint
        // 全部を選んだときも UID を並べて渡す（あとで UID が増えても、確かめていないものに署名しない）
        let userIds = key.certifiableUserIds.map(\.text).filter(selected.contains)
        let local = !exportable || signsLocallyOnly
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
