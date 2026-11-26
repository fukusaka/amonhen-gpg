import AmonhenGpgKit
import AppKit
import SwiftUI

/// 署名を頼む（主鍵のない Mac で）。ローカル署名して欲しい他者の鍵を選び、自分の鍵で署名した依頼のファイルにする。
/// 主鍵のある Mac は、自分の鍵からの依頼だと確かめてから開く。
struct RequestSignaturesSheet: View {
    let model: KeyringModel
    /// 依頼を保存したら、知らせる文で呼ぶ（シートは閉じる）。
    var onSaved: (String) -> Void = { _ in }
    @Environment(\.dismiss) private var dismiss
    @State private var selected: Set<String> = []
    @State private var signer: String?
    @State private var working = false
    @State private var failure: String?

    init(model: KeyringModel, onSaved: @escaping (String) -> Void = { _ in }) {
        self.model = model
        self.onSaved = onSaved
        _signer = State(initialValue: model.keyring.dataSigners.first?.key.fingerprint)
    }

    var body: some View {
        let keys = model.keyring.others.filter(\.canCertify)
        let signers = model.keyring.dataSigners
        VStack(alignment: .leading, spacing: 16) {
            Text(L("Ask Another Mac to Sign")).font(.title2.bold())
            Text(L("Choose keys whose fingerprints you compared with their owners. Open the request on your Mac with the primary key to sign them locally, then import the local signatures here."))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if keys.isEmpty {
                Text(L("No keys are waiting for your signature."))
            } else {
                List(keys, id: \.fingerprint) { key in
                    Toggle(isOn: Binding(
                        get: { selected.contains(key.fingerprint) },
                        set: { if $0 { selected.insert(key.fingerprint) } else { selected.remove(key.fingerprint) } }
                    )) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(key.primaryUserId?.text ?? key.fingerprint)
                            Text(Fingerprint.grouped(key.fingerprint))
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                .frame(minHeight: 120, maxHeight: 260)
            }
            if signers.isEmpty {
                Text(L("The request is signed with your key, but no key of yours can sign on this Mac. Import the keys on the other Mac through Keys to Accept instead."))
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            } else if signers.count > 1 {
                Picker(L("Sign the request with"), selection: $signer) {
                    ForEach(signers) { own in
                        Text(own.key.primaryUserId?.text ?? own.key.fingerprint).tag(Optional(own.key.fingerprint))
                    }
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
                Button(L("Save Request…")) { save() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(selected.isEmpty || signer == nil)
            }
            .disabled(working)
        }
        .padding(20)
        .frame(width: 520)
    }

    private func save() {
        guard let signer else { return }
        let panel = NSSavePanel()
        panel.title = L("Save Signing Request")
        panel.nameFieldStringValue = L("Signing request.asc")
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let fingerprints = model.keyring.others.map(\.fingerprint).filter(selected.contains)
        working = true
        failure = nil
        Task {
            let result = await model.perform { try $0.createSigningRequest(fingerprints, signer: signer, to: url) }
            working = false
            switch result {
            case .success:
                dismiss()
                onSaved(L("Saved a request for %ld keys to %@. Open it on your Mac with the primary key.", fingerprints.count, url.path))
            case let .failure(error) where isCanceled(error): break
            case let .failure(error): failure = describe(error)
            }
        }
    }
}

/// 署名の依頼を開いたもの（主鍵のある Mac で）。
struct OpenedSigningRequest: Identifiable {
    let id = UUID()
    let request: SigningRequest
    /// 依頼のファイルの中身（取り込むときに確かめ直す）。
    let data: Data
}

/// 署名の依頼に応える（主鍵のある Mac で）。鍵を取り込んでローカル署名し、その署名を返事のファイルにする。
struct SigningRequestSheet: View {
    let model: KeyringModel
    let opened: OpenedSigningRequest
    /// 返事を保存したら、知らせる文で呼ぶ（シートは閉じる）。
    var onSaved: (String) -> Void = { _ in }
    @Environment(\.dismiss) private var dismiss
    @State private var selected: Set<String>
    @State private var signer: String?
    @State private var working = false
    @State private var failure: String?

    init(model: KeyringModel, opened: OpenedSigningRequest, onSaved: @escaping (String) -> Void = { _ in }) {
        self.model = model
        self.opened = opened
        self.onSaved = onSaved
        _selected = State(initialValue: Set(opened.request.keys.map(\.fingerprint)))
        let signers = model.keyring.signers
        // 依頼した鍵で署名すれば、依頼した Mac で有効になる
        _signer = State(initialValue: (signers.first { $0.key.fingerprint == opened.request.requester } ?? signers.first)?.key.fingerprint)
    }

    var body: some View {
        let signers = model.keyring.signers
        let requester = model.keyring.usable.first { $0.key.fingerprint == opened.request.requester }
        VStack(alignment: .leading, spacing: 16) {
            Text(L("Signing Request")).font(.title2.bold())
            Label(
                L("Requested with your key %@.", requester?.key.primaryUserId?.text ?? Fingerprint.grouped(opened.request.requester)),
                systemImage: "checkmark.seal")
            Text(L("Sign only keys whose fingerprints you compared with their owners. The keys are imported into this keyring, signed locally, and the signatures are saved for the other Mac."))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            List(opened.request.keys, id: \.fingerprint) { key in
                Toggle(isOn: Binding(
                    get: { selected.contains(key.fingerprint) },
                    set: { if $0 { selected.insert(key.fingerprint) } else { selected.remove(key.fingerprint) } }
                )) {
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(key.certifiableUserIds, id: \.text) { Text($0.text) }
                        Text(Fingerprint.grouped(key.fingerprint))
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .frame(minHeight: 120, maxHeight: 260)
            if signers.isEmpty {
                Text(L("You have no key of your own that can sign on this Mac."))
                    .foregroundStyle(.orange)
            } else if signers.count > 1 {
                Picker(L("Sign with"), selection: $signer) {
                    ForEach(signers) { own in
                        Text(own.key.primaryUserId?.text ?? own.key.fingerprint).tag(Optional(own.key.fingerprint))
                    }
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
                Button(L("Sign and Save…")) { signAndSave() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(selected.isEmpty || signer == nil)
            }
            .disabled(working)
        }
        .padding(20)
        .frame(width: 520)
    }

    private func signAndSave() {
        guard let signer else { return }
        let panel = NSSavePanel()
        panel.title = L("Export Local Signatures")
        panel.nameFieldStringValue = L("Local signatures.asc")
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let keys = opened.request.keys.filter { selected.contains($0.fingerprint) }
        let data = opened.data
        working = true
        failure = nil
        Task {
            let result = await model.perform { gpg in
                try gpg.importSigningRequest(data: data)
                for key in keys {
                    // UID を並べて渡す（あとで UID が増えても、依頼になかったものには署名しない）
                    try gpg.signKey(
                        fingerprint: key.fingerprint, userIds: key.certifiableUserIds.map(\.text), signer: signer, local: true)
                }
                return try gpg.exportLocalSignatures(only: keys.map(\.fingerprint), to: url)
            }
            working = false
            switch result {
            case let .success(saved):
                dismiss()
                onSaved(L("Signed %ld keys locally and saved the signatures to %@. On the other Mac, choose Import Local Signatures.", saved.count, url.path))
            case let .failure(error) where isCanceled(error): break
            case let .failure(error): failure = describe(error)
            }
        }
    }
}
