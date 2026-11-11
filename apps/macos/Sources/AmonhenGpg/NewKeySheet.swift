import AmonhenGpgKit
import SwiftUI

/// 鍵を作る。方式と用途は gpg の既定（今の gpg なら ed25519 の署名・証明と cv25519 の暗号化）に任せる。
struct NewKeySheet: View {
    let model: KeyringModel
    /// 作れたとき、主鍵のフィンガープリントで呼ぶ（シートを閉じたあと）。
    var onCreated: (String) -> Void = { _ in }
    @Environment(\.dismiss) private var dismiss
    @State var name = ""
    @State var email = ""
    @State private var choice = ExpiryChoice.twoYears
    @State private var working = false
    @State private var failure: String?

    private var userId: UserIdParts { UserIdParts(name: name, comment: nil, email: email) }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(L("New Key")).font(.title2.bold())
            Form {
                TextField(L("Name"), text: $name, prompt: Text(L("Alice Example")))
                TextField(L("Email"), text: $email, prompt: Text(verbatim: "alice@example.com"))
                Picker(L("Expiry"), selection: $choice) {
                    ForEach(ExpiryChoice.allCases, id: \.self) { choice in
                        Text(choice.title).tag(choice)
                    }
                }
            }
            .formStyle(.columns)
            Text(L("You can extend the expiry later. An expiry limits the damage if you lose the key."))
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Text(L("gpg will ask for a passphrase to protect the new key."))
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
                Button(L("Create")) { create() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!userId.isValidForNewKey)
            }
            .disabled(working)
        }
        .padding(20)
        .frame(width: 440)
    }

    private func create() {
        working = true
        failure = nil
        let request = GenerateKey(userId: userId.text, algorithm: nil, capabilities: nil, expires: choice.expiry)
        Task {
            let result = await model.perform { try $0.generateKey(request: request) }
            working = false
            switch result {
            case let .success(fingerprint):
                dismiss()
                onCreated(fingerprint)
            case let .failure(error):
                failure = describe(error)
            }
        }
    }
}
