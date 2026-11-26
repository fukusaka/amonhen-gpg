import AmonhenGpgKit
import SwiftUI

/// ローカル署名用の鍵を作る（主鍵のない Mac で）。他者の鍵に、この Mac の中だけで有効な署名をするための鍵。
/// 証明だけの鍵で、人に渡さず、データの署名にも使わない。
struct LocalCertifierSheet: View {
    let model: KeyringModel
    /// 作れたとき、主鍵のフィンガープリントで呼ぶ（シートを閉じたあと）。
    var onCreated: (String) -> Void = { _ in }
    @Environment(\.dismiss) private var dismiss
    @State private var working = false
    @State private var failure: String?
    @State private var userId = OwnKey.localCertifierUserId(macName: Host.current().localizedName ?? "")

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(L("Key for Local Signatures")).font(.title2.bold())
            Text(L("Your primary key is not on this Mac, so it cannot sign others' keys here. This key signs others' keys locally on this Mac, and keys you sign with it become valid on this Mac only."))
                .fixedSize(horizontal: false, vertical: true)
            VStack(alignment: .leading, spacing: 6) {
                Label(L("It is not published, and it cannot sign files or messages."), systemImage: "lock")
                Label(L("Others cannot rely on its signatures. To vouch for a key publicly, sign it on the Mac with your primary key."), systemImage: "person.2")
            }
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            LabeledContent(L("Name")) { Text(userId).textSelection(.enabled) }
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
            }
            .disabled(working)
        }
        .padding(20)
        .frame(width: 480)
    }

    private func create() {
        working = true
        failure = nil
        let userId = userId
        Task {
            let result = await model.perform { try $0.createLocalCertifier(userId: userId) }
            working = false
            switch result {
            case let .success(fingerprint):
                dismiss()
                onCreated(fingerprint)
            case let .failure(error) where isCanceled(error): break
            case let .failure(error): failure = describe(error)
            }
        }
    }
}
