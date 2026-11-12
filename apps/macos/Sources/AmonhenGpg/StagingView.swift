import AmonhenGpgKit
import AppKit
import SwiftUI

/// 一時保管の画面が見るもの。gpg を待つ呼び出しは裏のスレッドで行う。
@Observable
final class StagingModel {
    let staging: Staging
    /// 本来の鍵束（取り込んだら読み直す）。
    let main: KeyringModel
    private(set) var keys: [Key] = []
    private(set) var working = false
    var failure: String?
    /// 操作の結果（取り込んだ、見つからなかった）。
    var message: String?

    init(main: KeyringModel, dir: URL) {
        self.main = main
        staging = Staging(main: main.gpg, dir: dir)
    }

    func find(_ query: StagingQuery) async {
        await run { staging in
            switch StagingOutcome(try staging.find(query)) {
            case .found: return nil
            case .withoutUserIds:
                return L("The keyserver has this key, but without any name or email address, so it cannot be imported. keys.openpgp.org publishes them only after the owner confirms them by mail. Try searching by email address, or get the key from its owner.")
            case .nothing: return L("No key was found.")
            }
        }
    }

    func add(_ urls: [URL]) async {
        await run { staging in
            for url in urls {
                try staging.add(try Data(contentsOf: url))
            }
            return nil
        }
    }

    func importKey(_ key: Key) async {
        let name = key.primaryUserId?.text ?? key.fingerprint
        let fingerprint = key.fingerprint
        await run { staging in
            try staging.importKey(fingerprint)
            return L("Imported %@ into Others' Keys.", name)
        }
        await main.reload()
    }

    func discard(_ key: Key) async {
        let fingerprint = key.fingerprint
        await run { staging in
            try staging.discard(fingerprint)
            return nil
        }
    }

    /// アプリの終わりに一時保管ごと捨てる。
    func discardAll() {
        try? staging.discardAll()
    }

    /// 待たずに読む（画像に書き出すときだけ）。
    func reloadNow() {
        keys = (try? staging.keys()) ?? []
    }

    /// 裏で `work` を行い、一時保管を読み直す。`work` が返した文を知らせる。
    private func run(_ work: @escaping @Sendable (Staging) throws -> String?) async {
        working = true
        failure = nil
        message = nil
        defer { working = false }
        let staging = staging
        let result = await Task.detached { () -> Result<(String?, [Key]), Error> in
            Result {
                let message = try work(staging)
                return (message, try staging.keys())
            }
        }.value
        switch result {
        case let .success((message, keys)):
            self.message = message
            self.keys = keys
        case let .failure(error):
            failure = describe(error)
            keys = (try? staging.keys()) ?? keys
        }
    }
}

/// 一時保管（docs/ui.md）。鍵サーバーや WKD で探した鍵、ファイルで受け取った鍵を、確かめてから取り込むか捨てる。
struct StagingView: View {
    let model: StagingModel
    @State private var text = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                TextField(L("Email address or fingerprint"), text: $text, prompt: Text(L("Email address or fingerprint")))
                    .textFieldStyle(.roundedBorder)
                    .onSubmit(find)
                Button(L("Find"), action: find)
                    .disabled(StagingQuery(text) == nil || model.working)
                Button(L("From File…"), action: openFiles)
                    .disabled(model.working)
                if model.working {
                    ProgressView().controlSize(.small)
                }
            }
            Text(L("Found keys stay here and are not in your keyring until you import them. Compare the fingerprint with its owner before importing. Keys left here are discarded when the app quits."))
                .font(.callout)
                .foregroundStyle(.secondary)
            // fixedSize を付けると、この並べ方では窓全体が描かれなくなる（折り返しは幅いっぱいで足りる）
            if let failure = model.failure {
                Text(failure)
                    .foregroundStyle(.red)
                    .textSelection(.enabled)
            } else if let message = model.message {
                Text(message).foregroundStyle(.secondary)
            }
            if model.keys.isEmpty {
                ContentUnavailableView(
                    L("Staging"), systemImage: "tray",
                    description: Text(L("Keys found on keyservers or through WKD will be kept here until you import them.")))
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 12) {
                        ForEach(model.keys, id: \.fingerprint) { key in
                            StagedKeyRow(key: key, working: model.working) {
                                Task { await model.importKey(key) }
                            } discard: {
                                Task { await model.discard(key) }
                            }
                            Divider()
                        }
                    }
                }
            }
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    private func find() {
        guard let query = StagingQuery(text), !model.working else { return }
        Task { await model.find(query) }
    }

    private func openFiles() {
        let panel = NSOpenPanel()
        panel.title = L("Open Keys")
        panel.message = L("Choose files with public keys to check before importing.")
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = false
        guard panel.runModal() == .OK, !panel.urls.isEmpty else { return }
        let urls = panel.urls
        Task { await model.add(urls) }
    }
}

/// 一時保管の鍵ひとつ。取り込む前に確かめられるよう、UID をすべてとフィンガープリント、作成日を出す。
struct StagedKeyRow: View {
    let key: Key
    let working: Bool
    let importKey: () -> Void
    let discard: () -> Void

    var body: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 4) {
                ForEach(Array(key.userIds.filter { !$0.attribute }.enumerated()), id: \.offset) { index, uid in
                    Text(uid.text)
                        .font(index == 0 ? .headline : .body)
                        .foregroundStyle(uid.validity == .revoked ? .secondary : .primary)
                        .strikethrough(uid.validity == .revoked)
                }
                Text(Fingerprint.grouped(key.fingerprint))
                    .font(.callout.monospaced())
                    .textSelection(.enabled)
                Text(details).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Button(L("Import"), action: importKey)
                .disabled(working)
            Button(L("Discard"), action: discard)
                .disabled(working)
        }
        .padding(.vertical, 4)
    }

    private var details: String {
        var parts: [String] = []
        if let created = key.created {
            parts.append(L("Created %@", Date(timeIntervalSince1970: TimeInterval(created)).formatted(date: .abbreviated, time: .omitted)))
        }
        switch key.validity {
        case .revoked: parts.append(L("Revoked"))
        case .expired: parts.append(L("Expired"))
        default:
            if let expires = key.expires {
                parts.append(L("Expires %@", Date(timeIntervalSince1970: TimeInterval(expires)).formatted(date: .abbreviated, time: .omitted)))
            }
        }
        return parts.joined(separator: " · ")
    }
}
