import AmonhenGpgKit
import AppKit
import SwiftUI

/// 一時保管の画面が見るもの。gpg を待つ呼び出しは裏のスレッドで行う。
@Observable
final class StagingModel {
    private(set) var staging: Staging
    /// 本来の鍵束（取り込んだら読み直す）。
    let main: KeyringModel
    private(set) var keys: [Key] = []
    private(set) var working = false
    var failure: String?
    /// 操作の結果（取り込んだ、見つからなかった）。
    var message: String?
    /// 直前に探した（ファイルから入れた）とき、見つかった鍵。一覧は一時保管にある鍵すべてなので、今回の分に印を付ける。
    private(set) var lastFound: Set<String> = []
    /// 直前の操作が探す（ファイルから入れる）ものだったか。見つからなかったとき、一覧が前の鍵だと添えるため。
    private(set) var searched = false

    init(main: KeyringModel, dir: URL) {
        self.main = main
        staging = Staging(main: main.gpg, dir: dir)
    }

    func find(_ query: StagingQuery) async {
        await run(search: true) { staging in
            let result = try staging.find(query)
            let found = Set(result.keys.map(\.fingerprint))
            switch StagingOutcome(result) {
            case .found: return (nil, found)
            case .withoutUserIds:
                return (L("The keyserver has this key, but without any name or email address, so it cannot be imported. keys.openpgp.org publishes them only after the owner confirms them by mail. Try searching by email address, or get the key from its owner."), found)
            case .nothing: return (L("No key was found."), found)
            }
        }
    }

    func add(_ urls: [URL]) async {
        await run(search: true) { staging in
            var found = Set<String>()
            for url in urls {
                found.formUnion(try staging.add(try Data(contentsOf: url)).keys.map(\.fingerprint))
            }
            return (nil, found)
        }
    }

    func importKey(_ key: Key) async {
        let name = key.primaryUserId?.text ?? key.fingerprint
        let fingerprint = key.fingerprint
        await run { staging in
            try staging.importKey(fingerprint)
            return (L("Imported %@ into Others' Keys.", name), nil)
        }
        await main.reload()
    }

    func discard(_ key: Key) async {
        let fingerprint = key.fingerprint
        await run { staging in
            try staging.discard(fingerprint)
            return (nil, nil)
        }
    }

    /// 別の gpg に替える（設定）。一時保管の鍵束は前の gpg で作ったので捨て、空の一時保管から始める。
    func use(_ gpg: Gpg) {
        let old = staging
        Task.detached { try? old.discardAll() }
        staging = Staging(main: gpg, dir: Staging.directory(in: old.dir.deletingLastPathComponent()))
        keys = []
        lastFound = []
        searched = false
        failure = nil
        message = nil
    }

    /// アプリの終わりに一時保管ごと捨てる。
    func discardAll() {
        try? staging.discardAll()
    }

    /// 待たずに読む（画像に書き出すときだけ）。
    func reloadNow() {
        keys = (try? staging.keys()) ?? []
    }

    /// 待たずにファイルの鍵を入れ、今回見つかった印を付ける（画像に書き出すときだけ）。
    func addNow(_ data: Data) {
        searched = true
        lastFound = Set(((try? staging.add(data))?.keys ?? []).map(\.fingerprint))
        reloadNow()
    }

    /// 裏で `work` を行い、一時保管を読み直す。`work` は知らせる文と、見つかった鍵（探す操作のとき）を返す。
    /// 探す操作でなければ、今回見つかった印は残す（取り込んだ・捨てた鍵は一覧から消える）。
    private func run(search: Bool = false, _ work: @escaping @Sendable (Staging) throws -> (String?, Set<String>?)) async {
        working = true
        failure = nil
        message = nil
        if search {
            searched = true
            lastFound = []
        }
        defer { working = false }
        let staging = staging
        let result = await Task.detached { () -> Result<(String?, Set<String>?, [Key]), Error> in
            Result {
                let (message, found) = try work(staging)
                return (message, found, try staging.keys())
            }
        }.value
        switch result {
        case let .success((message, found, keys)):
            self.message = message
            if let found { lastFound = found }
            self.keys = keys
        case let .failure(error):
            failure = describe(error)
            keys = (try? staging.keys()) ?? keys
        }
    }
}

/// 一時保管（docs/ui.md）。鍵サーバー・WKD・GitHub・GitLab で探した鍵、ファイルで受け取った鍵を、確かめてから取り込むか捨てる。
struct StagingView: View {
    let model: StagingModel
    @State private var text = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                TextField(L("Email address, fingerprint, or github:name"), text: $text, prompt: Text(L("Email address, fingerprint, or github:name")))
                    .help(L("Search WKD and keys.openpgp.org by email address or fingerprint, or fetch the keys a GitHub or GitLab user publishes with github:name or gitlab:name."))
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
            if model.failure != nil || model.message != nil {
                ResultBox(text: model.failure ?? model.message ?? "", isFailure: model.failure != nil, note: leftoverNote)
            }
            if model.keys.isEmpty {
                ContentUnavailableView(
                    L("Keys to Accept"), systemImage: "tray",
                    description: Text(L("Keys found on keyservers or through WKD will be kept here until you import them.")))
            } else {
                Text(L("Keys to accept (%ld)", model.keys.count)).font(.headline)
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 12) {
                        ForEach(model.keys, id: \.fingerprint) { key in
                            StagedKeyRow(key: key, isNew: model.lastFound.contains(key.fingerprint), working: model.working) {
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

    /// 探して何も入らなかったのに一覧に鍵があるとき、それが前の鍵だと添える。
    private var leftoverNote: String? {
        guard model.searched, model.lastFound.isEmpty, !model.keys.isEmpty else { return nil }
        return L("The keys listed below were found earlier and are still kept here.")
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

/// 一時保管の鍵ひとつ。取り込む前に確かめられるよう、UID をすべてとフィンガープリント、入手元、作成日を出す。
struct StagedKeyRow: View {
    let key: Key
    /// 直前に探して見つかった鍵か。
    var isNew = false
    let working: Bool
    let importKey: () -> Void
    let discard: () -> Void

    var body: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 4) {
                if isNew {
                    Text(L("Just found"))
                        .font(.caption.bold())
                        .foregroundStyle(.white)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Color.accentColor, in: Capsule())
                }
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
        // どこから来た鍵か（鍵サーバーのホスト名・WKD・ファイル）。持ち主に確かめるときの手がかりになる
        if key.origin != .unknown {
            parts.append(L("From %@", originWord(key)))
        }
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

/// 操作の結果を、一覧と見分けられるよう枠で囲んで出す。
struct ResultBox: View {
    let text: String
    let isFailure: Bool
    var note: String?

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: isFailure ? "exclamationmark.triangle.fill" : "info.circle.fill")
                .foregroundStyle(isFailure ? .orange : .accentColor)
            VStack(alignment: .leading, spacing: 4) {
                Text(text).textSelection(.enabled)
                if let note {
                    Text(note).font(.callout).foregroundStyle(.secondary)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(10)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 8))
    }
}
