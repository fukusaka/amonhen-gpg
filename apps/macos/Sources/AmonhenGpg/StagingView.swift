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
    /// 結果に添える文（一緒に取ってきた SSH の鍵のこと）。
    var note: String?
    /// 直前に探した（ファイルから入れた）とき、見つかった鍵。一覧は一時保管にある鍵すべてなので、今回の分に印を付ける。
    private(set) var lastFound: Set<String> = []
    /// 直前の操作が探す（ファイルから入れる）ものだったか。見つからなかったとき、一覧が前の鍵だと添えるため。
    private(set) var searched = false

    init(main: KeyringModel, dir: URL) {
        self.main = main
        staging = Staging(main: main.gpg, dir: dir)
    }

    func find(_ query: StagingQuery) async {
        // GitHub・GitLab のアカウントは SSH の鍵だけのこともあるので、どの鍵の話かを言う
        let nothing = if case .codeHost = query { L("This account publishes no OpenPGP key.") } else { L("No key was found.") }
        await run(search: true) { staging in
            let result: ImportResult
            do {
                result = try staging.find(query)
            } catch GpgError.NotFound {
                return (nothing, [])
            }
            let found = Set(result.keys.map(\.fingerprint))
            switch StagingOutcome(result) {
            case .found: return (nil, found)
            case .withoutUserIds:
                return (L("The keyserver has this key, but without any name or email address, so it cannot be imported. keys.openpgp.org publishes them only after the owner confirms them by mail. Try searching by email address, or get the key from its owner."), found)
            case .nothing: return (nothing, found)
            }
        }
    }

    /// この場所を出すよう頼んだ回数（鍵の窓から取り直したとき、主の窓をこの場所に切り替える）。
    private(set) var revealed = 0

    func reveal() { revealed += 1 }

    /// 検索欄に出すよう頼んだもの（取り直したときに引いたもの）。画面が欄に移したら消す。
    var requested: StagingQuery?

    /// 鍵束にある鍵を入手元から取り直して、ここに置く（取り込むと、鍵束の鍵が更新される）。
    func refresh(_ key: Key) async {
        let fingerprint = key.fingerprint
        // 何で引いたかが分かるよう、最初に引くもの（入手元のメールアドレス・アカウント、なければフィンガープリント）を欄に出す
        requested = Staging.refreshQueries(for: key).first
        await run(search: true) { staging in
            // 鍵サーバーにないときは誤りで返るので、見つからなかった結果として扱う
            let found: Set<String>
            do {
                found = Set(try staging.refresh(key).keys.map(\.fingerprint))
            } catch GpgError.NotFound {
                found = []
            }
            return (found.contains(fingerprint) ? nil : L("No copy of this key was found where it came from or on the keyserver."), found)
        }
    }

    /// 鍵束にもある鍵（取り込むと更新になる）。
    func existing(_ key: Key) -> Key? {
        main.keyring.own(key.fingerprint)?.key ?? main.keyring.others.first { $0.fingerprint == key.fingerprint }
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
        let update = existing(key) != nil
        await run { staging in
            try staging.importKey(fingerprint)
            return (update ? L("Updated %@ in your keyring.", name) : L("Imported %@ into Others' Keys.", name), nil)
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

    /// 鍵サーバー・名前の引き方を替えた（設定）。作ってある一時保管の dirmngr に書き直す。書けなければ返す。
    func applySettings() async -> String? {
        let staging = staging
        let result = await Task.detached { Result { try staging.applySettings() } }.value
        if case let .failure(error) = result { return describe(error) }
        return nil
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
        note = nil
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
        note = nil
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
    /// SSH の署名者のために取ってきた、受け入れ前の SSH の鍵。
    let signers: SignersModel
    var notify: (Notice) -> Void = { _ in }
    @State private var text = ""
    /// 探す種類（次に開いたときも同じ）。
    @AppStorage("StagingSearchKind") private var kind = StagingQuery.Kind.email

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Picker(L("Search by"), selection: $kind) {
                    ForEach(StagingQuery.Kind.allCases, id: \.self) { Text($0.title).tag($0) }
                }
                .labelsHidden()
                .fixedSize()
                .help(L("Email addresses search WKD, then keys.openpgp.org. Fingerprints search keys.openpgp.org. GitHub and GitLab fetch the keys a user publishes."))
                TextField(kind.prompt, text: $text, prompt: Text(kind.prompt))
                    .help(L("Pasting an email address, a fingerprint, github:name, gitlab:name or a profile URL picks the kind for you."))
                    .textFieldStyle(.roundedBorder)
                    .onSubmit(find)
                    .onChange(of: text) {
                        // 貼ったものが別の種類として読めれば、種類を合わせる（名前だけは GitHub・GitLab で区別できない）
                        if let other = StagingQuery(text)?.kind, other != kind { kind = other }
                    }
                Button(L("Find"), action: find)
                    .disabled(StagingQuery(text, as: kind) == nil || model.working || signers.searching)
                Button(L("From File…"), action: openFiles)
                    .disabled(model.working)
                if model.working || signers.searching {
                    ProgressView().controlSize(.small)
                }
            }
            .onAppear(perform: takeRequested)
            .onChange(of: model.requested) { takeRequested() }
            Text(L("Found keys stay here and are not in your keyring until you import them. Compare the fingerprint with its owner before importing. Keys left here are discarded when the app quits."))
                .font(.callout)
                .foregroundStyle(.secondary)
            // fixedSize を付けると、この並べ方では窓全体が描かれなくなる（折り返しは幅いっぱいで足りる）
            if let text = model.failure ?? model.message ?? model.note {
                ResultBox(text: text, isFailure: model.failure != nil, note: resultNote)
            }
            if isEmpty {
                // 上の欄と同じ VStack の中なので、広げないと左上に寄る
                EmptyPlace(L("Keys to Accept"), systemImage: "tray", message: Self.flowMessage, diagram: .keysToAccept)
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 12) {
                        if !model.keys.isEmpty {
                            Text(L("Keys to accept (%ld)", model.keys.count)).font(.headline)
                        }
                        ForEach(model.keys, id: \.fingerprint) { key in
                            StagedKeyRow(
                                key: key, existing: model.existing(key), isNew: model.lastFound.contains(key.fingerprint), working: model.working
                            ) {
                                Task { await model.importKey(key) }
                            } discard: {
                                Task { await model.discard(key) }
                            }
                            Divider()
                        }
                        ForEach(signers.searched) { account in
                            SearchedSshKeys(
                                account: account, userIdEmails: userIdEmails(account.account), model: signers,
                                keyring: model.main, notify: notify)
                                .padding(.top, model.keys.isEmpty && account.id == signers.searched.first?.id ? 0 : 12)
                        }
                        if !signers.pending.isEmpty {
                            PendingSshKeys(model: signers, keyring: model.main, notify: notify)
                                .padding(.top, model.keys.isEmpty && signers.searched.isEmpty ? 0 : 12)
                        }
                        if !signers.imports.isEmpty || !signers.skipped.isEmpty {
                            PendingImportedKeys(model: signers, keyring: model.main, notify: notify)
                                .padding(.top, 12)
                        }
                    }
                }
            }
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .toolbar {
            // 空のときは図が真ん中に出ているので、鍵があるときだけ
            if !isEmpty {
                FlowHelpButton(title: L("Keys to Accept"), message: Self.flowMessage, diagram: .keysToAccept)
            }
        }
    }

    private static var flowMessage: String {
        L("Keys found on keyservers, through WKD or on GitHub and GitLab, and SSH signing keys fetched for SSH Signers, wait here until you accept them.")
    }

    private var isEmpty: Bool {
        model.keys.isEmpty && signers.searched.isEmpty && signers.pending.isEmpty && signers.imports.isEmpty && signers.skipped.isEmpty
    }

    /// 頼まれたもの（取り直したときに引いたもの）を検索欄に移す。種類を先に決め、名前だけでも読めるようにする。
    private func takeRequested() {
        guard let query = model.requested else { return }
        model.requested = nil
        kind = query.kind
        text = query.text
    }

    /// 結果の枠の、本文の下に添える文。
    private var resultNote: String? {
        let lines = [model.failure ?? model.message == nil ? nil : model.note, leftoverNote].compactMap { $0 }
        return lines.isEmpty ? nil : lines.joined(separator: "\n")
    }

    /// アカウントが公開している GPG 鍵（一時保管にある、そのアカウントから取った鍵）の UID のメールアドレス。
    private func userIdEmails(_ account: Account) -> [String] {
        // gpg が入手元として記録した URL（core の `CodeHost::key_url`）
        let url = "https://\(account.display.lowercased()).gpg"
        return model.keys.filter { $0.origin == .url && $0.originUrl?.lowercased() == url }
            .flatMap { $0.userIds.filter { !$0.attribute && $0.validity != .revoked } }
            .compactMap { UserIdParts($0.text).email }
    }

    /// 探して何も入らなかったのに一覧に鍵があるとき、それが前の鍵だと添える。
    private var leftoverNote: String? {
        guard model.searched, model.lastFound.isEmpty, !model.keys.isEmpty else { return nil }
        return L("The keys listed below were found earlier and are still kept here.")
    }

    private func find() {
        guard let query = StagingQuery(text, as: kind), !model.working, !signers.searching else { return }
        Task {
            // GitHub・GitLab のアカウントなら、SSH の署名用の鍵も一緒に取ってくる（主体は利用者が選ぶ）
            guard case let .codeHost(host, user) = query else {
                await model.find(query)
                return
            }
            let ssh = Task { await signers.search(host, user) }
            await model.find(query)
            model.note = await ssh.value
        }
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
    /// 鍵束にある同じ鍵（取り込むと更新になる）。手元の版の期限と並べて見せる。
    var existing: Key?
    /// 直前に探して見つかった鍵か。
    var isNew = false
    let working: Bool
    let importKey: () -> Void
    let discard: () -> Void

    var body: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    if isNew {
                        Text(L("Just found"))
                            .font(.caption.bold())
                            .foregroundStyle(.white)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Color.accentColor, in: Capsule())
                    }
                    if existing != nil {
                        Text(L("In your keyring"))
                            .font(.caption.bold())
                            .foregroundStyle(.secondary)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .overlay(Capsule().strokeBorder(.secondary.opacity(0.5)))
                    }
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
                if let existing {
                    Text(L("Your copy: %@", expiryWord(existing) ?? ""))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer()
            Button(existing == nil ? L("Import") : L("Update"), action: importKey)
                .help(existing == nil ? "" : L("Merge this copy into the key in your keyring (a new expiry, revocations, subkeys and signatures)."))
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
        if let word = expiryWord(key, always: false) {
            parts.append(word)
        }
        return parts.joined(separator: " · ")
    }

    /// 失効・期限切れ・期限。`always` なら期限のない鍵は「期限なし」。
    private func expiryWord(_ key: Key, always: Bool = true) -> String? {
        let day = { (seconds: UInt64) in Date(timeIntervalSince1970: TimeInterval(seconds)).formatted(date: .abbreviated, time: .omitted) }
        switch key.validity {
        case .revoked: return L("Revoked")
        case .expired: return key.expires.map { L("Expired on %@", day($0)) } ?? L("Expired")
        default:
            if let expires = key.expires { return L("Expires %@", day(expires)) }
            return always ? L("Never expires") : nil
        }
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

extension StagingQuery.Kind {
    var title: String {
        switch self {
        case .email: L("Email Address")
        case .fingerprint: L("Fingerprint")
        case .gitHub: "GitHub"
        case .gitLab: "GitLab"
        }
    }

    /// 検索欄の中の案内。
    var prompt: String {
        switch self {
        case .email: L("alice@example.com")
        case .fingerprint: L("Full fingerprint (40 or 64 hex digits)")
        case .gitHub: L("GitHub user name")
        case .gitLab: L("GitLab user name")
        }
    }
}
