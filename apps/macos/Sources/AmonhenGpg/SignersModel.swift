import AmonhenGpgKit
import Foundation
import Observation

/// SSH の署名者の画面が見る記録。記録を変えるたびに自分の鍵で署名して保存する（gpg が pinentry でパスフレーズを聞く）。
@Observable
final class SignersModel {
    let dir: URL
    private(set) var loaded: LoadedSigners?
    private(set) var failure: String?
    /// 「変化を確かめる」の結果（人のメールアドレスごと）。受け入れたり退役させたりしたものは除く。
    private(set) var changes: [String: PersonChanges] = [:]
    /// 取ってきている人。
    private(set) var checking: Set<String> = []
    private(set) var saving = false
    /// 既存の allowed signers のファイルから読んだ、受け入れ前の行と、取り込めなかった行。アプリを終えると消える。
    private(set) var imports: [PendingImport] = []
    private(set) var skipped: [(path: String, line: SkippedLine)] = []
    /// 受け入れ前の鍵で GitHub・GitLab のアカウントを探したとき、一緒に取ってきた SSH の鍵。アプリを終えると消える。
    private(set) var searched: [SearchedAccount] = []
    private(set) var searching = false

    init(dir: URL = Signers.defaultDirectory()) {
        self.dir = dir
    }

    var record: SignerRecord { loaded?.record ?? newSignerRecord() }

    /// 受け入れ前の SSH の鍵（人と、取ってきた鍵）。アプリを終えると消える（受け入れ前の鍵の GPG の鍵と同じ）。
    var pending: [(email: String, key: PendingKey)] {
        record.people.flatMap { person in
            (changes[person.email]?.new ?? []).map { (email: person.email, key: $0) }
        }
    }

    /// 選んだ記録に署名する鍵（`SignersView` の「署名に使う鍵」）。なければ署名できる最初の自分の鍵（署名用の
    /// サブ鍵だけがこの Mac にある鍵も含む）。
    static let signerDefaultsKey = "SignersSigner"

    func signer(in keyring: Keyring) -> OwnKey? {
        let chosen = UserDefaults.standard.string(forKey: Self.signerDefaultsKey)
        return keyring.dataSigners.first { $0.key.fingerprint == chosen } ?? keyring.dataSigners.first
    }

    /// 記録を変えて保存する。取り消しは知らせない。保存できたら true。
    @discardableResult
    func save(_ edits: [SignerEdit], keyring: KeyringModel, title: String, notify: (Notice) -> Void) async -> Bool {
        guard let signer = signer(in: keyring.keyring) else {
            notify(Notice(title: title, message: L("The record of signers is signed with a key of yours. Create or import a key that can sign on this Mac.")))
            return false
        }
        switch await apply(edits, gpg: keyring.gpg, signer: signer.key.fingerprint) {
        case .success:
            return true
        case let .failure(error):
            if !isCanceled(error) {
                notify(Notice(title: title, message: describe(error)))
            }
            return false
        }
    }

    func reload(_ gpg: Gpg) async {
        let dir = dir.path
        let result = await Task.detached { Result { try gpg.loadSigners(dir: dir) } }.value
        switch result {
        case let .success(loaded):
            self.loaded = loaded
            failure = nil
        case let .failure(error):
            failure = describe(error)
        }
    }

    /// 記録を変えて、`signer`（自分の鍵）で署名して保存する。保存できなければ、記録は変えない。
    func apply(_ edits: [SignerEdit], gpg: Gpg, signer: String) async -> Result<Void, Error> {
        var record = record
        do {
            for edit in edits {
                record = try editSignerRecord(record: record, edit: edit)
            }
        } catch {
            return .failure(error)
        }
        saving = true
        let dir = dir.path
        let edited = record
        let result = await Task.detached { Result { try gpg.saveSigners(dir: dir, record: edited, signer: signer) } }.value
        saving = false
        await reload(gpg)
        if case .success = result {
            // 鍵を除いた人の取り直しの結果は古くなる（除いた鍵がアカウントにあれば、取り直すとまた受け入れ前の鍵に出る）
            for case let .removeKey(email, _) in edits {
                changes[email] = nil
            }
            forgetResolved()
        }
        return result
    }

    /// 既存の allowed signers のファイルを読み、行を受け入れ前にする（ファイルは変えない）。読めた行の数を返す。
    func readFile(_ url: URL) async -> Result<Int, Error> {
        let path = url.path
        let result = await Task.detached { () -> Result<ParsedSigners, Error> in
            Result { try parseAllowedSigners(text: try String(contentsOf: url, encoding: .utf8)) }
        }.value
        guard case let .success(parsed) = result else {
            return result.map { _ in 0 }
        }
        // 同じファイルを読み直したら置き換える
        imports.removeAll { $0.path == path }
        skipped.removeAll { $0.path == path }
        let record = record
        let accepted = Set(record.people.flatMap { p in p.keys.filter { !$0.retired }.map { "\(p.email) \($0.fingerprint)" } })
        let fresh = parsed.entries.filter { !accepted.contains("\($0.email) \($0.fingerprint)") }
        imports += fresh.map { PendingImport(entry: $0, path: path) }
        skipped += parsed.skipped.map { (path: path, line: $0) }
        return .success(fresh.count)
    }

    /// 読んだ行を受け入れる（まとめて 1 回で署名する）。`list` があれば、その一覧に入れる。
    func acceptImports(_ items: [PendingImport], list: String?, keyring: KeyringModel, notify: (Notice) -> Void) async {
        var edits: [SignerEdit] = []
        var people = Set(record.people.map(\.email))
        for item in items {
            let email = item.entry.email
            if !people.contains(email) {
                edits.append(.addPerson(email: email, account: nil))
                people.insert(email)
            }
            edits.append(.importKey(email: email, entry: item.entry, path: item.path))
            if let list {
                edits.append(.addMember(list: list, email: email))
            }
        }
        if await save(edits, keyring: keyring, title: L("Cannot accept the key"), notify: notify) {
            let done = Set(items.map(\.id))
            imports.removeAll { done.contains($0.id) }
        }
    }

    /// 受け入れ前の鍵で探したアカウントの SSH の鍵を取ってくる。同じアカウントの前の結果は置き換える。
    /// 鍵がなかったときと、取れなかったときは、知らせる文を返す。
    func search(_ host: CodeHost, _ user: String) async -> String? {
        searching = true
        defer { searching = false }
        let result = await Task.detached { Result { try SearchedAccount.fetch(host: host, user: user) } }.value
        switch result {
        case let .success(found):
            searched.removeAll { $0.id == found.id }
            guard !found.keys.isEmpty else { return L("The account has no SSH signing keys.") }
            searched.append(found)
            return nil
        case let .failure(error):
            searched.removeAll { $0.id == Account(host: host, user: user).display.lowercased() }
            if case GpgError.NotFound = error { return L("No such account was found.") }
            return L("Could not fetch SSH signing keys: %@", describe(error))
        }
    }

    /// 探したアカウントの鍵を、`email` の人の鍵として受け入れる（まとめて 1 回で署名する）。
    func acceptSearched(_ id: String, keys: [FetchedKey], as email: String, checked: Checked, keyring: KeyringModel, notify: (Notice) -> Void) async {
        guard let account = searched.first(where: { $0.id == id }) else { return }
        let edits = account.edits(accepting: keys, as: email, checked: checked)
        if await save(edits, keyring: keyring, title: L("Cannot accept the key"), notify: notify),
            let index = searched.firstIndex(where: { $0.id == id }) {
            let done = Set(keys.map(\.fingerprint))
            searched[index].keys.removeAll { done.contains($0.fingerprint) }
            if searched[index].keys.isEmpty { searched.remove(at: index) }
        }
    }

    func discardSearched(_ id: String) {
        searched.removeAll { $0.id == id }
    }

    func discardImports(from path: String) {
        imports.removeAll { $0.path == path }
        skipped.removeAll { $0.path == path }
    }

    /// 人のアカウントから鍵を取り直す。
    func check(_ person: Signer) async {
        guard !person.accounts.isEmpty, !checking.contains(person.email) else { return }
        checking.insert(person.email)
        let record = record
        let result = await Task.detached { Signers.changes(record: record, person: person) }.value
        checking.remove(person.email)
        changes[person.email] = result
    }

    func checkAll() async {
        await withTaskGroup(of: Void.self) { group in
            for person in record.people {
                group.addTask { await self.check(person) }
            }
        }
    }

    /// 記録に入った鍵、退役させた鍵、いなくなった人の結果を除く。
    private func forgetResolved() {
        let record = record
        for (email, var change) in changes {
            guard let person = record.people.first(where: { $0.email == email }) else {
                changes[email] = nil
                continue
            }
            let current = Set(person.keys.filter { !$0.retired }.map(\.fingerprint))
            // 入手元を記録した鍵は、もう「アカウントにもある」と比べる必要がない
            let sourced = Set(person.keys.filter { $0.source != nil }.map(\.fingerprint))
            change.new.removeAll { current.contains($0.key.fingerprint) }
            change.gone.removeAll { !current.contains($0) }
            change.absent.removeAll { !current.contains($0) || sourced.contains($0) }
            change.also = change.also.filter { current.contains($0.key) && !sourced.contains($0.key) }
            changes[email] = change
        }
    }
}
