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

    /// 選んだ記録に署名する鍵（`SignersView` の「署名に使う鍵」）。なければ署名できる最初の自分の鍵。
    static let signerDefaultsKey = "SignersSigner"

    func signer(in keyring: Keyring) -> OwnKey? {
        let chosen = UserDefaults.standard.string(forKey: Self.signerDefaultsKey)
        return keyring.signers.first { $0.key.fingerprint == chosen } ?? keyring.signers.first
    }

    /// 記録を変えて保存する。取り消しは知らせない。保存できたら true。
    @discardableResult
    func save(_ edits: [SignerEdit], keyring: KeyringModel, title: String, notify: (Notice) -> Void) async -> Bool {
        guard let signer = signer(in: keyring.keyring) else { return false }
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
            change.new.removeAll { current.contains($0.key.fingerprint) }
            change.gone.removeAll { !current.contains($0) }
            changes[email] = change
        }
    }
}
