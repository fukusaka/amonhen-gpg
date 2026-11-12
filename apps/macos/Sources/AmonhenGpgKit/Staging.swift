import Foundation

/// 一時保管で探すときの入力。メールアドレス（WKD、なければ鍵サーバー）か、完全なフィンガープリント（鍵サーバー）。
/// 名前での検索（`--search-keys`）はまだない。
public enum StagingQuery: Equatable, Sendable {
    case email(String)
    case fingerprint(String)

    /// 入力を読む。フィンガープリントは空白で区切られていてもよい（`Fingerprint.grouped` の形をそのまま貼れる）。
    /// 短い鍵 ID は別の鍵に当たり得るので受け付けない。
    public init?(_ text: String) {
        let text = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.contains("@") {
            let parts = text.split(separator: "@", omittingEmptySubsequences: false)
            guard parts.count == 2, !parts[0].isEmpty, parts[1].contains("."), !text.contains(where: { $0.isWhitespace || "<>".contains($0) })
            else { return nil }
            self = .email(text)
            return
        }
        let hex = text.filter { !$0.isWhitespace }.uppercased()
        let digits = hex.hasPrefix("0X") ? String(hex.dropFirst(2)) : hex
        guard [40, 64].contains(digits.count), digits.allSatisfy(\.isHexDigit) else { return nil }
        self = .fingerprint(digits)
    }
}

/// 一時保管の鍵束（docs/ui.md の「一時保管」）。鍵サーバーや WKD で取ってきた鍵をまずここに入れ、確かめてから
/// 本来の鍵束に公開鍵だけを移す。中身はアプリの終わりに捨てる。
public final class Staging: @unchecked Sendable {
    /// 本来の鍵束。
    public let main: Gpg
    public let dir: URL
    private let lock = NSLock()
    private var gpg: Gpg?

    public init(main: Gpg, dir: URL) {
        self.main = main
        self.dir = dir
    }

    /// 一時保管の鍵束。初めて使うときに作り、鍵サーバーを決めておく（新しい鍵束の dirmngr には設定がない）。
    private func staging() throws -> Gpg {
        lock.lock()
        defer { lock.unlock() }
        if let gpg { return gpg }
        let made = try main.staging(dir: dir.path)
        let conf = dir.appendingPathComponent("dirmngr.conf")
        if !FileManager.default.fileExists(atPath: conf.path) {
            try "keyserver \(Keyserver.default)\n".write(to: conf, atomically: true, encoding: .utf8)
        }
        gpg = made
        return made
    }

    /// 探して一時保管に入れる。
    @discardableResult
    public func find(_ query: StagingQuery) throws -> ImportResult {
        switch query {
        case let .email(email): try staging().locateExternalKey(email: email)
        case let .fingerprint(fpr): try staging().receiveKeys(fingerprints: [fpr], keyserver: Keyserver.default)
        }
    }

    /// ファイルなどで受け取った鍵を一時保管に入れる（秘密鍵は入れない）。
    @discardableResult
    public func add(_ data: Data) throws -> ImportResult {
        let keys = try main.showKeys(data: data)
        // 秘密鍵を含んでいれば、使い捨ての鍵束で公開鍵だけにしてから入れる（秘密鍵を一時保管に置かない）
        let secret = keys.contains { $0.secret != .none }
        return try staging().import(data: secret ? try publicOnly(data, fingerprints: keys.map(\.fingerprint)) : data)
    }

    /// 一時保管にある鍵。まだ何も入れていなければ空。
    public func keys() throws -> [Key] {
        lock.lock()
        let gpg = gpg
        lock.unlock()
        return try gpg?.listKeys() ?? []
    }

    /// 本来の鍵束に公開鍵を移し、一時保管からは消す。
    @discardableResult
    public func importKey(_ fingerprint: String) throws -> ImportResult {
        let staging = try staging()
        let result = try staging.copyPublicKeysTo(dest: main, fingerprints: [fingerprint])
        try staging.deletePublicKey(fingerprint: fingerprint)
        return result
    }

    /// 一時保管から捨てる（本来の鍵束には触らない）。
    public func discard(_ fingerprint: String) throws {
        try staging().deletePublicKey(fingerprint: fingerprint)
    }

    /// 一時保管の鍵束ごと捨てる（アプリの終わり）。一時保管の印のないディレクトリは消さない（`Gpg.discardStaging`）。
    public func discardAll() throws {
        lock.lock()
        let gpg = gpg
        self.gpg = nil
        lock.unlock()
        try gpg?.discardStaging()
    }

    /// 秘密鍵を含むデータから、公開鍵だけを取り出す。使い捨ての鍵束を通す。
    private func publicOnly(_ data: Data, fingerprints: [String]) throws -> Data {
        let scratch = dir.deletingLastPathComponent().appendingPathComponent(".\(dir.lastPathComponent)-in")
        let gpg = try main.staging(dir: scratch.path)
        defer { try? gpg.discardStaging() }
        _ = try gpg.import(data: data)
        return try gpg.exportPublicKeys(fingerprints: fingerprints, armor: false)
    }
}
