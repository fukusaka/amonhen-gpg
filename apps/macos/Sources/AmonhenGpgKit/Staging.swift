import Foundation

/// 一時保管で探すときの入力。メールアドレス（WKD、なければ鍵サーバー）か、完全なフィンガープリント（鍵サーバー）。
/// 名前での検索（`--search-keys`）は意図して作らない（docs/ui.md）。名前は鍵について何も示さず、名前で探せる鍵サーバーは
/// 他人の名前で上げられた鍵を多く返す。
public enum StagingQuery: Equatable, Sendable {
    case email(String)
    case fingerprint(String)
    /// GitHub・GitLab の利用者が公開している鍵。
    case codeHost(CodeHost, String)

    /// 入力を読む。フィンガープリントは空白で区切られていてもよい（`Fingerprint.grouped` の形をそのまま貼れる）。
    /// 短い鍵 ID は別の鍵に当たり得るので受け付けない。GitHub・GitLab は `github:名前`・`gitlab:名前` か、
    /// プロフィールの URL（`https://github.com/名前` など）で指す。
    public init?(_ text: String) {
        let text = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if let (host, user) = Self.codeHostUser(text) {
            self = .codeHost(host, user)
            return
        }
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

    /// `github:名前`・`gitlab:名前`、または `github.com/名前`（`https://`・`www.`・末尾の `.gpg` や `/` があってもよい）。
    /// 名前の細かい決まりは core（`CodeHost.keyUrl`）が確かめるので、ここでは使える文字だけを見る。
    private static func codeHostUser(_ text: String) -> (CodeHost, String)? {
        let lower = text.lowercased()
        let hosts: [(CodeHost, prefix: String, domain: String)] = [(.gitHub, "github:", "github.com/"), (.gitLab, "gitlab:", "gitlab.com/")]
        for (host, prefix, domain) in hosts {
            var rest: Substring
            if lower.hasPrefix(prefix) {
                rest = text.dropFirst(prefix.count)
            } else {
                var url = Substring(text)
                for scheme in ["https://", "http://"] where url.lowercased().hasPrefix(scheme) { url = url.dropFirst(scheme.count) }
                if url.lowercased().hasPrefix("www.") { url = url.dropFirst(4) }
                guard url.lowercased().hasPrefix(domain) else { continue }
                rest = url.dropFirst(domain.count)
                if rest.hasSuffix("/") { rest = rest.dropLast() }
                if rest.lowercased().hasSuffix(".gpg") { rest = rest.dropLast(4) }
            }
            let user = rest.trimmingCharacters(in: .whitespaces)
            guard !user.isEmpty, user.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || "-_.".contains($0)) }) else { return nil }
            return (host, user)
        }
        return nil
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

    private static let prefix = "amonhen-staging-"

    /// 一時保管の置き場所（`parent` の下）。作ったプロセスの ID を名前に入れ、落ちて残ったものを次の起動で見分ける。
    /// gpg-agent のソケットのパスには長さの上限（macOS では 104 バイト）があるので、名前は短くする。
    public static func directory(in parent: URL, pid: Int32 = ProcessInfo.processInfo.processIdentifier) -> URL {
        parent.appendingPathComponent("\(prefix)\(pid)-\(UUID().uuidString.prefix(4))")
    }

    /// アプリが落ちて残った一時保管を捨てる（gpg-agent・dirmngr を止めてから消す）。作ったプロセスが動いているもの
    /// （同時に開いている別のアプリ）と、一時保管の印がないもの（`Gpg.discardStaging` が断る）には触らない。
    /// 捨てた場所を返す。
    @discardableResult
    public static func discardStale(
        in parent: URL, gpg: Gpg, isRunning: (Int32) -> Bool = { kill($0, 0) == 0 || errno == EPERM }
    ) -> [URL] {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: parent.path)) ?? []
        var discarded: [URL] = []
        for name in names {
            // 秘密鍵から公開鍵だけを取り出す使い捨ての鍵束は `.<名前>-in`
            let base = name.hasPrefix(".") && name.hasSuffix("-in") ? String(name.dropFirst().dropLast(3)) : name
            guard base.hasPrefix(prefix),
                let pid = base.dropFirst(prefix.count).split(separator: "-").first.flatMap({ Int32($0) }),
                pid != ProcessInfo.processInfo.processIdentifier, !isRunning(pid)
            else { continue }
            let dir = parent.appendingPathComponent(name)
            // 印がなければ `staging` が中身のあるディレクトリとして断るので、利用者のものは消えない
            guard let staged = try? gpg.staging(dir: dir.path), (try? staged.discardStaging()) != nil else { continue }
            discarded.append(dir)
        }
        return discarded
    }

    /// 一時保管の鍵束。初めて使うときに作り、鍵サーバーを決めておく（新しい鍵束の dirmngr には設定がない）。
    private func staging() throws -> Gpg {
        lock.lock()
        defer { lock.unlock() }
        if let gpg { return gpg }
        let made = try main.staging(dir: dir.path)
        let conf = dir.appendingPathComponent("dirmngr.conf")
        if !FileManager.default.fileExists(atPath: conf.path) {
            try "keyserver \(Keyserver.current)\n".write(to: conf, atomically: true, encoding: .utf8)
        }
        gpg = made
        return made
    }

    /// 探して一時保管に入れる。
    @discardableResult
    public func find(_ query: StagingQuery) throws -> ImportResult {
        switch query {
        case let .email(email): try staging().locateExternalKey(email: email)
        case let .fingerprint(fpr): try staging().receiveKeys(fingerprints: [fpr], keyserver: Keyserver.current)
        case let .codeHost(host, user): try staging().fetchFromCodeHost(host: host, user: user)
        }
    }

    /// ファイルなどで受け取った鍵を一時保管に入れる（秘密鍵は入れない）。
    @discardableResult
    public func add(_ data: Data) throws -> ImportResult {
        let keys = try main.showKeys(data: data)
        // 秘密鍵を含んでいれば、使い捨ての鍵束で公開鍵だけにしてから入れる（秘密鍵を一時保管に置かない）
        let secret = keys.contains { $0.secret != .none }
        return try staging().importFromFile(data: secret ? try publicOnly(data, fingerprints: keys.map(\.fingerprint)) : data)
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

/// 探した結果を、一時保管に何が起きたかで分けたもの。
public enum StagingOutcome: Equatable, Sendable {
    /// 鍵が入った（新しく、または既にあって更新された）。
    case found
    /// 鍵はあったが、名前もメールアドレスもないので gpg が取り込まなかった。keys.openpgp.org は、持ち主がメールで
    /// 確かめた UID しか公開しないので、フィンガープリントで探すとこうなることがある。
    case withoutUserIds
    /// 何もなかった。
    case nothing

    public init(_ result: ImportResult) {
        if !result.keys.isEmpty || result.unchanged > 0 {
            self = .found
        } else if result.noUserId > 0 {
            self = .withoutUserIds
        } else {
            self = .nothing
        }
    }
}
