import Foundation

extension OwnKey {
    /// 期限を延ばせるか。主鍵の秘密鍵（証明に使う）がこの PC かカードにあり、失効していないこと。
    /// 期限切れの鍵は `status` では何にも使えないので、秘密鍵の場所を直に見る。
    public var canExtendExpiry: Bool {
        guard key.validity != .revoked else { return false }
        switch key.secret {
        case .available, .onCard: return true
        case .none, .stub: return false
        }
    }
}

extension OwnKey {
    /// 失効させられるか。主鍵の秘密鍵で署名するので、期限の延長と同じ条件
    /// （失効していない、主鍵の秘密鍵がこの PC かカードにある）。秘密鍵が別の PC にある鍵は、そちらか失効証明書で失効させる。
    public var canRevoke: Bool { canExtendExpiry }
}

extension OwnKey {
    /// 失効証明書がなく、作れるか。秘密鍵を失ったときに鍵を失効させるのに要る。
    /// 作るには主鍵の秘密鍵で署名するので、期限の延長と同じ条件（失効していない、主鍵の秘密鍵がこの PC かカードにある）。
    public var needsRevocationCertificate: Bool {
        !hasRevocationCertificate && canExtendExpiry
    }
}

extension Gpg {
    /// 鍵の期限を延ばす。主鍵と、期限のある失効していないサブ鍵を同じ期限にする
    /// （主鍵だけ延ばしても、サブ鍵が切れれば署名や復号に使えないので）。
    public func extendExpiry(of key: Key, to expires: Expiry) throws {
        try setExpiry(fingerprint: key.fingerprint, expires: expires)
        let subkeys = key.subkeys.filter { $0.validity != .revoked && $0.expires != nil }.map(\.fingerprint)
        if !subkeys.isEmpty {
            try setSubkeyExpiry(fingerprint: key.fingerprint, subkeys: subkeys, expires: expires)
        }
    }
}

extension OwnKey {
    /// 秘密鍵（主鍵かサブ鍵）がこの PC にあり、バックアップに書き出せるか。カード上の鍵は書き出せない。
    public var canBackUp: Bool {
        ([key.secret] + key.subkeys.map(\.secret)).contains(.available)
    }

    /// バックアップの既定のファイル名（`名前 鍵ID secret.asc`）。
    public var backupFileName: String { fileName("secret") }

    /// 公開鍵の既定のファイル名（`名前 鍵ID public.asc`）。
    public var publicKeyFileName: String { fileName("public") }

    /// SSH の公開鍵の既定のファイル名（`名前 鍵ID ssh.pub`）。
    public var sshPublicKeyFileName: String { fileName("ssh", extension: "pub") }

    private func fileName(_ kind: String, extension ext: String = "asc") -> String {
        let name = key.primaryUserId.map { UserIdParts($0.text).name } ?? "key"
        let safe = name.map { "/:\\".contains($0) ? "-" : $0 }
        return "\(String(safe)) \(key.fingerprint.suffix(16)) \(kind).\(ext)"
    }
}

extension OwnKey {
    /// バックアップを促すか。秘密鍵がこの PC にあり、バックアップの記録がないこと。
    /// 使えた鍵（期限切れ・失効）も、昔のものを復号するのに秘密鍵が要るので促す。
    public var needsBackup: Bool {
        canBackUp && backedUp == nil
    }
}

extension OwnKey {
    /// 秘密鍵ごと消してよいか。秘密鍵がこの PC にあるなら、バックアップの記録があること（消したら戻せないので）。
    /// 秘密鍵がカードや別の PC にあるだけなら、この PC から消しても秘密鍵は失わない。
    public var canDelete: Bool { !needsBackup }
}

/// 秘密鍵のバックアップを取った日時。gpg は記録しないので、アプリが鍵のフィンガープリントごとに覚える。
/// アプリで書き出したときと、ほかの方法で取ったと利用者が言ったときに記録する。
public struct BackupLog {
    private let defaults: UserDefaults
    private static let key = "backups"

    public init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    public var dates: [String: Date] {
        let stored = defaults.dictionary(forKey: Self.key) as? [String: Double] ?? [:]
        return stored.mapValues { Date(timeIntervalSince1970: $0) }
    }

    public func record(_ fingerprint: String, at date: Date = Date()) {
        var stored = defaults.dictionary(forKey: Self.key) as? [String: Double] ?? [:]
        stored[fingerprint] = date.timeIntervalSince1970
        defaults.set(stored, forKey: Self.key)
    }
}

extension Gpg {
    /// 秘密鍵を ASCII 形式で `url` に書き出す。書き出したものはパスフレーズで守られたまま。
    /// ファイルは持ち主だけが読める（0600）ように作ってから置き換える。
    public func backUpSecretKey(_ fingerprint: String, to url: URL) throws {
        try write(exportSecretKey(fingerprint: fingerprint, armor: true), to: url, permissions: 0o600)
    }

    /// 公開鍵を ASCII 形式で `url` に書き出す（渡す相手に読ませるので、ほかの人も読める 0644）。
    public func exportPublicKey(_ fingerprint: String, to url: URL) throws {
        try write(exportPublicKeys(fingerprints: [fingerprint], armor: true), to: url, permissions: 0o644)
    }

    /// サブ鍵の公開鍵を、`authorized_keys` に書く 1 行の形で `url` に書き出す（0644）。
    public func exportSshPublicKey(_ subkey: Subkey, to url: URL) throws {
        try write(Data((exportSshKey(fingerprint: subkey.fingerprint) + "\n").utf8), to: url, permissions: 0o644)
    }

    /// 隣に `permissions` で作ってから置き換える（書きかけや、緩い権限のファイルを残さない）。
    private func write(_ data: Data, to url: URL, permissions: Int) throws {
        let temporary = url.deletingLastPathComponent()
            .appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString.prefix(8))")
        guard FileManager.default.createFile(atPath: temporary.path, contents: data, attributes: [.posixPermissions: permissions]) else {
            throw CocoaError(.fileWriteUnknown, userInfo: [NSFilePathErrorKey: temporary.path])
        }
        guard rename(temporary.path, url.path) == 0 else {
            let error = POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            try? FileManager.default.removeItem(at: temporary)
            throw error
        }
    }
}

/// 公開鍵を送る鍵サーバー。送り先を確かめさせるので、gpg の既定に任せずに決めて渡す。
public enum Keyserver {
    public static let `default` = "hkps://keys.openpgp.org"
    /// 送る・探す鍵サーバー。起動の引数で変えられる（試験用の鍵サーバーに向ける）。起動のときに一度だけ決める。
    nonisolated(unsafe) public static var current = `default`

    /// 画面に出す名前（`keys.openpgp.org`）。
    public static func name(_ url: String) -> String {
        URL(string: url)?.host ?? url
    }
}

/// 取り込みの結果を、いくつかのファイルにわたってまとめたもの。
public struct ImportSummary: Equatable, Sendable {
    /// 新しく入った鍵。
    public var newKeys = 0
    /// 既にあり、UID・サブ鍵・署名・失効が増えた鍵。
    public var updatedKeys = 0
    /// 既にあり、何も変わらなかった鍵。
    public var unchangedKeys = 0
    /// 新しく入った秘密鍵。
    public var secretKeys = 0
    /// 新しく入った失効（失効証明書の取り込みなど）。
    public var revocations = 0
    /// gpg が取り込めなかった鍵。
    public var notImported = 0
    /// 読めなかったファイルと、その理由。
    public var failures: [(file: String, error: Error)] = []

    public init() {}

    public mutating func add(_ result: ImportResult) {
        // 秘密鍵を含む鍵は、公開鍵と秘密鍵で 1 行ずつ報告される。鍵の数は公開鍵の行で数える
        for key in result.keys where !key.secret {
            if key.newKey {
                newKeys += 1
            } else if key.newUserIds || key.newSubkeys || key.newSignatures {
                updatedKeys += 1
            }
        }
        unchangedKeys += Int(result.unchanged)
        secretKeys += Int(result.secretImported)
        // 失効証明書だけの取り込みは鍵ごとの報告（IMPORT_OK）がなく、件数にだけ出る
        revocations += Int(result.newRevocations)
        notImported += Int(result.notImported)
    }

    public static func == (a: ImportSummary, b: ImportSummary) -> Bool {
        (a.newKeys, a.updatedKeys, a.unchangedKeys, a.secretKeys, a.revocations, a.notImported)
            == (b.newKeys, b.updatedKeys, b.unchangedKeys, b.secretKeys, b.revocations, b.notImported)
            && a.failures.map(\.file) == b.failures.map(\.file)
    }
}

extension Gpg {
    /// ファイルを 1 つずつ取り込み、結果をまとめる。読めないファイルがあっても残りは取り込む。
    public func importFiles(_ urls: [URL]) -> ImportSummary {
        var summary = ImportSummary()
        for url in urls {
            do {
                summary.add(try `import`(data: try Data(contentsOf: url)))
            } catch {
                summary.failures.append((url.lastPathComponent, error))
            }
        }
        return summary
    }
}

/// macOS の GUI の pinentry。gpg-agent が端末用の pinentry を使っているときに、設定を案内する。
public enum Pinentry {
    /// pinentry-mac の置き場所の候補（Homebrew の Apple シリコン・Intel、GPG Suite）。
    static let macCandidates = [
        "/opt/homebrew/bin/pinentry-mac",
        "/usr/local/bin/pinentry-mac",
        "/usr/local/MacGPG2/libexec/pinentry-mac.app/Contents/MacOS/pinentry-mac",
    ]

    /// 入っている pinentry-mac。なければ nil。
    public static func macPath(isExecutable: (String) -> Bool = FileManager.default.isExecutableFile(atPath:)) -> String? {
        macCandidates.first(where: isExecutable)
    }
}

extension OwnKey {
    /// 名前とメールアドレス（UID）を足したり、失効させたり、主にしたりできるか。主鍵の秘密鍵で署名するので、
    /// 期限の延長と同じ条件（失効していない、主鍵の秘密鍵がこの PC かカードにある）。
    public var canEditUserIds: Bool { canExtendExpiry }
}

extension Key {
    /// 画像（写真 ID）でない UID。gpg は主な UID を先に並べる。
    public var namedUserIds: [UserId] {
        userIds.filter { !$0.attribute }
    }

    /// 主にできるか。失効しておらず、いまの主でないこと。
    public func canMakePrimary(_ uid: UserId) -> Bool {
        uid.validity != .revoked && uid != primaryUserId
    }

    /// 失効させられるか。失効していない UID がほかにも残ること（最後の 1 つは gpg が断る）。
    public func canRevoke(_ uid: UserId) -> Bool {
        uid.validity != .revoked && namedUserIds.filter { $0.validity != .revoked }.count > 1
    }

    /// 足そうとする UID が、失効していない UID と同じでないか（同じものを足しても gpg は何もしない）。
    public func hasActiveUserId(_ text: String) -> Bool {
        namedUserIds.contains { $0.validity != .revoked && $0.text == text }
    }
}

extension Gpg {
    /// UID を足す。どの UID にも主の印がなければ gpg は新しい自己署名の UID（足したもの）を主にし、印があれば
    /// 主は変わらない。どちらでも結果が決まるよう、足したあとで主が望みと違えば付け直す（一覧の名前が知らないうちに
    /// 変わらないように）。すでに主の UID を主にしようとすると gpg は「General error」で断るので、違うときだけ。
    /// 付け直すときは、パスフレーズを続けて 2 度聞くことがある。
    public func addUserId(_ text: String, to key: Key, makePrimary: Bool) throws {
        let previous = key.primaryUserId.flatMap { $0.validity == .revoked ? nil : $0.text }
        try addUserId(fingerprint: key.fingerprint, userId: text)
        guard let wanted = makePrimary ? text : previous else { return }
        let added = try listKeys().first { $0.fingerprint == key.fingerprint }
        if added?.primaryUserId?.text != wanted {
            try setPrimaryUserId(fingerprint: key.fingerprint, userId: wanted)
        }
    }
}

extension OwnKey {
    /// パスフレーズを変えられるか。秘密鍵（主鍵かサブ鍵）がこの PC にあること。カード上の鍵は PIN で守られ、
    /// パスフレーズはない。失効・期限切れの鍵でも、昔のものの復号に使うので変えられる。
    public var canChangePassphrase: Bool { canBackUp }
}

extension OwnKey {
    /// SSH の公開鍵として渡す認証サブ鍵。失効・期限切れでない認証サブ鍵のうち、いちばん新しいもの
    /// （gpg-agent も、使える認証サブ鍵が複数あると新しいものを出す）。
    public func sshSubkey(now: UInt64) -> Subkey? {
        key.subkeys
            .filter { $0.capabilities.authenticate && $0.validity != .revoked && $0.validity != .expired && ($0.expires ?? .max) > now }
            .max { ($0.created ?? 0) < ($1.created ?? 0) }
    }
}
