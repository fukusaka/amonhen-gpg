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
        return "\(String(safe)) \(key.keyId) \(kind).\(ext)"
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

/// 鍵を探して送る鍵サーバー。送り先を確かめさせるので、gpg の既定に任せずに決めて渡す。設定で選べる。
public enum Keyserver {
    public static let `default` = "hkps://keys.openpgp.org"
    /// 設定のメニューに出す候補。
    public static let candidates = ["hkps://keys.openpgp.org", "hkps://keyserver.ubuntu.com"]
    static let defaultsKey = "Keyserver"
    /// 起動の引数 `--keyserver` で決めたもの（試験用の鍵サーバーに向ける）。あれば設定より先。
    nonisolated(unsafe) public static var fixed: String?

    /// 探す・送る鍵サーバー。起動の引数、設定で選んだもの、既定の順。
    public static var current: String { fixed ?? chosen() ?? `default` }

    /// 設定で選んだもの（使えない URL は無視する）。
    public static func chosen(in defaults: UserDefaults = .standard) -> String? {
        defaults.string(forKey: defaultsKey).flatMap { isKeyserverUrl(url: $0) ? $0 : nil }
    }

    /// 選んだものを覚える。nil なら既定に戻す。
    public static func choose(_ url: String?, in defaults: UserDefaults = .standard) {
        if let url, url != `default` {
            defaults.set(url, forKey: defaultsKey)
        } else {
            defaults.removeObject(forKey: defaultsKey)
        }
    }

    /// 画面に出す名前（`keys.openpgp.org`）。
    public static func name(_ url: String) -> String {
        URL(string: url)?.host ?? url
    }
}

/// 受け入れ前の鍵（一時保管）の dirmngr が名前を引く仕組み。設定で選べる。
public enum NameResolver: String, CaseIterable, Sendable {
    /// dirmngr の既定（GnuPG に入っている libdns。/etc/resolv.conf だけを読む）。
    case gnupg
    /// OS の仕組み（`standard-resolver`）。VPN やドメインごとの DNS の環境でも引ける。
    case system

    static let defaultsKey = "NameResolver"

    public static var current: NameResolver {
        get { stored() }
        set { store(newValue) }
    }

    /// 設定で選んだもの。なければ GnuPG の既定。
    public static func stored(in defaults: UserDefaults = .standard) -> NameResolver {
        defaults.string(forKey: defaultsKey).flatMap(NameResolver.init(rawValue:)) ?? .gnupg
    }

    public static func store(_ value: NameResolver, in defaults: UserDefaults = .standard) {
        if value == .gnupg {
            defaults.removeObject(forKey: defaultsKey)
        } else {
            defaults.set(value.rawValue, forKey: defaultsKey)
        }
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

public enum GpgProgram {
    /// PATH になければ探す場所（Homebrew の Apple シリコン・Intel、GPG Suite）。
    static let fallbackDirectories = ["/opt/homebrew/bin", "/usr/local/bin", "/usr/local/MacGPG2/bin"]

    /// 使う gpg の場所。Finder から開いたアプリの PATH は `/usr/bin:/bin:/usr/sbin:/sbin` だけで、Homebrew の gpg が
    /// 入らないので、PATH のあとに決まった場所を探す。gpgconf などはコアが gpg の隣から使う。見つからなければ nil。
    public static func locate(
        path: String? = ProcessInfo.processInfo.environment["PATH"],
        isExecutable: (String) -> Bool = FileManager.default.isExecutableFile(atPath:)
    ) -> String? {
        let directories = (path ?? "").split(separator: ":").map(String.init) + fallbackDirectories
        return directories.map { "\($0)/gpg" }.first(where: isExecutable)
    }

    static let chosenKey = "GpgProgram"

    /// 設定で選んだ gpg の場所。nil なら自動（`locate`）。
    public static func chosen(in defaults: UserDefaults = .standard) -> String? {
        defaults.string(forKey: chosenKey).flatMap { $0.isEmpty ? nil : $0 }
    }

    /// 設定で選んだ gpg を覚える。nil なら自動に戻す。
    public static func choose(_ path: String?, in defaults: UserDefaults = .standard) {
        if let path, !path.isEmpty {
            defaults.set(path, forKey: chosenKey)
        } else {
            defaults.removeObject(forKey: chosenKey)
        }
    }

    /// 使う gpg。起動の引数（`--gpg`）、設定で選んだもの、自動で見つけたものの順。
    public static func resolve(
        option: String?, defaults: UserDefaults = .standard, locate: () -> String? = { GpgProgram.locate() }
    ) -> String? {
        option ?? chosen(in: defaults) ?? locate()
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
        Self.sshSubkey(of: key, now: now)
    }

    static func sshSubkey(of key: Key, now: UInt64) -> Subkey? {
        key.subkeys
            .filter { $0.capabilities.authenticate && $0.validity != .revoked && $0.validity != .expired && ($0.expires ?? .max) > now }
            .max { ($0.created ?? 0) < ($1.created ?? 0) }
    }
}

extension Gpg {
    /// 自分の鍵を SSH に出す（`sshCandidate`）か、出しているものをすべて止める。
    public func setSshEnabled(_ own: OwnKey, enabled: Bool) throws {
        if enabled {
            guard let keygrip = own.sshCandidate else { return }
            try setSshKeyEnabled(keygrip: keygrip, enabled: true)
        } else {
            for keygrip in own.sshKeygrips {
                try setSshKeyEnabled(keygrip: keygrip, enabled: false)
            }
        }
    }

    /// SSH 用の認証サブ鍵を加えて、SSH に出す。方式は gpg の既定、期限は主鍵に揃える（期限がなければ無期限）。
    /// パスフレーズは pinentry が聞く。加えたサブ鍵のフィンガープリントを返す。
    public func addSshSubkey(_ own: OwnKey, now: UInt64) throws -> String {
        let expires: Expiry = own.key.expires.map { .days(UInt32(max(1, (Int64($0) - Int64(now)) / 86_400))) } ?? .never
        let fingerprint = try addSubkey(
            fingerprint: own.key.fingerprint, algorithm: nil,
            capabilities: Capabilities(certify: false, sign: false, encrypt: false, authenticate: true), expires: expires)
        let keygrip = try listKeys()
            .first { $0.fingerprint == own.key.fingerprint }?
            .subkeys.first { $0.fingerprint == fingerprint }?.keygrip
        guard let keygrip else { throw GpgError.NotFound }
        try setSshKeyEnabled(keygrip: keygrip, enabled: true)
        return fingerprint
    }
}

extension OwnKey {
    /// SSH 用の認証サブ鍵を加えられるか。使える段にあり、使える認証サブ鍵がまだなく、主鍵の秘密鍵がこの PC かカードにあること。
    public func canAddSshSubkey(now: UInt64) -> Bool {
        status.tier == .usable && canExtendExpiry && sshSubkey(now: now) == nil
    }
}

extension SshKey {
    /// 公開鍵の既定のファイル名（説明から作り、なければ `ssh-key.pub`）。
    public var publicKeyFileName: String {
        let name = (comment ?? "").map { "/:\\".contains($0) ? "_" : $0 }
        return (name.isEmpty ? "ssh-key" : String(name)) + ".pub"
    }
}

extension SshKey {
    /// バックアップの既定のファイル名。gpg-agent の置き場所（`private-keys-v1.d`）にそのまま置ける名前。
    public var backupFileName: String { "\(keygrip).key" }

    /// バックアップを書き出せるか（gpg-agent がパスフレーズで守っている、カードにない鍵）。
    public var canBackUp: Bool { card == nil && protected == true }
}

extension Gpg {
    /// ファイルの中身が、取り込んだ SSH の鍵のバックアップ（`exportSshKeyBackup`）か。
    public static func isSshKeyBackup(_ data: Data) -> Bool {
        data.starts(with: Data("(21:protected-private-key".utf8))
    }

    /// 取り込んだ SSH の鍵を、gpg-agent がパスフレーズで守ったままの形でファイルに書く（本人だけが読める 0600）。
    public func exportSshKeyBackup(_ key: SshKey, to url: URL) throws {
        try write(exportSshKeyBackup(keygrip: key.keygrip), to: url, permissions: 0o600)
    }

    /// gpg-agent が持つ SSH の鍵の公開鍵を、`authorized_keys` の 1 行の形でファイルに書く（0644）。
    public func exportSshPublicKey(_ key: SshKey, to url: URL) throws {
        try write(Data((sshPublicKey(keygrip: key.keygrip) + "\n").utf8), to: url, permissions: 0o644)
    }
}

extension Key {
    /// 所有者信頼を、設定に使う値で（一覧の値から。決めていない・分からないものは `unknown`）。
    public var ownerTrustSetting: OwnerTrust {
        switch ownerTrust {
        case .never: .never
        case .marginal: .marginal
        case .full: .full
        case .ultimate: .ultimate
        default: .unknown
        }
    }
}

extension OwnerTrust {
    /// 他者の鍵に選ばせる値。絶対的（`ultimate`）は自分の鍵のもので、付けると他者の鍵が「自分の鍵」になるので出さない。
    public static let choicesForOthers: [OwnerTrust] = [.unknown, .never, .marginal, .full]
}

extension OwnKey {
    /// 秘密鍵がどこにもなく、所有者信頼（絶対的）だけで自分の鍵になっているか（秘密鍵は別の PC にある自分の鍵）。
    /// こうした鍵だけ、他者の鍵に戻せる（秘密鍵のある鍵は、所有者信頼に関わらず自分の鍵）。
    public var isMineByTrustOnly: Bool { key.secret == .none }
}
