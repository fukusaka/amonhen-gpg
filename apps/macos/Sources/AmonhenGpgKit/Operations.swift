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
    public var backupFileName: String {
        let name = key.primaryUserId.map { UserIdParts($0.text).name } ?? "key"
        let safe = name.map { "/:\\".contains($0) ? "-" : $0 }
        return "\(String(safe)) \(key.fingerprint.suffix(16)) secret.asc"
    }
}

extension Gpg {
    /// 秘密鍵を ASCII 形式で `url` に書き出す。書き出したものはパスフレーズで守られたまま。
    /// ファイルは持ち主だけが読める（0600）ように作ってから置き換える。
    public func backUpSecretKey(_ fingerprint: String, to url: URL) throws {
        let data = try exportSecretKey(fingerprint: fingerprint, armor: true)
        let temporary = url.deletingLastPathComponent()
            .appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString.prefix(8))")
        guard FileManager.default.createFile(atPath: temporary.path, contents: data, attributes: [.posixPermissions: 0o600]) else {
            throw CocoaError(.fileWriteUnknown, userInfo: [NSFilePathErrorKey: temporary.path])
        }
        guard rename(temporary.path, url.path) == 0 else {
            let error = POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            try? FileManager.default.removeItem(at: temporary)
            throw error
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
