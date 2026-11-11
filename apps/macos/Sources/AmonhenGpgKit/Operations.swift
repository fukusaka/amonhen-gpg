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
