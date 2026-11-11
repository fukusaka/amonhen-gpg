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
