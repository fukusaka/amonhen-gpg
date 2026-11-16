import Foundation

/// 鍵束を画面の 3 つの場所（docs/ui.md）に分けたもの。自分の鍵は段（使える・この PC では使えない・履歴）ごと。
public struct Keyring: Sendable {
    public var usable: [OwnKey] = []
    public var notOnThisDevice: [OwnKey] = []
    public var history: [OwnKey] = []
    /// 他者の鍵。
    public var others: [Key] = []
    /// gpg-agent が持つ SSH の鍵のうち、OpenPGP の鍵でないもの（ssh-add で取り込んだ鍵）。
    public var sshOnly: [SshKey] = []
    /// gpg-agent の SSH サポート（取れなければ nil）。
    public var sshSupport: SshSupport?
    /// gpg-agent が持つ鍵の、SSH の形のフィンガープリント（`SHA256:...`）。keygrip（大文字）で引く。
    public var sshFingerprints: [String: String] = [:]

    public init() {}

    /// `keys` を分ける。`sshKeys` は gpg-agent が SSH に出している鍵を知るため（取れなければ空）。`now` は UNIX 時刻（秒）。
    /// `hasRevocationCertificate` は自分の鍵ごとに、手元に失効証明書があるか（`Gpg.hasRevocationCertificate`）。
    /// `backups` はバックアップを取った日時（`BackupLog.dates`）。
    public init(
        keys: [Key], sshKeys: [SshKey], now: UInt64,
        hasRevocationCertificate: (String) -> Bool = { _ in true },
        backups: [String: Date] = [:]
    ) {
        let ssh = Set(sshKeys.filter(sshKeyEnabled(key:)).map(\.keygrip))
        for key in keys {
            guard keyIsMine(key: key) else {
                others.append(key)
                continue
            }
            let grips = ([key.keygrip] + key.subkeys.map(\.keygrip)).compactMap { $0 }
            let own = OwnKey(
                key: key, status: keyStatus(key: key, now: now), ssh: grips.contains(where: ssh.contains),
                hasRevocationCertificate: hasRevocationCertificate(key.fingerprint),
                backedUp: backups[key.fingerprint])
            switch own.status.tier {
            case .usable: usable.append(own)
            case .notOnThisDevice: notOnThisDevice.append(own)
            case .history: history.append(own)
            }
        }
        let grips = Set(keys.flatMap { ([$0.keygrip] + $0.subkeys.map(\.keygrip)).compactMap { $0 } })
        sshOnly = sshKeys.filter { !grips.contains($0.keygrip) }
        sshFingerprints = Dictionary(sshKeys.map { ($0.keygrip.uppercased(), $0.fingerprint) }, uniquingKeysWith: { a, _ in a })
        // 使える段とこの PC では使えない段は、期限が近いものから（延ばす必要のある鍵が上に来る）。履歴は新しいものから
        usable.sort { Key.expiresSooner($0.key, $1.key) }
        notOnThisDevice.sort { Key.expiresSooner($0.key, $1.key) }
        history.sort { ($0.key.created ?? 0) > ($1.key.created ?? 0) }
    }

    /// 他者の鍵に署名する（確認済みにする）のに使える自分の鍵。使える段にあり、証明の秘密鍵がこの PC かカードにあるもの。
    public var signers: [OwnKey] {
        usable.filter {
            switch $0.status.certify {
            case .thisDevice, .card: true
            case .elsewhere, .none: false
            }
        }
    }

    /// 自分の鍵をフィンガープリントで探す（どの段にあっても）。
    /// 鍵（サブ鍵）の SSH のフィンガープリント。gpg-agent が秘密鍵を持っていなければ nil。
    public func sshFingerprint(keygrip: String?) -> String? {
        keygrip.flatMap { sshFingerprints[$0.uppercased()] }
    }

    public func own(_ fingerprint: String) -> OwnKey? {
        (usable + notOnThisDevice + history).first { $0.key.fingerprint.caseInsensitiveCompare(fingerprint) == .orderedSame }
    }
}

extension Key {
    /// 期限が近い順。期限のない鍵は最後に置き、同じなら新しく作った鍵を先に、それも同じならフィンガープリントの順。
    static func expiresSooner(_ a: Key, _ b: Key) -> Bool {
        switch (a.expires, b.expires) {
        case let (x?, y?) where x != y: return x < y
        case (.some, .none): return true
        case (.none, .some): return false
        default:
            if a.created != b.created { return (a.created ?? 0) > (b.created ?? 0) }
            return a.fingerprint < b.fingerprint
        }
    }
}

/// 自分の鍵と、その使える状態。
public struct OwnKey: Sendable, Identifiable {
    public let key: Key
    public let status: KeyStatus
    /// 主鍵かサブ鍵のどれかを、gpg-agent が SSH に出しているか。
    public let ssh: Bool
    /// 手元（`openpgp-revocs.d`）に失効証明書があるか。
    public let hasRevocationCertificate: Bool
    /// 秘密鍵のバックアップを取った日時（`BackupLog`）。記録がなければ nil。
    public let backedUp: Date?

    public var id: String { key.fingerprint }

    /// 期限切れまでこの日数以内なら急ぐ（目立たせる）。
    public static let urgentExpiryDays = 14

    /// 期限までの日数。期限がなければ nil。
    public func daysUntilExpiry(now: UInt64) -> Int? {
        guard let expires = key.expires else { return nil }
        return Int((Int64(expires) - Int64(now)) / 86_400)
    }
}

/// UID（`名前 (コメント) <メール>`）を分けたもの。
public struct UserIdParts: Equatable, Sendable {
    public let name: String
    public let comment: String?
    public let email: String?

    public init(name: String, comment: String?, email: String?) {
        self.name = name
        self.comment = comment
        self.email = email
    }

    /// UID の文字（`名前 (コメント) <メール>`）。空の部分は入れない。
    public var text: String {
        var parts = [name.trimmingCharacters(in: .whitespaces)]
        if let comment = comment?.trimmingCharacters(in: .whitespaces), !comment.isEmpty {
            parts.append("(\(comment))")
        }
        if let email = email?.trimmingCharacters(in: .whitespaces), !email.isEmpty {
            parts.append("<\(email)>")
        }
        return parts.filter { !$0.isEmpty }.joined(separator: " ")
    }

    /// 鍵を作るのに足りるか。名前かメールのどちらかがあり、メールなら `@` を含むこと。
    public var isValidForNewKey: Bool {
        let name = name.trimmingCharacters(in: .whitespaces)
        let email = (email ?? "").trimmingCharacters(in: .whitespaces)
        if !email.isEmpty, !email.contains("@") || email.contains(where: { " <>".contains($0) }) { return false }
        if name.contains(where: { "<>()".contains($0) }) { return false }
        return !name.isEmpty || !email.isEmpty
    }

    public init(_ text: String) {
        var rest = text.trimmingCharacters(in: .whitespaces)
        var email: String?
        if rest.hasSuffix(">"), let open = rest.lastIndex(of: "<") {
            email = String(rest[rest.index(after: open)..<rest.index(before: rest.endIndex)])
            rest = rest[..<open].trimmingCharacters(in: .whitespaces)
        }
        var comment: String?
        if rest.hasSuffix(")"), let open = rest.lastIndex(of: "(") {
            comment = String(rest[rest.index(after: open)..<rest.index(before: rest.endIndex)])
            rest = rest[..<open].trimmingCharacters(in: .whitespaces)
        }
        self.name = rest.isEmpty ? (email ?? text) : rest
        self.comment = comment
        self.email = email
    }
}

extension Key {
    /// 署名して確認済みにできる UID（写真の UID と失効した UID を除く）。
    public var certifiableUserIds: [UserId] {
        userIds.filter { !$0.attribute && $0.validity != .revoked }
    }

    /// 確認済みにする操作を出すか。失効・期限切れの鍵と、もう確認済みの鍵には出さない。
    public var canCertify: Bool {
        switch validity {
        case .new, .unknown, .never, .marginal: !certifiableUserIds.isEmpty
        default: false
        }
    }

    /// 名前として出す UID。gpg は主たる UID を先に並べるので、失効していない最初のもの。
    public var primaryUserId: UserId? {
        let ids = userIds.filter { !$0.attribute }
        return ids.first { $0.validity != .revoked } ?? ids.first
    }
}

/// 鍵の方式の名前（`ed25519`・`RSA 4096` など）。楕円曲線の鍵は曲線の名前で示す。
public func algorithmName(algorithm: UInt32, length: UInt32, curve: String?) -> String {
    if let curve, !curve.isEmpty {
        return curve
    }
    // OpenPGP の公開鍵方式の番号（RFC 9580）
    let name: String
    switch algorithm {
    case 1, 2, 3: name = "RSA"
    case 16, 20: name = "ElGamal"
    case 17: name = "DSA"
    case 18: name = "ECDH"
    case 19: name = "ECDSA"
    case 22: name = "EdDSA"
    case 25: return "X25519"
    case 26: return "X448"
    case 27: return "Ed25519"
    case 28: return "Ed448"
    default: name = "#\(algorithm)"
    }
    return length > 0 ? "\(name) \(length)" : name
}
