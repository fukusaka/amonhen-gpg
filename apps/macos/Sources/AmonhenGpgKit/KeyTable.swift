import Foundation

/// 表（他者の鍵）の 1 行。列の値は並べ替えられるよう、どれも比べられる型にしてある。
public struct KeyTableRow: Identifiable, Hashable, Sendable {
    public let key: Key
    /// 主な UID の名前とメールアドレス（なければ空）。
    public let name: String
    public let email: String
    /// 主な UID のほかの、名前のある UID（失効したものも含む）。
    public let otherUserIds: [UserId]
    /// 有効性の並び（完全・部分的・不明・期限切れ・失効の順に小さい）。並べ替えに使う。
    public let verificationOrder: Int
    /// 所有者信頼の並び（完全・部分的・信頼しない・未設定の順に小さい）。並べ替えに使う。
    public let ownerTrustOrder: Int
    /// 鍵 ID（フィンガープリントの末尾 16 桁）。
    public let keyId: String
    /// 作成日（UNIX 時刻、秒。なければ 0）。
    public let created: UInt64
    /// 期限（UNIX 時刻、秒）。期限のない鍵は最後に来るよう最大の値。
    public let expires: UInt64
    /// 方式の名前（`ed25519`・`RSA 4096` など）。
    public let algorithm: String

    public var id: String { key.fingerprint }

    /// 失効か期限切れで、もう使えない鍵か（表では薄く出す）。
    public var isInactive: Bool { key.validity == .revoked || key.validity == .expired }

    public init(key: Key) {
        self.key = key
        let primary = key.primaryUserId
        let parts = primary.map { UserIdParts($0.text) }
        name = parts?.name ?? key.fingerprint
        email = parts?.email ?? ""
        otherUserIds = key.namedUserIds.filter { $0 != primary }
        verificationOrder = Self.order(key.validity)
        ownerTrustOrder = switch key.ownerTrustSetting {
        case .ultimate: 0
        case .full: 1
        case .marginal: 2
        case .never: 3
        case .unknown: 4
        }
        keyId = String(key.fingerprint.suffix(16))
        created = key.created ?? 0
        expires = key.expires ?? UInt64.max
        algorithm = algorithmName(algorithm: key.algorithm, length: key.length, curve: key.curve)
    }

    private static func order(_ validity: Validity) -> Int {
        switch validity {
        case .ultimate, .full: 0
        case .marginal: 1
        case .expired: 3
        case .revoked, .invalid, .disabled: 4
        default: 2
        }
    }
}

/// 他者の鍵の表を、有効性で絞り込む。
public enum KeyFilter: String, CaseIterable, Sendable {
    case all
    /// 完全に有効（自分の鍵か、信頼する人の署名で有効になった鍵）。
    case verified
    /// まだ完全には有効でない鍵。部分的に有効な鍵も、まだ署名で有効にできるのでここに入れる。
    case unverified
    /// 期限切れ・失効・無効の、もう使えない鍵。
    case inactive

    public func includes(_ key: Key) -> Bool {
        switch self {
        case .all: true
        case .verified: key.validity == .full || key.validity == .ultimate
        case .inactive: [.expired, .revoked, .invalid, .disabled].contains(key.validity)
        case .unverified: !KeyFilter.verified.includes(key) && !KeyFilter.inactive.includes(key)
        }
    }
}
