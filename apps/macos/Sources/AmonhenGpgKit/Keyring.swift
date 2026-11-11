import Foundation

/// 鍵束を画面の 3 つの場所（docs/ui.md）に分けたもの。自分の鍵は段（使える・この PC では使えない・履歴）ごと。
public struct Keyring: Sendable {
    public var usable: [OwnKey] = []
    public var notOnThisDevice: [OwnKey] = []
    public var history: [OwnKey] = []
    /// 他者の鍵。
    public var others: [Key] = []

    public init() {}

    /// `keys` を分ける。`sshKeys` は gpg-agent が SSH に出している鍵を知るため（取れなければ空）。`now` は UNIX 時刻（秒）。
    public init(keys: [Key], sshKeys: [SshKey], now: UInt64) {
        let ssh = Set(sshKeys.filter(sshKeyEnabled(key:)).map(\.keygrip))
        for key in keys {
            guard keyIsMine(key: key) else {
                others.append(key)
                continue
            }
            let grips = ([key.keygrip] + key.subkeys.map(\.keygrip)).compactMap { $0 }
            let own = OwnKey(key: key, status: keyStatus(key: key, now: now), ssh: grips.contains(where: ssh.contains))
            switch own.status.tier {
            case .usable: usable.append(own)
            case .notOnThisDevice: notOnThisDevice.append(own)
            case .history: history.append(own)
            }
        }
        // 履歴は新しいものから
        history.sort { ($0.key.created ?? 0) > ($1.key.created ?? 0) }
    }
}

/// 自分の鍵と、その使える状態。
public struct OwnKey: Sendable, Identifiable {
    public let key: Key
    public let status: KeyStatus
    /// 主鍵かサブ鍵のどれかを、gpg-agent が SSH に出しているか。
    public let ssh: Bool

    public var id: String { key.fingerprint }

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
    /// 名前として出す UID。gpg は主たる UID を先に並べるので、失効していない最初のもの。
    public var primaryUserId: UserId? {
        let ids = userIds.filter { !$0.attribute }
        return ids.first { $0.validity != .revoked } ?? ids.first
    }
}
