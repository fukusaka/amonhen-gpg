import Foundation

/// 署名タブの 1 行。署名と、署名した鍵が鍵束のどれか。
public struct SignatureRow: Sendable, Identifiable {
    public let id: Int
    public let certification: Certification
    /// 署名した鍵の名前。鍵束になければ nil（鍵 ID だけを出す）。
    public let signerName: String?
    /// 自分の鍵による署名か。
    public let byYou: Bool
}

/// 鍵に付いた署名を、信用の根拠になるものとそれ以外に分けたもの。
public struct KeySignatures: Sendable {
    /// 自分の鍵か、自分が確認済みにした鍵（有効性が full・ultimate）による署名。取り消されたものも含む。
    public var trusted: [SignatureRow] = []
    /// そのほか（確かめていない人・鍵束にない鍵）。本物の保証にはならない。
    public var others: [SignatureRow] = []
}

extension Keyring {
    /// 鍵のすべての UID の署名を分ける。署名した鍵は、フィンガープリント（なければ鍵 ID）で鍵束から探す。
    /// 並びは UID の順、その中は新しい署名から。
    public func signatures(_ all: [Certification], on key: Key) -> KeySignatures {
        let own = (usable + notOnThisDevice + history).map(\.key)
        let uidOrder = Dictionary(key.userIds.enumerated().map { ($1.text, $0) }, uniquingKeysWith: { a, _ in a })
        let sorted = all.enumerated().sorted { a, b in
            let ua = uidOrder[a.element.userId] ?? .max, ub = uidOrder[b.element.userId] ?? .max
            if ua != ub { return ua < ub }
            return (a.element.created ?? 0) > (b.element.created ?? 0)
        }
        var result = KeySignatures()
        for (index, c) in sorted {
            let isSigner: (Key) -> Bool = { k in
                if let f = c.signerFingerprint { return k.fingerprint.caseInsensitiveCompare(f) == .orderedSame }
                return k.fingerprint.uppercased().hasSuffix(c.signerKeyId.uppercased())
            }
            let mine = own.first(where: isSigner)
            let signer = mine ?? others.first(where: isSigner)
            let row = SignatureRow(
                id: index, certification: c,
                signerName: (signer?.primaryUserId?.text ?? c.signerUserId).map { UserIdParts($0).name },
                byYou: mine != nil)
            if mine != nil || signer.map({ $0.validity == .full || $0.validity == .ultimate }) == true {
                result.trusted.append(row)
            } else {
                result.others.append(row)
            }
        }
        return result
    }
}
