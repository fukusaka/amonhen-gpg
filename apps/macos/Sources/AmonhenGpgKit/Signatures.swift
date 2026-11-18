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

/// 鍵を確認済みにした署名の主（Web of Trust の 1 段）。
public struct Introducer: Sendable, Equatable {
    public let fingerprint: String
    public let name: String
    /// 自分の鍵か。自分の鍵でなければ、所有者信頼を付けた確認済みの鍵。
    public let byYou: Bool
    /// 自分の鍵でないときの所有者信頼（`full` か `marginal`）。
    public let trust: OwnerTrust
}

extension Keyring {
    /// 鍵の有効性の根拠になった署名の主。正しく、取り消されていない署名のうち、自分の鍵によるものと、
    /// 所有者信頼が完全・ある程度で、それ自体が確認済みの鍵によるもの（gpg の pgp 信用モデルと同じ考え）。
    /// 自分の鍵を先に、次に完全、ある程度の順。同じ鍵は 1 つにまとめる。
    public func introducers(_ all: [Certification], of key: Key) -> [Introducer] {
        let own = (usable + notOnThisDevice + history).map(\.key)
        var found: [Introducer] = []
        for c in all where c.check == .good && !c.revoked {
            let isSigner: (Key) -> Bool = { k in
                guard k.fingerprint.caseInsensitiveCompare(key.fingerprint) != .orderedSame else { return false }
                if let f = c.signerFingerprint { return k.fingerprint.caseInsensitiveCompare(f) == .orderedSame }
                return k.fingerprint.uppercased().hasSuffix(c.signerKeyId.uppercased())
            }
            let introducer: Introducer?
            if let mine = own.first(where: isSigner) {
                introducer = Introducer(fingerprint: mine.fingerprint, name: mine.primaryUserId.map { UserIdParts($0.text).name } ?? mine.keyId,
                                        byYou: true, trust: .ultimate)
            } else if let signer = others.first(where: isSigner),
                      signer.validity == .full || signer.validity == .ultimate,
                      signer.ownerTrustSetting == .full || signer.ownerTrustSetting == .marginal {
                introducer = Introducer(fingerprint: signer.fingerprint, name: signer.primaryUserId.map { UserIdParts($0.text).name } ?? signer.keyId,
                                        byYou: false, trust: signer.ownerTrustSetting)
            } else {
                introducer = nil
            }
            if let introducer, !found.contains(where: { $0.fingerprint == introducer.fingerprint }) {
                found.append(introducer)
            }
        }
        let rank: (Introducer) -> Int = { $0.byYou ? 0 : $0.trust == .full ? 1 : 2 }
        return found.sorted { (rank($0), $0.name) < (rank($1), $1.name) }
    }

    /// 自分の鍵が、ほかの鍵から受け取った署名の数（署名した鍵ごとに 1 つ。取り消されたものと自分の鍵によるものは数えない）。
    public func signerCount(_ all: [Certification], of key: Key) -> Int {
        let own = (usable + notOnThisDevice + history).map(\.key)
        let signers = all.filter { c in
            !c.revoked && !own.contains { k in
                if let f = c.signerFingerprint { return k.fingerprint.caseInsensitiveCompare(f) == .orderedSame }
                return k.fingerprint.uppercased().hasSuffix(c.signerKeyId.uppercased())
            }
        }.map { $0.signerKeyId.uppercased() }
        return Set(signers).count
    }
}
