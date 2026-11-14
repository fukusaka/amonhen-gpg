import Foundation

extension Key {
    /// 一覧の検索の語に合うか。語を空白で分け、すべての語がどこかに合えば合う（空なら合う）。
    /// - 名前・メールアドレス: 主でない UID も含め、大文字小文字を区別しない部分一致。
    /// - フィンガープリント・鍵 ID: 4 文字以上の 16 進の語は、主鍵とサブ鍵のフィンガープリントとの部分一致。
    ///   語全体が 16 進と空白だけで 8 文字以上なら、区切りの空白ごと貼り付けたフィンガープリントとみなし、空白を除いて比べる。
    public func matches(_ query: String) -> Bool {
        let query = query.trimmingCharacters(in: .whitespaces)
        if query.isEmpty { return true }
        let compact = query.filter { !$0.isWhitespace }
        if compact.count >= 8, compact.allSatisfy(\.isHexDigit), query.contains(" ") {
            return containsFingerprint(compact)
        }
        let texts = userIds.filter { !$0.attribute }.map(\.text)
        return query.split(whereSeparator: \.isWhitespace).allSatisfy { term in
            texts.contains { $0.range(of: term, options: [.caseInsensitive, .diacriticInsensitive]) != nil }
                || (term.count >= 4 && term.allSatisfy(\.isHexDigit) && containsFingerprint(String(term)))
        }
    }

    private func containsFingerprint(_ hex: String) -> Bool {
        ([fingerprint] + subkeys.map(\.fingerprint)).contains { $0.range(of: hex, options: .caseInsensitive) != nil }
    }
}

extension OwnKey {
    public func matches(_ query: String) -> Bool { key.matches(query) }
}

extension Keyring {
    /// 検索の語に合う鍵だけを残した鍵束。SSH だけの鍵と SSH サポートの状態はそのまま。
    public func filtered(by query: String) -> Keyring {
        guard !query.trimmingCharacters(in: .whitespaces).isEmpty else { return self }
        var result = self
        result.usable = usable.filter { $0.matches(query) }
        result.notOnThisDevice = notOnThisDevice.filter { $0.matches(query) }
        result.history = history.filter { $0.matches(query) }
        result.others = others.filter { $0.matches(query) }
        return result
    }
}
