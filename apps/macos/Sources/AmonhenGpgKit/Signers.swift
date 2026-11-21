import Foundation

/// git の allowed signers（docs/allowed-signers.md）の、画面から使う道具。記録の中身と操作はコア（`editSignerRecord` など）。
public enum Signers {
    /// 記録とファイルの置き場所（`~/Library/Application Support/Amonhen GPG`）。
    public static func defaultDirectory() -> URL {
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support")
        return support.appendingPathComponent("Amonhen GPG", isDirectory: true)
    }

    /// すべてのリポジトリで、このファイルを使わせる git のコマンド。
    public static func globalCommand(path: String) -> String {
        "git config --global gpg.ssh.allowedSignersFile \(shellQuoted(path))"
    }

    /// 1 つのリポジトリ（その中で実行する）で、このファイルを使わせる git のコマンド。
    public static func repositoryCommand(path: String) -> String {
        "git config gpg.ssh.allowedSignersFile \(shellQuoted(path))"
    }

    /// sh で 1 語になるように引用する。
    public static func shellQuoted(_ text: String) -> String {
        "'" + text.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    /// 一覧の名前から、ファイルの名前に使う ID を作る（英小文字・数字・`-`）。作れなければ `list`。
    /// すでにある ID と重なれば、`-2` などを付ける。
    public static func listId(for name: String, existing: [String]) -> String {
        var id = ""
        for c in name.lowercased() {
            if c.isASCII, c.isLetter || c.isNumber {
                id.append(c)
            } else if !id.isEmpty, !id.hasSuffix("-") {
                id.append("-")
            }
        }
        while id.hasSuffix("-") { id.removeLast() }
        if id.isEmpty { id = "list" }
        id = String(id.prefix(32))
        var candidate = id
        var n = 2
        while existing.contains(candidate) {
            candidate = "\(id)-\(n)"
            n += 1
        }
        return candidate
    }

    /// 今の時刻（UTC、RFC 3339。コアが記録に書く形と同じ）。
    public static func now() -> String {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f.string(from: Date())
    }

    /// 記録の時刻（RFC 3339）を日付にする。読めなければ nil。
    public static func date(_ text: String) -> Date? {
        ISO8601DateFormatter().date(from: text)
    }

    /// 人のアカウントをすべて取り直し、記録との差を返す（curl を待つので、裏のスレッドで呼ぶ）。
    /// 失敗したアカウントは `failures` に入れ、ほかのアカウントは続ける。
    public static func changes(record: SignerRecord, person: Signer) -> PersonChanges {
        var result = PersonChanges()
        let fetched = now()
        for account in person.accounts {
            do {
                let keys = try fetchSigningKeys(host: account.host, user: account.user)
                let changes = try signerChanges(
                    record: record, email: person.email, host: account.host, user: account.user, fetched: keys)
                for key in changes.new where !result.new.contains(where: { $0.key.fingerprint == key.fingerprint }) {
                    result.new.append(PendingKey(
                        key: key, source: KeySource(host: account.host, user: account.user, fetched: fetched)))
                }
                for gone in changes.gone where !result.gone.contains(gone) {
                    result.gone.append(gone)
                }
            } catch {
                result.failures.append(AccountFailure(account: account, error: error))
            }
        }
        result.checked = fetched
        return result
    }
}

/// 取ってきた鍵のうち、まだ受け入れていないもの。
public struct PendingKey: Sendable, Hashable {
    public let key: FetchedKey
    public let source: KeySource
}

public struct AccountFailure: Sendable {
    public let account: Account
    public let error: Error
}

/// 1 人の「変化を確かめる」の結果。
public struct PersonChanges: Sendable {
    public var new: [PendingKey] = []
    /// そのアカウントから消えた鍵のフィンガープリント。
    public var gone: [String] = []
    public var failures: [AccountFailure] = []
    /// 確かめた時刻（RFC 3339）。
    public var checked: String?

    public init() {}

    public var isEmpty: Bool { new.isEmpty && gone.isEmpty && failures.isEmpty }
}

extension SignerKey {
    /// 退役させた鍵か。
    public var retired: Bool { validBefore != nil }
}

extension Account {
    /// `github.com/alice` の形。
    public var display: String {
        "\(host == .gitHub ? "github.com" : "gitlab.com")/\(user)"
    }
}

extension SignerRecord {
    /// `email` の人が入っている一覧。
    public func lists(of email: String) -> [SignerList] {
        lists.filter { $0.members.contains(email) }
    }
}
