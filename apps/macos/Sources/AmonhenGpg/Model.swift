import AmonhenGpgKit
import Foundation
import Observation

/// 画面が見る鍵束。gpg を待つ呼び出しは裏のスレッドで行う。
@Observable
final class KeyringModel {
    private(set) var gpg: Gpg
    /// gpg の実行ファイルの場所（nil なら PATH の gpg）。
    private(set) var program: String?
    let homedir: String?
    let backups: BackupLog
    private(set) var keyring = Keyring()
    private(set) var loading = false
    private(set) var failure: String?

    init(program: String?, homedir: String?, backups: BackupLog = BackupLog()) {
        gpg = Gpg(program: program, homedir: homedir)
        self.program = program
        self.homedir = homedir
        self.backups = backups
    }

    /// 別の gpg に替えて、鍵束を読み直す（設定）。
    func use(_ gpg: Gpg, program: String?) async {
        self.gpg = gpg
        self.program = program
        await reload()
    }

    func reload() async {
        loading = true
        defer { loading = false }
        let gpg = gpg
        let dates = backups.dates
        let result = await Task.detached { () -> Result<Keyring, Error> in
            Result { try Self.read(gpg, backups: dates) }
        }.value
        apply(result)
    }

    /// 秘密鍵のバックアップを取ったと覚え、警告を消す。
    func recordBackup(_ fingerprint: String) async {
        backups.record(fingerprint)
        await reload()
    }

    /// 鍵束を変える操作を裏のスレッドで行い、終わったら（失敗しても）読み直す。
    /// パスフレーズは gpg-agent の pinentry が聞くので、その間も画面は止めない。
    func perform<T: Sendable>(_ work: @escaping @Sendable (Gpg) throws -> T) async -> Result<T, Error> {
        let gpg = gpg
        let result = await Task.detached { Result { try work(gpg) } }.value
        await reload()
        return result
    }

    /// 待たずに読む（画像に書き出すときだけ）。
    func reloadNow() {
        apply(Result { try Self.read(gpg, backups: backups.dates) })
    }

    private func apply(_ result: Result<Keyring, Error>) {
        switch result {
        case let .success(keyring):
            self.keyring = keyring
            failure = nil
        case let .failure(error):
            failure = describe(error)
        }
    }

    nonisolated private static func read(_ gpg: Gpg, backups: [String: Date]) throws -> Keyring {
        let keys = try gpg.listKeys()
        // SSH の状態が取れなくても（gpg-agent が動かないなど）、鍵の一覧は出す
        let sshKeys = (try? gpg.sshKeys()) ?? []
        var keyring = Keyring(
            keys: keys, sshKeys: sshKeys, now: UInt64(Date().timeIntervalSince1970),
            // 確かめられないときは、ないと警告しない
            hasRevocationCertificate: { (try? gpg.hasRevocationCertificate(fingerprint: $0)) ?? true },
            backups: backups)
        keyring.sshSupport = try? gpg.sshSupport()
        keyring.gpgVersion = try? gpg.version()
        return keyring
    }
}

/// 利用者がパスフレーズの入力を取り消したか。取り消しは失敗として知らせない。
func isCanceled(_ error: Error) -> Bool {
    if case GpgError.Canceled = error { true } else { false }
}

/// エラーを画面の文にする。
func describe(_ error: Error) -> String {
    guard let error = error as? GpgError else { return error.localizedDescription }
    switch error {
    case let .Spawn(program, message): return L("Cannot start %@: %@", program, message)
    case let .Gpg(_, _, stderr): return L("gpg failed: %@", stderr.trimmingCharacters(in: .whitespacesAndNewlines))
    case .Canceled: return L("The passphrase entry was canceled.")
    case .BadPassphrase: return L("The passphrase was wrong.")
    case let .NoPinentry(flavor): return describeNoPinentry(flavor: flavor)
    case let .Tool(program, _, stderr): return L("%@ failed: %@", program, stderr.trimmingCharacters(in: .whitespacesAndNewlines))
    case let .Agent(_, message): return L("gpg-agent refused: %@", message)
    case let .Parse(_, message): return L("Unexpected output from gpg: %@", message)
    case let .InvalidArgument(name, message): return L("Invalid %@: %@", name, message)
    case .NotFound: return L("The key was not found.")
    case let .NotApplied(message): return message
    case let .Io(path, message): return "\(path): \(message)"
    }
}

/// pinentry を出せないときの案内。gpg-agent.conf に pinentry-mac を設定してもらう（アプリは書き換えない）。
private func describeNoPinentry(flavor: String?) -> String {
    let problem = flavor.map { L("gpg-agent uses a pinentry for terminals (%@), so it cannot ask for the passphrase here.", $0) }
        ?? L("gpg-agent cannot start its pinentry to ask for the passphrase.")
    guard let path = Pinentry.macPath() else {
        return problem + "\n\n" + L("Install pinentry-mac (brew install pinentry-mac), add this line to gpg-agent.conf in your GnuPG folder (usually ~/.gnupg), and run gpgconf --kill gpg-agent:")
            + "\n\npinentry-program /opt/homebrew/bin/pinentry-mac"
    }
    return problem + "\n\n" + L("Add this line to gpg-agent.conf in your GnuPG folder (usually ~/.gnupg), then run gpgconf --kill gpg-agent:")
        + "\n\npinentry-program \(path)"
}
