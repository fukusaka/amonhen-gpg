import AmonhenGpgKit
import Foundation
import Observation

/// 画面が見る鍵束。gpg を待つ呼び出しは裏のスレッドで行う。
@Observable
final class KeyringModel {
    let gpg: Gpg
    private(set) var keyring = Keyring()
    private(set) var loading = false
    private(set) var failure: String?

    init(gpg: Gpg) {
        self.gpg = gpg
    }

    func reload() async {
        loading = true
        defer { loading = false }
        let gpg = gpg
        let result = await Task.detached { () -> Result<Keyring, Error> in
            Result { try Self.read(gpg) }
        }.value
        apply(result)
    }

    /// 待たずに読む（画像に書き出すときだけ）。
    func reloadNow() {
        apply(Result { try Self.read(gpg) })
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

    nonisolated private static func read(_ gpg: Gpg) throws -> Keyring {
        let keys = try gpg.listKeys()
        // SSH の状態が取れなくても（gpg-agent が動かないなど）、鍵の一覧は出す
        let sshKeys = (try? gpg.sshKeys()) ?? []
        return Keyring(keys: keys, sshKeys: sshKeys, now: UInt64(Date().timeIntervalSince1970))
    }
}

/// エラーを画面の文にする。
func describe(_ error: Error) -> String {
    guard let error = error as? GpgError else { return error.localizedDescription }
    switch error {
    case let .Spawn(program, message): return L("Cannot start %@: %@", program, message)
    case let .Gpg(_, _, stderr): return L("gpg failed: %@", stderr.trimmingCharacters(in: .whitespacesAndNewlines))
    case let .Agent(_, message): return L("gpg-agent refused: %@", message)
    case let .Parse(_, message): return L("Unexpected output from gpg: %@", message)
    case let .InvalidArgument(name, message): return L("Invalid %@: %@", name, message)
    case .NotFound: return L("The key was not found.")
    case let .NotApplied(message): return message
    case let .Io(path, message): return "\(path): \(message)"
    }
}
