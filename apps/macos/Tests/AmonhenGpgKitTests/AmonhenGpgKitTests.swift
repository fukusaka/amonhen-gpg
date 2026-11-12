import Foundation
import Testing

@testable import AmonhenGpgKit

/// 一時ディレクトリを鍵束にした gpg。テストではパスフレーズを空にして pinentry を出さない。
/// 利用者の鍵束（`~/.gnupg`）には触らない。
final class TemporaryKeyring {
    let dir: URL
    let gpg: Gpg

    init() throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("amonhen-gpg-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let empty = dir.appendingPathComponent("empty-passphrase")
        try Data().write(to: empty)
        try "pinentry-mode loopback\npassphrase-file \(empty.path)\n"
            .write(to: dir.appendingPathComponent("gpg.conf"), atomically: true, encoding: .utf8)
        gpg = Gpg(program: nil, homedir: dir.path)
    }

    /// パスフレーズを本物と同じ道（gpg-agent が pinentry を起動する）で聞く鍵束。pinentry は
    /// `scripts/fake-pinentry` で、`answer` を答える（nil なら取り消す）。
    init(pinentry answer: String?) throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("amonhen-gpg-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let source = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("../../scripts/fake-pinentry").standardized
        let pinentry = dir.appendingPathComponent("pinentry")
        try FileManager.default.copyItem(at: source, to: pinentry)
        try "pinentry-program \(pinentry.path)\n"
            .write(to: dir.appendingPathComponent("gpg-agent.conf"), atomically: true, encoding: .utf8)
        gpg = Gpg(program: nil, homedir: dir.path)
        try self.answer(answer)
    }

    /// pinentry の答えを変え、gpg-agent が覚えたパスフレーズを忘れさせる。
    func answer(_ answer: String?) throws {
        let file = dir.appendingPathComponent("pinentry-answer")
        if let answer {
            try Data(answer.utf8).write(to: file)
        } else {
            try? FileManager.default.removeItem(at: file)
        }
        let reload = Process()
        reload.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        reload.arguments = ["gpgconf", "--homedir", dir.path, "--reload", "gpg-agent"]
        try reload.run()
        reload.waitUntilExit()
    }

    deinit {
        let kill = Process()
        kill.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        kill.arguments = ["gpgconf", "--homedir", dir.path, "--kill", "all"]
        try? kill.run()
        kill.waitUntilExit()
        try? FileManager.default.removeItem(at: dir)
    }
}

private func gpgAvailable() -> Bool {
    (try? Gpg(program: nil, homedir: nil).version()) != nil
}

@Test func splitsUserIds() {
    #expect(UserIdParts("Alice (work) <alice@example.com>") == UserIdParts(name: "Alice", comment: "work", email: "alice@example.com"))
    #expect(UserIdParts("<bob@example.com>").name == "bob@example.com")
    #expect(UserIdParts("Carol").email == nil)
}

@Test func findsPinentryMac() {
    #expect(Pinentry.macPath(isExecutable: { _ in false }) == nil)
    #expect(Pinentry.macPath(isExecutable: { $0.hasPrefix("/usr/local/bin/") }) == "/usr/local/bin/pinentry-mac")
    // Homebrew（Apple シリコン）を先に
    #expect(Pinentry.macPath(isExecutable: { _ in true }) == "/opt/homebrew/bin/pinentry-mac")
}

@Test func composesUserIdsForNewKeys() {
    #expect(UserIdParts(name: "Alice ", comment: nil, email: " alice@example.com").text == "Alice <alice@example.com>")
    #expect(UserIdParts(name: "", comment: "", email: "alice@example.com").text == "<alice@example.com>")
    #expect(UserIdParts(name: "Alice", comment: "work", email: "").text == "Alice (work)")
    #expect(UserIdParts(name: "Alice", comment: nil, email: "alice@example.com").isValidForNewKey)
    #expect(UserIdParts(name: "", comment: nil, email: "alice@example.com").isValidForNewKey)
    #expect(!UserIdParts(name: "", comment: nil, email: "").isValidForNewKey)
    #expect(!UserIdParts(name: "Alice", comment: nil, email: "alice").isValidForNewKey)
    #expect(!UserIdParts(name: "Alice <x>", comment: nil, email: nil).isValidForNewKey)
}

@Test(.enabled(if: gpgAvailable()))
func groupsOwnKeysAndOthers() throws {
    let home = try TemporaryKeyring()
    let other = try TemporaryKeyring()
    let request = { (uid: String) in
        GenerateKey(
            userId: uid, algorithm: "ed25519",
            capabilities: Capabilities(certify: true, sign: true, encrypt: false, authenticate: false), expires: .never)
    }
    let mine = try home.gpg.generateKey(request: request("Alice <alice@example.com>"))
    let auth = try home.gpg.addSubkey(
        fingerprint: mine, algorithm: "ed25519",
        capabilities: Capabilities(certify: false, sign: false, encrypt: false, authenticate: true), expires: .never)
    let old = try home.gpg.generateKey(request: request("Alice 2019 <alice@old.example>"))
    try home.gpg.revokeKey(fingerprint: old, reason: .superseded, description: "")
    let bob = try other.gpg.generateKey(request: request("Bob <bob@example.com>"))
    _ = try home.gpg.import(data: try other.gpg.exportPublicKeys(fingerprints: [bob], armor: false))

    let grip = try #require(try home.gpg.listKeys().first { $0.fingerprint == mine }?.subkeys.first { $0.fingerprint == auth }?.keygrip)
    try home.gpg.setSshKeyEnabled(keygrip: grip, enabled: true)

    let ring = Keyring(keys: try home.gpg.listKeys(), sshKeys: try home.gpg.sshKeys(), now: UInt64(Date().timeIntervalSince1970))
    #expect(ring.usable.map(\.key.fingerprint) == [mine])
    #expect(ring.usable.first?.ssh == true)
    #expect(ring.usable.first?.status.sign == .thisDevice)
    #expect(ring.history.map(\.key.fingerprint) == [old])
    #expect(ring.others.map(\.fingerprint) == [bob])
    #expect(ring.usable.first?.key.primaryUserId.map { UserIdParts($0.text).email } == "alice@example.com")
}

@Test(.enabled(if: gpgAvailable()))
func extendsPrimaryAndSubkeys() throws {
    let home = try TemporaryKeyring()
    let fpr = try home.gpg.generateKey(
        request: GenerateKey(
            userId: "Alice <alice@example.com>", algorithm: "ed25519",
            capabilities: Capabilities(certify: true, sign: true, encrypt: false, authenticate: false), expires: .days(10)))
    let sub = try home.gpg.addSubkey(
        fingerprint: fpr, algorithm: "cv25519",
        capabilities: Capabilities(certify: false, sign: false, encrypt: true, authenticate: false), expires: .days(10))
    let now = UInt64(Date().timeIntervalSince1970)
    let own = try #require(Keyring(keys: try home.gpg.listKeys(), sshKeys: [], now: now).usable.first)
    #expect(own.canExtendExpiry)

    try home.gpg.extendExpiry(of: own.key, to: .days(730))
    let key = try #require(try home.gpg.listKeys().first { $0.fingerprint == fpr })
    let soon = now + 700 * 86_400
    #expect((key.expires ?? 0) > soon)
    #expect((key.subkeys.first { $0.fingerprint == sub }?.expires ?? 0) > soon)
}

@Test(.enabled(if: gpgAvailable()))
func cannotExtendWithoutPrimarySecret() throws {
    // 秘密鍵は別の PC にある自分の鍵（公開鍵を取り込み、所有者信頼を絶対にする）
    let home = try TemporaryKeyring()
    let other = try TemporaryKeyring()
    let mine = try other.gpg.generateKey(
        request: GenerateKey(userId: "Alice Home <alice@home.example>", algorithm: nil, capabilities: nil, expires: .never))
    _ = try home.gpg.import(data: try other.gpg.exportPublicKeys(fingerprints: [mine], armor: false))
    try home.gpg.setOwnerTrust(fingerprint: mine, trust: .ultimate)
    let ring = Keyring(keys: try home.gpg.listKeys(), sshKeys: [], now: UInt64(Date().timeIntervalSince1970))
    #expect(ring.notOnThisDevice.first?.canExtendExpiry == false)
}

@Test(.enabled(if: gpgAvailable()))
func revivesExpiredKey() throws {
    let home = try TemporaryKeyring()
    let fpr = try home.gpg.generateKey(
        request: GenerateKey(userId: "Alice 2019 <alice@old.example>", algorithm: nil, capabilities: nil, expires: .days(1)))
    // 2 日後から見れば期限切れ
    let later = UInt64(Date().timeIntervalSince1970) + 2 * 86_400
    let old = try #require(Keyring(keys: try home.gpg.listKeys(), sshKeys: [], now: later).history.first)
    #expect(old.canExtendExpiry)
    try home.gpg.extendExpiry(of: old.key, to: .days(365))
    let ring = Keyring(keys: try home.gpg.listKeys(), sshKeys: [], now: later)
    #expect(ring.usable.map(\.key.fingerprint) == [fpr])
}

@Test(.enabled(if: gpgAvailable()))
func backsUpSecretKeyToPrivateFile() throws {
    let home = try TemporaryKeyring()
    let fpr = try home.gpg.generateKey(
        request: GenerateKey(userId: "Alice / Work <alice@example.com>", algorithm: nil, capabilities: nil, expires: .never))
    let own = try #require(Keyring(keys: try home.gpg.listKeys(), sshKeys: [], now: UInt64(Date().timeIntervalSince1970)).usable.first)
    #expect(own.canBackUp)
    #expect(own.backupFileName == "Alice - Work \(fpr.suffix(16)) secret.asc")

    let file = home.dir.appendingPathComponent(own.backupFileName)
    try home.gpg.backUpSecretKey(fpr, to: file)
    let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
    #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)
    #expect(try String(contentsOf: file, encoding: .utf8).hasPrefix("-----BEGIN PGP PRIVATE KEY BLOCK-----"))

    // 別の鍵束に取り込めば、秘密鍵ごと戻る
    let other = try TemporaryKeyring()
    let result = try other.gpg.import(data: try Data(contentsOf: file))
    #expect(result.secretImported == 1)
}

@Test(.enabled(if: gpgAvailable()))
func recreatesMissingRevocationCertificate() throws {
    let home = try TemporaryKeyring()
    let fpr = try home.gpg.generateKey(
        request: GenerateKey(userId: "Alice <alice@example.com>", algorithm: nil, capabilities: nil, expires: .never))
    let gpg = home.gpg
    func own() throws -> OwnKey {
        let ring = Keyring(
            keys: try gpg.listKeys(), sshKeys: [], now: UInt64(Date().timeIntervalSince1970),
            hasRevocationCertificate: { (try? gpg.hasRevocationCertificate(fingerprint: $0)) ?? true })
        return try #require(ring.usable.first)
    }
    // gpg は鍵を作るときに失効証明書を残す
    #expect(try !own().needsRevocationCertificate)

    let path = home.dir.appendingPathComponent("openpgp-revocs.d/\(fpr).rev")
    try FileManager.default.removeItem(at: path)
    #expect(try own().needsRevocationCertificate)
    #expect(try gpg.saveRevocationCertificate(fingerprint: fpr) == path.path)
    #expect(try !own().needsRevocationCertificate)
    // 作っただけでは失効しない
    #expect(try own().key.validity != .revoked)

    // 秘密鍵が別の PC にある自分の鍵には作れないので、促さない
    let other = try TemporaryKeyring()
    _ = try other.gpg.import(data: try gpg.exportPublicKeys(fingerprints: [fpr], armor: true))
    try other.gpg.setOwnerTrust(fingerprint: fpr, trust: .ultimate)
    let ring = Keyring(
        keys: try other.gpg.listKeys(), sshKeys: [], now: UInt64(Date().timeIntervalSince1970),
        hasRevocationCertificate: { _ in false })
    let elsewhere = try #require(ring.notOnThisDevice.first)
    #expect(!elsewhere.needsRevocationCertificate)
}

@Test(.enabled(if: gpgAvailable()))
func remembersBackups() throws {
    let home = try TemporaryKeyring()
    let fpr = try home.gpg.generateKey(
        request: GenerateKey(userId: "Alice <alice@example.com>", algorithm: nil, capabilities: nil, expires: .never))
    let suite = "amonhen-gpg-tests-\(UUID().uuidString)"
    let defaults = try #require(UserDefaults(suiteName: suite))
    defer { defaults.removePersistentDomain(forName: suite) }
    let log = BackupLog(defaults: defaults)
    func own() throws -> OwnKey {
        try #require(Keyring(keys: try home.gpg.listKeys(), sshKeys: [], now: UInt64(Date().timeIntervalSince1970), backups: log.dates).usable.first)
    }
    #expect(try own().needsBackup)

    let date = Date(timeIntervalSince1970: 1_700_000_000)
    log.record(fpr, at: date)
    #expect(try own().backedUp == date)
    #expect(try !own().needsBackup)
    // 記録は残り、フィンガープリントで引ける
    #expect(BackupLog(defaults: defaults).dates.keys.sorted() == [fpr])
}

@Test(.enabled(if: gpgAvailable()))
func importsFilesAndSummarizes() throws {
    let other = try TemporaryKeyring()
    let bob = try other.gpg.generateKey(
        request: GenerateKey(userId: "Bob <bob@example.org>", algorithm: nil, capabilities: nil, expires: .never))
    let mine = try other.gpg.generateKey(
        request: GenerateKey(userId: "Alice <alice@example.com>", algorithm: nil, capabilities: nil, expires: .never))
    let publicFile = other.dir.appendingPathComponent("bob.asc")
    try other.gpg.exportPublicKeys(fingerprints: [bob], armor: true).write(to: publicFile)
    let secretFile = other.dir.appendingPathComponent("alice-secret.asc")
    try other.gpg.backUpSecretKey(mine, to: secretFile)
    let broken = other.dir.appendingPathComponent("broken.asc")
    try Data("not a key".utf8).write(to: broken)

    let home = try TemporaryKeyring()
    let first = home.gpg.importFiles([publicFile, secretFile, broken])
    #expect(first.newKeys == 2)
    #expect(first.secretKeys == 1)
    #expect(first.failures.map(\.file) == ["broken.asc"])

    // 同じものをもう一度取り込んでも、何も変わらない
    let second = home.gpg.importFiles([publicFile])
    #expect(second.newKeys == 0)
    #expect(second.unchangedKeys == 1)

    // 失効証明書（gpg が作ったものは誤用を防ぐため先頭が `:` になっている）
    let certificate = try String(
        contentsOf: other.dir.appendingPathComponent("openpgp-revocs.d/\(bob).rev"), encoding: .utf8)
    let revocation = other.dir.appendingPathComponent("bob.rev")
    try certificate.replacingOccurrences(of: ":-----BEGIN", with: "-----BEGIN").write(to: revocation, atomically: true, encoding: .utf8)
    let third = home.gpg.importFiles([revocation])
    #expect(third.revocations == 1)
}

@Test(.enabled(if: gpgAvailable()))
func passphrasesThroughPinentry() throws {
    let passphrase = "correct horse battery staple"
    let home = try TemporaryKeyring(pinentry: passphrase)
    let fpr = try home.gpg.generateKey(
        request: GenerateKey(userId: "Alice <alice@example.com>", algorithm: nil, capabilities: nil, expires: .days(10)))
    let key = try #require(try home.gpg.listKeys().first)

    try home.answer(nil)
    #expect {
        try home.gpg.extendExpiry(of: key, to: .days(365))
    } throws: { if case GpgError.Canceled = $0 { true } else { false } }
    try home.answer("wrong")
    #expect {
        try home.gpg.extendExpiry(of: key, to: .days(365))
    } throws: { if case GpgError.BadPassphrase = $0 { true } else { false } }

    // 取り消したバックアップは、ファイルを残さない
    try home.answer(nil)
    let file = home.dir.appendingPathComponent("backup.asc")
    #expect {
        try home.gpg.backUpSecretKey(fpr, to: file)
    } throws: { if case GpgError.Canceled = $0 { true } else { false } }
    #expect(!FileManager.default.fileExists(atPath: file.path))

    try home.answer(passphrase)
    try home.gpg.extendExpiry(of: key, to: .days(365))
    try home.gpg.backUpSecretKey(fpr, to: file)
    #expect(FileManager.default.fileExists(atPath: file.path))
}
