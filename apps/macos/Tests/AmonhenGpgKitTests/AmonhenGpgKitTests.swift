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
    #expect(ring.notOnThisDevice.first?.canChangePassphrase == false)
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
    // 延ばしたあとの鍵は、段が変わってもフィンガープリントで見つかる（成功を知らせるのに使う）
    #expect(ring.own(fpr.lowercased())?.status.tier == .usable)
    #expect(ring.own("0123456789ABCDEF0123456789ABCDEF01234567") == nil)
}

@Test(.enabled(if: gpgAvailable()))
func revokesOwnKey() throws {
    let home = try TemporaryKeyring()
    let fpr = try home.gpg.generateKey(
        request: GenerateKey(userId: "Alice <alice@example.com>", algorithm: nil, capabilities: nil, expires: .never))
    let now = UInt64(Date().timeIntervalSince1970)
    let own = try #require(Keyring(keys: try home.gpg.listKeys(), sshKeys: [], now: now).usable.first)
    #expect(own.canRevoke)

    try home.gpg.revokeKey(fingerprint: fpr, reason: .superseded, description: "Replaced by a new key")
    let ring = Keyring(keys: try home.gpg.listKeys(), sshKeys: [], now: now)
    let revoked = try #require(ring.own(fpr))
    #expect(revoked.status.tier == .history)
    #expect(revoked.key.validity == .revoked)
    // もう一度は失効させられない。秘密鍵は残る（昔のものの復号に使う）
    #expect(!revoked.canRevoke)
    #expect(revoked.canBackUp)

    // 書き出した公開鍵を受け取った人の鍵束でも、失効している
    #expect(revoked.publicKeyFileName == "Alice \(fpr.suffix(16)) public.asc")
    let file = home.dir.appendingPathComponent(revoked.publicKeyFileName)
    try home.gpg.exportPublicKey(fpr, to: file)
    let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
    #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o644)
    let other = try TemporaryKeyring()
    _ = try other.gpg.import(data: try Data(contentsOf: file))
    #expect(try other.gpg.listKeys().first?.validity == .revoked)
    #expect(Keyserver.name(Keyserver.default) == "keys.openpgp.org")
}

@Test(.enabled(if: gpgAvailable()))
func editsUserIds() throws {
    let home = try TemporaryKeyring()
    let fpr = try home.gpg.generateKey(
        request: GenerateKey(userId: "Alice <alice@example.com>", algorithm: nil, capabilities: nil, expires: .never))
    let now = UInt64(Date().timeIntervalSince1970)
    func own() throws -> OwnKey { try #require(Keyring(keys: try home.gpg.listKeys(), sshKeys: [], now: now).own(fpr)) }
    #expect(try own().canEditUserIds)
    let first = try #require(try own().key.primaryUserId)
    // 1 つしかない UID は失効させられず、もう主
    #expect(!(try own().key.canRevoke(first)))
    #expect(!(try own().key.canMakePrimary(first)))

    // gpg のままだと足した UID が主になるが、主は変えない
    try home.gpg.addUserId("Alice <alice@work.example>", to: try own().key, makePrimary: false)
    var key = try own().key
    #expect(key.namedUserIds.map(\.text) == ["Alice <alice@example.com>", "Alice <alice@work.example>"])
    #expect(key.hasActiveUserId("Alice <alice@work.example>"))
    let work = try #require(key.namedUserIds.last)
    #expect(key.canMakePrimary(work))
    #expect(key.canRevoke(first))

    // 主にすると、gpg は先に並べる（一覧の名前になる）
    try home.gpg.setPrimaryUserId(fingerprint: fpr, userId: work.text)
    key = try own().key
    #expect(key.primaryUserId?.text == "Alice <alice@work.example>")
    // 足すときに主にもできる
    try home.gpg.addUserId("Alice <alice@new.example>", to: key, makePrimary: true)
    #expect(try own().key.primaryUserId?.text == "Alice <alice@new.example>")
    // 主の印があるときに足しても、主は変わらない（すでに主のものを主にし直して gpg に断られない）
    try home.gpg.addUserId("Alice <alice@club.example>", to: try own().key, makePrimary: false)
    #expect(try own().key.primaryUserId?.text == "Alice <alice@new.example>")

    // 古いほうを失効させる。失効した UID は残るが、主にも失効にもできない。最後の 1 つは失効させられない
    try home.gpg.revokeUserId(fingerprint: fpr, userId: "Alice <alice@example.com>")
    key = try own().key
    let revoked = try #require(key.namedUserIds.first { $0.text == "Alice <alice@example.com>" })
    #expect(revoked.validity == .revoked)
    #expect(!key.canMakePrimary(revoked))
    #expect(!key.canRevoke(revoked))
    #expect(!key.hasActiveUserId(revoked.text))
    try home.gpg.revokeUserId(fingerprint: fpr, userId: work.text)
    try home.gpg.revokeUserId(fingerprint: fpr, userId: "Alice <alice@club.example>")
    key = try own().key
    #expect(key.primaryUserId?.text == "Alice <alice@new.example>")
    #expect(!key.canRevoke(try #require(key.primaryUserId)))
}

@Test(.enabled(if: gpgAvailable()))
func exportsSshPublicKey() throws {
    let home = try TemporaryKeyring()
    let fpr = try home.gpg.generateKey(
        request: GenerateKey(userId: "Alice <alice@example.com>", algorithm: nil, capabilities: nil, expires: .never))
    let now = UInt64(Date().timeIntervalSince1970)
    func own() throws -> OwnKey { try #require(Keyring(keys: try home.gpg.listKeys(), sshKeys: [], now: now).own(fpr)) }
    // 認証サブ鍵がなければ渡せない
    #expect(try own().sshSubkey(now: now) == nil)

    let auth = try home.gpg.addSubkey(
        fingerprint: fpr, algorithm: "ed25519",
        capabilities: Capabilities(certify: false, sign: false, encrypt: false, authenticate: true), expires: .never)
    let subkey = try #require(try own().sshSubkey(now: now))
    #expect(subkey.fingerprint == auth)
    #expect(try own().sshPublicKeyFileName == "Alice \(fpr.suffix(16)) ssh.pub")

    let file = home.dir.appendingPathComponent(try own().sshPublicKeyFileName)
    try home.gpg.exportSshPublicKey(subkey, to: file)
    let line = try String(contentsOf: file, encoding: .utf8)
    #expect(line.hasPrefix("ssh-ed25519 "))
    #expect(line.hasSuffix(" openpgp:0x\(auth.suffix(8))\n"))
    let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
    #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o644)

    // 失効させた認証サブ鍵は渡さない
    try home.gpg.revokeSubkey(fingerprint: fpr, subkey: auth, reason: .retired, description: "")
    #expect(try own().sshSubkey(now: now) == nil)
}

@Test(.enabled(if: gpgAvailable()))
func backsUpSecretKeyToPrivateFile() throws {
    let home = try TemporaryKeyring()
    let fpr = try home.gpg.generateKey(
        request: GenerateKey(userId: "Alice / Work <alice@example.com>", algorithm: nil, capabilities: nil, expires: .never))
    let own = try #require(Keyring(keys: try home.gpg.listKeys(), sshKeys: [], now: UInt64(Date().timeIntervalSince1970)).usable.first)
    #expect(own.canBackUp)
    #expect(own.canChangePassphrase)
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

@Test func readsStagingQueries() {
    #expect(StagingQuery("alice@example.com") == .email("alice@example.com"))
    #expect(StagingQuery(" Alice@Example.org ") == .email("Alice@Example.org"))
    let fpr = "5DDA16B5FFEADD5E944BD9DFBB8F6AF01166B837"
    #expect(StagingQuery(fpr.lowercased()) == .fingerprint(fpr))
    #expect(StagingQuery("5DDA 16B5 FFEA DD5E 944B  D9DF BB8F 6AF0 1166 B837") == .fingerprint(fpr))
    #expect(StagingQuery("0x" + fpr) == .fingerprint(fpr))
    // 短い鍵 ID・名前・壊れたメールアドレスは受け付けない
    #expect(StagingQuery("1166B837") == nil)
    #expect(StagingQuery("BB8F6AF01166B837") == nil)
    #expect(StagingQuery("Alice Example") == nil)
    #expect(StagingQuery("alice@") == nil)
    #expect(StagingQuery("Alice <alice@example.com>") == nil)
    #expect(StagingQuery("") == nil)
}

@Test(.enabled(if: gpgAvailable()))
func stagingKeepsKeysApartUntilImported() throws {
    let bob = try TemporaryKeyring()
    let bobFpr = try bob.gpg.generateKey(
        request: GenerateKey(userId: "Bob <bob@example.org>", algorithm: nil, capabilities: nil, expires: .never))
    let carolFpr = try bob.gpg.generateKey(
        request: GenerateKey(userId: "Carol <carol@example.net>", algorithm: nil, capabilities: nil, expires: .never))

    let home = try TemporaryKeyring()
    let dir = home.dir.deletingLastPathComponent().appendingPathComponent("amonhen-staging-\(UUID().uuidString.prefix(8))")
    let staging = Staging(main: home.gpg, dir: dir)
    defer { try? staging.discardAll() }
    #expect(try staging.keys().isEmpty)

    // 秘密鍵を含むファイルでも、一時保管には公開鍵だけが入る
    try staging.add(try bob.gpg.exportSecretKey(fingerprint: bobFpr, armor: true))
    try staging.add(try bob.gpg.exportPublicKeys(fingerprints: [carolFpr], armor: true))
    let staged = try staging.keys()
    #expect(Set(staged.map(\.fingerprint)) == [bobFpr, carolFpr])
    #expect(staged.allSatisfy { $0.secret == .none })
    #expect(try home.gpg.listKeys().isEmpty)
    // 鍵サーバーを決めてある
    let conf = try String(contentsOf: dir.appendingPathComponent("dirmngr.conf"), encoding: .utf8)
    #expect(conf == "keyserver hkps://keys.openpgp.org\n")

    // 取り込むと本来の鍵束に移り、一時保管からは消える。捨てた鍵は本来の鍵束に入らない
    try staging.importKey(bobFpr)
    try staging.discard(carolFpr)
    #expect(try home.gpg.listKeys().map(\.fingerprint) == [bobFpr])
    #expect(try home.gpg.listKeys().first?.secret == SecretState.none)
    #expect(try staging.keys().isEmpty)

    try staging.discardAll()
    #expect(!FileManager.default.fileExists(atPath: dir.path))
    #expect(try home.gpg.listKeys().map(\.fingerprint) == [bobFpr])
}

@Test(.enabled(if: gpgAvailable()))
func certifiesOthersKeys() throws {
    let bob = try TemporaryKeyring()
    let bobFpr = try bob.gpg.generateKey(
        request: GenerateKey(userId: "Bob <bob@example.org>", algorithm: nil, capabilities: nil, expires: .never))
    try bob.gpg.addUserId(fingerprint: bobFpr, userId: "Bob (work) <bob@work.example>")

    let home = try TemporaryKeyring()
    _ = try home.gpg.generateKey(
        request: GenerateKey(userId: "Alice <alice@example.com>", algorithm: nil, capabilities: nil, expires: .never))
    _ = try home.gpg.import(data: try bob.gpg.exportPublicKeys(fingerprints: [bobFpr], armor: true))
    let now = UInt64(Date().timeIntervalSince1970)
    var ring = Keyring(keys: try home.gpg.listKeys(), sshKeys: [], now: now)
    let signer = try #require(ring.signers.first)
    let key = try #require(ring.others.first)
    #expect(key.canCertify)
    #expect(key.certifiableUserIds.count == 2)

    // 確かめた UID だけに、書き出さない署名をする
    try home.gpg.signKey(fingerprint: bobFpr, userIds: ["Bob <bob@example.org>"], signer: signer.key.fingerprint, local: true)
    ring = Keyring(keys: try home.gpg.listKeys(), sshKeys: [], now: now)
    let verified = try #require(ring.others.first)
    #expect(verified.validity == .full)
    #expect(!verified.canCertify)
    let validities = Dictionary(uniqueKeysWithValues: verified.userIds.map { ($0.text, $0.validity) })
    #expect(validities["Bob <bob@example.org>"] == .full)
    #expect(validities["Bob (work) <bob@work.example>"] != .full)
    // 書き出さない署名は、公開鍵を渡しても相手に届かない
    let exported = try home.gpg.exportPublicKeys(fingerprints: [bobFpr], armor: true)
    let other = try TemporaryKeyring()
    _ = try other.gpg.import(data: exported)
    #expect(try other.gpg.listKeys().first?.validity != .full)

    // 秘密鍵のない鍵束には、署名に使える鍵がない
    #expect(Keyring(keys: try other.gpg.listKeys(), sshKeys: [], now: now).signers.isEmpty)
}

@Test func namesAlgorithms() {
    #expect(algorithmName(algorithm: 22, length: 255, curve: "ed25519") == "ed25519")
    #expect(algorithmName(algorithm: 1, length: 4096, curve: nil) == "RSA 4096")
    #expect(algorithmName(algorithm: 17, length: 2048, curve: "") == "DSA 2048")
    #expect(algorithmName(algorithm: 27, length: 0, curve: nil) == "Ed25519")
    #expect(algorithmName(algorithm: 99, length: 0, curve: nil) == "#99")
}

@Test(.enabled(if: gpgAvailable()))
func listsSshKeysThatAreNotOpenPgpKeys() throws {
    let home = try TemporaryKeyring(pinentry: "correct horse battery staple")
    try home.gpg.enableSshSupport()
    _ = try home.gpg.generateKey(
        request: GenerateKey(userId: "Alice <alice@example.com>", algorithm: nil, capabilities: nil, expires: .never))
    let file = home.dir.appendingPathComponent("id_ed25519")
    let keygen = Process()
    keygen.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    keygen.arguments = ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "test", "-f", file.path]
    try keygen.run()
    keygen.waitUntilExit()
    try #require(keygen.terminationStatus == 0)
    try home.gpg.addSshKey(path: file.path)

    var ring = Keyring(keys: try home.gpg.listKeys(), sshKeys: try home.gpg.sshKeys(), now: UInt64(Date().timeIntervalSince1970))
    // OpenPGP の鍵は自分の鍵の段に、ssh-add で取り込んだ鍵だけが sshOnly に
    #expect(ring.usable.count == 1)
    let ssh = try #require(ring.sshOnly.first)
    #expect(ring.sshOnly.count == 1)
    #expect(sshKeyEnabled(key: ssh))
    #expect(ssh.fingerprint.hasPrefix("SHA256:"))

    try home.gpg.setSshKeyEnabled(keygrip: ssh.keygrip, enabled: false)
    ring = Keyring(keys: try home.gpg.listKeys(), sshKeys: try home.gpg.sshKeys(), now: UInt64(Date().timeIntervalSince1970))
    #expect(ring.sshOnly.map { sshKeyEnabled(key: $0) } == [false])
}

@Test(.enabled(if: gpgAvailable()))
func deletesSecretKeyOnlyAfterBackup() throws {
    let home = try TemporaryKeyring()
    let fpr = try home.gpg.generateKey(
        request: GenerateKey(userId: "Alice <alice@example.com>", algorithm: nil, capabilities: nil, expires: .never))
    let suite = "amonhen-gpg-tests-\(UUID().uuidString)"
    let defaults = try #require(UserDefaults(suiteName: suite))
    defer { defaults.removePersistentDomain(forName: suite) }
    let log = BackupLog(defaults: defaults)
    func own() throws -> OwnKey {
        try #require(Keyring(keys: try home.gpg.listKeys(), sshKeys: [], now: UInt64(Date().timeIntervalSince1970), backups: log.dates).own(fpr))
    }
    // 秘密鍵がこの PC にあり、バックアップの記録がなければ消させない
    #expect(try !own().canDelete)
    let file = home.dir.appendingPathComponent("backup.asc")
    try home.gpg.backUpSecretKey(fpr, to: file)
    log.record(fpr)
    #expect(try own().canDelete)

    try home.gpg.deleteSecretAndPublicKey(fingerprint: fpr)
    #expect(try home.gpg.listKeys().isEmpty)
    // バックアップから戻せる
    _ = try home.gpg.import(data: try Data(contentsOf: file))
    #expect(try own().key.secret == .available)

    // 秘密鍵が別の PC にあるだけの鍵は、この PC から消しても秘密鍵を失わない
    let other = try TemporaryKeyring()
    _ = try other.gpg.import(data: try home.gpg.exportPublicKeys(fingerprints: [fpr], armor: true))
    try other.gpg.setOwnerTrust(fingerprint: fpr, trust: .ultimate)
    let elsewhere = try #require(Keyring(keys: try other.gpg.listKeys(), sshKeys: [], now: 0).own(fpr))
    #expect(elsewhere.canDelete)
}

@Test func classifiesStagingOutcomes() {
    func result(considered: UInt32, noUserId: UInt32 = 0, unchanged: UInt32 = 0, keys: [ImportedKey] = []) -> ImportResult {
        ImportResult(
            considered: considered, noUserId: noUserId, imported: UInt32(keys.count), unchanged: unchanged, newUserIds: 0,
            newSubkeys: 0, newSignatures: 0, newRevocations: 0, secretRead: 0, secretImported: 0, secretUnchanged: 0,
            notImported: 0, keys: keys)
    }
    let key = ImportedKey(
        fingerprint: "ABAF11C65A2970B130ABE3C479BE3E4300411886", newKey: true, newUserIds: false, newSignatures: false,
        newSubkeys: false, secret: false)
    #expect(StagingOutcome(result(considered: 1, keys: [key])) == .found)
    #expect(StagingOutcome(result(considered: 1, unchanged: 1)) == .found)
    // keys.openpgp.org で、持ち主が UID を確かめていない鍵
    #expect(StagingOutcome(result(considered: 1, noUserId: 1)) == .withoutUserIds)
    #expect(StagingOutcome(result(considered: 0)) == .nothing)
}

@Test(.enabled(if: gpgAvailable()))
func discardsStagingLeftByCrashedApps() throws {
    let home = try TemporaryKeyring()
    // 本物の一時ディレクトリは見ない（動いているアプリの一時保管を、テストの「動いていない」で消さないように）。
    // gpg-agent のソケットのパスの長さの上限に収まるよう、短い場所にする
    let parent = URL(fileURLWithPath: "/tmp/amonhen-t-\(UUID().uuidString.prefix(4))")
    try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: parent) }
    let bob = try TemporaryKeyring()
    let bobFpr = try bob.gpg.generateKey(
        request: GenerateKey(userId: "Bob <bob@example.org>", algorithm: nil, capabilities: nil, expires: .never))
    let key = try bob.gpg.exportPublicKeys(fingerprints: [bobFpr], armor: true)

    // 落ちたアプリ（pid 111）と、動いているアプリ（pid 222）の一時保管。鍵を入れて gpg-agent も動かしておく
    let crashed = Staging(main: home.gpg, dir: Staging.directory(in: parent, pid: 111))
    try crashed.add(key)
    let running = Staging(main: home.gpg, dir: Staging.directory(in: parent, pid: 222))
    try running.add(key)
    defer { try? running.discardAll() }
    // 秘密鍵から公開鍵だけを取り出す途中で落ちた、使い捨ての鍵束
    let scratch = parent.appendingPathComponent(".\(Staging.directory(in: parent, pid: 111).lastPathComponent)-in")
    _ = try home.gpg.staging(dir: scratch.path)
    // 名前は似ているが、一時保管の印がないディレクトリ（利用者のものかもしれない）
    let unmarked = Staging.directory(in: parent, pid: 111)
    try FileManager.default.createDirectory(at: unmarked, withIntermediateDirectories: true)
    try Data("keep".utf8).write(to: unmarked.appendingPathComponent("file"))
    // 名前の形が違うもの
    let other = parent.appendingPathComponent("amonhen-staging-ABCDEF12")
    _ = try home.gpg.staging(dir: other.path)

    let discarded = Staging.discardStale(in: parent, gpg: home.gpg, isRunning: { $0 == 222 })
    #expect(Set(discarded.map(\.lastPathComponent)) == [crashed.dir.lastPathComponent, scratch.lastPathComponent])
    #expect(!FileManager.default.fileExists(atPath: crashed.dir.path))
    #expect(!FileManager.default.fileExists(atPath: scratch.path))
    #expect(try running.keys().map(\.fingerprint) == [bobFpr])
    #expect(FileManager.default.fileExists(atPath: unmarked.appendingPathComponent("file").path))
    #expect(FileManager.default.fileExists(atPath: other.path))
    _ = try? home.gpg.staging(dir: other.path).discardStaging()
}
