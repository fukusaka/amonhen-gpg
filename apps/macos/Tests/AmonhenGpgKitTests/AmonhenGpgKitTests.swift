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
