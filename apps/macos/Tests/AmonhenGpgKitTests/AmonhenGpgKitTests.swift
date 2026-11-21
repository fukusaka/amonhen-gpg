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

/// 試験用の UserDefaults。テストごとに決まった名前を使い、始まりと終わりに空にする。cfprefsd は消した domain も
/// 空のファイルとして書き戻すので、毎回新しい名前にすると空のファイルが増え続ける（決まった名前なら増えない）。
/// 並行して動くテストどうしで混ざらないよう、名前はテストごとに変える。
private final class TemporaryDefaults {
    let name: String
    let defaults: UserDefaults

    init(_ test: String) throws {
        name = "amonhen-gpg-tests-\(test)"
        defaults = try #require(UserDefaults(suiteName: name))
        defaults.removePersistentDomain(forName: name)
    }

    deinit {
        defaults.removePersistentDomain(forName: name)
    }
}

private func gpgAvailable() -> Bool {
    (try? Gpg(program: nil, homedir: nil).version()) != nil
}

private func sampleKey(_ fingerprint: String, subkey: String, userIds: [String], revoked: Set<String> = []) -> Key {
    let none = Capabilities(certify: false, sign: false, encrypt: false, authenticate: false)
    return Key(
        fingerprint: fingerprint, keyId: String(fingerprint.suffix(16)), keygrip: nil, validity: .full, ownerTrust: .unknown,
        algorithm: 22, length: 255, curve: "ed25519", created: nil, expires: nil, capabilities: none, usable: none,
        disabled: false, secret: .none,
        subkeys: [
            Subkey(
                fingerprint: subkey, keyId: String(subkey.suffix(16)), keygrip: nil, validity: .full, algorithm: 18,
                length: 255, curve: "cv25519", created: nil, expires: nil, capabilities: none, secret: .none)
        ],
        userIds: userIds.map {
            UserId(text: $0, validity: revoked.contains($0) ? .revoked : .full, created: nil, expires: nil, hash: nil, attribute: false)
        },
        origin: .unknown, originUrl: nil, lastUpdate: nil)
}

@Test func searchesNamesEmailsAndFingerprints() {
    let bob = sampleKey(
        "632DF0CFE483AB636C529CE921F0F4C7E693133C", subkey: "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555",
        userIds: ["Bob Builder <bob@example.org>", "Robert B. <robert@work.example>"], revoked: ["Robert B. <robert@work.example>"])
    #expect(bob.matches(""))
    #expect(bob.matches("  "))
    // 名前・メールアドレスは大文字小文字を区別しない部分一致。主でない UID と失効した UID も探す
    #expect(bob.matches("builder"))
    #expect(bob.matches("BOB@EXAMPLE"))
    #expect(bob.matches("work.example"))
    #expect(!bob.matches("carol"))
    // 語はすべて合わなければならない
    #expect(bob.matches("bob example.org"))
    #expect(!bob.matches("bob carol"))
    // 4 文字以上の 16 進の語はフィンガープリント（サブ鍵も）
    #expect(bob.matches("E693133C"))
    #expect(bob.matches("e693"))
    #expect(bob.matches("EEEE5555"))
    #expect(!bob.matches("133"))
    // 区切りの空白ごと貼り付けたフィンガープリント
    #expect(bob.matches("632D F0CF E483 AB63 6C52"))
    #expect(!bob.matches("632D F0CF 0000 0000"))
}

@Test func filtersTheKeyring() {
    var ring = Keyring()
    ring.others = [
        sampleKey("1111111111111111111111111111111111111111", subkey: "2222222222222222222222222222222222222222", userIds: ["Bob <bob@example.org>"]),
        sampleKey("3333333333333333333333333333333333333333", subkey: "4444444444444444444444444444444444444444", userIds: ["Carol <carol@example.net>"]),
    ]
    #expect(ring.filtered(by: "").others.count == 2)
    #expect(ring.filtered(by: "carol").others.map(\.fingerprint) == ["3333333333333333333333333333333333333333"])
    #expect(ring.filtered(by: "dave").others.isEmpty)
}

@Test func makesTableRowsThatSort() {
    var bob = sampleKey(
        "1111111111111111111111111111111111111111", subkey: "2222222222222222222222222222222222222222",
        userIds: ["Bob Builder <bob@example.org>", "Bob <bob@work.example>"])
    bob.created = 200
    var carol = sampleKey("3333333333333333333333333333333333333333", subkey: "4444444444444444444444444444444444444444", userIds: ["Carol <carol@example.net>"])
    carol.validity = .unknown
    carol.created = 100
    carol.expires = 1_000
    var dave = sampleKey("5555555555555555555555555555555555555555", subkey: "6666666666666666666666666666666666666666", userIds: ["Dave <dave@example.com>"])
    dave.validity = .revoked
    let rows = [bob, carol, dave].map(KeyTableRow.init)

    #expect(rows[0].name == "Bob Builder")
    #expect(rows[0].email == "bob@example.org")
    #expect(rows[0].otherUserIds.map(\.text) == ["Bob <bob@work.example>"])
    #expect(rows[0].keyId == "1111111111111111")
    #expect(rows[0].algorithm == "ed25519")
    #expect(!rows[0].isInactive && rows[2].isInactive)
    // 確認済み・未確認・失効の順
    #expect(rows.sorted { $0.verificationOrder < $1.verificationOrder }.map(\.name) == ["Bob Builder", "Carol", "Dave"])
    // 期限のない鍵は最後
    #expect(rows.sorted { $0.expires < $1.expires }.first?.name == "Carol")
    #expect(rows.sorted { $0.created < $1.created }.map(\.name) == ["Dave", "Carol", "Bob Builder"])
}

@Test func filtersKeysByVerification() {
    func key(_ validity: Validity) -> Key {
        var key = sampleKey(
            "1111111111111111111111111111111111111111", subkey: "2222222222222222222222222222222222222222", userIds: ["A <a@example.org>"])
        key.validity = validity
        return key
    }
    let all: [Validity] = [.ultimate, .full, .marginal, .unknown, .never, .new, .expired, .revoked, .invalid, .disabled]
    func pick(_ filter: KeyFilter) -> [Validity] { all.filter { filter.includes(key($0)) } }
    #expect(pick(.all) == all)
    #expect(pick(.verified) == [.ultimate, .full])
    // 一部確認はまだ確認できるので未確認に
    #expect(pick(.unverified) == [.marginal, .unknown, .never, .new])
    #expect(pick(.inactive) == [.expired, .revoked, .invalid, .disabled])
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

@Test func findsGpgOutsideTheFinderPath() {
    // Finder から開いたアプリの PATH には Homebrew がない
    let finder = "/usr/bin:/bin:/usr/sbin:/sbin"
    #expect(GpgProgram.locate(path: finder, isExecutable: { $0 == "/opt/homebrew/bin/gpg" }) == "/opt/homebrew/bin/gpg")
    #expect(GpgProgram.locate(path: finder, isExecutable: { $0 == "/usr/local/MacGPG2/bin/gpg" }) == "/usr/local/MacGPG2/bin/gpg")
    // PATH にあればそれを先に
    #expect(GpgProgram.locate(path: "/opt/gnupg/bin:" + finder, isExecutable: { $0.hasSuffix("/gpg") }) == "/opt/gnupg/bin/gpg")
    #expect(GpgProgram.locate(path: nil, isExecutable: { _ in false }) == nil)
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
    let read = { Keyring(keys: try home.gpg.listKeys(), sshKeys: try home.gpg.sshKeys(), now: UInt64(Date().timeIntervalSince1970)) }
    // SSH に出す前から、出せる認証サブ鍵が分かる
    let before = try #require(try read().usable.first)
    #expect(!before.ssh)
    #expect(before.sshCandidate == grip)
    try home.gpg.setSshEnabled(before, enabled: true)

    let ring = try read()
    #expect(ring.usable.map(\.key.fingerprint) == [mine])
    #expect(ring.usable.first?.ssh == true)
    #expect(ring.usable.first?.sshKeygrips == [grip.uppercased()])
    #expect(ring.usable.first?.status.sign == .thisDevice)
    #expect(ring.history.map(\.key.fingerprint) == [old])
    #expect(ring.others.map(\.fingerprint) == [bob])
    #expect(ring.usable.first?.key.primaryUserId.map { UserIdParts($0.text).email } == "alice@example.com")
    // 止める
    try home.gpg.setSshEnabled(try #require(ring.usable.first), enabled: false)
    #expect(try read().usable.first?.ssh == false)
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
func groupsRealSignaturesFromAnotherKeyring() throws {
    let home = try TemporaryKeyring()
    let me = try home.gpg.generateKey(
        request: GenerateKey(userId: "Alice <alice@example.com>", algorithm: nil, capabilities: nil, expires: .never))
    // Bob と Carol は別の鍵束で作り、Carol が Bob に署名したものを受け取る
    let other = try TemporaryKeyring()
    let bob = try other.gpg.generateKey(
        request: GenerateKey(userId: "Bob <bob@example.com>", algorithm: nil, capabilities: nil, expires: .never))
    let carol = try other.gpg.generateKey(
        request: GenerateKey(userId: "Carol <carol@example.com>", algorithm: nil, capabilities: nil, expires: .never))
    try other.gpg.signKey(fingerprint: bob, userIds: [], signer: carol, local: false)
    _ = try home.gpg.import(data: try other.gpg.exportPublicKeys(fingerprints: [bob], armor: false))
    try home.gpg.signKey(fingerprint: bob, userIds: [], signer: me, local: true)

    let keys = try home.gpg.listKeys()
    let ring = Keyring(keys: keys, sshKeys: [], now: UInt64(Date().timeIntervalSince1970))
    let key = try #require(keys.first { $0.fingerprint == bob })
    let groups = ring.signatures(try home.gpg.certifications(fingerprint: bob), on: key)
    #expect(groups.trusted.map(\.certification.signerFingerprint) == [me])
    #expect(groups.trusted.first?.byYou == true)
    #expect(groups.trusted.first?.certification.exportable == false)
    // Carol の鍵は手元にないので、そのほかの、確かめられない署名になる
    #expect(groups.others.map(\.certification.signerFingerprint) == [carol])
    #expect(groups.others.first?.certification.check == .missingKey)
    #expect(groups.others.first?.signerName == nil)
}

@Test func ordersOwnKeysByExpiry() {
    func key(_ fingerprint: String, created: UInt64, expires: UInt64?) -> Key {
        var key = sampleKey(fingerprint, subkey: "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555", userIds: [])
        key.created = created
        key.expires = expires
        return key
    }
    let never = key("1111111111111111111111111111111111111111", created: 100, expires: nil)
    let later = key("2222222222222222222222222222222222222222", created: 100, expires: 900)
    let soon = key("3333333333333333333333333333333333333333", created: 100, expires: 500)
    let neverNewer = key("4444444444444444444444444444444444444444", created: 200, expires: nil)
    // 期限が近いものから、期限のない鍵は最後（そのうちでは新しいものから）
    let sorted = [never, later, soon, neverNewer].sorted(by: Key.expiresSooner).map(\.fingerprint)
    #expect(sorted == [soon, later, neverNewer, never].map(\.fingerprint))
}

@Test func findsSshFingerprintsByKeygrip() {
    let ssh = SshKey(
        keygrip: "abcdef0123456789abcdef0123456789abcdef01", fingerprint: "SHA256:xyz", card: nil, protected: true,
        sshcontrol: .notListed, useForSsh: false, confirm: false, comment: nil)
    let ring = Keyring(keys: [], sshKeys: [ssh], now: 0)
    // keygrip の大文字小文字は問わない
    #expect(ring.sshFingerprint(keygrip: "ABCDEF0123456789ABCDEF0123456789ABCDEF01") == "SHA256:xyz")
    #expect(ring.sshFingerprint(keygrip: "0000000000000000000000000000000000000000") == nil)
    #expect(ring.sshFingerprint(keygrip: nil) == nil)
}

@Test func groupsSignaturesByWhetherYouVerifiedTheSigner() {
    var me = sampleKey("1111111111111111111111111111111111111111", subkey: "1111000011110000111100001111000011110000", userIds: ["Me <me@example.com>"])
    me.secret = .available
    me.validity = .ultimate
    let dave = sampleKey("2222222222222222222222222222222222222222", subkey: "2222000022220000222200002222000022220000", userIds: ["Dave <dave@example.com>"])
    var erin = sampleKey("3333333333333333333333333333333333333333", subkey: "3333000033330000333300003333000033330000", userIds: ["Erin <erin@example.com>"])
    erin.validity = .unknown
    let bob = sampleKey("4444444444444444444444444444444444444444", subkey: "4444000044440000444400004444000044440000",
                        userIds: ["Bob <bob@example.org>", "Bob <bob@work.example>"])
    let ring = Keyring(keys: [me, dave, erin, bob], sshKeys: [], now: 0)
    func cert(_ uid: String, _ signer: String?, keyId: String, created: UInt64, revoked: Bool = false) -> Certification {
        Certification(userId: uid, signerFingerprint: signer, signerKeyId: keyId, signerUserId: nil, created: created, expires: nil,
                      exportable: true, check: signer == nil ? .missingKey : .good, revoked: revoked)
    }
    let all = [
        cert("Bob <bob@work.example>", dave.fingerprint, keyId: dave.keyId, created: 5),
        cert("Bob <bob@example.org>", erin.fingerprint, keyId: erin.keyId, created: 3),
        cert("Bob <bob@example.org>", nil, keyId: "AAAABBBBCCCCDDDD", created: 2),
        cert("Bob <bob@example.org>", nil, keyId: me.keyId, created: 4, revoked: true),
        cert("Bob <bob@example.org>", dave.fingerprint, keyId: dave.keyId, created: 1),
    ]
    let groups = ring.signatures(all, on: bob)
    // 自分の鍵（鍵 ID だけでも見つける。取り消しも残す）と、確認済みの Dave。UID の順、その中は新しい順
    #expect(groups.trusted.map(\.signerName) == ["Me", "Dave", "Dave"])
    #expect(groups.trusted.map(\.byYou) == [true, false, false])
    #expect(groups.trusted.map(\.certification.userId) == ["Bob <bob@example.org>", "Bob <bob@example.org>", "Bob <bob@work.example>"])
    // 確認していない Erin と、鍵束にない鍵
    #expect(groups.others.map(\.signerName) == ["Erin", nil])
}

@Test(.enabled(if: gpgAvailable()))
func addsSubkeyForSsh() throws {
    let home = try TemporaryKeyring()
    let now = UInt64(Date().timeIntervalSince1970)
    let fpr = try home.gpg.generateKey(
        request: GenerateKey(
            userId: "Alice <alice@example.com>", algorithm: nil,
            capabilities: Capabilities(certify: true, sign: true, encrypt: false, authenticate: false), expires: .days(100)))
    func own() throws -> OwnKey {
        try #require(Keyring(keys: try home.gpg.listKeys(), sshKeys: try home.gpg.sshKeys(), now: now).own(fpr))
    }
    #expect(try own().canAddSshSubkey(now: now))
    #expect(try own().sshCandidate == nil)

    let added = try home.gpg.addSshSubkey(try own(), now: now)
    let mine = try own()
    let subkey = try #require(mine.sshSubkey(now: now))
    #expect(subkey.fingerprint == added)
    // 期限は主鍵に揃い、SSH に出ている
    #expect(abs(Int64(subkey.expires ?? 0) - Int64(mine.key.expires ?? 0)) < 2 * 86_400)
    #expect(mine.ssh)
    #expect(!mine.canAddSshSubkey(now: now))
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
    let defaults = try TemporaryDefaults("backups")
    let log = BackupLog(defaults: defaults.defaults)
    func own() throws -> OwnKey {
        try #require(Keyring(keys: try home.gpg.listKeys(), sshKeys: [], now: UInt64(Date().timeIntervalSince1970), backups: log.dates).usable.first)
    }
    #expect(try own().needsBackup)

    let date = Date(timeIntervalSince1970: 1_700_000_000)
    log.record(fpr, at: date)
    #expect(try own().backedUp == date)
    #expect(try !own().needsBackup)
    // 記録は残り、フィンガープリントで引ける
    #expect(BackupLog(defaults: defaults.defaults).dates.keys.sorted() == [fpr])
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
    // GitHub・GitLab の利用者（名前の大文字小文字はそのまま）
    #expect(StagingQuery("github:Web-Flow") == .codeHost(.gitHub, "Web-Flow"))
    #expect(StagingQuery("GitLab: first.last") == .codeHost(.gitLab, "first.last"))
    #expect(StagingQuery("https://github.com/web-flow") == .codeHost(.gitHub, "web-flow"))
    #expect(StagingQuery("github.com/web-flow.gpg") == .codeHost(.gitHub, "web-flow"))
    #expect(StagingQuery("https://www.gitlab.com/someone/") == .codeHost(.gitLab, "someone"))
    #expect(StagingQuery("github:") == nil)
    #expect(StagingQuery("github:a/b") == nil)
    #expect(StagingQuery("https://github.com/org/repo") == nil)
    #expect(StagingQuery("https://example.com/key.gpg") == nil)
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

    // 説明と公開鍵は、鍵ファイルの .pub と同じ
    #expect(ssh.comment == "test")
    #expect(ssh.publicKeyFileName == "test.pub")
    let out = home.dir.appendingPathComponent(ssh.publicKeyFileName)
    try home.gpg.exportSshPublicKey(ssh, to: out)
    let original = try String(contentsOf: home.dir.appendingPathComponent("id_ed25519.pub"), encoding: .utf8)
    #expect(try String(contentsOf: out, encoding: .utf8) == original)

    // バックアップは、gpg-agent が守ったままの形で、本人だけが読めるファイルに
    #expect(ssh.canBackUp)
    #expect(ssh.backupFileName == "\(ssh.keygrip).key")
    let backup = home.dir.appendingPathComponent(ssh.backupFileName)
    try home.gpg.exportSshKeyBackup(ssh, to: backup)
    #expect(Gpg.isSshKeyBackup(try Data(contentsOf: backup)))
    #expect(!Gpg.isSshKeyBackup(try Data(contentsOf: file)))
    let permissions = try FileManager.default.attributesOfItem(atPath: backup.path)[.posixPermissions] as? Int
    #expect(permissions == 0o600)
    // 別の鍵束に戻す（gpg 2.5.14 から）
    let other = try TemporaryKeyring(pinentry: nil)
    try other.gpg.enableSshSupport()
    if try other.gpg.version() >= sshRestoreMinimumVersion() {
        #expect(try other.gpg.importSshKeyBackup(backup: Data(contentsOf: backup)) == ssh.keygrip)
        #expect(try other.gpg.sshPublicKey(keygrip: ssh.keygrip) == original.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    // gpg-agent から消す
    try home.gpg.deleteSshKey(keygrip: ssh.keygrip)
    #expect(try home.gpg.sshKeys().filter { $0.comment == "test" }.isEmpty)
}

@Test(.enabled(if: gpgAvailable()))
func deletesSecretKeyOnlyAfterBackup() throws {
    let home = try TemporaryKeyring()
    let fpr = try home.gpg.generateKey(
        request: GenerateKey(userId: "Alice <alice@example.com>", algorithm: nil, capabilities: nil, expires: .never))
    let defaults = try TemporaryDefaults("delete")
    let log = BackupLog(defaults: defaults.defaults)
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

@Test func warnsAboutOldGpg() {
    var keyring = Keyring()
    #expect(keyring.outdatedGpg == nil)
    keyring.gpgVersion = Version(major: 2, minor: 4, patch: 5)
    #expect(keyring.outdatedGpg?.description == "2.4.5")
    keyring.gpgVersion = Version(major: 2, minor: 4, patch: 6)
    #expect(keyring.outdatedGpg == nil)
    #expect(minimumGpgVersion().description == "2.4.6")
}

@Test func choosesTheGpgProgram() throws {
    let defaults = try #require(UserDefaults(suiteName: "amonhen-gpg-test-\(UUID().uuidString)"))
    let found = { () -> String? in "/opt/homebrew/bin/gpg" }
    // 選んでいなければ自動、選べばそれ、起動の引数がいちばん先
    #expect(GpgProgram.chosen(in: defaults) == nil)
    #expect(GpgProgram.resolve(option: nil, defaults: defaults, locate: found) == "/opt/homebrew/bin/gpg")
    GpgProgram.choose("/usr/local/bin/gpg", in: defaults)
    #expect(GpgProgram.resolve(option: nil, defaults: defaults, locate: found) == "/usr/local/bin/gpg")
    #expect(GpgProgram.resolve(option: "/tmp/gpg", defaults: defaults, locate: found) == "/tmp/gpg")
    GpgProgram.choose(nil, in: defaults)
    #expect(GpgProgram.chosen(in: defaults) == nil)
}

@Test(.enabled(if: gpgAvailable()))
func ownerTrustMakesSignedKeysVerified() throws {
    let home = try TemporaryKeyring()
    let me = try home.gpg.generateKey(
        request: GenerateKey(userId: "Alice <alice@example.com>", algorithm: nil, capabilities: nil, expires: .never))
    // Carol が Bob に署名した鍵を、別の鍵束から受け取る。Carol は自分で確認済みにする
    let other = try TemporaryKeyring()
    let bob = try other.gpg.generateKey(
        request: GenerateKey(userId: "Bob <bob@example.com>", algorithm: nil, capabilities: nil, expires: .never))
    let carol = try other.gpg.generateKey(
        request: GenerateKey(userId: "Carol <carol@example.com>", algorithm: nil, capabilities: nil, expires: .never))
    try other.gpg.signKey(fingerprint: bob, userIds: [], signer: carol, local: false)
    _ = try home.gpg.import(data: try other.gpg.exportPublicKeys(fingerprints: [bob, carol], armor: false))
    try home.gpg.signKey(fingerprint: carol, userIds: [], signer: me, local: true)
    let key = { (fpr: String) in try #require(try home.gpg.listKeys().first { $0.fingerprint == fpr }) }

    #expect(try key(carol).ownerTrustSetting == .unknown)
    #expect(try key(bob).validity != .full)
    // Carol を完全に信頼すると、Carol が署名した Bob の鍵も確認済みになる
    try home.gpg.setOwnerTrust(fingerprint: carol, trust: .full)
    #expect(try key(carol).ownerTrustSetting == .full)
    #expect(try key(bob).validity == .full)
    // ある程度なら 1 人の署名では足りない
    try home.gpg.setOwnerTrust(fingerprint: carol, trust: .marginal)
    #expect(try key(carol).ownerTrustSetting == .marginal)
    #expect(try key(bob).validity != .full)
    // 他者の鍵に選ばせる値に、絶対的はない
    #expect(!OwnerTrust.choicesForOthers.contains(.ultimate))
    #expect(Keyring(keys: try home.gpg.listKeys(), sshKeys: [], now: UInt64(Date().timeIntervalSince1970)).own(carol) == nil)
}

@Test func findsWhoMadeAKeyVerified() {
    var me = sampleKey("1111111111111111111111111111111111111111", subkey: "1111000011110000111100001111000011110000", userIds: ["Me <me@example.com>"])
    me.secret = .available
    me.validity = .ultimate
    me.ownerTrust = .ultimate
    // 完全に信頼する確認済みの Carol、ある程度信頼する確認済みの Dave、信頼を決めていない Erin、信頼するが確認していない Fay
    var carol = sampleKey("2222222222222222222222222222222222222222", subkey: "2222000022220000222200002222000022220000", userIds: ["Carol <carol@example.net>"])
    carol.ownerTrust = .full
    var dave = sampleKey("3333333333333333333333333333333333333333", subkey: "3333000033330000333300003333000033330000", userIds: ["Dave <dave@example.com>"])
    dave.ownerTrust = .marginal
    let erin = sampleKey("4444444444444444444444444444444444444444", subkey: "4444000044440000444400004444000044440000", userIds: ["Erin <erin@example.com>"])
    var fay = sampleKey("5555555555555555555555555555555555555555", subkey: "5555000055550000555500005555000055550000", userIds: ["Fay <fay@example.com>"])
    fay.ownerTrust = .full
    fay.validity = .unknown
    let bob = sampleKey("6666666666666666666666666666666666666666", subkey: "6666000066660000666600006666000066660000", userIds: ["Bob <bob@example.org>"])
    let ring = Keyring(keys: [me, carol, dave, erin, fay, bob], sshKeys: [], now: 0)
    func cert(_ signer: Key?, keyId: String? = nil, check: SignatureCheck = .good, revoked: Bool = false) -> Certification {
        Certification(userId: "Bob <bob@example.org>", signerFingerprint: signer?.fingerprint, signerKeyId: keyId ?? signer!.keyId,
                      signerUserId: nil, created: 1, expires: nil, exportable: true, check: check, revoked: revoked)
    }
    let all = [
        cert(dave), cert(carol), cert(carol), cert(erin), cert(fay),
        cert(nil, keyId: "AAAABBBBCCCCDDDD", check: .missingKey),
        cert(me, revoked: true),
    ]
    // 自分の署名は取り消されているので根拠にならない。完全、ある程度の順。同じ鍵は 1 つ
    #expect(ring.introducers(all, of: bob).map(\.name) == ["Carol", "Dave"])
    #expect(ring.introducers(all, of: bob).map(\.trust) == [.full, .marginal])
    #expect(ring.introducers(all + [cert(me)], of: bob).first?.byYou == true)
    // 受け取った署名は、署名した鍵ごとに数える（取り消しと自分の鍵は数えない。確かめられない鍵も数える）
    #expect(ring.signerCount(all, of: bob) == 5)
}

@Test(.enabled(if: gpgAvailable()))
func marksAnImportedKeyAsYourOwn() throws {
    // 秘密鍵は別の PC にある自分の鍵。公開鍵だけを取り込むと、まず他者の鍵になる
    let home = try TemporaryKeyring()
    let other = try TemporaryKeyring()
    let fpr = try other.gpg.generateKey(
        request: GenerateKey(userId: "Alice Home <alice@home.example>", algorithm: nil, capabilities: nil, expires: .never))
    _ = try home.gpg.import(data: try other.gpg.exportPublicKeys(fingerprints: [fpr], armor: false))
    let ring = { Keyring(keys: try home.gpg.listKeys(), sshKeys: [], now: UInt64(Date().timeIntervalSince1970)) }
    #expect(try ring().others.map(\.fingerprint) == [fpr])
    // 自分の鍵にする（所有者信頼を絶対的に）と、この PC では使えない自分の鍵になる
    try home.gpg.setOwnerTrust(fingerprint: fpr, trust: .ultimate)
    let own = try #require(try ring().notOnThisDevice.first)
    #expect(own.key.fingerprint == fpr)
    #expect(own.isMineByTrustOnly)
    // 戻すと、また他者の鍵
    try home.gpg.setOwnerTrust(fingerprint: fpr, trust: .unknown)
    #expect(try ring().others.map(\.fingerprint) == [fpr])
    // 秘密鍵のある鍵は、所有者信頼だけの自分の鍵ではない
    let mine = try home.gpg.generateKey(
        request: GenerateKey(userId: "Alice <alice@example.com>", algorithm: nil, capabilities: nil, expires: .never))
    #expect(try ring().own(mine)?.isMineByTrustOnly == false)
}

@Test func makesSignerListIdsAndGitCommands() {
    #expect(Signers.listId(for: "Work", existing: []) == "work")
    #expect(Signers.listId(for: "  My Team / OSS ", existing: []) == "my-team-oss")
    #expect(Signers.listId(for: "仕事", existing: []) == "list")
    #expect(Signers.listId(for: "Work", existing: ["work", "work-2"]) == "work-3")
    #expect(Signers.shellQuoted("/a b/it's") == "'/a b/it'\\''s'")
    #expect(Signers.globalCommand(path: "/x y/work.allowed_signers")
        == "git config --global gpg.ssh.allowedSignersFile '/x y/work.allowed_signers'")
    #expect(Signers.repositoryCommand(path: "/w.allowed_signers") == "git config gpg.ssh.allowedSignersFile '/w.allowed_signers'")
    #expect(Signers.defaultDirectory().path.hasSuffix("Library/Application Support/Amonhen GPG"))
    #expect(Signers.date(Signers.now()) != nil)
    #expect(Account(host: .gitLab, user: "bob").display == "gitlab.com/bob")
}

/// 記録を変えて署名して保存し、読み直す（コアの結合テストの、FFI を通した版）。
@Test func keepsSignersThroughTheBinding() throws {
    let home = try TemporaryKeyring()
    let me = try home.gpg.generateKey(request: GenerateKey(
        userId: "Alice <alice@example.com>", algorithm: "ed25519",
        capabilities: Capabilities(certify: true, sign: true, encrypt: false, authenticate: false), expires: .never))
    let dir = home.dir.appendingPathComponent("signers").path
    let sshDir = home.dir.appendingPathComponent("ssh")
    try FileManager.default.createDirectory(at: sshDir, withIntermediateDirectories: true)
    let keygen = Process()
    keygen.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
    keygen.arguments = ["-q", "-t", "ed25519", "-N", "", "-C", "bob", "-f", sshDir.appendingPathComponent("bob").path]
    try keygen.run()
    keygen.waitUntilExit()
    let line = try String(contentsOf: sshDir.appendingPathComponent("bob.pub"), encoding: .utf8)

    #expect(try home.gpg.loadSigners(dir: dir).signature == .noRecord)
    var record = newSignerRecord()
    for edit: SignerEdit in [
        .addPerson(email: "bob@example.com", account: Account(host: .gitHub, user: "bob")),
        .acceptKey(email: "bob@example.com", key: line, source: nil, checked: .fingerprint),
        .addList(id: "work", name: "Work"),
        .addMember(list: "work", email: "bob@example.com"),
    ] {
        record = try editSignerRecord(record: record, edit: edit)
    }
    #expect(throws: GpgError.self) { try editSignerRecord(record: record, edit: .addList(id: "Bad Id", name: "x")) }
    try home.gpg.saveSigners(dir: dir, record: record, signer: me)
    let loaded = try home.gpg.loadSigners(dir: dir)
    #expect(loaded.signature == .valid(signer: me))
    #expect(loaded.files.map(\.state) == [.matches])
    #expect(loaded.record.lists(of: "bob@example.com").map(\.id) == ["work"])
    let text = try String(contentsOfFile: signersFile(dir: dir, list: "work"), encoding: .utf8)
    #expect(text.contains("bob@example.com namespaces=\"git\" ssh-ed25519 "))
    #expect(!loaded.record.people[0].keys[0].retired)

    // 既存の allowed signers のファイルを読んで取り込む
    let body = line.split(separator: " ").prefix(2).joined(separator: " ")
    let parsed = try parseAllowedSigners(text: "carol@example.com valid-after=\"20260101Z\" \(body)\n*@example.com \(body)\n")
    #expect(parsed.entries.map(\.email) == ["carol@example.com"])
    #expect(parsed.skipped.map(\.reason) == [.pattern])
    var imported = try editSignerRecord(record: record, edit: .addPerson(email: "carol@example.com", account: nil))
    imported = try editSignerRecord(record: imported, edit: .importKey(email: "carol@example.com", entry: parsed.entries[0], path: "/x/allowed_signers"))
    let carol = try #require(imported.people.first { $0.email == "carol@example.com" }?.keys.first)
    #expect(carol.checked == .file)
    #expect(carol.validAfter == "2026-01-01T00:00:00Z")
    #expect(carol.imported?.line == 1)
}
