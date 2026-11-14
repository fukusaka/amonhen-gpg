import AmonhenGpgKit
import SwiftUI

/// 鍵の詳細。鍵ごとの窓（`KeyWindow`）の中身。上にフィンガープリントを出し、その下をタブに分ける。
/// - 概要: 鍵 ID・有効性・期限・方式、自分の鍵なら秘密鍵の場所・バックアップ・失効証明書・SSH。
/// - 名前とメール: UID ごとの有効性と、自分の鍵でいつ確認したか（署名）。ほかの人の署名は、知らない人のものは本物の保証にならないので数だけ。
/// - 鍵: 主鍵・サブ鍵ごとの方式・用途・期限・フィンガープリント・keygrip・秘密鍵の場所（一覧では主鍵とサブ鍵の違いを出さないので）。
struct KeyDetailView: View {
    enum Tab: String { case overview, names, keys }

    let model: KeyringModel
    let key: Key
    /// 先に読んだ署名（画像に書き出すとき。なければ開いてから裏で読む）。
    var preloaded: [Certification]?
    /// 最初に出すタブ（画像に書き出すとき）。
    var initialTab: Tab = .overview
    /// 確認済みにする（未確認の他者の鍵のとき。窓の上に確認のシートを出す）。
    var certify: ((Key) -> Void)?
    @State private var loaded: [Certification]?
    @State private var tab: Tab?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                Text(key.primaryUserId?.text ?? key.fingerprint).font(.title2.bold())
                Spacer()
                if let certify, key.canCertify {
                    Button(L("Mark as Verified…")) { certify(key) }
                }
            }
            FingerprintView(fingerprint: key.fingerprint)
            TabView(selection: Binding(get: { tab ?? initialTab }, set: { tab = $0 })) {
                scrolling { overview }
                    .tabItem { Text(L("Overview")) }.tag(Tab.overview)
                scrolling { names }
                    .tabItem { Text(L("Names and addresses")) }.tag(Tab.names)
                scrolling { keys }
                    .tabItem { Text(L("Keys")) }.tag(Tab.keys)
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .task {
            guard preloaded == nil else { return }
            let gpg = model.gpg
            let fingerprint = key.fingerprint
            loaded = await Task.detached { try? gpg.certifications(fingerprint: fingerprint) }.value
        }
    }

    private func scrolling(@ViewBuilder _ content: () -> some View) -> some View {
        ScrollView {
            content()
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    // MARK: 概要

    private var overview: some View {
        let own = model.keyring.own(key.fingerprint)
        return Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 8) {
            fact(L("Key ID"), Text(Fingerprint.grouped(String(key.fingerprint.suffix(16)))).monospaced().textSelection(.enabled))
            fact(L("Validity"), Text(validityWord(key.validity)))
            fact(L("Created"), Text(date(key.created) ?? "—"))
            fact(L("Expires"), Text(expiry(key.expires, validity: key.validity)))
            fact(L("Algorithm"), Text(algorithmName(algorithm: key.algorithm, length: key.length, curve: key.curve)))
            if let own {
                Divider().gridCellUnsizedAxes(.horizontal)
                fact(L("Secret key"), Text(secretWord(own.key.secret)))
                fact(L("Backup"), Text(own.backedUp.map { L("Backed up on %@", $0.formatted(date: .abbreviated, time: .omitted)) }
                    ?? L("No backup recorded")))
                fact(L("Revocation certificate"), Text(own.hasRevocationCertificate ? L("On this Mac") : L("Missing")))
                fact(L("SSH"), Text(own.ssh ? L("Set for SSH") : L("Not set for SSH")))
            }
        }
    }

    private func fact(_ label: String, _ value: some View) -> some View {
        GridRow(alignment: .firstTextBaseline) {
            Text(label).foregroundStyle(.secondary).gridColumnAlignment(.trailing)
            value
        }
    }

    // MARK: 名前とメール

    private var names: some View {
        let certifications = preloaded ?? loaded ?? []
        return VStack(alignment: .leading, spacing: 12) {
            ForEach(Array(key.userIds.filter { !$0.attribute }.enumerated()), id: \.offset) { _, uid in
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text(uid.text)
                            .strikethrough(uid.validity == .revoked)
                            .textSelection(.enabled)
                        Spacer()
                        Text(validityWord(uid.validity)).foregroundStyle(.secondary)
                    }
                    CertificationLines(split: model.keyring.certifications(certifications, for: uid))
                }
            }
        }
    }

    // MARK: 鍵

    private var keys: some View {
        VStack(alignment: .leading, spacing: 16) {
            keyBlock(L("Primary key"), fingerprint: key.fingerprint, keygrip: key.keygrip, secret: key.secret,
                     algorithm: algorithmName(algorithm: key.algorithm, length: key.length, curve: key.curve),
                     capabilities: key.capabilities, created: key.created, expires: key.expires, validity: key.validity)
            ForEach(key.subkeys, id: \.fingerprint) { sub in
                Divider()
                keyBlock(L("Subkey"), fingerprint: sub.fingerprint, keygrip: sub.keygrip, secret: sub.secret,
                         algorithm: algorithmName(algorithm: sub.algorithm, length: sub.length, curve: sub.curve),
                         capabilities: sub.capabilities, created: sub.created, expires: sub.expires, validity: sub.validity)
            }
        }
    }

    private func keyBlock(
        _ kind: String, fingerprint: String, keygrip: String?, secret: SecretState, algorithm: String,
        capabilities: Capabilities, created: UInt64?, expires: UInt64?, validity: Validity
    ) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("\(kind) · \(algorithm)").font(.headline)
                .foregroundStyle(validity == .revoked || validity == .expired ? .secondary : .primary)
            Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 4) {
                fact(L("Use"), Text(uses(capabilities)))
                fact(L("Created"), Text(date(created) ?? "—"))
                fact(L("Expires"), Text(expiry(expires, validity: validity)))
                if secret != .none {
                    fact(L("Secret key"), Text(secretWord(secret)))
                }
                fact(L("Fingerprint"), Text(Fingerprint.grouped(fingerprint)).monospaced().textSelection(.enabled))
                if let keygrip {
                    fact(L("Keygrip"), Text(keygrip).monospaced().textSelection(.enabled))
                }
            }
            .font(.callout)
        }
    }

    private func uses(_ c: Capabilities) -> String {
        var names: [String] = []
        if c.certify { names.append(L("Certify")) }
        if c.sign { names.append(L("Sign")) }
        if c.encrypt { names.append(L("Encrypt")) }
        if c.authenticate { names.append(L("Authenticate")) }
        return names.joined(separator: " · ")
    }

    private func expiry(_ expires: UInt64?, validity: Validity) -> String {
        switch validity {
        case .revoked: L("Revoked")
        case .expired: L("Expired")
        default: date(expires) ?? L("Never")
        }
    }

    private func date(_ seconds: UInt64?) -> String? {
        seconds.map { Date(timeIntervalSince1970: TimeInterval($0)).formatted(date: .abbreviated, time: .omitted) }
    }
}

/// 秘密鍵の場所を言葉で。
func secretWord(_ secret: SecretState) -> String {
    switch secret {
    case .none: L("Not in your keyring")
    case .available: L("On this Mac")
    case .stub: L("Stored elsewhere")
    case .onCard(let serial): L("On smart card %@", serial)
    }
}

/// 有効性は記号ではなく言葉で（docs/ui.md）。
func validityWord(_ validity: Validity) -> String {
    switch validity {
    case .revoked: L("Revoked")
    case .expired: L("Expired")
    case .full, .ultimate: L("Verified")
    case .marginal: L("Partly verified")
    default: L("Not verified")
    }
}

/// 持ち主と声に出して照らし合わせるためのフィンガープリント。大きく 2 行に分ける（gpg の表示と同じ切れ目）。
struct FingerprintView: View {
    let fingerprint: String

    var body: some View {
        Text(Fingerprint.lines(fingerprint))
            .font(.system(size: 24, weight: .medium, design: .monospaced))
            .multilineTextAlignment(.center)
            .lineSpacing(4)
            .textSelection(.enabled)
            .padding(10)
            .frame(maxWidth: .infinity)
            .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))
    }
}

/// UID の下に出す署名。自分の鍵の署名は 1 つずつ（どの鍵で・いつ・公開するか）、ほかの人の署名は数だけ。
struct CertificationLines: View {
    let split: UserIdCertifications

    var body: some View {
        ForEach(Array(split.mine.enumerated()), id: \.offset) { _, c in
            Label {
                VStack(alignment: .leading, spacing: 1) {
                    Text(L("Verified with your key %@ on %@", signer(c), date(c)))
                        .strikethrough(c.revoked)
                    Text(note(c)).foregroundStyle(c.check == .bad ? .orange : .secondary)
                }
            } icon: {
                Image(systemName: c.revoked || c.check == .bad ? "xmark.seal" : "checkmark.seal.fill")
                    .foregroundStyle(c.revoked || c.check == .bad ? Color.secondary : Color.green)
            }
            .font(.callout)
        }
        if !split.others.isEmpty {
            Text(L("Signed by %ld other people", split.others.count))
                .font(.callout)
                .foregroundStyle(.secondary)
                .help(split.others.map(signer).joined(separator: "\n"))
        }
    }

    private func signer(_ c: Certification) -> String {
        c.signerUserId.map { UserIdParts($0).name } ?? c.signerKeyId
    }

    private func date(_ c: Certification) -> String {
        c.created.map { Date(timeIntervalSince1970: TimeInterval($0)).formatted(date: .long, time: .omitted) } ?? "—"
    }

    private func note(_ c: Certification) -> String {
        if c.check == .bad { return L("This signature does not check out.") }
        if c.revoked { return L("You withdrew this signature.") }
        return c.exportable ? L("Published with the key") : L("Kept only in your keyring")
    }
}

/// 鍵ごとの窓。フィンガープリントで開き、同じ鍵なら同じ窓を前に出す。鍵束から消えた鍵なら、そう出す。
struct KeyWindow: View {
    let model: KeyringModel
    let fingerprint: String
    @State private var certifying: Key?
    @State private var notice: Notice?

    var body: some View {
        if let key = model.keyring.own(fingerprint)?.key
            ?? model.keyring.others.first(where: { $0.fingerprint.caseInsensitiveCompare(fingerprint) == .orderedSame })
        {
            KeyDetailView(model: model, key: key) { certifying = $0 }
                .frame(minWidth: 520, minHeight: 420)
            .navigationTitle(key.primaryUserId.map { UserIdParts($0.text).name } ?? key.fingerprint)
            .sheet(item: Binding(get: { certifying.map(IdentifiedKey.init) }, set: { certifying = $0?.key })) { item in
                CertifySheet(model: model, key: item.key) {
                    let name = item.key.primaryUserId?.text ?? item.key.fingerprint
                    notice = Notice(title: L("Marked as verified"), message: L("%@ is now verified in your keyring.", name))
                }
            }
            .alert(item: $notice) { notice in
                Alert(title: Text(notice.title), message: Text(notice.message))
            }
        } else {
            ContentUnavailableView(L("This key is no longer in your keyring"), systemImage: "key.slash")
                .frame(minWidth: 520, minHeight: 360)
        }
    }
}

/// 選んでいる鍵（メニューの「詳細を表示」で窓を開くため）。
struct SelectedKeyFingerprint: FocusedValueKey {
    typealias Value = String
}

extension FocusedValues {
    var selectedKeyFingerprint: String? {
        get { self[SelectedKeyFingerprint.self] }
        set { self[SelectedKeyFingerprint.self] = newValue }
    }
}

/// 「鍵」メニュー。選んでいる鍵の窓を ⌘I で開く。
struct KeyCommands: Commands {
    @FocusedValue(\.selectedKeyFingerprint) private var selected
    @Environment(\.openWindow) private var openWindow

    var body: some Commands {
        CommandMenu(L("Key")) {
            Button(L("Show Details")) {
                if let selected { openWindow(id: "key", value: selected) }
            }
            .keyboardShortcut("i")
            .disabled(selected == nil)
        }
    }
}
