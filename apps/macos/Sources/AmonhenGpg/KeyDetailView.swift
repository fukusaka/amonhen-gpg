import AmonhenGpgKit
import AppKit
import SwiftUI

/// 鍵の詳細。鍵ごとの窓（`KeyWindow`）の中身。上にフィンガープリントを出し、その下をタブに分ける。
/// - 概要: 鍵 ID・有効性・期限・方式、自分の鍵なら秘密鍵の場所・バックアップ・失効証明書・SSH。
/// - 名前とメール: UID ごとの有効性。
/// - 署名: 自分の鍵か自分が確認済みにした鍵による署名と、そのほかの署名（知らない人のものは本物の保証にならないので、分けて薄く出す）。
/// - 鍵: 主鍵・サブ鍵ごとの方式・用途・期限・フィンガープリント・keygrip・秘密鍵の場所（一覧では主鍵とサブ鍵の違いを出さないので）。
struct KeyDetailView: View {
    enum Tab: String { case overview, names, keys, signatures }

    let model: KeyringModel
    let key: Key
    /// 先に読んだ署名（画像に書き出すとき。なければ開いてから裏で読む）。
    var preloaded: [Certification]?
    /// 最初に出すタブ（画像に書き出すとき）。
    var initialTab: Tab = .overview
    /// 確認済みにする（未確認の他者の鍵のとき。窓の上に確認のシートを出す）。
    var certify: ((Key) -> Void)?
    /// 入手元から取り直す（他者の鍵のとき。受け入れ前の鍵に置く）。
    var refresh: ((Key) -> Void)?
    @State private var loaded: [Certification]?
    /// 失効の理由と説明（鍵・サブ鍵・UID のどれかが失効しているときだけ読む）。
    @State private var revocations: Revocations?
    @State private var tab: Tab?
    /// 所有者信頼を設定できなかった理由。
    @State private var trustFailure: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                Text(key.primaryUserId?.text ?? key.fingerprint).font(.title2.bold())
                Spacer()
                if let refresh, model.keyring.own(key.fingerprint) == nil {
                    Button(L("Fetch Again")) { refresh(key) }
                        .help(L("Fetch this key again from where it came from, or from the keyserver, to get a new expiry or a revocation. It waits in Keys to Accept until you update it."))
                }
                if let certify, key.canCertify {
                    Button(model.keyring.signers.isEmpty ? L("Sign Key… (needs your primary key)") : L("Sign Key…")) { certify(key) }
                        .disabled(model.keyring.signers.isEmpty)
                }
            }
            FingerprintView(fingerprint: key.fingerprint)
            TabView(selection: Binding(get: { tab ?? initialTab }, set: { tab = $0 })) {
                scrolling { overview }
                    .tabItem { Text(L("Overview")) }.tag(Tab.overview)
                scrolling { names }
                    .tabItem { Text(L("Names")) }.tag(Tab.names)
                scrolling { keys }
                    .tabItem { Text(L("Keys")) }.tag(Tab.keys)
                scrolling { signatures }
                    .tabItem { Text(L("Signatures")) }.tag(Tab.signatures)
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .alert(L("Cannot change the owner trust"), isPresented: Binding(get: { trustFailure != nil }, set: { if !$0 { trustFailure = nil } })) {
            Button(L("OK"), role: .cancel) {}
        } message: {
            Text(trustFailure ?? "")
        }
        .task {
            let gpg = model.gpg
            let fingerprint = key.fingerprint
            if key.validity == .revoked || key.subkeys.contains(where: { $0.validity == .revoked })
                || key.userIds.contains(where: { $0.validity == .revoked })
            {
                revocations = await Task.detached { try? gpg.revocations(fingerprint: fingerprint) }.value
            }
            guard preloaded == nil else { return }
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
            fact(L("Key ID"), KeyIdText(keyId: key.keyId, fingerprint: key.fingerprint))
            fact(L("Validity"), Text(validityWord(key.validity)))
            // 他者の鍵だけ（自分の鍵は絶対的）
            if own == nil {
                fact(L("Owner trust"), VStack(alignment: .leading, spacing: 4) {
                    OwnerTrustPicker(key: key) { trust in
                        Task { trustFailure = await model.setOwnerTrust(key, trust).map(describe) }
                    }
                    .labelsHidden()
                    .pickerStyle(.menu)
                    .fixedSize()
                    Text(ownerTrustNote())
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                })
            }
            // 何で確認済みになったか（Web of Trust。他者の鍵だけ。署名を読み終えてから）
            if own == nil, key.validity == .full || key.validity == .marginal {
                let by = model.keyring.introducers(preloaded ?? loaded ?? [], of: key)
                if !by.isEmpty {
                    fact(L("Verified by"), Text(by.map(introducerWord).joined(separator: "\n")))
                }
            }
            fact(L("Created"), Text(date(key.created) ?? "—"))
            fact(L("Expires"), Text(expiry(key.expires, validity: key.validity)))
            if let revocation = revocations?.key {
                fact(L("Revoked because"), RevocationText(revocation: revocation))
            }
            fact(L("Algorithm"), Text(algorithmName(algorithm: key.algorithm, length: key.length, curve: key.curve)))
            // gpg は自分で作った鍵の入手元を記録しないことが多いので、自分の鍵で分からなければ出さない
            if own == nil || key.origin != .unknown {
                fact(L("Origin"), Text(originWord(key)).textSelection(.enabled))
            }
            if let updated = key.lastUpdate {
                fact(L("Last refreshed"), Text(date(updated) ?? "—"))
            }
            if let own {
                Divider().gridCellUnsizedAxes(.horizontal)
                fact(L("Secret key"), Text(secretWord(own.key.secret)))
                fact(L("Backup"), Text(own.backedUp.map { L("Backed up on %@", $0.formatted(date: .abbreviated, time: .omitted)) }
                    ?? L("No backup recorded")))
                fact(L("Revocation certificate"), Text(own.hasRevocationCertificate ? L("On this Mac") : L("Missing")))
                // 自分の鍵は、受け取った署名の数だけ（誰の署名かは署名タブ）
                fact(L("Signatures from others"), Text((preloaded ?? loaded).map { "\(model.keyring.signerCount($0, of: key))" } ?? "—"))
                fact(L("SSH"), VStack(alignment: .leading, spacing: 2) {
                    Text(own.ssh ? L("Set for SSH") : L("Not set for SSH"))
                    // 認証サブ鍵を SSH 鍵として見たときのフィンガープリント（authorized_keys などと照らし合わせる）
                    if let fpr = model.keyring.sshFingerprint(keygrip: own.sshSubkey(now: UInt64(Date().timeIntervalSince1970))?.keygrip) {
                        Text(fpr).monospaced().foregroundStyle(.secondary).textSelection(.enabled)
                    }
                })
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
        VStack(alignment: .leading, spacing: 12) {
            ForEach(Array(key.userIds.filter { !$0.attribute }.enumerated()), id: \.offset) { _, uid in
                VStack(alignment: .leading, spacing: 2) {
                    HStack {
                        Text(uid.text)
                            .strikethrough(uid.validity == .revoked)
                            .textSelection(.enabled)
                        Spacer()
                        Text(validityWord(uid.validity)).foregroundStyle(.secondary)
                    }
                    if let revocation = revocations?.userIds.first(where: { $0.userId == uid.text })?.revocation {
                        RevocationText(revocation: revocation)
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
    }

    // MARK: 署名

    private var signatures: some View {
        let groups = model.keyring.signatures(preloaded ?? loaded ?? [], on: key)
        return Group {
            if preloaded == nil, loaded == nil {
                ProgressView().controlSize(.small)
            } else if groups.trusted.isEmpty, groups.others.isEmpty {
                Text(L("No signatures from other keys.")).foregroundStyle(.secondary)
            } else {
                SignatureGrid(trusted: groups.trusted, others: groups.others)
            }
        }
    }

    // MARK: 鍵

    private var keys: some View {
        VStack(alignment: .leading, spacing: 16) {
            keyBlock(L("Primary key"), fingerprint: key.fingerprint, keyId: key.keyId, keygrip: key.keygrip, secret: key.secret,
                     algorithm: algorithmName(algorithm: key.algorithm, length: key.length, curve: key.curve),
                     capabilities: key.capabilities, created: key.created, expires: key.expires, validity: key.validity)
            ForEach(key.subkeys, id: \.fingerprint) { sub in
                Divider()
                keyBlock(L("Subkey"), fingerprint: sub.fingerprint, keyId: sub.keyId, keygrip: sub.keygrip, secret: sub.secret,
                         algorithm: algorithmName(algorithm: sub.algorithm, length: sub.length, curve: sub.curve),
                         capabilities: sub.capabilities, created: sub.created, expires: sub.expires, validity: sub.validity)
            }
        }
    }

    private func keyBlock(
        _ kind: String, fingerprint: String, keyId: String, keygrip: String?, secret: SecretState, algorithm: String,
        capabilities: Capabilities, created: UInt64?, expires: UInt64?, validity: Validity
    ) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("\(kind) · \(algorithm)").font(.headline)
                .foregroundStyle(validity == .revoked || validity == .expired ? .secondary : .primary)
            Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 4) {
                fact(L("Use"), Text(uses(capabilities)))
                fact(L("Created"), Text(date(created) ?? "—"))
                fact(L("Expires"), Text(expiry(expires, validity: validity)))
                if let revocation = revocation(of: fingerprint) {
                    fact(L("Revoked because"), RevocationText(revocation: revocation))
                }
                if secret != .none {
                    fact(L("Secret key"), Text(secretWord(secret)))
                }
                fact(L("Key ID"), KeyIdText(keyId: keyId, fingerprint: fingerprint))
                fact(L("Fingerprint"), Text(Fingerprint.grouped(fingerprint)).monospaced().textSelection(.enabled))
                if capabilities.authenticate, let ssh = model.keyring.sshFingerprint(keygrip: keygrip) {
                    fact(L("SSH"), Text(ssh).monospaced().textSelection(.enabled))
                }
                if let keygrip {
                    fact(L("Keygrip"), Text(keygrip).monospaced().textSelection(.enabled))
                }
            }
            .font(.callout)
        }
    }

    /// 主鍵かサブ鍵の失効（フィンガープリントで）。
    private func revocation(of fingerprint: String) -> Revocation? {
        if fingerprint == key.fingerprint { return revocations?.key }
        return revocations?.subkeys.first { $0.fingerprint.caseInsensitiveCompare(fingerprint) == .orderedSame }?.revocation
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

/// 表の行でスペースを押すと出る、鍵の一瞥（クイックルック）。照らし合わせるフィンガープリントと、有効性・期限。
struct KeyQuickLook: View {
    let key: Key
    let showDetails: () -> Void

    var body: some View {
        let parts = key.primaryUserId.map { UserIdParts($0.text) }
        VStack(alignment: .leading, spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(parts?.name ?? key.fingerprint).font(.headline)
                if let email = parts?.email { Text(email).foregroundStyle(.secondary) }
            }
            // 窓より狭いので、文字を少し小さく（大きいままだと 1 行目が収まらない）
            FingerprintView(fingerprint: key.fingerprint, size: 20)
            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 4) {
                GridRow {
                    Text(L("Validity")).foregroundStyle(.secondary)
                    Text(validityWord(key.validity))
                }
                GridRow {
                    Text(L("Expires")).foregroundStyle(.secondary)
                    Text(key.expires.map { Date(timeIntervalSince1970: TimeInterval($0)).formatted(date: .abbreviated, time: .omitted) }
                        ?? L("Never"))
                }
                GridRow {
                    Text(L("Algorithm")).foregroundStyle(.secondary)
                    Text(algorithmName(algorithm: key.algorithm, length: key.length, curve: key.curve))
                }
            }
            .font(.callout)
            HStack {
                Spacer()
                Button(L("Show Details"), action: showDetails)
            }
        }
        .padding(16)
        .frame(width: 420)
    }
}

/// 鍵をどこから取り込んだか。取り込んだ先の URL があれば、そのホスト名を添える。
func originWord(_ key: Key) -> String {
    let host = key.originUrl.flatMap { URL(string: $0)?.host() ?? $0 }
    let word = switch key.origin {
    case .unknown: L("Unknown")
    case .keyserver, .preferredKeyserver: L("Keyserver")
    case .dane: L("DNS (DANE)")
    case .wkd: L("The email domain (WKD)")
    case .url: L("A web address")
    case .file: L("A file")
    case .generated: L("Created in this keyring")
    }
    return host.map { "\(word) · \($0)" } ?? word
}

/// 失効の理由と、失効させた人の説明。秘密鍵が漏れたという理由は目立たせる（その鍵の古い署名も信用できない）。
struct RevocationText: View {
    let revocation: Revocation

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(cause)
                .foregroundStyle(revocation.cause == .compromised ? AnyShapeStyle(.orange) : AnyShapeStyle(.foreground))
            if let comment = revocation.comment {
                Text(comment).foregroundStyle(.secondary).textSelection(.enabled)
            }
        }
    }

    private var cause: String {
        switch revocation.cause {
        case .unspecified: L("No reason was given")
        case .superseded: L("Replaced by a new key")
        case .compromised: L("The secret key was exposed")
        case .retired: L("No longer used")
        case .userIdInvalid: L("No longer valid")
        }
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

/// 鍵を確認済みにした署名の主を、自分の鍵か所有者信頼と一緒に。
func introducerWord(_ introducer: Introducer) -> String {
    if introducer.byYou { return L("%@ (your key)", introducer.name) }
    return introducer.trust == .full ? L("%@ (trusted fully)", introducer.name) : L("%@ (trusted marginally)", introducer.name)
}

/// 有効性は記号ではなく言葉で（docs/ui.md）。
func validityWord(_ validity: Validity) -> String {
    switch validity {
    case .revoked: L("Revoked")
    case .expired: L("Expired")
    case .ultimate: L("Ultimate")
    case .full: L("Full")
    case .marginal: L("Marginal")
    case .never: L("Not valid")
    default: L("Unknown")
    }
}

/// 鍵 ID（gpg の長い形）と、すべての形式を出すボタン。
struct KeyIdText: View {
    let keyId: String
    let fingerprint: String
    @State private var showing = false

    var body: some View {
        HStack(spacing: 6) {
            Text(keyId).monospaced().textSelection(.enabled)
            Button {
                showing.toggle()
            } label: {
                Image(systemName: "ellipsis.circle")
            }
            .buttonStyle(.borderless)
            .help(L("All Forms"))
            .popover(isPresented: $showing, arrowEdge: .bottom) {
                KeyIdForms(keyId: keyId, fingerprint: fingerprint)
            }
        }
    }
}

/// 鍵 ID とフィンガープリントを、gpg の書き方ごとに並べる。値を押すとコピーする。鍵 ID は `--keyid-format` の
/// long・0xlong・short・0xshort、フィンガープリントは `--fingerprint` の区切りと、区切らない形。
struct KeyIdForms: View {
    let keyId: String
    let fingerprint: String
    @State private var copied: String?

    private var forms: [(label: String, value: String)] {
        let short = String(keyId.suffix(8))
        return [
            (L("Key ID (long)"), keyId),
            (L("Key ID (0xlong)"), "0x" + keyId),
            (L("Key ID (short)"), short),
            (L("Key ID (0xshort)"), "0x" + short),
            (L("Fingerprint"), Fingerprint.grouped(fingerprint)),
            (L("Fingerprint (no spaces)"), fingerprint),
        ]
    }

    var body: some View {
        Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 8) {
            ForEach(forms, id: \.label) { form in
                GridRow {
                    Text(form.label).foregroundStyle(.secondary)
                    // 値を押すとコピーする（ボタンを並べず、値そのものを押させる）
                    Button {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(form.value, forType: .string)
                        copied = form.label
                    } label: {
                        Text(form.value).monospaced()
                    }
                    .buttonStyle(.plain)
                    .help(L("Click to copy"))
                    // 出ていないときも場所を取っておく（出たときにポップアップの幅が変わらないように）
                    Text(L("Copied"))
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .opacity(copied == form.label ? 1 : 0)
                }
            }
        }
        .padding(16)
        .fixedSize()
    }
}

/// 持ち主と声に出して照らし合わせるためのフィンガープリント。大きく 2 行に分ける（gpg の表示と同じ切れ目）。
struct FingerprintView: View {
    let fingerprint: String
    var size: CGFloat = 24

    var body: some View {
        Text(Fingerprint.lines(fingerprint))
            .font(.system(size: size, weight: .medium, design: .monospaced))
            .multilineTextAlignment(.center)
            .lineSpacing(4)
            // 高さを詰められても（ポップオーバー）2 行のまま
            .lineLimit(2, reservesSpace: true)
            // シートの中身が増えても高さを詰めない（詰めると 1 行目の途中で切れる）
            .fixedSize(horizontal: false, vertical: true)
            .textSelection(.enabled)
            .padding(10)
            .frame(maxWidth: .infinity)
            .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))
    }
}

/// 署名の表。確認済みの鍵からの署名と、そのほか（薄く出す）を、列を揃えて 1 つの表に。
/// 列は署名した人・どの名前とメールに・確かめた結果・日付・公開するか。取り消された署名には線を引く。
struct SignatureGrid: View {
    let trusted: [SignatureRow]
    let others: [SignatureRow]

    var body: some View {
        Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 6) {
            GridRow {
                Label {
                    Text(L("From keys you verified"))
                } icon: {
                    Image(systemName: "checkmark.seal.fill").foregroundStyle(.green)
                }
                .font(.headline)
                .gridCellColumns(5)
            }
            columnHeads
            if trusted.isEmpty {
                GridRow { Text(L("None.")).foregroundStyle(.secondary).gridCellColumns(5) }
            }
            ForEach(trusted) { row($0) }
            if !others.isEmpty {
                GridRow {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(L("Other signatures (%ld)", others.count)).font(.headline)
                        Text(L("These are from people you haven't verified. They aren't proof that the key is genuine."))
                            .foregroundStyle(.secondary)
                    }
                    .padding(.top, 14)
                    .gridCellColumns(5)
                }
                columnHeads
                ForEach(others) { row($0).foregroundStyle(.secondary) }
            }
        }
        .font(.callout)
    }

    private var columnHeads: some View {
        GridRow {
            Text(L("Signed by"))
            Text(L("Name and address"))
            Text(L("Result"))
            Text(L("Date"))
            Text(L("Kind"))
        }
        .foregroundStyle(.secondary)
    }

    private func row(_ row: SignatureRow) -> some View {
        let c = row.certification
        return GridRow {
            signer(row)
                .strikethrough(c.revoked)
                .help(c.signerFingerprint.map(Fingerprint.grouped) ?? Fingerprint.grouped(c.signerKeyId))
            Text(UserIdParts(c.userId).email ?? c.userId)
                .lineLimit(1)
                .help(c.userId)
            Text(result(c)).foregroundStyle(c.check == .bad ? AnyShapeStyle(.orange) : AnyShapeStyle(.foreground))
            Text(c.created.map { Date(timeIntervalSince1970: TimeInterval($0)).formatted(date: .numeric, time: .omitted) } ?? "—")
            Text(c.exportable ? L("Published") : L("Local only"))
        }
    }

    @ViewBuilder private func signer(_ row: SignatureRow) -> some View {
        if let name = row.signerName {
            Text(row.byYou ? L("%@ (you)", name) : name).lineLimit(1)
        } else {
            // 鍵束にない鍵は名前が分からないので、鍵 ID だけ
            HStack(spacing: 4) {
                Text(L("Key ID"))
                Text(Fingerprint.grouped(row.certification.signerKeyId)).monospaced()
            }
            .lineLimit(1)
        }
    }

    private func result(_ c: Certification) -> String {
        if c.revoked { return L("Withdrawn") }
        switch c.check {
        case .good: return L("Good")
        case .bad: return L("Does not check out")
        default: return L("Can't check")
        }
    }
}

/// 鍵ごとの窓。フィンガープリントで開き、同じ鍵なら同じ窓を前に出す。鍵束から消えた鍵なら、そう出す。
struct KeyWindow: View {
    let model: KeyringModel
    let staging: StagingModel
    let fingerprint: String
    @State private var certifying: Key?
    @State private var notice: Notice?
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        if let key = model.keyring.own(fingerprint)?.key
            ?? model.keyring.others.first(where: { $0.fingerprint.caseInsensitiveCompare(fingerprint) == .orderedSame })
        {
            KeyDetailView(model: model, key: key, certify: { certifying = $0 }, refresh: { key in
                // 取ってきた鍵は主の窓の受け入れ前の鍵に出る
                staging.reveal()
                openWindow(id: "main")
                Task { await staging.refresh(key) }
            })
                .frame(minWidth: 520, minHeight: 420)
            .navigationTitle(key.primaryUserId.map { UserIdParts($0.text).name } ?? key.fingerprint)
            .sheet(item: Binding(get: { certifying.map(IdentifiedKey.init) }, set: { certifying = $0?.key })) { item in
                CertifySheet(model: model, key: item.key) {
                    let name = item.key.primaryUserId?.text ?? item.key.fingerprint
                    notice = Notice(title: L("Signed"), message: L("%@ is signed and is now valid in your keyring.", name))
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
