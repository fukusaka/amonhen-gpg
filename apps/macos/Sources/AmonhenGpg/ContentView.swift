import AmonhenGpgKit
import AppKit
import SwiftUI

/// 画面の 3 つの場所（docs/ui.md）。
enum Place: String, Hashable, CaseIterable {
    case mine, others, staging

    var title: String {
        switch self {
        case .mine: L("My Keys")
        case .others: L("Others' Keys")
        case .staging: L("Staging")
        }
    }

    var symbol: String {
        switch self {
        case .mine: "key.fill"
        case .others: "person.2"
        case .staging: "tray"
        }
    }
}

struct ContentView: View {
    let model: KeyringModel
    let staging: StagingModel
    @State var place: Place = .mine
    /// 使えた鍵（履歴）を開いておくか。
    var showsHistory = false
    @State private var creating = false
    @State private var notice: Notice?
    /// 作ったばかりの鍵（バックアップを勧める）。
    @State private var created: OwnKey?
    /// バックアップ済みにするか確かめている鍵。
    @State private var markingBackedUp: OwnKey?
    /// 鍵サーバーに送るか確かめている鍵。
    @State private var sending: OwnKey?
    /// 失効させたばかりの鍵（ほかの人に知らせるよう勧める）。
    @State private var revoked: OwnKey?

    var body: some View {
        NavigationSplitView {
            List(Place.allCases, id: \.self, selection: $place) { place in
                Label(place.title, systemImage: place.symbol)
            }
            .navigationSplitViewColumnWidth(min: 160, ideal: 180)
        } detail: {
            Group {
                if let failure = model.failure {
                    ContentUnavailableView(
                        L("Cannot read the keyring"), systemImage: "exclamationmark.triangle", description: Text(failure))
                } else {
                    switch place {
                    case .mine:
                        OwnKeysView(
                            model: model, showsHistory: showsHistory,
                            actions: OwnKeyActions(
                                notify: { notice = $0 }, revoked: { revoked = $0 }, backUp: backUp,
                                markBackedUp: { markingBackedUp = $0 }, exportPublicKey: exportPublicKey,
                                sendToKeyserver: { sending = $0 },
                                createRevocationCertificate: createRevocationCertificate),
                            create: { creating = true }, importKeys: importKeys)
                    case .others: OthersView(model: model, importKeys: importKeys, notify: { notice = $0 })
                    case .staging: StagingView(model: staging)
                    }
                }
            }
            .navigationTitle(place.title)
            .toolbar {
                if place == .mine {
                    Button {
                        creating = true
                    } label: {
                        Label(L("New Key…"), systemImage: "plus")
                    }
                    .help(L("New Key…"))
                }
                if place != .staging {
                    Button(action: importKeys) {
                        Label(L("Import…"), systemImage: "square.and.arrow.down")
                    }
                    .help(L("Import…"))
                }
                Button {
                    Task { await model.reload() }
                } label: {
                    Label(L("Reload"), systemImage: "arrow.clockwise")
                }
                .disabled(model.loading)
            }
        }
        .sheet(isPresented: $creating) {
            NewKeySheet(model: model) { fingerprint in
                created = model.keyring.usable.first { $0.id == fingerprint }
            }
        }
        .alert(
            L("Key created"), isPresented: Binding(get: { created != nil }, set: { if !$0 { created = nil } }),
            presenting: created
        ) { own in
            Button(L("Back Up Now…")) { backUp(own) }
            Button(L("Later"), role: .cancel) {}
        } message: { _ in
            Text(L("Back up the secret key now and keep it somewhere other than this Mac. Without it, losing this Mac means losing the key."))
        }
        .alert(
            L("Mark as Backed Up?"),
            isPresented: Binding(get: { markingBackedUp != nil }, set: { if !$0 { markingBackedUp = nil } }),
            presenting: markingBackedUp
        ) { own in
            Button(L("Mark as Backed Up")) { Task { await model.recordBackup(own.key.fingerprint) } }
            Button(L("Cancel"), role: .cancel) {}
        } message: { _ in
            Text(L("Do this only if you already keep a backup of this secret key somewhere other than this Mac. The app will stop warning about it."))
        }
        .alert(
            L("Send to %@?", Keyserver.name(Keyserver.default)),
            isPresented: Binding(get: { sending != nil }, set: { if !$0 { sending = nil } }),
            presenting: sending
        ) { own in
            Button(L("Send")) { send(own) }
            Button(L("Cancel"), role: .cancel) {}
        } message: { own in
            Text(L("Anyone will be able to download the public key of %@. Keyservers keep what they receive, so this cannot be undone. keys.openpgp.org shows the email address only after you confirm it by mail.", own.key.primaryUserId?.text ?? own.key.fingerprint))
        }
        .alert(
            L("Key revoked"), isPresented: Binding(get: { revoked != nil }, set: { if !$0 { revoked = nil } }),
            presenting: revoked
        ) { own in
            Button(L("Send to Keyserver…")) { sending = own }
            Button(L("Export Public Key…")) { exportPublicKey(own) }
            Button(L("Later"), role: .cancel) {}
        } message: { own in
            Text(Notice(revoked: own).message)
        }
        .alert(item: $notice) { notice in
            Alert(title: Text(notice.title), message: Text(notice.message))
        }
    }

    /// 鍵のファイルを選ばせ、取り込む。秘密鍵を含むときはパスフレーズを gpg が聞く。
    private func importKeys() {
        let panel = NSOpenPanel()
        panel.title = L("Import Keys")
        panel.message = L("Choose files with public keys, secret key backups or revocation certificates.")
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = false
        guard panel.runModal() == .OK, !panel.urls.isEmpty else { return }
        let urls = panel.urls
        Task {
            switch await model.perform({ $0.importFiles(urls) }) {
            case let .success(summary): notice = Notice(summary)
            case let .failure(error): notice = Notice(title: L("Cannot import keys"), message: describe(error))
            }
        }
    }

    /// 秘密鍵を書き出す先を選ばせ、書き出す。パスフレーズは gpg が聞く。
    private func backUp(_ own: OwnKey) {
        let panel = NSSavePanel()
        panel.title = L("Back Up Secret Key")
        panel.message = L("The backup stays protected by the key's passphrase. Keep it somewhere other than this Mac, such as a USB drive.")
        panel.nameFieldStringValue = own.backupFileName
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let fingerprint = own.key.fingerprint
        Task {
            switch await model.perform({ try $0.backUpSecretKey(fingerprint, to: url) }) {
            case .success:
                await model.recordBackup(fingerprint)
                notice = Notice(title: L("Backed up"), message: L("Saved the secret key to %@.", url.path))
            case let .failure(error) where isCanceled(error):
                break
            case let .failure(error):
                notice = Notice(title: L("Cannot back up the secret key"), message: describe(error))
            }
        }
    }

    /// 公開鍵を書き出す先を選ばせ、書き出す（相手に渡す、失効を知らせる）。
    private func exportPublicKey(_ own: OwnKey) {
        let panel = NSSavePanel()
        panel.title = L("Export Public Key")
        panel.nameFieldStringValue = own.publicKeyFileName
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let fingerprint = own.key.fingerprint
        Task {
            switch await model.perform({ try $0.exportPublicKey(fingerprint, to: url) }) {
            case .success:
                notice = Notice(title: L("Exported"), message: L("Saved the public key to %@.", url.path))
            case let .failure(error):
                notice = Notice(title: L("Cannot export the public key"), message: describe(error))
            }
        }
    }

    /// 公開鍵を鍵サーバーに送る（確かめたあと）。秘密鍵は送らない。
    private func send(_ own: OwnKey) {
        let fingerprint = own.key.fingerprint
        Task {
            switch await model.perform({ try $0.sendKeys(fingerprints: [fingerprint], keyserver: Keyserver.default) }) {
            case .success:
                notice = Notice(title: L("Sent"), message: L("Sent the public key to %@.", Keyserver.name(Keyserver.default)))
            case let .failure(error):
                notice = Notice(title: L("Cannot send the public key"), message: describe(error))
            }
        }
    }

    /// 失効証明書を作り、gpg が置く場所（`openpgp-revocs.d`）に置く。パスフレーズは gpg が聞く。
    private func createRevocationCertificate(_ own: OwnKey) {
        let fingerprint = own.key.fingerprint
        Task {
            switch await model.perform({ try $0.saveRevocationCertificate(fingerprint: fingerprint) }) {
            case let .success(path):
                notice = Notice(
                    title: L("Revocation certificate created"),
                    message: L("Saved it to %@. Keep a copy with the secret key backup, somewhere other than this Mac.", path))
            case let .failure(error) where isCanceled(error):
                break
            case let .failure(error):
                notice = Notice(title: L("Cannot create a revocation certificate"), message: describe(error))
            }
        }
    }
}

// MARK: - 自分の鍵

/// 鍵ごとの操作。行から呼び、シートなどは一覧の側で出す。
struct OwnKeyActions {
    /// 操作の結果を知らせる。
    var notify: (Notice) -> Void = { _ in }
    /// 失効させたあと（ほかの人に知らせるよう勧める）。
    var revoked: (OwnKey) -> Void = { _ in }
    var extendExpiry: (OwnKey) -> Void = { _ in }
    var revoke: (OwnKey) -> Void = { _ in }
    var backUp: (OwnKey) -> Void = { _ in }
    var markBackedUp: (OwnKey) -> Void = { _ in }
    var exportPublicKey: (OwnKey) -> Void = { _ in }
    var sendToKeyserver: (OwnKey) -> Void = { _ in }
    var createRevocationCertificate: (OwnKey) -> Void = { _ in }
}

/// 操作の結果を知らせる（成功も失敗も）。
struct Notice: Identifiable {
    let id = UUID()
    let title: String
    let message: String
}

extension Notice {
    /// 延ばした期限を知らせる。gpg が実際に付けた期限（読み直した鍵）で書く。
    init(extended own: OwnKey) {
        let name = own.key.primaryUserId.map { UserIdParts($0.text).name } ?? own.key.fingerprint
        guard let expires = own.key.expires else {
            self.init(title: L("Expiry extended"), message: L("%@ no longer expires.", name))
            return
        }
        let date = Date(timeIntervalSince1970: TimeInterval(expires))
        self.init(title: L("Expiry extended"), message: L("%@ is usable until %@.", name, date.formatted(date: .long, time: .omitted)))
    }

    /// 失効させたことと、ほかの人に知らせる必要があることを伝える。
    init(revoked own: OwnKey) {
        let name = own.key.primaryUserId.map { UserIdParts($0.text).name } ?? own.key.fingerprint
        self.init(
            title: L("Key revoked"),
            message: L("%@ is revoked. Others learn about it only when they get the updated public key, from a keyserver or from you.", name))
    }

    /// 取り込みの結果を文にする。
    init(_ summary: ImportSummary) {
        var lines: [String] = []
        if summary.newKeys > 0 { lines.append(L("New keys: %ld", summary.newKeys)) }
        if summary.secretKeys > 0 { lines.append(L("Secret keys: %ld", summary.secretKeys)) }
        if summary.updatedKeys > 0 { lines.append(L("Updated keys: %ld", summary.updatedKeys)) }
        if summary.revocations > 0 { lines.append(L("Revocations: %ld", summary.revocations)) }
        if summary.unchangedKeys > 0 { lines.append(L("Already up to date: %ld", summary.unchangedKeys)) }
        if summary.notImported > 0 { lines.append(L("Not imported: %ld", summary.notImported)) }
        for failure in summary.failures {
            lines.append(L("%@: %@", failure.file, describe(failure.error)))
        }
        let nothing = summary.newKeys + summary.secretKeys + summary.updatedKeys + summary.revocations + summary.unchangedKeys == 0
        self.init(
            title: nothing ? L("No keys were imported") : L("Imported keys"),
            message: lines.isEmpty ? L("The files contained no keys.") : lines.joined(separator: "\n"))
    }
}

struct OwnKeysView: View {
    let model: KeyringModel
    @State var showsHistory = false
    /// 行の操作（期限の延長は、ここでシートを出す）。
    var actions = OwnKeyActions()
    var create: () -> Void = {}
    var importKeys: () -> Void = {}
    @State private var extending: OwnKey?
    @State private var revoking: OwnKey?

    var body: some View {
        list
            .sheet(item: $extending) { own in
                ExtendExpirySheet(model: model, own: own) { actions.notify(Notice(extended: $0)) }
            }
            .sheet(item: $revoking) { own in
                RevokeKeySheet(model: model, own: own, backUp: actions.backUp, onRevoked: actions.revoked)
            }
    }

    private var rowActions: OwnKeyActions {
        var actions = actions
        actions.extendExpiry = { extending = $0 }
        actions.revoke = { revoking = $0 }
        return actions
    }

    @ViewBuilder private var list: some View {
        let keyring = model.keyring
        let now = UInt64(Date().timeIntervalSince1970)
        if keyring.usable.isEmpty && keyring.notOnThisDevice.isEmpty && keyring.history.isEmpty {
            ContentUnavailableView {
                Label(L("No keys of your own"), systemImage: "key")
            } description: {
                Text(L("Create a key, or import one you use on another computer."))
            } actions: {
                HStack {
                    Button(L("New Key…"), action: create)
                    Button(L("Import…"), action: importKeys)
                }
            }
        } else {
            List {
                if !keyring.usable.isEmpty {
                    Section(L("Usable")) {
                        ForEach(keyring.usable) { OwnKeyRow(own: $0, now: now, actions: rowActions) }
                    }
                }
                if !keyring.notOnThisDevice.isEmpty {
                    Section(L("Not usable on this Mac")) {
                        ForEach(keyring.notOnThisDevice) { OwnKeyRow(own: $0, now: now, actions: rowActions) }
                    }
                }
                if !keyring.history.isEmpty {
                    Section {
                        DisclosureGroup(isExpanded: $showsHistory) {
                            ForEach(keyring.history) { OwnKeyRow(own: $0, now: now, actions: rowActions) }
                        } label: {
                            Text(L("Used before (%ld)", keyring.history.count))
                        }
                    }
                }
            }
        }
    }
}

struct OwnKeyRow: View {
    let own: OwnKey
    let now: UInt64
    var actions = OwnKeyActions()

    var body: some View {
        let parts = own.key.primaryUserId.map { UserIdParts($0.text) }
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: symbol)
                .font(.title2)
                .foregroundStyle(own.status.tier == .history ? .secondary : .primary)
                .frame(width: 28)
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Text(parts?.name ?? own.key.fingerprint).font(.headline)
                    if let email = parts?.email {
                        Text(email).foregroundStyle(.secondary)
                    }
                }
                switch own.status.tier {
                case .usable:
                    HStack(spacing: 14) {
                        UsageLabel(name: L("Sign"), availability: own.status.sign)
                        UsageLabel(name: L("Decrypt"), availability: own.status.decrypt)
                        UsageLabel(name: "SSH", availability: own.ssh ? own.status.authenticate : .none)
                    }
                case .notOnThisDevice:
                    Text(L("The secret key is not on this Mac.")).foregroundStyle(.secondary)
                case .history:
                    Text(historyNote).foregroundStyle(.secondary)
                }
                if own.needsBackup {
                    Warning(text: L("No backup"), action: L("Back Up…")) { actions.backUp(own) }
                        .help(L("This app has no record of a backup of this secret key. Without one, losing this Mac means losing the key."))
                }
                if own.needsRevocationCertificate {
                    Warning(text: L("No revocation certificate"), action: L("Create…")) {
                        actions.createRevocationCertificate(own)
                    }
                    .help(L("Without it, you cannot revoke this key if you lose the secret key or forget the passphrase."))
                }
                Text(Fingerprint.grouped(own.key.fingerprint))
                    .font(.caption.monospaced())
                    .foregroundStyle(.tertiary)
                    .textSelection(.enabled)
            }
            Spacer()
            if own.status.tier != .history, let days = own.daysUntilExpiry(now: now), days < 60 {
                Label(L("Expires in %ld days", max(days, 0)), systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .font(.callout)
                if own.canExtendExpiry {
                    Button(L("Extend…")) { actions.extendExpiry(own) }
                        .controlSize(.small)
                }
            } else if own.status.tier == .history, own.canExtendExpiry {
                // 期限切れの鍵は延ばせば使える段に戻る
                Button(L("Extend…")) { actions.extendExpiry(own) }
                    .controlSize(.small)
            }
            Menu {
                menuItems
            } label: {
                Image(systemName: "ellipsis.circle")
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .fixedSize()
        }
        .padding(.vertical, 4)
        .listRowSeparator(.hidden)
        .contextMenu { menuItems }
    }

    @ViewBuilder private var menuItems: some View {
        Button(L("Extend Expiry…")) { actions.extendExpiry(own) }
            .disabled(!own.canExtendExpiry)
        Button(L("Back Up Secret Key…")) { actions.backUp(own) }
            .disabled(!own.canBackUp)
        Button(L("Mark as Backed Up…")) { actions.markBackedUp(own) }
            .disabled(!own.needsBackup)
        Button(L("Create Revocation Certificate…")) { actions.createRevocationCertificate(own) }
            .disabled(!own.needsRevocationCertificate)
        Divider()
        Button(L("Export Public Key…")) { actions.exportPublicKey(own) }
        Button(L("Send to Keyserver…")) { actions.sendToKeyserver(own) }
        Divider()
        Button(L("Revoke Key…"), role: .destructive) { actions.revoke(own) }
            .disabled(!own.canRevoke)
    }

    private var symbol: String {
        switch own.status.tier {
        case .usable:
            let onCard = [own.status.sign, own.status.decrypt, own.status.authenticate].contains {
                if case .card = $0 { true } else { false }
            }
            return onCard ? "creditcard" : "key.fill"
        case .notOnThisDevice: return "desktopcomputer"
        case .history: return own.key.validity == .revoked ? "xmark.seal" : "clock"
        }
    }

    private var historyNote: String {
        if own.key.validity == .revoked {
            return L("Revoked")
        }
        guard let expires = own.key.expires else { return L("Expired") }
        let date = Date(timeIntervalSince1970: TimeInterval(expires))
        return L("Expired on %@", date.formatted(date: .abbreviated, time: .omitted))
    }
}

/// 自分の鍵の警告ひとつと、それを解消する操作。
struct Warning: View {
    let text: String
    let action: String
    let perform: () -> Void

    var body: some View {
        HStack(spacing: 6) {
            Label(text, systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
            Button(action, action: perform)
                .controlSize(.small)
        }
        .font(.callout)
    }
}

/// 用途ひとつ（署名・復号・SSH）と、それがどこでできるか。
struct UsageLabel: View {
    let name: String
    let availability: Availability

    var body: some View {
        HStack(spacing: 4) {
            Text(name)
            if let place {
                Image(systemName: "checkmark").foregroundStyle(.green)
                Text(place).foregroundStyle(.secondary)
            } else {
                Text("—").foregroundStyle(.tertiary)
            }
        }
        .font(.callout)
    }

    private var place: String? {
        switch availability {
        case .thisDevice: L("This Mac")
        case let .card(serial): L("Card %@", serial)
        case .elsewhere: L("Elsewhere")
        case .none: nil
        }
    }
}

// MARK: - 他者の鍵

struct OthersView: View {
    let model: KeyringModel
    var importKeys: () -> Void = {}
    var notify: (Notice) -> Void = { _ in }
    @State private var certifying: Key?

    var body: some View {
        list
            .sheet(item: Binding(get: { certifying.map(IdentifiedKey.init) }, set: { certifying = $0?.key })) { item in
                CertifySheet(model: model, key: item.key) {
                    let name = item.key.primaryUserId?.text ?? item.key.fingerprint
                    notify(Notice(title: L("Marked as verified"), message: L("%@ is now verified in your keyring.", name)))
                }
            }
    }

    @ViewBuilder private var list: some View {
        let keys = model.keyring.others
        if keys.isEmpty {
            ContentUnavailableView {
                Label(L("No keys from others"), systemImage: "person.2")
            } description: {
                Text(L("Import keys of people you exchange encrypted or signed messages with."))
            } actions: {
                Button(L("Import…"), action: importKeys)
            }
        } else {
            List(keys, id: \.fingerprint) { key in
                let parts = key.primaryUserId.map { UserIdParts($0.text) }
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(spacing: 6) {
                            Text(parts?.name ?? key.fingerprint).font(.headline)
                            if let email = parts?.email {
                                Text(email).foregroundStyle(.secondary)
                            }
                        }
                        Text(Fingerprint.grouped(key.fingerprint))
                            .font(.caption.monospaced())
                            .foregroundStyle(.tertiary)
                            .textSelection(.enabled)
                    }
                    Spacer()
                    Text(validityWord(key)).foregroundStyle(.secondary)
                    if key.canCertify {
                        Button(L("Verify…")) { certifying = key }
                            .controlSize(.small)
                    }
                    Menu {
                        menuItems(key)
                    } label: {
                        Image(systemName: "ellipsis.circle")
                    }
                    .menuStyle(.borderlessButton)
                    .menuIndicator(.hidden)
                    .fixedSize()
                }
                .padding(.vertical, 4)
                .listRowSeparator(.hidden)
                .contextMenu { menuItems(key) }
            }
        }
    }

    @ViewBuilder private func menuItems(_ key: Key) -> some View {
        Button(L("Mark as Verified…")) { certifying = key }
            .disabled(!key.canCertify)
    }

    /// 有効性は記号ではなく言葉で（docs/ui.md）。
    private func validityWord(_ key: Key) -> String {
        switch key.validity {
        case .revoked: L("Revoked")
        case .expired: L("Expired")
        case .full, .ultimate: L("Verified")
        case .marginal: L("Partly verified")
        default: L("Not verified")
        }
    }
}

enum Fingerprint {
    /// 4 桁ずつ区切る（声に出して照らし合わせやすいように）。
    static func grouped(_ fingerprint: String) -> String {
        stride(from: 0, to: fingerprint.count, by: 4).map { start in
            let from = fingerprint.index(fingerprint.startIndex, offsetBy: start)
            let to = fingerprint.index(from, offsetBy: 4, limitedBy: fingerprint.endIndex) ?? fingerprint.endIndex
            return String(fingerprint[from..<to])
        }.joined(separator: " ")
    }
}

/// シートに渡すため、鍵をフィンガープリントで見分ける。
struct IdentifiedKey: Identifiable {
    let key: Key
    var id: String { key.fingerprint }
}
