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
    /// 一覧の検索の語（自分の鍵と他者の鍵。一時保管には鍵サーバーを探す欄が別にあるので使わない）。
    @State var query = ""
    /// 他者の鍵を、確認の状態で絞り込む（次に開いたときも同じ）。
    @AppStorage("OthersFilter") private var othersFilter = KeyFilter.all
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
    /// 名前とメールアドレスを変えたばかりの鍵（更新した公開鍵を渡すよう勧める）。
    @State private var userIdsChanged: OwnKey?
    /// パスフレーズを変えるか確かめている鍵。
    @State private var changingPassphrase: OwnKey?
    /// パスフレーズを変えたばかりの鍵（バックアップを取り直すよう勧める）。
    @State private var passphraseChanged: OwnKey?

    var body: some View {
        NavigationSplitView {
            List(Place.allCases, id: \.self, selection: $place) { place in
                Label(place.title, systemImage: place.symbol)
                    .badge(count(place))
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
                            model: model, query: query, showsHistory: showsHistory,
                            actions: OwnKeyActions(
                                notify: { notice = $0 }, revoked: { revoked = $0 }, userIdsChanged: { userIdsChanged = $0 },
                                backUp: backUp,
                                markBackedUp: { markingBackedUp = $0 }, exportPublicKey: exportPublicKey,
                                sendToKeyserver: { sending = $0 }, changePassphrase: { changingPassphrase = $0 },
                                copySshPublicKey: copySshPublicKey, exportSshPublicKey: exportSshPublicKey,
                                createRevocationCertificate: createRevocationCertificate),
                            create: { creating = true }, importKeys: importKeys)
                        .searchable(text: $query, placement: .toolbar, prompt: L("Name, email or fingerprint"))
                    case .others:
                        OthersView(
                            model: model, query: query, filter: othersFilter, importKeys: importKeys, notify: { notice = $0 },
                            showAll: { othersFilter = .all })
                            .searchable(text: $query, placement: .toolbar, prompt: L("Name, email or fingerprint"))
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
                if place == .others {
                    Menu {
                        Picker(L("Show"), selection: $othersFilter) {
                            ForEach(KeyFilter.allCases, id: \.self) { Text($0.title).tag($0) }
                        }
                        .pickerStyle(.inline)
                    } label: {
                        Label(
                            L("Filter"),
                            systemImage: othersFilter == .all
                                ? "line.3.horizontal.decrease.circle" : "line.3.horizontal.decrease.circle.fill")
                    }
                    .help(othersFilter == .all ? L("Filter") : othersFilter.title)
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
            L("Send to %@?", Keyserver.name(Keyserver.current)),
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
        .alert(
            L("Change the passphrase?"),
            isPresented: Binding(get: { changingPassphrase != nil }, set: { if !$0 { changingPassphrase = nil } }),
            presenting: changingPassphrase
        ) { own in
            Button(L("Change")) { changePassphrase(own) }
            Button(L("Cancel"), role: .cancel) {}
        } message: { _ in
            Text(L("gpg will ask for the current passphrase, then the new one twice. Backups you made earlier stay protected by the current passphrase, so remember it as long as you keep them."))
        }
        .alert(
            L("Passphrase changed"),
            isPresented: Binding(get: { passphraseChanged != nil }, set: { if !$0 { passphraseChanged = nil } }),
            presenting: passphraseChanged
        ) { own in
            Button(L("Back Up…")) { backUp(own) }
            Button(L("Later"), role: .cancel) {}
        } message: { _ in
            Text(L("Backups you made earlier still need the old passphrase. Make a new backup protected by the new one."))
        }
        .alert(
            L("Names and email addresses changed"),
            isPresented: Binding(get: { userIdsChanged != nil }, set: { if !$0 { userIdsChanged = nil } }),
            presenting: userIdsChanged
        ) { own in
            Button(L("Send to Keyserver…")) { sending = own }
            Button(L("Export Public Key…")) { exportPublicKey(own) }
            Button(L("Later"), role: .cancel) {}
        } message: { _ in
            Text(L("Others see the change only when they get the updated public key, from a keyserver or from you."))
        }
        .alert(item: $notice) { notice in
            Alert(title: Text(notice.title), message: Text(notice.message))
        }
    }

    /// 鍵のファイルを選ばせ、取り込む。秘密鍵を含むときはパスフレーズを gpg が聞く。
    /// サイドバーに出す鍵の数（一時保管は出さない）。
    private func count(_ place: Place) -> Int {
        switch place {
        case .mine: model.keyring.usable.count + model.keyring.notOnThisDevice.count + model.keyring.history.count
        case .others: model.keyring.others.count
        case .staging: 0
        }
    }

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

    /// 認証サブ鍵の公開鍵を、`authorized_keys` に貼る 1 行としてコピーする。
    private func copySshPublicKey(_ own: OwnKey) {
        guard let subkey = own.sshSubkey(now: UInt64(Date().timeIntervalSince1970)) else { return }
        let fingerprint = subkey.fingerprint
        Task {
            switch await model.perform({ try $0.exportSshKey(fingerprint: fingerprint) }) {
            case let .success(line):
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(line, forType: .string)
                notice = Notice(title: L("Copied"), message: sshNote(own, L("Copied the SSH public key. Paste it as one line into ~/.ssh/authorized_keys on the server.")))
            case let .failure(error):
                notice = Notice(title: L("Cannot copy the SSH public key"), message: describe(error))
            }
        }
    }

    /// 認証サブ鍵の公開鍵を、`authorized_keys` の 1 行の形でファイルに書き出す。
    private func exportSshPublicKey(_ own: OwnKey) {
        guard let subkey = own.sshSubkey(now: UInt64(Date().timeIntervalSince1970)) else { return }
        let panel = NSSavePanel()
        panel.title = L("Export SSH Public Key")
        panel.nameFieldStringValue = own.sshPublicKeyFileName
        guard panel.runModal() == .OK, let url = panel.url else { return }
        Task {
            switch await model.perform({ try $0.exportSshPublicKey(subkey, to: url) }) {
            case .success:
                notice = Notice(title: L("Exported"), message: sshNote(own, L("Saved the SSH public key to %@.", url.path)))
            case let .failure(error):
                notice = Notice(title: L("Cannot export the SSH public key"), message: describe(error))
            }
        }
    }

    /// gpg-agent がまだこの鍵を SSH に出していなければ、そう添える（公開鍵を置いても、ssh が秘密鍵を使えない）。
    private func sshNote(_ own: OwnKey, _ message: String) -> String {
        own.ssh ? message : message + "\n\n" + L("To log in with it, gpg-agent must also offer this key to ssh. It does not yet: the row does not show SSH ✓.")
    }

    /// 公開鍵を鍵サーバーに送る（確かめたあと）。秘密鍵は送らない。
    private func send(_ own: OwnKey) {
        let fingerprint = own.key.fingerprint
        Task {
            switch await model.perform({ try $0.sendKeys(fingerprints: [fingerprint], keyserver: Keyserver.current) }) {
            case .success:
                notice = Notice(title: L("Sent"), message: L("Sent the public key to %@.", Keyserver.name(Keyserver.current)))
            case let .failure(error):
                notice = Notice(title: L("Cannot send the public key"), message: describe(error))
            }
        }
    }

    /// パスフレーズを変える。今のものと新しいものは pinentry が聞く（アプリは触れない）。取り消したときは何も言わない。
    private func changePassphrase(_ own: OwnKey) {
        let fingerprint = own.key.fingerprint
        Task {
            switch await model.perform({ try $0.changePassphrase(fingerprint: fingerprint) }) {
            case .success:
                passphraseChanged = model.keyring.own(fingerprint) ?? own
            case let .failure(error) where isCanceled(error): break
            case let .failure(error):
                notice = Notice(title: L("Cannot change the passphrase"), message: describe(error))
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
    /// 名前とメールアドレスを変えたあと（更新した公開鍵を渡すよう勧める）。
    var userIdsChanged: (OwnKey) -> Void = { _ in }
    var showDetails: (OwnKey) -> Void = { _ in }
    var extendExpiry: (OwnKey) -> Void = { _ in }
    var editUserIds: (OwnKey) -> Void = { _ in }
    var revoke: (OwnKey) -> Void = { _ in }
    var delete: (OwnKey) -> Void = { _ in }
    var backUp: (OwnKey) -> Void = { _ in }
    var markBackedUp: (OwnKey) -> Void = { _ in }
    var exportPublicKey: (OwnKey) -> Void = { _ in }
    var sendToKeyserver: (OwnKey) -> Void = { _ in }
    var changePassphrase: (OwnKey) -> Void = { _ in }
    var copySshPublicKey: (OwnKey) -> Void = { _ in }
    var exportSshPublicKey: (OwnKey) -> Void = { _ in }
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
    /// 検索の語。空でなければ、合う鍵だけを出し、SSH の段は隠して、使えた鍵の段は開く。
    var query = ""
    @State var showsHistory = false
    /// 行の操作（期限の延長は、ここでシートを出す）。
    var actions = OwnKeyActions()
    var create: () -> Void = {}
    var importKeys: () -> Void = {}
    @State private var extending: OwnKey?
    @State private var revoking: OwnKey?
    @Environment(\.openWindow) private var openWindow
    @State private var deleting: OwnKey?
    @State private var editingUserIds: OwnKey?

    var body: some View {
        list
            .sheet(item: $extending) { own in
                ExtendExpirySheet(model: model, own: own) { actions.notify(Notice(extended: $0)) }
            }
            .sheet(item: $deleting) { own in
                DeleteKeySheet(model: model, own: own, backUp: actions.backUp, revoke: { revoking = $0 }) { name in
                    actions.notify(Notice(title: L("Key deleted"), message: L("Deleted %@ from this Mac.", name)))
                }
            }
            .sheet(item: $editingUserIds) { own in
                UserIdsSheet(model: model, own: own, onChanged: actions.userIdsChanged)
            }
            .sheet(item: $revoking) { own in
                RevokeKeySheet(model: model, own: own, backUp: actions.backUp, onRevoked: actions.revoked)
            }
    }

    private var rowActions: OwnKeyActions {
        var actions = actions
        actions.extendExpiry = { extending = $0 }
        actions.editUserIds = { editingUserIds = $0 }
        actions.revoke = { revoking = $0 }
        actions.showDetails = { openWindow(id: "key", value: $0.key.fingerprint) }
        actions.delete = { deleting = $0 }
        return actions
    }

    @ViewBuilder private var list: some View {
        let searching = !query.trimmingCharacters(in: .whitespaces).isEmpty
        let keyring = model.keyring.filtered(by: query)
        let now = UInt64(Date().timeIntervalSince1970)
        if searching && keyring.usable.isEmpty && keyring.notOnThisDevice.isEmpty && keyring.history.isEmpty {
            NoSearchResults(query: query)
        } else if keyring.usable.isEmpty && keyring.notOnThisDevice.isEmpty && keyring.history.isEmpty {
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
                if !searching {
                    SshSection(model: model, notify: actions.notify)
                }
                if !keyring.history.isEmpty {
                    Section {
                        DisclosureGroup(isExpanded: searching ? .constant(true) : $showsHistory) {
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
                OtherUserIdLines(key: own.key)
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
        // 行のどこをダブルクリックしても詳細を開く（ボタンの押下は妨げない）
        .contentShape(Rectangle())
        .simultaneousGesture(TapGesture(count: 2).onEnded { actions.showDetails(own) })
        .contextMenu { menuItems }
    }

    @ViewBuilder private var menuItems: some View {
        Button(L("Details…")) { actions.showDetails(own) }
        Divider()
        Button(L("Extend Expiry…")) { actions.extendExpiry(own) }
            .disabled(!own.canExtendExpiry)
        Button(L("Names and Email Addresses…")) { actions.editUserIds(own) }
            .disabled(!own.canEditUserIds)
        Button(L("Change Passphrase…")) { actions.changePassphrase(own) }
            .disabled(!own.canChangePassphrase)
        Button(L("Back Up Secret Key…")) { actions.backUp(own) }
            .disabled(!own.canBackUp)
        Button(L("Mark as Backed Up…")) { actions.markBackedUp(own) }
            .disabled(!own.needsBackup)
        Button(L("Create Revocation Certificate…")) { actions.createRevocationCertificate(own) }
            .disabled(!own.needsRevocationCertificate)
        Divider()
        Button(L("Export Public Key…")) { actions.exportPublicKey(own) }
        Button(L("Send to Keyserver…")) { actions.sendToKeyserver(own) }
        Button(L("Copy SSH Public Key")) { actions.copySshPublicKey(own) }
            .disabled(own.sshSubkey(now: now) == nil)
        Button(L("Export SSH Public Key…")) { actions.exportSshPublicKey(own) }
            .disabled(own.sshSubkey(now: now) == nil)
        Divider()
        Button(L("Revoke Key…"), role: .destructive) { actions.revoke(own) }
            .disabled(!own.canRevoke)
        Divider()
        Button(L("Delete Key with Secret Key…"), role: .destructive) { actions.delete(own) }
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
    /// 検索の語。空でなければ、合う鍵だけを出す。
    var query = ""
    /// 確認の状態での絞り込み。
    var filter = KeyFilter.all
    var importKeys: () -> Void = {}
    var notify: (Notice) -> Void = { _ in }
    /// 絞り込みを外す（絞り込んで 1 つもないとき）。
    var showAll: () -> Void = {}
    @State private var certifying: Key?
    @Environment(\.openWindow) private var openWindow
    @State private var deleting: Key?
    @State private var selection: KeyTableRow.ID?
    /// 行の並べ替えと、列の表示・並び・幅。次に開いたときも同じになるよう覚えておく。
    @State private var sortOrder = OthersTableSettings.sortOrder
    @State private var columns = OthersTableSettings.columns

    var body: some View {
        list
            .sheet(item: Binding(get: { certifying.map(IdentifiedKey.init) }, set: { certifying = $0?.key })) { item in
                CertifySheet(model: model, key: item.key) {
                    let name = item.key.primaryUserId?.text ?? item.key.fingerprint
                    notify(Notice(title: L("Marked as verified"), message: L("%@ is now verified in your keyring.", name)))
                }
            }
            .alert(
                L("Delete the public key of %@?", deleting?.primaryUserId?.text ?? ""),
                isPresented: Binding(get: { deleting != nil }, set: { if !$0 { deleting = nil } }),
                presenting: deleting
            ) { key in
                Button(L("Delete"), role: .destructive) { delete(key) }
                Button(L("Cancel"), role: .cancel) {}
            } message: { _ in
                Text(L("You will no longer be able to encrypt to it or verify its signatures. Your verification of it is deleted too. You can import it again later."))
            }
    }

    @ViewBuilder private var list: some View {
        let found = model.keyring.filtered(by: query).others
        let keys = found.filter(filter.includes)
        if keys.isEmpty, !query.trimmingCharacters(in: .whitespaces).isEmpty, filter == .all || found.isEmpty {
            NoSearchResults(query: query)
        } else if keys.isEmpty, filter != .all, !found.isEmpty || !model.keyring.others.isEmpty {
            ContentUnavailableView {
                Label(L("No %@ Keys", filter.title), systemImage: "line.3.horizontal.decrease.circle")
            } actions: {
                Button(L("Show All"), action: showAll)
            }
        } else if keys.isEmpty {
            ContentUnavailableView {
                Label(L("No keys from others"), systemImage: "person.2")
            } description: {
                Text(L("Import keys of people you exchange encrypted or signed messages with."))
            } actions: {
                Button(L("Import…"), action: importKeys)
            }
        } else {
            table(keys.map(KeyTableRow.init).sorted(using: sortOrder))
        }
    }

    /// 他者の鍵の表。どの列でも並べ替えられる。ダブルクリックで詳細、右クリックで操作。期限切れ・失効の鍵は薄く出す。
    private func table(_ rows: [KeyTableRow]) -> some View {
        Table(rows, selection: $selection, sortOrder: $sortOrder, columnCustomization: $columns) {
            TableColumn(L("Name"), value: \.name) { row in
                HStack(spacing: 4) {
                    Text(row.name).fontWeight(.medium)
                    if !row.otherUserIds.isEmpty {
                        Text(verbatim: "+\(row.otherUserIds.count)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .help(row.otherUserIds.map(\.text).joined(separator: "\n"))
                    }
                }
                .dimmed(row.isInactive)
            }
            .width(min: 90, ideal: 130)
            .customizationID("name")
            // 名前は消せない（どの鍵か分からなくなる）
            .disabledCustomizationBehavior(.visibility)
            TableColumn(L("Email"), value: \.email) { row in
                Text(row.email).dimmed(row.isInactive)
            }
            .width(min: 120, ideal: 170)
            .customizationID("email")
            TableColumn(L("Verification"), value: \.verificationOrder) { row in
                HStack(spacing: 6) {
                    Text(validityWord(row.key.validity)).foregroundStyle(.secondary)
                    if row.key.canCertify {
                        Button(L("Verify…")) { certifying = row.key }
                            .buttonStyle(.bordered)
                            .controlSize(.small)
                    }
                }
            }
            .width(min: 130, ideal: 130)
            .customizationID("verification")
            TableColumn(L("Key ID"), value: \.keyId) { row in
                Text(Fingerprint.grouped(row.keyId))
                    .font(.callout.monospaced())
                    .textSelection(.enabled)
                    .dimmed(row.isInactive)
            }
            .width(min: 150, ideal: 150)
            .customizationID("keyId")
            TableColumn(L("Created"), value: \.created) { row in
                Text(shortDate(row.key.created) ?? "—").dimmed(row.isInactive)
            }
            .width(min: 80, ideal: 85)
            .customizationID("created")
            TableColumn(L("Expires"), value: \.expires) { row in
                Group {
                    switch row.key.validity {
                    case .revoked: Text(L("Revoked"))
                    case .expired: Text(L("Expired"))
                    default: Text(shortDate(row.key.expires) ?? L("Never"))
                    }
                }
                .dimmed(row.isInactive)
            }
            .width(min: 80, ideal: 85)
            .customizationID("expires")
            TableColumn(L("Algorithm"), value: \.algorithm) { row in
                Text(row.algorithm).dimmed(row.isInactive)
            }
            .width(min: 70, ideal: 75)
            .customizationID("algorithm")
        }
        .contextMenu(forSelectionType: KeyTableRow.ID.self) { ids in
            if let key = rows.first(where: { ids.contains($0.id) })?.key {
                menuItems(key)
            }
        } primaryAction: { ids in
            if let key = rows.first(where: { ids.contains($0.id) })?.key { openWindow(id: "key", value: key.fingerprint) }
        }
        .focusedSceneValue(\.selectedKeyFingerprint, selection)
        .onChange(of: sortOrder) { OthersTableSettings.sortOrder = sortOrder }
        .onChange(of: columns) { OthersTableSettings.columns = columns }
    }

    private func shortDate(_ seconds: UInt64?) -> String? {
        seconds.map { Date(timeIntervalSince1970: TimeInterval($0)).formatted(date: .numeric, time: .omitted) }
    }

    @ViewBuilder private func menuItems(_ key: Key) -> some View {
        Button(L("Details…")) { openWindow(id: "key", value: key.fingerprint) }
        Button(L("Mark as Verified…")) { certifying = key }
            .disabled(!key.canCertify)
        Divider()
        Button(L("Delete Public Key…"), role: .destructive) { deleting = key }
    }

    /// 公開鍵を消す（確かめたあと）。秘密鍵のある鍵は gpg が拒む。
    private func delete(_ key: Key) {
        let fingerprint = key.fingerprint
        let name = key.primaryUserId?.text ?? key.fingerprint
        Task {
            switch await model.perform({ try $0.deletePublicKey(fingerprint: fingerprint) }) {
            case .success: break
            case let .failure(error):
                notify(Notice(title: L("Cannot delete %@", name), message: describe(error)))
            }
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

    /// 4 桁ずつ区切り、前半と後半の 2 行にする（40 桁なら 5 組ずつ）。
    static func lines(_ fingerprint: String) -> String {
        let groups = grouped(fingerprint).split(separator: " ")
        let half = (groups.count + 1) / 2
        return [groups[..<half], groups[half...]].map { $0.joined(separator: " ") }.joined(separator: "\n")
    }
}

/// シートに渡すため、鍵をフィンガープリントで見分ける。
struct IdentifiedKey: Identifiable {
    let key: Key
    var id: String { key.fingerprint }
}

/// 一覧の行で、主な名前の下に出すほかの名前とメールアドレス。失効したものは、消えたのではないと分かるよう
/// 後ろに薄く取り消し線で出す。主と同じ名前なら、メールアドレスだけを出す。
struct OtherUserIdLines: View {
    let key: Key

    var body: some View {
        let primary = key.primaryUserId.map { UserIdParts($0.text).name }
        let others = key.namedUserIds.filter { $0 != key.primaryUserId }
        ForEach(others.filter { $0.validity != .revoked } + others.filter { $0.validity == .revoked }, id: \.self) { uid in
            let other = UserIdParts(uid.text)
            let revoked = uid.validity == .revoked
            Text(other.name == primary ? other.email ?? uid.text : uid.text)
                .strikethrough(revoked)
                .foregroundStyle(revoked ? .tertiary : .secondary)
                .help(revoked ? L("Revoked") : "")
        }
    }
}

/// 検索に合う鍵がないとき。システムの `ContentUnavailableView.search` はアプリの訳を使わないので、自分で出す。
struct NoSearchResults: View {
    let query: String

    var body: some View {
        ContentUnavailableView {
            Label(L("No Matching Keys"), systemImage: "magnifyingglass")
        } description: {
            Text(L("No key has a name, email address or fingerprint matching “%@”.", query))
        }
    }
}

extension View {
    /// もう使えない鍵（期限切れ・失効）の行を薄く出す。
    func dimmed(_ dim: Bool) -> some View {
        foregroundStyle(dim ? AnyShapeStyle(.tertiary) : AnyShapeStyle(.primary))
    }
}

/// 他者の鍵の表で覚えておくもの（UserDefaults）。行の並べ替えは、列の名前と向きにして残す。
enum OthersTableSettings {
    private static let sortKey = "OthersTableSort"
    private static let columnsKey = "OthersTableColumns"
    /// 並べ替えられる列（名前は列の customizationID と同じ）。
    private static let sortable: [(id: String, comparator: KeyPathComparator<KeyTableRow>)] = [
        ("name", KeyPathComparator(\.name)), ("email", KeyPathComparator(\.email)),
        ("verification", KeyPathComparator(\.verificationOrder)), ("keyId", KeyPathComparator(\.keyId)),
        ("created", KeyPathComparator(\.created)), ("expires", KeyPathComparator(\.expires)),
        ("algorithm", KeyPathComparator(\.algorithm)),
    ]

    static var sortOrder: [KeyPathComparator<KeyTableRow>] {
        get {
            let saved = UserDefaults.standard.stringArray(forKey: sortKey) ?? []
            let comparators = saved.compactMap { item -> KeyPathComparator<KeyTableRow>? in
                let parts = item.split(separator: ":")
                guard let id = parts.first, var comparator = sortable.first(where: { $0.id == id })?.comparator else { return nil }
                comparator.order = parts.last == "reverse" ? .reverse : .forward
                return comparator
            }
            return comparators.isEmpty ? [KeyPathComparator(\.name)] : comparators
        }
        set {
            let saved = newValue.compactMap { comparator -> String? in
                guard let id = sortable.first(where: { $0.comparator.keyPath == comparator.keyPath })?.id else { return nil }
                return "\(id):\(comparator.order == .reverse ? "reverse" : "forward")"
            }
            UserDefaults.standard.set(saved, forKey: sortKey)
        }
    }

    static var columns: TableColumnCustomization<KeyTableRow> {
        get {
            guard let data = UserDefaults.standard.data(forKey: columnsKey),
                let columns = try? JSONDecoder().decode(TableColumnCustomization<KeyTableRow>.self, from: data)
            else { return TableColumnCustomization() }
            return columns
        }
        set {
            UserDefaults.standard.set(try? JSONEncoder().encode(newValue), forKey: columnsKey)
        }
    }
}

extension KeyFilter {
    /// フィルターのメニューに出す名前。
    var title: String {
        switch self {
        case .all: L("All")
        case .verified: L("Verified")
        case .unverified: L("Not verified")
        case .inactive: L("Expired or Revoked")
        }
    }
}
