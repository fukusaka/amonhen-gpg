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
    @State var place: Place = .mine
    /// 使えた鍵（履歴）を開いておくか。
    var showsHistory = false
    @State private var creating = false
    @State private var notice: Notice?
    /// 作ったばかりの鍵（バックアップを勧める）。
    @State private var created: OwnKey?

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
                            model: model, showsHistory: showsHistory, backUp: backUp, create: { creating = true })
                    case .others: OthersView(keys: model.keyring.others)
                    case .staging:
                        ContentUnavailableView(
                            L("Staging"), systemImage: "tray",
                            description: Text(L("Keys found on keyservers or through WKD will be kept here until you import them.")))
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
        .alert(item: $notice) { notice in
            Alert(title: Text(notice.title), message: Text(notice.message))
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
                notice = Notice(title: L("Backed up"), message: L("Saved the secret key to %@.", url.path))
            case let .failure(error):
                notice = Notice(title: L("Cannot back up the secret key"), message: describe(error))
            }
        }
    }
}

// MARK: - 自分の鍵

/// 鍵ごとの操作。行から呼び、シートなどは一覧の側で出す。
struct OwnKeyActions {
    var extendExpiry: (OwnKey) -> Void = { _ in }
    var backUp: (OwnKey) -> Void = { _ in }
}

/// 操作の結果を知らせる（成功も失敗も）。
struct Notice: Identifiable {
    let id = UUID()
    let title: String
    let message: String
}

struct OwnKeysView: View {
    let model: KeyringModel
    @State var showsHistory = false
    var backUp: (OwnKey) -> Void = { _ in }
    var create: () -> Void = {}
    @State private var extending: OwnKey?

    var body: some View {
        list
            .sheet(item: $extending) { ExtendExpirySheet(model: model, own: $0) }
    }

    private var actions: OwnKeyActions {
        OwnKeyActions(extendExpiry: { extending = $0 }, backUp: backUp)
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
                Button(L("New Key…"), action: create)
            }
        } else {
            List {
                if !keyring.usable.isEmpty {
                    Section(L("Usable")) {
                        ForEach(keyring.usable) { OwnKeyRow(own: $0, now: now, actions: actions) }
                    }
                }
                if !keyring.notOnThisDevice.isEmpty {
                    Section(L("Not usable on this Mac")) {
                        ForEach(keyring.notOnThisDevice) { OwnKeyRow(own: $0, now: now, actions: actions) }
                    }
                }
                if !keyring.history.isEmpty {
                    Section {
                        DisclosureGroup(isExpanded: $showsHistory) {
                            ForEach(keyring.history) { OwnKeyRow(own: $0, now: now, actions: actions) }
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
    let keys: [Key]

    var body: some View {
        if keys.isEmpty {
            ContentUnavailableView(
                L("No keys from others"), systemImage: "person.2",
                description: Text(L("Import keys of people you exchange encrypted or signed messages with.")))
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
                }
                .padding(.vertical, 4)
                .listRowSeparator(.hidden)
            }
        }
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
