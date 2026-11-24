import AmonhenGpgKit
import AppKit
import SwiftUI

/// SSH の署名者（docs/allowed-signers.md）。GPG で署名する人は、他者の鍵で確認済みにする（git は gpg に任せる）。人の SSH の署名用の鍵を一覧ごとにまとめ、git が読む allowed signers の
/// ファイルを書く。記録は自分の鍵で署名する。git の設定は変えず、コマンドを見せる。
struct SignersView: View {
    let model: SignersModel
    let keyring: KeyringModel
    var notify: (Notice) -> Void = { _ in }
    /// 受け入れ前の鍵の画面を開く（取ってきた鍵はそこで受け入れる）。
    var showKeysToAccept: () -> Void = {}
    /// 記録に署名する自分の鍵（次に開いたときも同じ）。
    @AppStorage(SignersModel.signerDefaultsKey) private var signerFingerprint = ""
    @State private var addingPerson = false
    @State private var addingList = false
    @State private var removingPerson: Signer?
    /// 退役させるか、除くか確かめている鍵（人のメールアドレスとフィンガープリント）。
    @State private var retiring: KeyRef?
    @State private var removingKey: KeyRef?
    @State private var removingList: SignerList?

    private var signers: [OwnKey] { keyring.keyring.dataSigners }

    /// 記録に署名する鍵。選んだ鍵がなければ、署名できる最初の自分の鍵。
    private var signer: OwnKey? {
        signers.first { $0.key.fingerprint == signerFingerprint } ?? signers.first
    }

    var body: some View {
        content
            .toolbar {
                if signers.count > 1 {
                    Picker(L("Sign with"), selection: Binding(
                        get: { signer?.key.fingerprint ?? "" }, set: { signerFingerprint = $0 })
                    ) {
                        ForEach(signers) { own in
                            Text(own.key.primaryUserId?.text ?? own.key.fingerprint).tag(own.key.fingerprint)
                        }
                    }
                    .help(L("The key of yours that signs the record of signers"))
                }
                Button(action: importFile) {
                    Label(L("Import Allowed Signers File…"), systemImage: "square.and.arrow.down")
                }
                .help(L("Import Allowed Signers File…"))
                .disabled(signer == nil)
                Button {
                    addingList = true
                } label: {
                    Label(L("New List…"), systemImage: "list.bullet.rectangle")
                }
                .help(L("New List…"))
                .disabled(signer == nil)
                Button {
                    addingPerson = true
                } label: {
                    Label(L("Add Person…"), systemImage: "person.badge.plus")
                }
                .help(L("Add Person…"))
                .disabled(signer == nil)
                Button {
                    Task { await model.checkAll() }
                } label: {
                    Label(L("Check for Changes"), systemImage: "arrow.triangle.2.circlepath")
                }
                .help(L("Check for Changes"))
                .disabled(model.record.people.isEmpty || !model.checking.isEmpty)
                // 空のときは図が真ん中に出ているので、誰かいるときだけ
                if !isEmpty {
                    FlowHelpButton(title: L("SSH Signers"), message: Self.flowMessage, diagram: .sshSigners)
                }
            }
            .sheet(isPresented: $addingPerson) {
                AddSignerSheet(record: model.record) { email, account, lists in
                    var edits: [SignerEdit] = [.addPerson(email: email, account: account)]
                    edits += lists.map { .addMember(list: $0, email: email) }
                    if await save(edits, title: L("Cannot add the person")) {
                        if let person = model.record.people.first(where: { $0.email == email }) {
                            await model.check(person)
                        }
                        return true
                    }
                    return false
                }
            }
            .sheet(isPresented: $addingList) {
                NewSignerListSheet(record: model.record) { id, name in
                    await save([.addList(id: id, name: name)], title: L("Cannot add the list"))
                }
            }
            .alert(
                L("Remove %@?", removingPerson?.email ?? ""),
                isPresented: Binding(get: { removingPerson != nil }, set: { if !$0 { removingPerson = nil } }),
                presenting: removingPerson
            ) { person in
                Button(L("Remove Person"), role: .destructive) {
                    Task { await save([.removePerson(email: person.email)], title: L("Cannot remove the person")) }
                }
                Button(L("Cancel"), role: .cancel) {}
            } message: { _ in
                Text(L("Their keys are removed from every list. git stops verifying their commits, including old ones. To keep old commits verified, retire their keys instead."))
            }
            .alert(
                L("Retire this key?"),
                isPresented: Binding(get: { retiring != nil }, set: { if !$0 { retiring = nil } }),
                presenting: retiring
            ) { ref in
                Button(L("Retire")) {
                    Task { await save([.retireKey(email: ref.email, fingerprint: ref.fingerprint)], title: L("Cannot retire the key")) }
                }
                Button(L("Cancel"), role: .cancel) {}
            } message: { ref in
                Text(L("git keeps verifying commits %@ signed with %@ before now, and stops for later ones. Retire a key the owner no longer uses, or one that may be in someone else's hands.", ref.email, ref.fingerprint))
            }
            .alert(
                L("Remove this key?"),
                isPresented: Binding(get: { removingKey != nil }, set: { if !$0 { removingKey = nil } }),
                presenting: removingKey
            ) { ref in
                Button(L("Remove Key"), role: .destructive) {
                    Task { await save([.removeKey(email: ref.email, fingerprint: ref.fingerprint)], title: L("Cannot remove the key")) }
                }
                Button(L("Cancel"), role: .cancel) {}
            } message: { ref in
                Text(L("git stops verifying every commit signed with %@, including old ones. To keep old commits verified, retire it instead.", ref.fingerprint))
            }
            .alert(
                L("Remove the list %@?", removingList?.name ?? ""),
                isPresented: Binding(get: { removingList != nil }, set: { if !$0 { removingList = nil } }),
                presenting: removingList
            ) { list in
                Button(L("Remove List"), role: .destructive) {
                    Task { await save([.removeList(id: list.id)], title: L("Cannot remove the list")) }
                }
                Button(L("Cancel"), role: .cancel) {}
            } message: { list in
                Text(L("Its file %@ is deleted. git settings that point at it stop verifying signatures. The people stay.", signersFile(dir: model.dir.path, list: list.id)))
            }
            .task { await model.reload(keyring.gpg) }
    }

    private static var flowMessage: String {
        L("Add the people whose SSH-signed commits you want git to verify. Their signing keys are fetched from GitHub or GitLab, and you accept each one. Put people into lists, one file per team or repository.")
    }

    private var isEmpty: Bool { model.record.people.isEmpty && model.record.lists.isEmpty }

    @ViewBuilder private var content: some View {
        if let failure = model.failure {
            ContentUnavailableView(
                L("Cannot read the record of signers"), systemImage: "exclamationmark.triangle", description: Text(failure))
        } else if signer == nil {
            ContentUnavailableView(
                L("No key of yours can sign"), systemImage: "signature",
                description: Text(L("The record of signers is signed with a key of yours. Create or import a key that can sign on this Mac.")))
        } else if isEmpty {
            EmptyPlace(L("No signers yet"), systemImage: "signature", message: Self.flowMessage, diagram: .sshSigners) {
                Button(L("New List…")) { addingList = true }
                Button(L("Add Person…")) { addingPerson = true }
                Button(L("Import Allowed Signers File…"), action: importFile)
            }
        } else {
            list
        }
    }

    private var list: some View {
        let record = model.record
        return List {
            statusSection
            ForEach(record.lists, id: \.id) { list in
                Section {
                    SignerListFile(path: signersFile(dir: model.dir.path, list: list.id), state: fileState(list))
                    if list.members.isEmpty {
                        Text(L("No one in this list yet. Add people from their menu."))
                            .foregroundStyle(.secondary)
                    }
                    // 人の段と同じ ID（メールアドレス）だと、List が行を取り違えるので、一覧の ID を前に付ける
                    ForEach(list.members.map { (id: "\(list.id)/\($0)", email: $0) }, id: \.id) { member in
                        let email = member.email
                        HStack {
                            Text(email)
                            Spacer()
                            Button(L("Remove from List")) {
                                Task { await save([.removeMember(list: list.id, email: email)], title: L("Cannot change the list")) }
                            }
                            .controlSize(.small)
                        }
                    }
                } header: {
                    HStack {
                        Text(list.name)
                        Spacer()
                        Button(L("Remove List…")) { removingList = list }
                            .buttonStyle(.borderless)
                            .font(.caption)
                    }
                }
            }
            Section(L("People")) {
                if record.people.isEmpty {
                    Text(L("No one yet. Add people with Add Person…."))
                        .foregroundStyle(.secondary)
                }
                ForEach(record.people.map { (id: "person/\($0.email)", person: $0) }, id: \.id) { item in
                    let person = item.person
                    SignerRow(
                        person: person, record: record, changes: model.changes[person.email],
                        checking: model.checking.contains(person.email),
                        actions: SignerRowActions(
                            showKeysToAccept: showKeysToAccept,
                            retire: { retiring = KeyRef(email: person.email, fingerprint: $0) },
                            removeKey: { removingKey = KeyRef(email: person.email, fingerprint: $0) },
                            recordAlso: { fingerprint, source in
                                guard let key = person.keys.first(where: { $0.fingerprint == fingerprint }) else { return }
                                Task {
                                    await save(
                                        [.acceptKey(email: person.email, key: key.key, source: source, checked: .account)],
                                        title: L("Cannot change the key"))
                                }
                            },
                            check: { Task { await model.check(person) } },
                            addTo: { list in
                                Task { await save([.addMember(list: list, email: person.email)], title: L("Cannot change the list")) }
                            },
                            remove: { removingPerson = person }))
                }
            }
        }
    }

    /// 記録の署名と、ファイルが記録と合っているか。
    @ViewBuilder private var statusSection: some View {
        let differing = (model.loaded?.files ?? []).filter { $0.state != .matches }
        switch model.loaded?.signature {
        case .missing?, .invalid?:
            Section {
                Label(L("The record is not signed by a key of yours. It may have been changed outside the app. Check the people and keys below; saving signs it again."), systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
            }
        default:
            EmptyView()
        }
        if !differing.isEmpty {
            Section {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(differing, id: \.list) { file in
                        Label(
                            file.state == .missing
                                ? L("%@ is missing.", (file.path as NSString).lastPathComponent)
                                : L("%@ was changed outside the app.", (file.path as NSString).lastPathComponent),
                            systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                    }
                    Button(L("Write the Files Again")) {
                        Task { await save([], title: L("Cannot write the files")) }
                    }
                }
            }
        }
    }

    private func fileState(_ list: SignerList) -> FileState? {
        model.loaded?.files.first { $0.list == list.id }?.state
    }

    /// 既存の allowed signers のファイルを選ばせて読み、行を受け入れ前の鍵に置く。ファイルは変えない。
    private func importFile() {
        let panel = NSOpenPanel()
        panel.title = L("Import Allowed Signers File")
        panel.message = L("Choose an allowed signers file, such as the one gpg.ssh.allowedSignersFile points at. Its keys wait in Keys to Accept; the file is not changed.")
        panel.directoryURL = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh")
        panel.showsHiddenFiles = true
        panel.canChooseDirectories = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        Task {
            switch await model.readFile(url) {
            case let .success(count):
                let skipped = model.skipped.filter { $0.path == url.path }.count
                notify(Notice(
                    title: L("Read %@", url.lastPathComponent),
                    message: L("%ld keys wait in Keys to Accept. %ld lines could not be imported; Keys to Accept shows why.", count, skipped)))
                if count > 0 || skipped > 0 { showKeysToAccept() }
            case let .failure(error):
                notify(Notice(title: L("Cannot read the file"), message: describe(error)))
            }
        }
    }

    /// 記録を変えて保存する。取り消しは知らせない。
    @discardableResult
    private func save(_ edits: [SignerEdit], title: String) async -> Bool {
        await model.save(edits, keyring: keyring, title: title, notify: notify)
    }
}

/// 一覧のファイルと、git に使わせるコマンド。
private struct SignerListFile: View {
    let path: String
    let state: FileState?

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Image(systemName: "doc.text")
                .foregroundStyle(.secondary)
            Text(path)
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer()
            Menu(L("Use with git")) {
                Button(L("Copy Command for All Repositories")) { copy(Signers.globalCommand(path: path)) }
                Button(L("Copy Command for One Repository")) { copy(Signers.repositoryCommand(path: path)) }
                Divider()
                Button(L("Show in Finder")) {
                    NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
                }
                .disabled(state == nil || state == .missing)
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
            .help(L("git reads this file when gpg.ssh.allowedSignersFile points at it. The app does not change git's settings; run the command yourself (for one repository, run it inside that repository)."))
        }
    }

    private func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}

struct SignerRowActions {
    var showKeysToAccept: () -> Void = {}
    var retire: (String) -> Void = { _ in }
    var removeKey: (String) -> Void = { _ in }
    /// ファイルなどから受け入れた鍵が、アカウントにもあったと記録する。
    var recordAlso: (String, KeySource) -> Void = { _, _ in }
    var check: () -> Void = {}
    var addTo: (String) -> Void = { _ in }
    var remove: () -> Void = {}
}

/// 1 人。アカウント、入っている一覧、受け入れた鍵、取り直して分かった変化。
private struct SignerRow: View {
    let person: Signer
    let record: SignerRecord
    let changes: PersonChanges?
    let checking: Bool
    let actions: SignerRowActions

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline) {
                Text(person.email).font(.headline)
                Text(person.accounts.map(\.display).joined(separator: ", "))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                if checking {
                    ProgressView().controlSize(.small)
                }
                Menu {
                    Button(L("Check for Changes"), action: actions.check)
                        .disabled(person.accounts.isEmpty || checking)
                    let addable = record.lists.filter { !$0.members.contains(person.email) }
                    if addable.isEmpty {
                        // 中が空のメニューは押せるように見えるので、押せない項目にする
                        Button(L("Add to List")) {}.disabled(true)
                    } else {
                        Menu(L("Add to List")) {
                            ForEach(addable, id: \.id) { list in
                                Button(list.name) { actions.addTo(list.id) }
                            }
                        }
                    }
                    Divider()
                    Button(L("Remove Person…"), role: .destructive, action: actions.remove)
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
                .menuStyle(.borderlessButton)
                .menuIndicator(.hidden)
                .fixedSize()
            }
            let lists = record.lists(of: person.email)
            Text(lists.isEmpty ? L("In no list, so git does not see these keys.") : L("Lists: %@", lists.map(\.name).joined(separator: ", ")))
                .font(.caption)
                .foregroundStyle(lists.isEmpty ? .orange : .secondary)
            ForEach(person.keys, id: \.fingerprint) { key in
                AcceptedKeyRow(
                    key: key,
                    gone: changes?.gone.contains(key.fingerprint) == true || changes?.absent.contains(key.fingerprint) == true,
                    also: changes?.also[key.fingerprint],
                    retire: { actions.retire(key.fingerprint) }, remove: { actions.removeKey(key.fingerprint) },
                    recordAlso: { actions.recordAlso(key.fingerprint, $0) })
            }
            if let new = changes?.new, !new.isEmpty {
                HStack {
                    Label(L("%ld new keys wait in Keys to Accept.", new.count), systemImage: "tray.and.arrow.down")
                        .font(.caption)
                        .foregroundStyle(.blue)
                    Button(L("Show"), action: actions.showKeysToAccept)
                        .controlSize(.small)
                }
            }
            ForEach(Array((changes?.failures ?? []).enumerated()), id: \.offset) { _, failure in
                Label(L("Cannot fetch from %@: %@", failure.account.display, describe(failure.error)), systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
            if let changes, changes.isEmpty {
                Text(L("No changes on the accounts."))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 4)
    }
}

/// 受け入れた鍵。
private struct AcceptedKeyRow: View {
    let key: SignerKey
    /// アカウントから消えた鍵。
    let gone: Bool
    /// アカウントにもあった（ファイルなどから受け入れた鍵）。
    let also: KeySource?
    let retire: () -> Void
    let remove: () -> Void
    let recordAlso: (KeySource) -> Void

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: key.retired ? "key.slash" : "key")
                .foregroundStyle(key.retired ? .secondary : .primary)
            VStack(alignment: .leading, spacing: 2) {
                Text(key.fingerprint)
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
                Text(detail)
                    .font(.caption)
                    .foregroundStyle(gone ? .orange : .secondary)
            }
            Spacer()
            if let also {
                Button(L("Record as Also on the Account")) { recordAlso(also) }
                    .controlSize(.small)
                    .help(L("The same key is on %@. Record it, so later checks compare the key with that account.", Account(host: also.host, user: also.user).display))
            }
            if gone, !key.retired {
                Button(L("Retire"), action: retire)
                    .controlSize(.small)
                    .help(L("Commits signed before now stay verified; later ones are not."))
            }
            Menu {
                Button(L("Retire Key…"), action: retire)
                    .disabled(key.retired)
                Divider()
                Button(L("Remove Key…"), role: .destructive, action: remove)
            } label: {
                Image(systemName: "ellipsis.circle")
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .fixedSize()
        }
    }

    private var detail: String {
        var parts: [String]
        switch key.checked {
        case .fingerprint: parts = [L("Compared with the owner")]
        case .account: parts = [L("As taken from the account")]
        case .file: parts = [L("Imported from %@", key.imported.map { "\(($0.path as NSString).lastPathComponent):\($0.line)" } ?? L("a file"))]
        }
        if let source = key.source {
            parts.append(Account(host: source.host, user: source.user).display)
        }
        if let after = key.validAfter {
            parts.append(L("Valid from %@", Signers.date(after).map { $0.formatted(date: .abbreviated, time: .shortened) } ?? after))
        }
        if let also {
            parts.append(L("Also on %@", Account(host: also.host, user: also.user).display))
        }
        if let before = key.validBefore {
            parts.append(L("Retired %@", Signers.date(before).map { $0.formatted(date: .abbreviated, time: .shortened) } ?? before))
        } else if gone {
            parts.append(key.source == nil ? L("Not on the account") : L("No longer on the account"))
        }
        return parts.joined(separator: " · ")
    }
}

/// 人の鍵を指す（確かめの画面に渡す）。
struct KeyRef: Hashable {
    let email: String
    let fingerprint: String
}

/// 取ってきた鍵のフィンガープリントを、持ち主と照らし合わせる。見分けやすいよう等幅の字体で大きく出す。
private struct CompareSshKeySheet: View {
    let email: String
    let fingerprint: String
    let matches: () -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(L("Compare the fingerprint")).font(.title2.bold())
            Text(L("Ask %@ to read out the fingerprint of their signing key by another channel, in person or on the phone, and compare it with this one.", email))
            Text(fingerprint)
                .font(.system(size: 18, design: .monospaced))
                .textSelection(.enabled)
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
            Text(L("The owner can show it with ssh-keygen -lf followed by their public key file."))
                .font(.callout)
                .foregroundStyle(.secondary)
            HStack {
                Spacer()
                Button(L("Cancel"), role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button(L("It Matches")) {
                    matches()
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 520)
    }
}

/// 受け入れ前の鍵の画面の、既存の allowed signers のファイルから読んだ行の段。ファイルごとに、入れる一覧を選んで
/// 受け入れる（まとめても 1 つずつでも）。取り込めなかった行は理由を添えて見せる。
struct PendingImportedKeys: View {
    let model: SignersModel
    let keyring: KeyringModel
    var notify: (Notice) -> Void = { _ in }
    /// ファイルごとの、入れる一覧（空ならどの一覧にも入れない）。
    @State private var lists: [String: String] = [:]

    var body: some View {
        let paths = Array(Set(model.imports.map(\.path) + model.skipped.map(\.path))).sorted()
        ForEach(paths, id: \.self) { path in
            let items = model.imports.filter { $0.path == path }
            let skipped = model.skipped.filter { $0.path == path }
            VStack(alignment: .leading, spacing: 8) {
                Text(L("Keys from %@ (%ld)", (path as NSString).lastPathComponent, items.count)).font(.headline)
                Text(L("From an allowed signers file you chose. Accepting records them as imported from that file; the file is not changed."))
                    .font(.callout)
                    .foregroundStyle(.secondary)
                HStack {
                    Picker(L("Put people in"), selection: Binding(get: { lists[path] ?? "" }, set: { lists[path] = $0 })) {
                        Text(L("No list")).tag("")
                        ForEach(model.record.lists, id: \.id) { Text($0.name).tag($0.id) }
                    }
                    .fixedSize()
                    Spacer()
                    Button(L("Accept All")) { accept(items, path: path) }
                        .disabled(items.isEmpty || model.saving || model.signer(in: keyring.keyring) == nil)
                    Button(L("Discard")) { model.discardImports(from: path) }
                }
                ForEach(items) { item in
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        Image(systemName: "doc.badge.plus").foregroundStyle(.blue)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(item.entry.email).font(.headline)
                            Text(item.entry.fingerprint)
                                .font(.caption.monospaced())
                                .textSelection(.enabled)
                            Text(detail(item.entry))
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button(L("Accept")) { accept([item], path: path) }
                            .controlSize(.small)
                            .disabled(model.saving || model.signer(in: keyring.keyring) == nil)
                    }
                }
                ForEach(skipped, id: \.line.line) { skip in
                    Label(L("Line %ld not imported: %@", Int(skip.line.line), L(skip.line.reason.englishDescription)), systemImage: "minus.circle")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
                Divider()
            }
        }
    }

    private func detail(_ entry: ParsedEntry) -> String {
        var parts = [L("Line %ld", Int(entry.line))]
        if !entry.otherPrincipals.isEmpty {
            parts.append(L("Other addresses (not imported): %@", entry.otherPrincipals.joined(separator: ", ")))
        }
        if let after = entry.validAfter {
            parts.append(L("Valid from %@", Signers.date(after).map { $0.formatted(date: .abbreviated, time: .shortened) } ?? after))
        }
        if let before = entry.validBefore {
            parts.append(L("Retired %@", Signers.date(before).map { $0.formatted(date: .abbreviated, time: .shortened) } ?? before))
        }
        return parts.joined(separator: " · ")
    }

    private func accept(_ items: [PendingImport], path: String) {
        let list = lists[path].flatMap { $0.isEmpty ? nil : $0 }
        Task { await model.acceptImports(items, list: list, keyring: keyring, notify: notify) }
    }
}

/// 受け入れ前の鍵の画面の、探したアカウントの SSH の署名用の鍵の段。サービスは鍵が誰のメールアドレスのものかを
/// 示さないので、主体（git が署名した人として出すメールアドレス）を候補から選んでから受け入れる。
struct SearchedSshKeys: View {
    let account: SearchedAccount
    /// アカウントが公開している GPG 鍵の UID のメールアドレス（候補に足す）。
    var userIdEmails: [String] = []
    let model: SignersModel
    let keyring: KeyringModel
    var notify: (Notice) -> Void = { _ in }
    /// 選んだ候補。`nil` なら初めの候補、`""` なら手で入れたアドレス。
    @State private var chosen: String?
    @State private var typed = ""
    /// 持ち主と照らし合わせてから受け入れる鍵。
    @State private var comparing: FetchedKey?

    /// 候補。すでにこのアカウントを結び付けている人を先に、次にサービスから推定したもの。
    private var choices: [(email: String, word: String)] {
        let linked = model.record.people(with: account.account)
        let people = Set(model.record.people.map { $0.email.lowercased() })
        var out = linked.map { (email: $0, word: L("In SSH Signers with this account")) }
        for candidate in account.candidates(addingUserIds: userIdEmails)
        where !out.contains(where: { $0.email.lowercased() == candidate.email.lowercased() }) {
            let word = candidate.source.word(account.account.host)
            out.append((email: candidate.email, word: people.contains(candidate.email.lowercased()) ? L("%@, in SSH Signers", word) : word))
        }
        return out
    }

    private var email: String {
        switch chosen {
        case "": typed.trimmingCharacters(in: .whitespaces)
        case let email?: email
        case nil: choices.first?.email ?? ""
        }
    }

    private var canAccept: Bool {
        !email.isEmpty && email.contains("@") && !model.saving && model.signer(in: keyring.keyring) != nil
    }

    var body: some View {
        let open = account.keys.filter { model.record.holder(of: $0.fingerprint) == nil }
        VStack(alignment: .leading, spacing: 10) {
            Text(L("SSH signing keys on %@ (%ld)", account.account.display, account.keys.count)).font(.headline)
            Text(L("The service does not say whose email address goes with these keys. Choose the address git shows as the signer; the choices are guesses from the account."))
                .font(.callout)
                .foregroundStyle(.secondary)
            if model.signer(in: keyring.keyring) == nil {
                Text(L("You have no key of your own that can sign on this Mac."))
                    .foregroundStyle(.orange)
            }
            HStack {
                Picker(L("Signer"), selection: Binding(get: { chosen ?? choices.first?.email ?? "" }, set: { chosen = $0 })) {
                    ForEach(choices, id: \.email) { choice in
                        Text("\(choice.email) — \(choice.word)").tag(choice.email)
                    }
                    Divider()
                    Text(L("Other Address…")).tag("")
                }
                .fixedSize()
                Spacer()
                Button(L("Accept All")) { accept(open, checked: .account) }
                    .disabled(open.isEmpty || !canAccept)
                    .help(L("Trust the keys as the account shows them."))
                Button(L("Discard")) { model.discardSearched(account.id) }
            }
            if chosen == "" {
                // メニューはいちばん長い候補の幅になるので、横に並べると欄かボタンがつぶれる。下の行に出す
                TextField(L("Email address"), text: $typed, prompt: Text("alice@example.com"))
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 360)
            }
            ForEach(account.keys, id: \.fingerprint) { key in
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Image(systemName: "key.badge.plus").foregroundStyle(.blue)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(key.fingerprint)
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                        if let title = key.title {
                            Text(title).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    Spacer()
                    if let holder = model.record.holder(of: key.fingerprint) {
                        Text(L("Accepted for %@", holder)).font(.caption).foregroundStyle(.secondary)
                    } else {
                        Button(L("Accept")) { accept([key], checked: .account) }
                            .controlSize(.small)
                            .help(L("Trust the key as the account shows it."))
                            .disabled(!canAccept)
                        Button(L("Compare and Accept…")) { comparing = key }
                            .controlSize(.small)
                            .help(L("Compare the fingerprint with the owner first."))
                            .disabled(!canAccept)
                    }
                }
            }
            Divider()
        }
        .sheet(item: Binding(get: { comparing.map(ComparedKey.init) }, set: { comparing = $0?.key })) { item in
            CompareSshKeySheet(email: email, fingerprint: item.key.fingerprint) {
                accept([item.key], checked: .fingerprint)
            }
        }
    }

    private func accept(_ keys: [FetchedKey], checked: Checked) {
        let email = email
        Task {
            await model.acceptSearched(account.id, keys: keys, as: email, checked: checked, keyring: keyring, notify: notify)
        }
    }

    private struct ComparedKey: Identifiable {
        let key: FetchedKey
        var id: String { key.fingerprint }
    }
}

extension CandidateSource {
    /// 候補の出どころ（選ぶときの手がかり）。
    func word(_ host: CodeHost) -> String {
        let service = host == .gitHub ? "GitHub" : "GitLab"
        switch self {
        case .verified: return L("Verified by %@", service)
        case .userId: return L("In the account's OpenPGP key")
        case .profile: return L("Public profile")
        case .noReply: return L("%@ no-reply address", service)
        }
    }
}

/// 受け入れ前の鍵の画面の、SSH の署名用の鍵の段。取ってきた鍵を、人ごとに受け入れる。
struct PendingSshKeys: View {
    let model: SignersModel
    let keyring: KeyringModel
    var notify: (Notice) -> Void = { _ in }
    /// 持ち主と照らし合わせてから受け入れる鍵。
    @State private var comparing: (email: String, key: PendingKey)?

    var body: some View {
        let pending = model.pending
        VStack(alignment: .leading, spacing: 10) {
            Text(L("SSH signing keys to accept (%ld)", pending.count)).font(.headline)
            Text(L("Fetched for SSH Signers. They are in no allowed signers file until you accept them."))
                .font(.callout)
                .foregroundStyle(.secondary)
            if model.signer(in: keyring.keyring) == nil {
                Text(L("You have no key of your own that can sign on this Mac."))
                    .foregroundStyle(.orange)
            }
            ForEach(pending, id: \.key.key.fingerprint) { item in
                VStack(alignment: .leading, spacing: 4) {
                    Text(item.email).font(.headline)
                    PendingKeyRow(
                        pending: item.key,
                        accept: { accept(item.email, item.key, checked: .account) },
                        acceptCompared: { comparing = item })
                        .disabled(model.saving || model.signer(in: keyring.keyring) == nil)
                }
                Divider()
            }
        }
        .sheet(isPresented: Binding(get: { comparing != nil }, set: { if !$0 { comparing = nil } })) {
            if let item = comparing {
                CompareSshKeySheet(email: item.email, fingerprint: item.key.key.fingerprint) {
                    accept(item.email, item.key, checked: .fingerprint)
                }
            }
        }
    }

    private func accept(_ email: String, _ pending: PendingKey, checked: Checked) {
        Task {
            await model.save(
                [.acceptKey(email: email, key: pending.key.key, source: pending.source, checked: checked)],
                keyring: keyring, title: L("Cannot accept the key"), notify: notify)
        }
    }
}

/// 取ってきて、まだ受け入れていない鍵。
private struct PendingKeyRow: View {
    let pending: PendingKey
    let accept: () -> Void
    let acceptCompared: () -> Void

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: "key.badge.plus" )
                .foregroundStyle(.blue)
            VStack(alignment: .leading, spacing: 2) {
                Text(pending.key.fingerprint)
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
                Text(L("New on %@", Account(host: pending.source.host, user: pending.source.user).display)
                    + (pending.key.title.map { " · \($0)" } ?? ""))
                    .font(.caption)
                    .foregroundStyle(.blue)
            }
            Spacer()
            Button(L("Accept"), action: accept)
                .controlSize(.small)
                .help(L("Trust the key as the account shows it."))
            Button(L("Compare and Accept…"), action: acceptCompared)
                .controlSize(.small)
                .help(L("Compare the fingerprint with the owner first."))
        }
    }
}

/// 人を足す。メールアドレス（git が署名した人として出す）と、鍵を取ってくるアカウント。
private struct AddSignerSheet: View {
    let record: SignerRecord
    /// 足せたら true（シートを閉じる）。
    let add: (String, Account?, [String]) async -> Bool
    @Environment(\.dismiss) private var dismiss
    @State private var email = ""
    @State private var host = CodeHost.gitHub
    @State private var user = ""
    @State private var lists: Set<String> = []
    @State private var working = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(L("Add Person")).font(.title2.bold())
            Form {
                TextField(L("Email address"), text: $email, prompt: Text("alice@example.com"))
                Picker(L("Account on"), selection: $host) {
                    Text("GitHub").tag(CodeHost.gitHub)
                    Text("GitLab").tag(CodeHost.gitLab)
                }
                TextField(L("User name"), text: $user, prompt: Text("alice"))
                if !record.lists.isEmpty {
                    ForEach(record.lists, id: \.id) { list in
                        Toggle(list.name, isOn: Binding(
                            get: { lists.contains(list.id) },
                            set: { if $0 { lists.insert(list.id) } else { lists.remove(list.id) } }))
                    }
                }
            }
            Text(L("The email address is what git shows as the signer. Their SSH signing keys are fetched from the account; you accept each one."))
                .font(.callout)
                .foregroundStyle(.secondary)
            HStack {
                Spacer()
                Button(L("Cancel"), role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button(L("Add")) {
                    working = true
                    let account = user.isEmpty ? nil : Account(host: host, user: user.trimmingCharacters(in: .whitespaces))
                    Task {
                        let ok = await add(email.trimmingCharacters(in: .whitespaces), account, Array(lists))
                        working = false
                        if ok { dismiss() }
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(working || !email.contains("@"))
            }
        }
        .padding(20)
        .frame(width: 440)
    }
}

/// 一覧を足す。ID（ファイルの名前）は名前から作る。
private struct NewSignerListSheet: View {
    let record: SignerRecord
    let add: (String, String) async -> Bool
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var working = false

    var body: some View {
        let id = Signers.listId(for: name, existing: record.lists.map(\.id))
        VStack(alignment: .leading, spacing: 16) {
            Text(L("New List")).font(.title2.bold())
            TextField(L("Name"), text: $name, prompt: Text(L("Work")))
            Text(L("One allowed signers file per list, such as one per team or repository: %@", "\(id).allowed_signers"))
                .font(.callout)
                .foregroundStyle(.secondary)
            HStack {
                Spacer()
                Button(L("Cancel"), role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button(L("Add")) {
                    working = true
                    // ID は押したときの名前から作る（描いたときの値をつかんだままにしない）
                    let id = Signers.listId(for: name, existing: record.lists.map(\.id))
                    Task {
                        let ok = await add(id, name)
                        working = false
                        if ok { dismiss() }
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(working || name.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
        .padding(20)
        .frame(width: 400)
    }
}
