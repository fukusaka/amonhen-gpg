import AmonhenGpgKit
import AppKit
import SwiftUI

/// 設定（⌘,）。使う gpg を選ぶ。選ばなければ自動で探す（`GpgProgram.locate`）。鍵サーバーと、受け入れ前の鍵が
/// 名前を引く仕組みも選ぶ。
struct SettingsView: View {
    let model: KeyringModel
    let staging: StagingModel
    /// 起動の引数 `--gpg` で決まっていれば、その場所（設定では変えられない）。
    let fixedProgram: String?
    @State private var chosen = GpgProgram.chosen()
    @State private var working = false
    @State private var failure: String?
    @State private var keyserver = Keyserver.current
    /// 「その他」で打っている URL。
    @State private var typed = Keyserver.candidates.contains(Keyserver.current) ? "" : Keyserver.current
    @State private var other = !Keyserver.candidates.contains(Keyserver.current)
    @State private var resolver = NameResolver.current
    @State private var keyserverFailure: String?

    var body: some View {
        Form {
            Section("GnuPG") {
                LabeledContent(L("gpg program")) {
                    Text(model.program ?? L("Not found"))
                        .font(.body.monospaced())
                        .textSelection(.enabled)
                }
                LabeledContent(L("Version")) {
                    if model.failure == nil, let version = model.keyring.gpgVersion {
                        if model.keyring.outdatedGpg != nil {
                            Label(L("%@ (older than %@)", version.description, minimumGpgVersion().description),
                                  systemImage: "exclamationmark.triangle.fill")
                                .foregroundStyle(.orange)
                        } else {
                            Text(version.description)
                        }
                    } else {
                        Text("—")
                    }
                }
                if fixedProgram != nil {
                    Text(L("Set by the --gpg launch option."))
                        .foregroundStyle(.secondary)
                } else {
                    LabeledContent(L("Change")) {
                        HStack {
                            Button(L("Choose…"), action: choose)
                            Button(L("Find Automatically")) { apply(nil) }
                                .disabled(chosen == nil)
                        }
                        .disabled(working)
                    }
                    Text(chosen == nil
                         ? L("Found automatically: the first gpg in PATH, /opt/homebrew/bin, /usr/local/bin or /usr/local/MacGPG2/bin.")
                         : L("Chosen in Settings."))
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                if let failure {
                    Label(failure, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.red)
                }
            }
            keyserverSection
        }
        .formStyle(.grouped)
        .frame(width: 540)
        .fixedSize(horizontal: false, vertical: true)
    }

    private static let otherTag = ""

    @ViewBuilder private var keyserverSection: some View {
        Section(L("Keyserver")) {
            if Keyserver.fixed != nil {
                LabeledContent(L("Keyserver")) {
                    Text(Keyserver.current)
                        .font(.body.monospaced())
                        .textSelection(.enabled)
                }
                Text(L("Set by the --keyserver launch option."))
                    .foregroundStyle(.secondary)
            } else {
                Picker(L("Keyserver"), selection: Binding(
                    get: { other ? Self.otherTag : keyserver },
                    set: { tag in
                        if tag == Self.otherTag {
                            other = true
                        } else {
                            other = false
                            typed = ""
                            setKeyserver(tag)
                        }
                    }
                )) {
                    ForEach(Keyserver.candidates, id: \.self) { Text(Keyserver.name($0)).tag($0) }
                    Divider()
                    Text(L("Other…")).tag(Self.otherTag)
                }
                if other {
                    // 欄は行の幅いっぱいにする（ラベル付きだと右に寄って狭くなり、長い URL が見えない）
                    HStack {
                        TextField(L("URL"), text: $typed, prompt: Text("hkps://keys.example.org"))
                            .labelsHidden()
                            .textFieldStyle(.roundedBorder)
                            .onSubmit(useTyped)
                        Button(L("Use This URL"), action: useTyped)
                            .disabled(typed.trimmingCharacters(in: .whitespaces).isEmpty || typed == keyserver)
                    }
                }
                Text(L("Used to search Keys to Accept and to send your keys."))
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            Picker(L("Name lookup"), selection: Binding(
                get: { resolver },
                set: { value in
                    keyserverFailure = nil
                    resolver = value
                    NameResolver.current = value
                    applyToStaging()
                }
            )) {
                Text(L("GnuPG (built in)")).tag(NameResolver.gnupg)
                Text(L("macOS")).tag(NameResolver.system)
            }
            Text(L("If searching fails, for example with a VPN, choose macOS."))
                .font(.callout)
                .foregroundStyle(.secondary)
            if let keyserverFailure {
                Label(keyserverFailure, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
            }
        }
    }

    /// 打った URL を使う。使えない URL なら知らせて、今の鍵サーバーのまま。
    private func useTyped() {
        let url = typed.trimmingCharacters(in: .whitespaces)
        guard isKeyserverUrl(url: url) else {
            keyserverFailure = L("Not a keyserver URL: %@. Start it with hkps://, hkp://, https:// or ldaps://.", url)
            return
        }
        typed = url
        setKeyserver(url)
    }

    private func setKeyserver(_ url: String) {
        keyserverFailure = nil
        keyserver = url
        Keyserver.choose(url)
        applyToStaging()
    }

    private func applyToStaging() {
        Task {
            if let error = await staging.applySettings() {
                keyserverFailure = error
            }
        }
    }

    /// 実行ファイルを選ぶ。/opt などの隠れた場所も見せ、symlink は解かずに残す（Homebrew で更新しても同じ場所）。
    private func choose() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.showsHiddenFiles = true
        panel.resolvesAliases = false
        panel.treatsFilePackagesAsDirectories = true
        panel.message = L("Choose the gpg program.")
        let current = model.program.map { URL(fileURLWithPath: $0).deletingLastPathComponent() }
        panel.directoryURL = current ?? URL(fileURLWithPath: "/opt/homebrew/bin")
        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            apply(url.path)
        }
    }

    /// `path` の gpg に替える（nil なら自動で探す）。選んだものは、版を読めたときだけ使う。
    private func apply(_ path: String?) {
        let program = path ?? GpgProgram.locate()
        let gpg = Gpg(program: program, homedir: model.homedir)
        working = true
        Task {
            let result = await Task.detached { Result { try gpg.version() } }.value
            working = false
            if let path, case let .failure(error) = result {
                failure = L("Cannot use %@: %@", path, describe(error))
                return
            }
            failure = nil
            GpgProgram.choose(path)
            chosen = path
            staging.use(gpg)
            await model.use(gpg, program: program)
        }
    }
}
