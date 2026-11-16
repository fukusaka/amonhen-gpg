import AmonhenGpgKit
import AppKit
import SwiftUI

/// 設定（⌘,）。使う gpg を選ぶ。選ばなければ自動で探す（`GpgProgram.locate`）。
struct SettingsView: View {
    let model: KeyringModel
    let staging: StagingModel
    /// 起動の引数 `--gpg` で決まっていれば、その場所（設定では変えられない）。
    let fixedProgram: String?
    @State private var chosen = GpgProgram.chosen()
    @State private var working = false
    @State private var failure: String?

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
        }
        .formStyle(.grouped)
        .frame(width: 540)
        .fixedSize(horizontal: false, vertical: true)
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
