import AmonhenGpgKit
import AppKit
import SwiftUI

/// 起動の引数。
/// - `--gpg <path>`: 使う gpg（既定は `PATH` の gpg）
/// - `--homedir <dir>`: 鍵の置き場所（既定は `GNUPGHOME` か `~/.gnupg`）
/// - `--snapshot <file.png>`: 窓を開かずに、画面を画像に書き出して終わる（見た目の確認用。使えた鍵は開いておく）
/// - `--place mine|others|staging`: 書き出す場所
struct Options {
    var gpg: String?
    var homedir: String?
    var snapshot: String?
    var place = Place.mine

    init(_ arguments: [String]) {
        var rest = arguments.dropFirst().makeIterator()
        while let arg = rest.next() {
            switch arg {
            case "--gpg": gpg = rest.next()
            case "--homedir": homedir = rest.next()
            case "--snapshot": snapshot = rest.next()
            case "--place": place = rest.next().flatMap(Place.init(rawValue:)) ?? .mine
            default: break
            }
        }
    }
}

let options = Options(CommandLine.arguments)
let model = KeyringModel(gpg: Gpg(program: options.gpg, homedir: options.homedir))

struct GpgApp: App {
    @NSApplicationDelegateAdaptor var delegate: AppDelegate

    var body: some Scene {
        Window("amonhen-gpgui", id: "main") {
            ContentView(model: model)
                .frame(minWidth: 720, minHeight: 420)
                .task { await model.reload() }
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        // .app に入れずに実行ファイルを起動したときも、普通のアプリとして前に出す
        NSApp.setActivationPolicy(.regular)
        NSApp.activate()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}

if let path = options.snapshot {
    Snapshot.write(ContentView(model: model, place: options.place, showsHistory: true), size: CGSize(width: 960, height: 600), to: URL(fileURLWithPath: path)) {
        model.reloadNow()
    }
} else {
    GpgApp.main()
}
