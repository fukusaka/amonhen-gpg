import AmonhenGpgKit
import AppKit
import SwiftUI

/// 起動の引数。
/// - `--gpg <path>`: 使う gpg（既定は `PATH` の gpg）
/// - `--homedir <dir>`: 鍵の置き場所（既定は `GNUPGHOME` か `~/.gnupg`）
/// - `--snapshot <file.png>`: 窓を開いて、その窓を画像に撮って終わる（見た目の確認用。使えた鍵は開いておく。初めは
///   起動したアプリに「画面収録」の許可が要る）
/// - `--place mine|others|staging`: 書き出す場所
/// - `--sheet extend|create|revoke|certify|details|otherdetails|delete|userids`: 一覧の代わりに、シートの中身を撮る（最初の自分の鍵で）
/// - `--appearance light|dark`: 見た目を決める（既定はシステムの設定）
/// - `--search <text>`: 一覧の検索欄にこの語を入れておく
/// - `--stage <file>`: 鍵のファイルを一時保管に入れてから書き出す（一時保管の見た目の確認用）
/// - `--keyserver <url>`: 送る・探す鍵サーバー（既定は keys.openpgp.org。試験用の鍵サーバーは `scripts/test-keyserver.sh`）
struct Options {
    var gpg: String?
    var homedir: String?
    var snapshot: String?
    var place = Place.mine
    var sheet: SheetPreview.Kind?
    var stage: String?
    var keyserver: String?
    var appearance: NSAppearance?
    var search: String?

    init(_ arguments: [String]) {
        var rest = arguments.dropFirst().makeIterator()
        while let arg = rest.next() {
            switch arg {
            case "--gpg": gpg = rest.next()
            case "--homedir": homedir = rest.next()
            case "--snapshot": snapshot = rest.next()
            case "--place": place = rest.next().flatMap(Place.init(rawValue:)) ?? .mine
            case "--sheet": sheet = rest.next().flatMap(SheetPreview.Kind.init(rawValue:))
            case "--stage": stage = rest.next()
            case "--keyserver": keyserver = rest.next()
            case "--search": search = rest.next()
            case "--appearance":
                appearance = switch rest.next() {
                case "light": NSAppearance(named: .aqua)
                case "dark": NSAppearance(named: .darkAqua)
                default: nil
                }
            default: break
            }
        }
    }
}

let options = Options(CommandLine.arguments)
if let keyserver = options.keyserver {
    Keyserver.current = keyserver
}
// Finder から開くと PATH に Homebrew がないので、gpg の場所を探して渡す（見つからなければ gpg のまま。読めずに知らせる）
let model = KeyringModel(gpg: Gpg(program: options.gpg ?? GpgProgram.locate(), homedir: options.homedir))
/// 一時保管は起動ごとに一時ディレクトリに作り、終わるときに捨てる。落ちて残った前の一時保管は、起動したときに捨てる。
let staging = StagingModel(main: model, dir: Staging.directory(in: FileManager.default.temporaryDirectory))

struct GpgApp: App {
    @NSApplicationDelegateAdaptor var delegate: AppDelegate

    var body: some Scene {
        Window("Amonhen GPG", id: "main") {
            if options.snapshot != nil, let sheet = options.sheet {
                SheetPreview(model: model, kind: sheet)
            } else if options.snapshot != nil {
                // 鍵束は起動する前に読んである
                ContentView(model: model, staging: staging, place: options.place, query: options.search ?? "", showsHistory: true)
                    .frame(minWidth: 720, minHeight: 420)
            } else {
                ContentView(model: model, staging: staging)
                    .frame(minWidth: 720, minHeight: 420)
                    .task { await model.reload() }
            }
        }
        .windowResizability(options.sheet != nil && options.snapshot != nil ? .contentSize : .automatic)
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        let gpg = model.gpg
        Task.detached {
            Staging.discardStale(in: FileManager.default.temporaryDirectory, gpg: gpg)
        }
        // .app に入れずに実行ファイルを起動したときも、普通のアプリとして前に出す
        NSApp.setActivationPolicy(.regular)
        NSApp.activate()
        if let path = options.snapshot {
            Snapshot.capture(to: URL(fileURLWithPath: path)) { staging.discardAll() }
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }

    func applicationWillTerminate(_ notification: Notification) {
        staging.discardAll()
    }
}

if let appearance = options.appearance {
    NSApplication.shared.appearance = appearance
}
// 撮るときは、窓を出す前に鍵束を読み、一時保管に入れておく（読み終わる前の画面を撮らないように）
if options.snapshot != nil {
    model.reloadNow()
    if let stage = options.stage, let data = FileManager.default.contents(atPath: stage) {
        staging.addNow(data)
    }
}
GpgApp.main()
