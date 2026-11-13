import AppKit
import SwiftUI

/// 画面を窓に出さずに PNG に書き出す（見た目の確認用）。
enum Snapshot {
    /// `cleanup` は書き出したあと、終わる前に呼ぶ（一時保管を捨てる）。
    static func write(_ view: some View, size: CGSize, to url: URL, prepare: () -> Void, cleanup: () -> Void = {}) {
        let app = NSApplication.shared
        app.setActivationPolicy(.prohibited)
        prepare()
        let window = NSWindow(
            contentRect: CGRect(origin: .zero, size: size), styleMask: [.titled, .fullSizeContentView],
            backing: .buffered, defer: false)
        // 窓の背景は画像に入らないので、窓と同じ色を敷く（一覧の外の文字が背景なしで描かれないように）
        window.contentView = NSHostingView(
            rootView: view.frame(width: size.width, height: size.height).background(Color(nsColor: .windowBackgroundColor)))
        // 一覧（NSTableView）などが中身を並べ終えるまで回す
        for _ in 0..<5 {
            RunLoop.main.run(until: Date().addingTimeInterval(0.1))
            window.contentView?.layoutSubtreeIfNeeded()
        }
        guard let content = window.contentView,
            let bitmap = content.bitmapImageRepForCachingDisplay(in: content.bounds)
        else { finish(1, cleanup) }
        content.cacheDisplay(in: content.bounds, to: bitmap)
        guard let png = bitmap.representation(using: .png, properties: [:]) else { finish(1, cleanup) }
        do {
            try png.write(to: url)
        } catch {
            FileHandle.standardError.write(Data("\(error)\n".utf8))
            finish(1, cleanup)
        }
        finish(0, cleanup)
    }

    private static func finish(_ status: Int32, _ cleanup: () -> Void) -> Never {
        cleanup()
        exit(status)
    }
}

/// シートを単独で書き出すための入れ物（`--sheet`）。鍵束を読んでから中身を決める。
struct SheetPreview: View {
    enum Kind: String {
        case extend, create, revoke, certify, details, delete, userids
    }

    let model: KeyringModel
    let kind: Kind

    var body: some View {
        let own = model.keyring.usable.first ?? model.keyring.history.first
        switch kind {
        case .extend:
            if let own {
                ExtendExpirySheet(model: model, own: own)
            }
        case .revoke:
            if let own {
                RevokeKeySheet(model: model, own: own)
            }
        case .delete:
            if let own {
                DeleteKeySheet(model: model, own: own)
            }
        case .userids:
            if let own {
                UserIdsSheet(model: model, own: own)
            }
        case .details:
            if let own {
                KeyDetailSheet(key: own.key)
            }
        case .certify:
            if let key = model.keyring.others.first(where: \.canCertify) {
                CertifySheet(model: model, key: key)
            }
        case .create:
            NewKeySheet(model: model, name: "Alice Example", email: "alice@example.com")
        }
    }
}
