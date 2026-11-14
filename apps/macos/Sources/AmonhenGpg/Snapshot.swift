import AppKit
import SwiftUI

/// 本物の窓を開いて、その窓だけを PNG に撮る（見た目の確認用）。macOS 26 のガラス（サイドバー・ツールバー）は窓を
/// 画面に出さないと描かれないので、画面に出して `screencapture` で撮る。初めは、起動したアプリ（端末など）に
/// 「画面収録」の許可が要る。
enum Snapshot {
    /// 窓の中身の大きさ（窓の既定の大きさと同じ）。
    static let windowSize = CGSize(width: 1100, height: 640)

    /// 窓が出て中身を並べ終えたころに撮り、`cleanup` を呼んで終わる。
    static func capture(to url: URL, cleanup: @escaping () -> Void) {
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
            guard let window = NSApp.windows.first(where: \.isVisible) else { finish(1, "no window to capture", cleanup) }
            if window.attachedSheet == nil, window.styleMask.contains(.resizable) {
                window.setContentSize(windowSize)
                window.center()
            }
            // 一覧などが中身を並べ、ガラスが描かれるまで待つ
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                let process = Process()
                process.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
                // -o: 影を入れない、-x: 音を出さない、-l: この窓だけ
                process.arguments = ["-o", "-x", "-l", String(window.windowNumber), url.path]
                do {
                    try process.run()
                    process.waitUntilExit()
                } catch {
                    finish(1, "\(error)", cleanup)
                }
                guard process.terminationStatus == 0, FileManager.default.fileExists(atPath: url.path) else {
                    finish(1, "screencapture failed; allow Screen Recording for the app that launched this", cleanup)
                }
                finish(0, nil, cleanup)
            }
        }
    }

    private static func finish(_ status: Int32, _ message: String?, _ cleanup: () -> Void) -> Never {
        if let message { FileHandle.standardError.write(Data("\(message)\n".utf8)) }
        cleanup()
        exit(status)
    }
}

/// シートを単独で書き出すための入れ物（`--sheet`）。鍵束を読んでから中身を決める。
struct SheetPreview: View {
    enum Kind: String {
        case extend, create, revoke, certify, details, otherdetails, delete, userids
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
                KeyDetailSheet(model: model, key: own.key, preloaded: try? model.gpg.certifications(fingerprint: own.key.fingerprint))
            }
        case .otherdetails:
            if let key = model.keyring.others.first {
                KeyDetailSheet(model: model, key: key, preloaded: try? model.gpg.certifications(fingerprint: key.fingerprint))
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
