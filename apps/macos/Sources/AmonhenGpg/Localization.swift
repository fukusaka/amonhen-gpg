import Foundation

/// 画面の文字の訳。コードには英語で書き（それが鍵）、日本語は `apps/macos/Localization/ja.lproj/Localizable.strings`。
enum L10n {
    /// 訳の置き場所。`.app` なら Contents/Resources、開発中の実行ファイルならソースの中。
    nonisolated private static let root: Bundle = {
        if Bundle.main.url(forResource: "Localizable", withExtension: "strings", subdirectory: nil, localization: "ja") != nil {
            return .main
        }
        let source = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Localization")
        return Bundle(url: source) ?? .main
    }()

    /// 画面の言語。利用者の設定の順で選ぶ（素の実行ファイルでは Bundle が英語しか選ばないので、自分で選ぶ）。
    nonisolated static let language: String? =
        Bundle.preferredLocalizations(from: root.localizations, forPreferences: Locale.preferredLanguages).first

    nonisolated static let bundle: Bundle =
        language.flatMap { root.url(forResource: $0, withExtension: "lproj") }.flatMap(Bundle.init(url:)) ?? root
}

/// `key`（英語）の訳。
nonisolated func L(_ key: String) -> String {
    L10n.bundle.localizedString(forKey: key, value: key, table: nil)
}

/// `format`（英語。`%@`・`%ld`）の訳に、`args` を入れる。
nonisolated func L(_ format: String, _ args: CVarArg...) -> String {
    String(format: L(format), locale: Locale.current, arguments: args)
}
