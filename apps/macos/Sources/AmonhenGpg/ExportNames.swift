import AmonhenGpgKit
import Foundation

/// Mac の間で運ぶファイルの既定の名前（この Mac の名前と今日の日付を入れる）。
enum ExportNames {
    private static var stamp: (mac: String, day: String) {
        (ExportFileName.macName(Host.current().localizedName ?? ""), ExportFileName.day(Date()))
    }

    /// 署名の依頼（主鍵のない Mac で書き出す）。
    static var signingRequest: String {
        let (mac, day) = stamp
        return L("Signing request from %@ %@.asc", mac, day)
    }

    /// ローカル署名（主鍵のある Mac で書き出す）。
    static var localSignatures: String {
        let (mac, day) = stamp
        return L("Local signatures from %@ %@.asc", mac, day)
    }
}
