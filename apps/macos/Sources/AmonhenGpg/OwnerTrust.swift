import AmonhenGpgKit
import SwiftUI

/// 他者の鍵の所有者信頼（その人が、ほかの鍵をどれだけ確かめてから署名する人か）。鍵の詳細の概要と、他者の鍵の行のメニューで選ぶ。
/// 選ぶと gpg が有効性を計算し直し、その人が署名したほかの鍵が「確認済み」になることがある。
struct OwnerTrustPicker: View {
    let key: Key
    /// 選んだ値を設定する（失敗は呼んだ側で知らせる）。
    let set: (OwnerTrust) -> Void

    var body: some View {
        Picker(L("Owner Trust"), selection: Binding(get: { key.ownerTrustSetting }, set: { set($0) })) {
            ForEach(OwnerTrust.choicesForOthers, id: \.self) { trust in
                Text(ownerTrustWord(trust)).tag(trust)
            }
        }
    }
}

extension KeyringModel {
    /// 所有者信頼を設定する。失敗したら、その理由。
    func setOwnerTrust(_ key: Key, _ trust: OwnerTrust) async -> Error? {
        guard trust != key.ownerTrustSetting else { return nil }
        let fingerprint = key.fingerprint
        if case let .failure(error) = await perform({ try $0.setOwnerTrust(fingerprint: fingerprint, trust: trust) }) {
            return error
        }
        return nil
    }
}

/// 所有者信頼を言葉で。
func ownerTrustWord(_ trust: OwnerTrust) -> String {
    switch trust {
    case .unknown: L("Not set")
    case .never: L("Not at all")
    case .marginal: L("Marginally")
    case .full: L("Fully")
    case .ultimate: L("Ultimately (your key)")
    }
}

/// 所有者信頼が何に効くか（gpg の既定: 完全に信頼する人なら 1 人、ある程度なら 3 人の署名で、その鍵が確認済みになる）。
func ownerTrustNote() -> String {
    L("How far you rely on this person to check other keys before signing them. A key becomes valid when it is signed by one valid key whose owner you trust fully, or by three you trust marginally.")
}
