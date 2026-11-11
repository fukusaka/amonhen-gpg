import AmonhenGpgKit
import SwiftUI

/// 選べる期限。gpg には「今から何日」で渡す。
enum ExpiryChoice: Hashable, CaseIterable {
    case oneYear, twoYears, fiveYears, never

    var expiry: Expiry {
        switch self {
        case .oneYear: .days(365)
        case .twoYears: .days(730)
        case .fiveYears: .days(1825)
        case .never: .never
        }
    }

    var title: String {
        switch self {
        case .oneYear: L("1 year")
        case .twoYears: L("2 years")
        case .fiveYears: L("5 years")
        case .never: L("No expiry")
        }
    }

    /// 選んだときの期限の日付。期限なしなら nil。
    func date(from now: Date) -> Date? {
        guard case let .days(days) = expiry else { return nil }
        return now.addingTimeInterval(TimeInterval(days) * 86_400)
    }
}

/// 期限を延ばす。主鍵と、期限のあるサブ鍵をまとめて延ばす（`Gpg.extendExpiry`）。
struct ExtendExpirySheet: View {
    let model: KeyringModel
    let own: OwnKey
    @Environment(\.dismiss) private var dismiss
    @State private var choice = ExpiryChoice.twoYears
    @State private var working = false
    @State private var failure: String?

    var body: some View {
        let now = Date()
        VStack(alignment: .leading, spacing: 16) {
            Text(L("Extend Expiry")).font(.title2.bold())
            Text(own.key.primaryUserId?.text ?? own.key.fingerprint)
                .font(.headline)
            Text(current).foregroundStyle(.secondary)
            Picker(L("New expiry"), selection: $choice) {
                ForEach(ExpiryChoice.allCases, id: \.self) { choice in
                    Text(choice.title).tag(choice)
                }
            }
            .pickerStyle(.radioGroup)
            Group {
                if let date = choice.date(from: now) {
                    Text(L("The key will be usable until %@.", date.formatted(date: .long, time: .omitted)))
                } else {
                    Text(L("A key without expiry stays valid even if you lose it and cannot revoke it."))
                        .foregroundStyle(.orange)
                }
            }
            .font(.callout)
            .fixedSize(horizontal: false, vertical: true)
            Text(L("gpg will ask for the passphrase of this key."))
                .font(.callout)
                .foregroundStyle(.secondary)
            if let failure {
                Text(failure)
                    .foregroundStyle(.red)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                if working {
                    ProgressView().controlSize(.small)
                }
                Spacer()
                Button(L("Cancel"), role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button(L("Extend")) { extend() }
                    .keyboardShortcut(.defaultAction)
            }
            .disabled(working)
        }
        .padding(20)
        .frame(width: 440)
    }

    private var current: String {
        guard let expires = own.key.expires else { return L("Currently: no expiry") }
        let date = Date(timeIntervalSince1970: TimeInterval(expires))
        return L("Currently: until %@", date.formatted(date: .long, time: .omitted))
    }

    private func extend() {
        working = true
        failure = nil
        let key = own.key
        let expiry = choice.expiry
        Task {
            let result = await model.perform { try $0.extendExpiry(of: key, to: expiry) }
            working = false
            switch result {
            case .success: dismiss()
            case let .failure(error): failure = describe(error)
            }
        }
    }
}
