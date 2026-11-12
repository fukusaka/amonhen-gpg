import AmonhenGpgKit
import SwiftUI

/// 鍵の詳細。UID ごとの有効性と、主鍵・サブ鍵の方式・用途・期限を出す（一覧では主鍵とサブ鍵の違いを出さないので）。
struct KeyDetailSheet: View {
    let key: Key
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(key.primaryUserId?.text ?? key.fingerprint).font(.title2.bold())
            Text(Fingerprint.grouped(key.fingerprint))
                .font(.body.monospaced())
                .textSelection(.enabled)
            Section {
                ForEach(Array(key.userIds.filter { !$0.attribute }.enumerated()), id: \.offset) { _, uid in
                    HStack {
                        Text(uid.text)
                            .strikethrough(uid.validity == .revoked)
                        Spacer()
                        Text(validityWord(uid.validity)).foregroundStyle(.secondary)
                    }
                }
            } header: {
                Text(L("Names and addresses")).font(.headline)
            }
            Section {
                Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 6) {
                    GridRow {
                        Text(L("Key")).foregroundStyle(.secondary)
                        Text(L("Use")).foregroundStyle(.secondary)
                        Text(L("Created")).foregroundStyle(.secondary)
                        Text(L("Expires")).foregroundStyle(.secondary)
                    }
                    row(L("Primary key"), algorithm: algorithmName(algorithm: key.algorithm, length: key.length, curve: key.curve),
                        capabilities: key.capabilities, created: key.created, expires: key.expires, validity: key.validity)
                    ForEach(key.subkeys, id: \.fingerprint) { sub in
                        row(L("Subkey"), algorithm: algorithmName(algorithm: sub.algorithm, length: sub.length, curve: sub.curve),
                            capabilities: sub.capabilities, created: sub.created, expires: sub.expires, validity: sub.validity)
                    }
                }
                .font(.callout)
            } header: {
                Text(L("Keys")).font(.headline)
            }
            HStack {
                Spacer()
                Button(L("Close")) { dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 560)
    }

    private func row(
        _ kind: String, algorithm: String, capabilities: Capabilities, created: UInt64?, expires: UInt64?, validity: Validity
    ) -> some View {
        GridRow {
            Text("\(kind) · \(algorithm)")
            Text(uses(capabilities))
            Text(date(created) ?? "—")
            Group {
                switch validity {
                case .revoked: Text(L("Revoked"))
                case .expired: Text(L("Expired"))
                default: Text(date(expires) ?? L("Never"))
                }
            }
        }
        .foregroundStyle(validity == .revoked || validity == .expired ? .secondary : .primary)
    }

    private func uses(_ c: Capabilities) -> String {
        var names: [String] = []
        if c.certify { names.append(L("Certify")) }
        if c.sign { names.append(L("Sign")) }
        if c.encrypt { names.append(L("Encrypt")) }
        if c.authenticate { names.append(L("Authenticate")) }
        return names.joined(separator: " · ")
    }

    private func date(_ seconds: UInt64?) -> String? {
        seconds.map { Date(timeIntervalSince1970: TimeInterval($0)).formatted(date: .abbreviated, time: .omitted) }
    }
}

/// 有効性は記号ではなく言葉で（docs/ui.md）。
func validityWord(_ validity: Validity) -> String {
    switch validity {
    case .revoked: L("Revoked")
    case .expired: L("Expired")
    case .full, .ultimate: L("Verified")
    case .marginal: L("Partly verified")
    default: L("Not verified")
    }
}
