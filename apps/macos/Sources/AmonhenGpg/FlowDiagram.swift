import SwiftUI

/// 鍵の流れの図（空の画面の説明に添える）。列を左から右へ矢印でつなぎ、各列には箱を縦に並べる。
struct FlowDiagram: View {
    struct Step: Hashable {
        let symbol: String
        let title: String
        var note: String?
        /// 添え書きが設定の名前などのコード（等幅で 1 行に収める）。
        var code = false
        /// 今の画面（強調する）。
        var current = false
    }

    let columns: [[Step]]

    var body: some View {
        // 窓が狭ければ、箱を細くして添え書きを省き、それでも入らなければ出さない（説明の文は残る）
        ViewThatFits(in: .horizontal) {
            diagram(width: 116, notes: true)
            diagram(width: 84, notes: false)
            EmptyView()
        }
    }

    private func diagram(width: CGFloat, notes: Bool) -> some View {
        HStack(alignment: .center, spacing: 8) {
            ForEach(Array(columns.enumerated()), id: \.offset) { index, steps in
                if index > 0 {
                    Image(systemName: "arrow.right")
                        .font(.callout.weight(.semibold))
                        .foregroundStyle(.tertiary)
                }
                VStack(spacing: 6) {
                    ForEach(steps, id: \.self) { box($0, width: width, notes: notes) }
                }
            }
        }
        .fixedSize()
        .accessibilityElement(children: .combine)
    }

    private func box(_ step: Step, width: CGFloat, notes: Bool) -> some View {
        VStack(spacing: 4) {
            Image(systemName: step.symbol)
                .font(.title3)
                .foregroundStyle(step.current ? Color.accentColor : .secondary)
                .frame(height: 22)
            Text(step.title)
                .font(.callout.weight(step.current ? .semibold : .regular))
                .foregroundStyle(.primary)
            if notes, let note = step.note {
                if step.code {
                    Text(note)
                        .font(.caption2.monospaced())
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .minimumScaleFactor(0.6)
                } else {
                    Text(note)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .multilineTextAlignment(.center)
        .fixedSize(horizontal: false, vertical: true)
        .frame(width: width)
        .padding(.vertical, 8)
        .padding(.horizontal, 4)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(step.current ? Color.accentColor.opacity(0.12) : Color.secondary.opacity(0.08)))
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .strokeBorder(step.current ? Color.accentColor.opacity(0.5) : Color.secondary.opacity(0.2)))
    }
}

extension FlowDiagram {
    /// 受け入れ前の鍵: 取ってきた鍵が、確かめてから行き先へ移る。
    static var keysToAccept: FlowDiagram {
        FlowDiagram(columns: [
            [
                Step(symbol: "globe", title: L("Keyservers and WKD")),
                Step(symbol: "chevron.left.forwardslash.chevron.right", title: L("GitHub and GitLab")),
                Step(symbol: "doc", title: L("Files")),
            ],
            [Step(symbol: "tray", title: L("Keys to Accept"), note: L("Compare fingerprints"), current: true)],
            [
                Step(symbol: "person.2", title: L("Others' Keys"), note: L("Import GPG keys")),
                Step(symbol: "signature", title: L("SSH Signers"), note: L("Accept SSH keys")),
            ],
        ])
    }

    /// SSH の署名者: 鍵を受け入れて人に付け、一覧ごとのファイルを git が読む。
    static var sshSigners: FlowDiagram {
        FlowDiagram(columns: [
            [
                Step(symbol: "chevron.left.forwardslash.chevron.right", title: L("GitHub and GitLab"), note: L("Accounts")),
                Step(symbol: "doc", title: L("Allowed signers files")),
            ],
            [Step(symbol: "tray", title: L("Keys to Accept"), note: L("Check and accept"))],
            [Step(symbol: "person.2", title: L("People and keys"), note: L("Signed with your key"), current: true)],
            [Step(symbol: "list.bullet", title: L("Lists"), note: L("One file each"), current: true)],
            [Step(symbol: "terminal", title: "git", note: "gpg.ssh.allowedSignersFile", code: true)],
        ])
    }
}

/// 空の場所の表示: 記号・題・説明、流れの図、ボタンを縦に並べて真ん中に置く（ContentUnavailableView に似せる）。
/// 図は説明（幅を絞る）とは別に置き、表示の幅いっぱいで収まるかを決める。
struct EmptyPlace<Actions: View>: View {
    let symbol: String
    let title: String
    let message: String
    let diagram: FlowDiagram
    @ViewBuilder let actions: Actions

    init(
        _ title: String, systemImage: String, message: String, diagram: FlowDiagram,
        @ViewBuilder actions: () -> Actions = { EmptyView() }
    ) {
        self.title = title
        symbol = systemImage
        self.message = message
        self.diagram = diagram
        self.actions = actions()
    }

    var body: some View {
        // スクロールの中に置き、中身の高さを外に伝えない（縮まない中身が窓より高いと、窓の中身全体がずれて
        // サイドバーや上の欄が隠れる）。収まるときは真ん中に置く。
        GeometryReader { geometry in
            ScrollView {
                stack
                    .padding()
                    .frame(minWidth: geometry.size.width, minHeight: geometry.size.height)
            }
            .scrollBounceBehavior(.basedOnSize)
        }
    }

    private var stack: some View {
        VStack(spacing: 20) {
            VStack(spacing: 10) {
                Image(systemName: symbol)
                    .font(.system(size: 40))
                    .foregroundStyle(.secondary)
                Text(title)
                    .font(.title2.bold())
                Text(message)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 420)
                    .fixedSize(horizontal: false, vertical: true)
            }
            diagram
            HStack { actions }
        }
    }
}
