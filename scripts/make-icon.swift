// アプリのアイコンを描いて .icns にする。図柄はコードで持つ（色や形はここを直して作り直す）。
//   swift scripts/make-icon.swift [出力先のフォルダ]
// 出力: AppIcon.icns（正式版）・AppIcon-Snapshot.icns（snapshot 版。右下にオレンジの帯）・AppIcon.png（1024 px の見本）・
//       AppIcon-sizes.png（16・32・64 px の見本。4 倍と等倍を並べた表）
//
// 図柄: 南京錠の形をした革のキーホルダー。縁にクリーム色のステッチがあるキャラメル色の革のタグ（南京錠の形）が、
// 太い鋼の二重リングに鍵 2 本といっしょに下がる。タグの掛け金の部分がそのまま輪を通すループで、本体には指紋の
// 型押し（指紋を見比べて相手の鍵を確かめる）。南京錠の形と太い輪は堅さ（強いセキュリティ）、ふっくらした革と
// ステッチ、色の明るい鍵は「自分の鍵を手元で大事にしまう」気軽さ。鍵は丸い持ち手・つば・刻みのある刃の形で、
// 持ち手は輪の両肩に分けて上を混ませない。背景はミントからティールの明るいグラデーション。32 px でも茶色の
// 錠の形と黄・赤の鍵が見分けられるよう、形は太く少なく。
// 64 px 以下は別の描き方（Detail）: 図柄を大きくし、陰影を省き、輪とステッチと指紋を太く少なく、鍵は歯を大きく
// 2 つに。32 px 以下は輪を小さくして持ち手を輪の外へずらし（輪は手前）、指紋は弧 2 本。16 px はステッチと指紋も省く。
// macOS のアイコンの枠（1024 の中の 824 の角の丸い四角）に合わせる。
import AppKit

let outDir = URL(fileURLWithPath: CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "apps/macos/Icons")

func color(_ hex: UInt32, _ alpha: CGFloat = 1) -> CGColor {
    CGColor(
        srgbRed: CGFloat((hex >> 16) & 0xff) / 255, green: CGFloat((hex >> 8) & 0xff) / 255,
        blue: CGFloat(hex & 0xff) / 255, alpha: alpha)
}

/// 描き込みの細かさ。小さい出力では細部が消えるので、形を太く少なくした別の描き方にする。
enum Detail {
    case full   // 128 px 以上: 細部まで。
    case small  // 33〜64 px: 輪・ステッチ・指紋を太く、陰影を省く。
    case tiny   // 17〜32 px: さらに太く、指紋は弧 2 本、ステッチは大きな破線。
    case micro  // 16 px 以下: 錠の形・輪・2 本の鍵だけ。ステッチと指紋は省く。

    init(size: Int) { self = size <= 16 ? .micro : size <= 32 ? .tiny : size <= 64 ? .small : .full }
}

/// 1024 の座標（左上が原点）で描く。
func draw(_ ctx: CGContext, snapshot: Bool, detail: Detail = .full) {
    /// 細かさごとの値（full, small, tiny, micro）。micro を省くと tiny と同じ。
    func pick<T>(_ full: T, _ small: T, _ tiny: T, _ micro: T? = nil) -> T {
        switch detail { case .full: full; case .small: small; case .tiny: tiny; case .micro: micro ?? tiny }
    }
    // 影の大きさは変換を受けないので、出力の大きさに合わせて縮める。
    let px = ctx.ctm.a
    func shadow(_ dy: CGFloat, _ blur: CGFloat, _ c: CGColor) {
        ctx.setShadow(offset: CGSize(width: 0, height: -dy * px), blur: blur * px, color: c)
    }
    ctx.translateBy(x: 0, y: 1024)
    ctx.scaleBy(x: 1, y: -1)
    let body = CGRect(x: 100, y: 100, width: 824, height: 824)
    let shape = CGPath(roundedRect: body, cornerWidth: 185, cornerHeight: 185, transform: nil)

    // 影（アイコンの枠の外に薄く）。
    ctx.saveGState()
    shadow(10, 20, color(0x000000, 0.22))
    ctx.addPath(shape)
    ctx.setFillColor(color(0x1D9AA6))
    ctx.fillPath()
    ctx.restoreGState()

    ctx.saveGState()
    ctx.addPath(shape)
    ctx.clip()
    let space = CGColorSpace(name: CGColorSpace.sRGB)!
    func gradient(_ colors: [CGColor], _ locations: [CGFloat]? = nil) -> CGGradient {
        CGGradient(colorsSpace: space, colors: colors as CFArray, locations: locations)!
    }
    /// path の中を上から下（from → to）へのグラデーションで塗る。
    func fill(_ path: CGPath, _ g: CGGradient, from: CGPoint, to: CGPoint, rule: CGPathFillRule = .winding) {
        ctx.saveGState()
        ctx.addPath(path)
        ctx.clip(using: rule)
        ctx.drawLinearGradient(g, start: from, end: to, options: [.drawsBeforeStartLocation, .drawsAfterEndLocation])
        ctx.restoreGState()
    }

    // 背景: 左上が明るいミント、右下が深いティール。
    fill(shape, gradient([color(0x7FE6CF), color(0x2EB5AE), color(0x177E93)], [0, 0.55, 1]),
         from: CGPoint(x: 260, y: 100), to: CGPoint(x: 760, y: 924))

    // 小さい出力では図柄を大きくして枠いっぱいに使う。
    ctx.saveGState()
    let zoom: CGFloat = pick(1, 1.06, 1.1, 1.12), zoomAt = CGPoint(x: 512, y: 475)
    ctx.translateBy(x: zoomAt.x, y: zoomAt.y)
    ctx.scaleBy(x: zoom, y: zoom)
    ctx.translateBy(x: -zoomAt.x, y: -zoomAt.y)

    // 二重リング（スプリットリング）: 太い鋼の輪。中心と、帯の中心の半径・太さ。
    // 32 px 以下では輪を小さくし、下の端の高さは変えない（ループとの掛かり方を保つ）。
    let ringRadius: CGFloat = pick(134, 134, 100, 92), ringAt = CGPoint(x: 512, y: 444 - ringRadius), ringThick: CGFloat = pick(44, 60, 76, 96)
    let ringPath = CGPath(ellipseIn: CGRect(x: ringAt.x - ringRadius, y: ringAt.y - ringRadius, width: ringRadius * 2, height: ringRadius * 2), transform: nil)
        .copy(strokingWithWidth: ringThick, lineCap: .butt, lineJoin: .round, miterLimit: 10)
    let steel = gradient([color(0x7D8B9C), color(0xF7F9FB), color(0xCDD5DE), color(0x66778C)], [0, 0.4, 0.62, 1])
    /// 輪を描く。鋼は中心からの放射で光の筋。2 巻きの合わせ目に細い線。
    func drawRing() {
        if detail != .full {
            // 小さい出力: 明るい鋼の平塗りに、濃い縁取り。
            ctx.saveGState()
            ctx.addPath(ringPath)
            ctx.clip()
            ctx.addPath(ringPath)
            ctx.setFillColor(color(0xE4E9EF))
            ctx.fillPath()
            ctx.addPath(ringPath)
            ctx.setStrokeColor(color(0x3E4B5C))
            ctx.setLineWidth(pick(0, 32, 30, 40))
            ctx.strokePath()
            ctx.restoreGState()
            return
        }
        ctx.saveGState()
        ctx.addPath(ringPath)
        ctx.clip()
        ctx.drawRadialGradient(steel, startCenter: ringAt, startRadius: ringRadius - ringThick / 2,
                               endCenter: ringAt, endRadius: ringRadius + ringThick / 2, options: [])
        ctx.setStrokeColor(color(0x4A5868, 0.7))
        ctx.setLineWidth(4)
        ctx.addEllipse(in: CGRect(x: ringAt.x - ringRadius - 1, y: ringAt.y - ringRadius - 1, width: ringRadius * 2 + 2, height: ringRadius * 2 + 2))
        ctx.strokePath()
        ctx.restoreGState()
    }
    ctx.saveGState()
    shadow(8, 16, color(0x0A3A48, 0.35))
    ctx.addPath(ringPath)
    ctx.setFillColor(color(0xC8D1DA))
    ctx.fillPath()
    ctx.restoreGState()
    drawRing()

    // 鍵: 穴の中心を原点に、刃が +y（下）へ伸びる形。丸い持ち手・つば・刻みのある刃。
    // 32 px 以下では輪を持ち手の穴に通さず、持ち手を輪の外へずらして輪を手前に描く（重なりを縁だけにする）。
    let threaded = detail == .full || detail == .small
    let bowRadius: CGFloat = pick(92, 100, 112, 110), holeRadius: CGFloat = pick(42, 46, 44, 0), bowDrop: CGFloat = 14
    let bladeWidth: CGFloat = pick(76, 92, 84, 124), bladeEnd: CGFloat = pick(360, 330, 350, 290)
    let keyShape: CGPath = {
        let bow = CGPath(ellipseIn: CGRect(x: -bowRadius, y: bowDrop - bowRadius, width: bowRadius * 2, height: bowRadius * 2), transform: nil)
        let collarTop = bowDrop + bowRadius - 16
        let collar = CGPath(roundedRect: CGRect(x: -50, y: collarTop, width: 100, height: 42), cornerWidth: 12, cornerHeight: 12, transform: nil)
        let half = bladeWidth / 2
        let blade = CGMutablePath()
        blade.move(to: CGPoint(x: -half, y: collarTop + 20))
        blade.addLine(to: CGPoint(x: -half, y: bladeEnd - 22))
        blade.addLine(to: CGPoint(x: -half + 22, y: bladeEnd))
        // 刃の右の縁に刻み（先から根元へ）。
        var y = bladeEnd - 6
        blade.addLine(to: CGPoint(x: half, y: y - 14))
        // 小さい出力では大きな歯を 2 つだけ。
        let notches: [(depth: CGFloat, step: CGFloat)] = pick(
            [(24, 38), (14, 32), (28, 40), (16, 34)], [(34, 46), (34, 56)], [(44, 30), (44, 40)], [(54, 64)])
        for n in notches {
            y -= n.step
            blade.addLine(to: CGPoint(x: half - n.depth, y: y - 4))
            blade.addLine(to: CGPoint(x: half, y: y - 22))
            y -= 22
        }
        blade.addLine(to: CGPoint(x: half, y: collarTop + 20))
        blade.closeSubpath()
        let hole = CGPath(ellipseIn: CGRect(x: -holeRadius, y: -holeRadius, width: holeRadius * 2, height: holeRadius * 2), transform: nil)
        return holeRadius > 0 ? bow.union(collar).union(blade).subtracting(hole) : bow.union(collar).union(blade)
    }()
    /// 輪のどこ（角度）に、どの色の鍵を下げるか。輪が持ち手の穴を通るよう、穴の外側だけ輪を手前に描き直す。
    func hang(angle: CGFloat, tilt: CGFloat, size: CGFloat = 1, light: UInt32, dark: UInt32, edge: UInt32) {
        let reachOut = ringRadius + (threaded ? 0 : bowRadius * size * 0.62)
        let at = CGPoint(x: ringAt.x + reachOut * cos(angle), y: ringAt.y + reachOut * sin(angle))
        let place = CGAffineTransform(translationX: at.x, y: at.y).rotated(by: tilt).scaledBy(x: size, y: size)
        var t = place
        let path = keyShape.copy(using: &t)!
        ctx.saveGState()
        shadow(10, 16, color(0x0A3A48, 0.35))
        ctx.addPath(path)
        ctx.setFillColor(color(dark))
        ctx.fillPath()
        ctx.restoreGState()
        // 光は持ち手の左上から。
        let a = CGPoint(x: -bowRadius, y: -bowRadius).applying(place), b = CGPoint(x: 0, y: bladeEnd).applying(place)
        fill(path, gradient([color(light), color(dark)]), from: a, to: b)
        if detail != .full {
            // 小さい出力: 溝とつやは省き、濃い縁取りで背景から切り離す。
            ctx.saveGState()
            ctx.addPath(path)
            ctx.clip()
            ctx.addPath(path)
            ctx.setStrokeColor(color(edge))
            ctx.setLineWidth(pick(0, 24, 0, 0))
            ctx.strokePath()
            ctx.restoreGState()
        } else {
        // 刃の溝（細い線）と持ち手の内側のつや。
        ctx.saveGState()
        ctx.concatenate(place)
        ctx.setLineCap(.round)
        ctx.setStrokeColor(color(0x000000, 0.14))
        ctx.setLineWidth(12)
        ctx.move(to: CGPoint(x: -10, y: bowDrop + bowRadius + 46))
        ctx.addLine(to: CGPoint(x: -10, y: bladeEnd - 42))
        ctx.strokePath()
        ctx.setStrokeColor(color(0xFFFFFF, 0.35))
        ctx.setLineWidth(8)
        ctx.addArc(center: CGPoint(x: 0, y: bowDrop), radius: bowRadius - 14, startAngle: .pi * 1.05, endAngle: .pi * 1.45, clockwise: false)
        ctx.strokePath()
        ctx.restoreGState()
        }
        // 穴の片側（輪に沿って下側）だけ輪を手前に。
        guard threaded else { return }
        ctx.saveGState()
        ctx.translateBy(x: at.x, y: at.y)
        ctx.rotate(by: angle)
        ctx.clip(to: CGRect(x: -140, y: 0, width: 280, height: 140))
        ctx.rotate(by: -angle)
        ctx.translateBy(x: -at.x, y: -at.y)
        let reach = bowRadius * size + 6
        ctx.addEllipse(in: CGRect(x: at.x - reach, y: at.y - reach, width: reach * 2, height: reach * 2))
        ctx.clip()
        drawRing()
        ctx.restoreGState()
    }
    hang(angle: -.pi * 0.86, tilt: pick(0.64, 0.58, 0.52, 0.5), size: 0.94, light: 0xFFE69A, dark: 0xE9A21E, edge: 0x9A5A08)
    hang(angle: -.pi * 0.14, tilt: -pick(0.64, 0.58, 0.52, 0.5), size: 0.94, light: 0xFFA597, dark: 0xE8534F, edge: 0x9A2222)
    if !threaded { drawRing() }

    // キーホルダーの革: 南京錠の形。下の太い本体と、輪に掛かる太いループ（掛け金の形）。
    let loopAt = CGPoint(x: 512, y: 472), loopRadius: CGFloat = 82, loopThick: CGFloat = 70
    let fobRect = CGRect(x: 312, y: 510, width: 400, height: 336)
    func fobShape(inset i: CGFloat) -> CGPath {
        let loop = CGMutablePath()
        loop.move(to: CGPoint(x: loopAt.x - loopRadius, y: fobRect.minY + 40))
        loop.addLine(to: CGPoint(x: loopAt.x - loopRadius, y: loopAt.y))
        loop.addArc(center: loopAt, radius: loopRadius, startAngle: .pi, endAngle: 0, clockwise: false)
        loop.addLine(to: CGPoint(x: loopAt.x + loopRadius, y: fobRect.minY + 40))
        let band = loop.copy(strokingWithWidth: loopThick - i * 2, lineCap: .butt, lineJoin: .round, miterLimit: 10)
        let r = fobRect.insetBy(dx: i, dy: i)
        let body = CGPath(roundedRect: r, cornerWidth: 118 - i, cornerHeight: 118 - i, transform: nil)
        return body.union(band)
    }
    let fob = fobShape(inset: 0)
    ctx.saveGState()
    shadow(18, 28, color(0x06303C, 0.45))
    ctx.addPath(fob)
    ctx.setFillColor(color(0x8A4A26))
    ctx.fillPath()
    ctx.restoreGState()
    fill(fob, gradient([color(0xC27A45), color(0x9A5228), color(0x6E361A)], [0, 0.5, 1]),
         from: CGPoint(x: 512, y: loopAt.y - loopRadius - loopThick / 2), to: CGPoint(x: 512, y: fobRect.maxY))
    // ふっくらした厚み: 下の縁の内側に柔らかい影、上の縁に光（小さい出力では省く）。
    let outside = CGMutablePath()
    outside.addRect(CGRect(x: 0, y: 0, width: 1024, height: 1024))
    outside.addPath(fob)
    if detail == .full {
    ctx.saveGState()
    ctx.addPath(fob)
    ctx.clip()
    shadow(-10, 22, color(0x3A1806, 0.55))
    ctx.addPath(outside)
    ctx.setFillColor(color(0x000000))
    ctx.fillPath(using: .evenOdd)
    ctx.restoreGState()
    ctx.saveGState()
    ctx.addPath(fob)
    ctx.clip()
    shadow(8, 14, color(0xFFFFFF, 0.3))
    ctx.addPath(outside)
    ctx.setFillColor(color(0x000000))
    ctx.fillPath(using: .evenOdd)
    ctx.restoreGState()
    }
    // 革の切り口: 縁を濃い色で磨いたように細く。
    ctx.saveGState()
    ctx.addPath(fob)
    ctx.clip()
    ctx.addPath(fob)
    ctx.setStrokeColor(color(0x4A2008, pick(0.55, 0.9, 0.9)))
    ctx.setLineWidth(pick(10, 28, 40, 56))
    ctx.strokePath()
    ctx.restoreGState()
    // ステッチ: 縁から少し内側に、クリーム色の破線（16 px では省く）。
    if detail != .micro {
    ctx.saveGState()
    ctx.addPath(fobShape(inset: pick(20, 30, 40)))
    ctx.setLineDash(phase: pick(0, 0, 0), lengths: pick([18, 12], [40, 34], [56, 48]))
    ctx.setLineCap(.round)
    ctx.setLineWidth(pick(7, 16, 24))
    ctx.setStrokeColor(color(0xFFE9C2))
    ctx.strokePath()
    ctx.restoreGState()
    }

    // 型押しの指紋（16 px では省く）: 本体の真ん中に、縦長の弧を重ねた渦（ところどころ切れる）。暗い溝の下に細い光。
    ctx.saveGState()
    let print = CGPoint(x: 512, y: 694)
    ctx.setLineCap(.round)
    // (横の半径, 縦の半径, 始め, 終わり) — 角度は真上を 0 に時計回り（ラジアン）。
    // 小さい出力では太い弧を少しだけ、光の線は省く。
    let ridges: [(CGFloat, CGFloat, CGFloat, CGFloat)] = pick([
        (16, 26, -2.2, 2.2), (40, 52, -2.5, 1.6), (40, 52, 2.0, 2.6), (64, 80, -2.6, 2.7),
        (88, 106, -2.2, -0.5), (88, 106, -0.2, 2.4),
    ], [(22, 32, -2.4, 2.4), (56, 70, -2.6, 2.6), (92, 110, -2.4, 2.4)], [(34, 44, -2.5, 2.5), (84, 100, -2.4, 2.4)])
    let grooves: [(CGFloat, CGColor)] = detail == .full
        ? [(3.5, color(0xFFFFFF, 0.16)), (0, color(0x3A1806, 0.6))] : [(0, color(0x3A1806, pick(0, 0.75, 0.8)))]
    for (dy, c) in detail == .micro ? [] : grooves {
        ctx.setStrokeColor(c)
        ctx.setLineWidth(pick(11, 18, 28))
        for (rx, ry, from, to) in ridges {
            let steps = 40
            for i in 0...steps {
                let a = from + (to - from) * CGFloat(i) / CGFloat(steps)
                let pt = CGPoint(x: print.x + rx * sin(a), y: print.y + 18 + dy - ry * cos(a) + (cos(a) < 0 ? 0 : 0))
                if i == 0 { ctx.move(to: pt) } else { ctx.addLine(to: pt) }
            }
            ctx.strokePath()
        }
    }
    ctx.restoreGState()

    // ループが輪に掛かる: 輪の左側だけループの手前に描き直す。
    ctx.saveGState()
    ctx.clip(to: CGRect(x: 0, y: 390, width: loopAt.x + loopRadius - loopThick / 2, height: 120))
    drawRing()
    ctx.restoreGState()

    ctx.restoreGState()

    // snapshot 版: 右下の角にオレンジの帯。
    if snapshot {
        ctx.saveGState()
        ctx.translateBy(x: 760, y: 760)
        ctx.rotate(by: -.pi / 4)
        ctx.setFillColor(color(0xFF8A3D))
        ctx.fill(CGRect(x: -330, y: -46, width: 660, height: 92))
        let text = NSAttributedString(string: "SNAPSHOT", attributes: [
            .font: NSFont.systemFont(ofSize: 50, weight: .heavy), .foregroundColor: NSColor.white,
        ])
        let line = CTLineCreateWithAttributedString(text)
        let width = CTLineGetTypographicBounds(line, nil, nil, nil)
        // 文字は上下を戻して描く（座標を上下反転しているため）。
        ctx.scaleBy(x: 1, y: -1)
        ctx.textPosition = CGPoint(x: -width / 2, y: -17)
        CTLineDraw(line, ctx)
        ctx.restoreGState()
    }
    ctx.restoreGState()
}

func png(size: Int, snapshot: Bool) -> Data {
    let ctx = CGContext(
        data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: 0,
        space: CGColorSpace(name: CGColorSpace.sRGB)!, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    ctx.scaleBy(x: CGFloat(size) / 1024, y: CGFloat(size) / 1024)
    draw(ctx, snapshot: snapshot, detail: Detail(size: size))
    let rep = NSBitmapImageRep(cgImage: ctx.makeImage()!)
    return rep.representation(using: .png, properties: [:])!
}

try FileManager.default.createDirectory(at: outDir, withIntermediateDirectories: true)
for (name, snapshot) in [("AppIcon", false), ("AppIcon-Snapshot", true)] {
    let iconset = FileManager.default.temporaryDirectory.appendingPathComponent("\(name).iconset")
    try? FileManager.default.removeItem(at: iconset)
    try FileManager.default.createDirectory(at: iconset, withIntermediateDirectories: true)
    for base in [16, 32, 128, 256, 512] {
        try png(size: base, snapshot: snapshot).write(to: iconset.appendingPathComponent("icon_\(base)x\(base).png"))
        try png(size: base * 2, snapshot: snapshot).write(to: iconset.appendingPathComponent("icon_\(base)x\(base)@2x.png"))
    }
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
    process.arguments = ["-c", "icns", iconset.path, "-o", outDir.appendingPathComponent("\(name).icns").path]
    try process.run()
    process.waitUntilExit()
    guard process.terminationStatus == 0 else { fatalError("iconutil が失敗した") }
    try png(size: 1024, snapshot: snapshot).write(to: outDir.appendingPathComponent("\(name).png"))
}
// 小さい出力の見本: 16・32・64 px を、4 倍（ニアレストネイバー）と等倍で並べた表にする。
let small = [16, 32, 64]
var images: [CGImage] = []
for size in small {
    let data = png(size: size, snapshot: false)
    images.append(NSBitmapImageRep(data: data)!.cgImage!)
}
let gap = 24, sheetWidth = small.reduce(0) { $0 + $1 * 4 } + gap * (small.count + 1)
let sheetHeight = 64 * 4 + 64 + gap * 3
let sheet = CGContext(
    data: nil, width: sheetWidth, height: sheetHeight, bitsPerComponent: 8, bytesPerRow: 0,
    space: CGColorSpace(name: CGColorSpace.sRGB)!, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
sheet.setFillColor(color(0xECECEC))
sheet.fill(CGRect(x: 0, y: 0, width: sheetWidth, height: sheetHeight))
sheet.interpolationQuality = .none
var x = gap
for (size, image) in zip(small, images) {
    // 上の段に 4 倍、下の段に等倍（座標は左下が原点）。
    sheet.draw(image, in: CGRect(x: x, y: sheetHeight - gap - size * 4, width: size * 4, height: size * 4))
    sheet.draw(image, in: CGRect(x: x, y: gap, width: size, height: size))
    x += size * 4 + gap
}
try NSBitmapImageRep(cgImage: sheet.makeImage()!).representation(using: .png, properties: [:])!
    .write(to: outDir.appendingPathComponent("AppIcon-sizes.png"))
print("出力: \(outDir.path)")
