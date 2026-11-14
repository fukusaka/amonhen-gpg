// README の頭のバナーを描く。図柄はアイコン（scripts/make-icon.swift）に合わせる: ミントからティールの背景に、
// 革のキーホルダーのクリーム色のステッチを縁に回し、右には指紋の型押しのような淡い弧と、封蝋で閉じたバックアップの
// 封筒、その上に放り出した鍵の束。左にアイコンと名前と一言。
//   swift scripts/make-banner.swift [出力先のファイル]
// 出力: docs/images/banner.png（1600×400 の 2 倍の解像度）。先に scripts/make-icon.swift で AppIcon.png を作っておく。
import AppKit

let out = URL(fileURLWithPath: CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "docs/images/banner.png")
let icon = NSImage(contentsOfFile: "apps/macos/Icons/AppIcon.png")!

func color(_ hex: UInt32, _ alpha: CGFloat = 1) -> CGColor {
    CGColor(
        srgbRed: CGFloat((hex >> 16) & 0xff) / 255, green: CGFloat((hex >> 8) & 0xff) / 255,
        blue: CGFloat(hex & 0xff) / 255, alpha: alpha)
}

let width: CGFloat = 1600, height: CGFloat = 400, scale: CGFloat = 2

/// 1600×400 の座標（左上が原点）で描く。
func draw(_ ctx: CGContext) {
    ctx.translateBy(x: 0, y: height)
    ctx.scaleBy(x: 1, y: -1)
    let body = CGRect(x: 0, y: 0, width: width, height: height)
    ctx.addPath(CGPath(roundedRect: body, cornerWidth: 28, cornerHeight: 28, transform: nil))
    ctx.clip()
    let space = CGColorSpace(name: CGColorSpace.sRGB)!

    // 背景: アイコンと同じミントからティール（左上が明るく、右下が深い）。
    let background = CGGradient(
        colorsSpace: space, colors: [color(0x7FE6CF), color(0x2EB5AE), color(0x177E93)] as CFArray, locations: [0, 0.5, 1])!
    ctx.drawLinearGradient(background, start: CGPoint(x: 0, y: 0), end: CGPoint(x: width, y: height), options: [])

    // 右: 指紋の型押しのような弧。中心を右下の外に置き、途切れのある楕円を重ねる（種を決めた乱数で切れ目を散らす）。
    var seed: UInt64 = 0x5EED_F0B2
    func random() -> CGFloat {
        seed = seed &* 6364136223846793005 &+ 1442695040888963407
        return CGFloat(seed >> 33) / CGFloat(1 << 31)
    }
    let center = CGPoint(x: 1330, y: 250)
    ctx.setLineCap(.round)
    for i in 0..<14 {
        let rx = 40 + CGFloat(i) * 26, ry = 52 + CGFloat(i) * 32
        let ridge = CGPath(ellipseIn: CGRect(x: center.x - rx, y: center.y - ry, width: rx * 2, height: ry * 2), transform: nil)
        let length = CGFloat.pi * 2 * sqrt((rx * rx + ry * ry) / 2)
        let gap = 18 + random() * 40
        ctx.saveGState()
        ctx.addPath(ridge)
        ctx.setLineDash(phase: random() * length, lengths: [length * (0.3 + random() * 0.3), gap, length * 0.2, gap])
        ctx.setStrokeColor(color(0x0B4F5E, 0.16 - CGFloat(i) * 0.006))
        ctx.setLineWidth(9)
        ctx.strokePath()
        ctx.restoreGState()
    }

    // 右: 指紋の上に、バックアップの封筒を 2 通、机に置いたように重ねる（秘密鍵のバックアップと失効証明書）。
    // 手前の封筒は赤い封蝋で閉じ、蝋に鍵の形を押す（大事にしまってある）。影は机に置いた物のように近く短く。
    func gradient(_ colors: [CGColor]) -> CGGradient { CGGradient(colorsSpace: space, colors: colors as CFArray, locations: nil)! }
    /// 机に置いた物の影（近く短く）。
    func lyingShadow() {
        ctx.setShadow(offset: CGSize(width: 2 * scale, height: -3 * scale), blur: 5 * scale, color: color(0x0A3A48, 0.38))
    }
    // 封蝋に押す鍵: 穴の中心を原点に、刃が +y（下）へ伸びる形（アイコンの鍵を簡単にしたもの）。
    let keyMark: CGPath = {
        let bow = CGPath(ellipseIn: CGRect(x: -11, y: -11, width: 22, height: 22), transform: nil)
        let hole = CGPath(ellipseIn: CGRect(x: -4.5, y: -4.5, width: 9, height: 9), transform: nil)
        let blade = CGMutablePath()
        blade.addRect(CGRect(x: -3.5, y: 8, width: 7, height: 30))
        blade.addRect(CGRect(x: 3, y: 26, width: 8, height: 5))
        blade.addRect(CGRect(x: 3, y: 33, width: 6, height: 5))
        return bow.union(blade).subtracting(hole)
    }()
    /// 封筒を 1 通置く（中心・大きさ・傾き）。裏向きで、上のふたが三角に閉じている。sealed なら、ふたの先に封蝋。
    func envelope(at center: CGPoint, size: CGSize, tilt: CGFloat, paper: UInt32, shade: UInt32, sealed: Bool) {
        ctx.saveGState()
        ctx.translateBy(x: center.x, y: center.y)
        ctx.rotate(by: tilt)
        let w = size.width, h = size.height
        let body = CGPath(roundedRect: CGRect(x: -w / 2, y: -h / 2, width: w, height: h), cornerWidth: 8, cornerHeight: 8, transform: nil)
        ctx.saveGState()
        lyingShadow()
        ctx.addPath(body)
        ctx.setFillColor(color(paper))
        ctx.fillPath()
        ctx.restoreGState()
        ctx.saveGState()
        ctx.addPath(body)
        ctx.clip()
        ctx.drawLinearGradient(gradient([color(paper), color(shade)]), start: CGPoint(x: 0, y: -h / 2), end: CGPoint(x: 0, y: h / 2), options: [])
        // 裏の合わせ目: 下の角から中ほどへ。
        ctx.setStrokeColor(color(0x8A6A3A, 0.22))
        ctx.setLineWidth(2)
        ctx.move(to: CGPoint(x: -w / 2, y: h / 2))
        ctx.addLine(to: CGPoint(x: 0, y: h * 0.06))
        ctx.addLine(to: CGPoint(x: w / 2, y: h / 2))
        ctx.strokePath()
        // ふた: 上の辺から中ほどへの三角。下に薄い影。
        let tip = CGPoint(x: 0, y: h * 0.12)
        let flap = CGMutablePath()
        flap.move(to: CGPoint(x: -w / 2, y: -h / 2))
        flap.addLine(to: CGPoint(x: w / 2, y: -h / 2))
        flap.addQuadCurve(to: tip, control: CGPoint(x: w * 0.12, y: tip.y - 6))
        flap.addQuadCurve(to: CGPoint(x: -w / 2, y: -h / 2), control: CGPoint(x: -w * 0.12, y: tip.y - 6))
        flap.closeSubpath()
        ctx.saveGState()
        ctx.setShadow(offset: CGSize(width: 0, height: -2 * scale), blur: 4 * scale, color: color(0x6A4A1A, 0.25))
        ctx.addPath(flap)
        ctx.setFillColor(color(paper))
        ctx.fillPath()
        ctx.restoreGState()
        ctx.restoreGState()
        if sealed {
            // 封蝋: 縁がゆるく波打つ（溶けた蝋の）赤い円に、内側の輪と、押した鍵の形。
            let r: CGFloat = 34
            let wax = CGMutablePath()
            for i in 0...72 {
                let a = CGFloat(i) / 72 * .pi * 2
                let rr = r + 2.2 * sin(a * 5) + 1.4 * sin(a * 3 + 1)
                let p = CGPoint(x: tip.x + rr * cos(a), y: tip.y + rr * sin(a))
                if i == 0 { wax.move(to: p) } else { wax.addLine(to: p) }
            }
            wax.closeSubpath()
            ctx.saveGState()
            ctx.setShadow(offset: CGSize(width: 1 * scale, height: -3 * scale), blur: 4 * scale, color: color(0x5A1008, 0.45))
            ctx.addPath(wax)
            ctx.setFillColor(color(0xC63A2A))
            ctx.fillPath()
            ctx.restoreGState()
            ctx.saveGState()
            ctx.addPath(wax)
            ctx.clip()
            ctx.drawRadialGradient(gradient([color(0xF06A52), color(0xB02A1C)]), startCenter: CGPoint(x: tip.x - 10, y: tip.y - 12),
                                   startRadius: 0, endCenter: tip, endRadius: r + 3, options: [])
            ctx.restoreGState()
            ctx.setStrokeColor(color(0x8E1E12, 0.6))
            ctx.setLineWidth(3)
            ctx.strokeEllipse(in: CGRect(x: tip.x - 22, y: tip.y - 22, width: 44, height: 44))
            var mark = CGAffineTransform(translationX: tip.x - 2, y: tip.y - 14).rotated(by: 0.5).scaledBy(x: 0.82, y: 0.82)
            ctx.addPath(keyMark.copy(using: &mark)!)
            ctx.setFillColor(color(0x8E1E12, 0.75))
            ctx.fillPath(using: .evenOdd)
        }
        ctx.restoreGState()
    }
    envelope(at: CGPoint(x: 1236, y: 150), size: CGSize(width: 290, height: 180), tilt: -0.13,
             paper: 0xF2E8D6, shade: 0xE2D3B8, sealed: false)
    envelope(at: CGPoint(x: 1352, y: 238), size: CGSize(width: 320, height: 196), tilt: 0.08,
             paper: 0xFFF8EA, shade: 0xF0E2C8, sealed: true)

    // 封筒の上に、アイコンと同じ形の鍵の束を放り出したように置く。3 本とも鋼の輪に通したまま、輪から外へばらばらの
    // 向きに開く（下がっているのではなく、置いてある）。封蝋は隠さない。
    // 鍵: 穴の中心を原点に、刃が +y（下）へ伸びる形。丸い持ち手・つば・刻みのある刃（アイコンの鍵を縮めたもの）。
    let bowRadius: CGFloat = 46, holeRadius: CGFloat = 21, bladeWidth: CGFloat = 38, bladeEnd: CGFloat = 186
    let keyShape: CGPath = {
        let bow = CGPath(ellipseIn: CGRect(x: -bowRadius, y: 7 - bowRadius, width: bowRadius * 2, height: bowRadius * 2), transform: nil)
        let collarTop = 7 + bowRadius - 8
        let collar = CGPath(roundedRect: CGRect(x: -25, y: collarTop, width: 50, height: 21), cornerWidth: 6, cornerHeight: 6, transform: nil)
        let half = bladeWidth / 2
        let blade = CGMutablePath()
        blade.move(to: CGPoint(x: -half, y: collarTop + 10))
        blade.addLine(to: CGPoint(x: -half, y: bladeEnd - 11))
        blade.addLine(to: CGPoint(x: -half + 11, y: bladeEnd))
        var y = bladeEnd - 3
        blade.addLine(to: CGPoint(x: half, y: y - 7))
        for (depth, step) in [(CGFloat(12), CGFloat(19)), (7, 16), (14, 20), (8, 17)] {
            y -= step
            blade.addLine(to: CGPoint(x: half - depth, y: y - 2))
            blade.addLine(to: CGPoint(x: half, y: y - 11))
            y -= 11
        }
        blade.addLine(to: CGPoint(x: half, y: collarTop + 10))
        blade.closeSubpath()
        let hole = CGPath(ellipseIn: CGRect(x: -holeRadius, y: -holeRadius, width: holeRadius * 2, height: holeRadius * 2), transform: nil)
        return bow.union(collar).union(blade).subtracting(hole)
    }()
    let keySize: CGFloat = 0.66
    let ringAt = CGPoint(x: 1268, y: 196), ringRadius: CGFloat = 40, ringThick: CGFloat = 14
    let ringPath = CGPath(ellipseIn: CGRect(x: ringAt.x - ringRadius, y: ringAt.y - ringRadius, width: ringRadius * 2, height: ringRadius * 2), transform: nil)
        .copy(strokingWithWidth: ringThick, lineCap: .butt, lineJoin: .round, miterLimit: 10)
    let steel = CGGradient(
        colorsSpace: space, colors: [color(0x7D8B9C), color(0xF7F9FB), color(0xCDD5DE), color(0x66778C)] as CFArray,
        locations: [0, 0.4, 0.62, 1])!
    func drawRing() {
        ctx.saveGState()
        ctx.addPath(ringPath)
        ctx.clip()
        ctx.drawRadialGradient(steel, startCenter: ringAt, startRadius: ringRadius - ringThick / 2,
                               endCenter: ringAt, endRadius: ringRadius + ringThick / 2, options: [])
        ctx.restoreGState()
    }
    ctx.saveGState()
    lyingShadow()
    ctx.addPath(ringPath)
    ctx.setFillColor(color(0xC8D1DA))
    ctx.fillPath()
    ctx.restoreGState()
    drawRing()
    /// 輪の angle（度。0 が右、時計回り）の所に通した鍵を、輪から外へ向けて置く。turn は外向きからのずれ（度）。
    /// 輪が持ち手の穴を通るよう、穴の外側だけ輪を手前に描き直す。
    func hang(angle degrees: CGFloat, turn: CGFloat, light: UInt32, dark: UInt32) {
        let angle = degrees * .pi / 180
        let at = CGPoint(x: ringAt.x + ringRadius * cos(angle), y: ringAt.y + ringRadius * sin(angle))
        var place = CGAffineTransform(translationX: at.x, y: at.y).rotated(by: angle - .pi / 2 + turn * .pi / 180)
            .scaledBy(x: keySize, y: keySize)
        let path = keyShape.copy(using: &place)!
        ctx.saveGState()
        lyingShadow()
        ctx.addPath(path)
        ctx.setFillColor(color(dark))
        ctx.fillPath()
        ctx.restoreGState()
        ctx.saveGState()
        ctx.addPath(path)
        ctx.clip(using: .evenOdd)
        let a = CGPoint(x: -bowRadius, y: -bowRadius).applying(place), b = CGPoint(x: 0, y: bladeEnd).applying(place)
        ctx.drawLinearGradient(gradient([color(light), color(dark)]), start: a, end: b, options: [.drawsBeforeStartLocation, .drawsAfterEndLocation])
        ctx.restoreGState()
        ctx.saveGState()
        ctx.translateBy(x: at.x, y: at.y)
        ctx.rotate(by: angle)
        ctx.clip(to: CGRect(x: -60, y: 0, width: 120, height: 60))
        ctx.rotate(by: -angle)
        ctx.translateBy(x: -at.x, y: -at.y)
        let reach = bowRadius * keySize + 3
        ctx.addEllipse(in: CGRect(x: at.x - reach, y: at.y - reach, width: reach * 2, height: reach * 2))
        ctx.clip()
        drawRing()
        ctx.restoreGState()
    }
    hang(angle: 196, turn: 6, light: 0xD9C8FF, dark: 0x8C6FE0)
    hang(angle: 100, turn: 14, light: 0xFFA597, dark: 0xE8534F)
    hang(angle: -48, turn: -8, light: 0xFFE69A, dark: 0xE9A21E)

    // 縁: 革のキーホルダーと同じクリーム色のステッチ。
    let stitch = CGPath(
        roundedRect: body.insetBy(dx: 18, dy: 18), cornerWidth: 14, cornerHeight: 14, transform: nil)
    ctx.saveGState()
    ctx.addPath(stitch)
    ctx.setLineDash(phase: 0, lengths: [22, 14])
    ctx.setLineWidth(5)
    ctx.setStrokeColor(color(0xFFE9C2, 0.85))
    ctx.strokePath()
    ctx.restoreGState()

    // 左: アイコンと名前・一言。文字は上下を戻して描く（座標を上下反転しているため）。
    let iconRect = CGRect(x: 64, y: 72, width: 256, height: 256)
    ctx.saveGState()
    ctx.translateBy(x: iconRect.minX, y: iconRect.maxY)
    ctx.scaleBy(x: 1, y: -1)
    let cg = icon.cgImage(forProposedRect: nil, context: nil, hints: nil)!
    ctx.draw(cg, in: CGRect(origin: .zero, size: iconRect.size))
    ctx.restoreGState()
    func text(_ s: String, _ size: CGFloat, _ weight: NSFont.Weight, _ fill: NSColor, at: CGPoint) {
        let shadow = NSShadow()
        shadow.shadowColor = NSColor(white: 0, alpha: 0.18)
        shadow.shadowOffset = NSSize(width: 0, height: -2)
        shadow.shadowBlurRadius = 6
        let line = CTLineCreateWithAttributedString(NSAttributedString(string: s, attributes: [
            .font: NSFont.systemFont(ofSize: size, weight: weight), .foregroundColor: fill, .shadow: shadow,
        ]))
        ctx.saveGState()
        ctx.translateBy(x: at.x, y: at.y)
        ctx.scaleBy(x: 1, y: -1)
        ctx.textPosition = .zero
        CTLineDraw(line, ctx)
        ctx.restoreGState()
    }
    text("Amonhen GPG", 84, .bold, .white, at: CGPoint(x: 340, y: 204))
    text("Keep your own GnuPG keys usable and safe.", 30, .medium, NSColor(white: 1, alpha: 0.88), at: CGPoint(x: 344, y: 256))
}

let pixels = NSBitmapImageRep(
    bitmapDataPlanes: nil, pixelsWide: Int(width * scale), pixelsHigh: Int(height * scale), bitsPerSample: 8,
    samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
let ctx = NSGraphicsContext(bitmapImageRep: pixels)!.cgContext
ctx.scaleBy(x: scale, y: scale)
draw(ctx)
try! FileManager.default.createDirectory(at: out.deletingLastPathComponent(), withIntermediateDirectories: true)
try! pixels.representation(using: .png, properties: [:])!.write(to: out)
print(out.path)
