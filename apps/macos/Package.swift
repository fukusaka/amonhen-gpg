// swift-tools-version: 6.2
import PackageDescription

// Rust のコア（crates/ffi）を静的ライブラリとしてリンクする。先に scripts/build-core.sh を実行すること
// （UniFFI の生成したヘッダーと Swift のコードもそこで作る）。
let coreLibDir = Context.packageDirectory + "/../../target/release"

let package = Package(
    name: "AmonhenGpg",
    platforms: [.macOS("14.4")],
    products: [
        .library(name: "AmonhenGpgKit", targets: ["AmonhenGpgKit"]),
        .executable(name: "AmonhenGpg", targets: ["AmonhenGpg"]),
    ],
    targets: [
        .systemLibrary(name: "CAmonhenGpg", path: "Sources/CAmonhenGpg"),
        .target(
            name: "AmonhenGpgKit",
            dependencies: ["CAmonhenGpg"],
            // -l では同じ場所の動的ライブラリ（バインディングの生成に使う）が選ばれ、アプリが target/ を指してしまうので、
            // 静的ライブラリをじかに渡す。
            linkerSettings: [
                .unsafeFlags([coreLibDir + "/libamonhen_gpg_ffi.a"])
            ]
        ),
        .executableTarget(
            name: "AmonhenGpg",
            dependencies: ["AmonhenGpgKit"],
            swiftSettings: [.defaultIsolation(MainActor.self)]
        ),
        .testTarget(name: "AmonhenGpgKitTests", dependencies: ["AmonhenGpgKit"]),
    ]
)
