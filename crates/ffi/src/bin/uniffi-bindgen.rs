//! Swift などのバインディングを生成する（`scripts/build-core.sh` が使う）。

fn main() {
    uniffi::uniffi_bindgen_main()
}
