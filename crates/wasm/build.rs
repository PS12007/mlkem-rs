// Export the linker-defined global `__heap_base` (the first address after
// the stack and static data) so JavaScript knows where free memory starts.
// The crate has no allocator; callers place inputs and outputs there.
fn main() {
    if std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("wasm32") {
        println!("cargo:rustc-link-arg-cdylib=--export=__heap_base");
    }
}
