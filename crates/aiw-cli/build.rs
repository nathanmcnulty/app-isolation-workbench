fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc")
    {
        // Native plan validation and Start can overflow the default 1 MiB
        // main-thread stack in Windows debug builds. Reserve the measured
        // 8 MiB for this CLI only; this does not set its initial commitment.
        println!("cargo:rustc-link-arg-bin=aiw=/STACK:8388608");
    }
}
