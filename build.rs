fn compile_ref_impl(l: usize) {
    // Needed because the tests have to be executed sequentially.
    // If we run them simultaneously, the global state of the RNG
    // in the C ref implementation will have a synchronization issue.
    println!("cargo:rustc-env=RUST_TEST_THREADS=1");

    cc::Build::new()
        .define("SABER_L", format!("{}", l).as_str())
        .file("src/c/pack_unpack.c")
        .file("src/c/poly.c")
        .file("src/c/fips202.c")
        .file("src/c/verify.c")
        .file("src/c/cbd.c")
        .file("src/c/SABER_indcpa.c")
        .file("src/c/kem.c")
        .object("src/c/rng.o")
        .compile("c_reference");

    println!("cargo:rustc-link-lib=crypto");
}

fn main() {
    // allow variant feature flags only mutually exclusive
    let mut flags = [
        cfg!(feature = "lightsaber"),
        cfg!(feature = "saber"),
        cfg!(feature = "firesaber"),
    ];
    let count = flags.iter().filter(|b| **b).count();
    if count >= 2 {
        panic!(
            "Sorry, you must only specify one feature: EITHER lightsaber EITHER saber OR firesaber"
        );
    } else if count == 0 {
        // default is “saber”
        flags[1] = true;
    }

    // emit configuration flag for the rank of the module
    let mut l = 0;
    for (i, is_set) in flags.iter().enumerate() {
        // cargo:rustc-cfg=SABER_L_IS_2  … must be emitted for lightsaber, etc
        if *is_set {
            println!("cargo:rustc-cfg=SABER_L_IS_{}", i + 2);
            l = i + 2;
        }
    }

    // NOTE in current rust 1.60 the “test” configuration variable is not supported.
    //      thus, we use the feature “cref” and you *have* to set it: e.g. `cargo test --features=cref`.
    //      https://github.com/rust-lang/cargo/issues/2549
    if cfg!(feature = "cref") {
        compile_ref_impl(l);
    }
}
