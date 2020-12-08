use std::env;
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_path = Path::new(&out_dir).join("bindings.rs");
    let wrapper = "bindgen/wrapper.h";

    if env::var("DOCS_RS").is_ok() {
        // Use pre-built Linux bindings when building documentation.
        std::fs::copy("src/bindings_linux.rs", out_path)
            .expect("Couldn't copy bindings to output directory");
        return; // bye!
    }

    // Tell cargo to tell rustc to link libacl.so, only on Linux.
    #[cfg(target_os = "linux")]
    println!("cargo:rustc-link-lib=acl");

    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed={}", wrapper);

    // Build bindings for "wrapper.h". Tell cargo to invalidate the built
    // crate when any included header file changes.
    let mut builder = bindgen::Builder::default()
        .header(wrapper)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks));

    // Speify the types, functions, and constants we want to include.

    let types = ["acl_.*", "uid_t"];
    let funcs = ["acl_.*"];
    let vars = ["ACL_.*", "ENOENT", "ENOTSUP", "EINVAL", "ENOMEM"];

    for type_ in &types {
        builder = builder.whitelist_type(type_);
    }

    for func_ in &funcs {
        builder = builder.whitelist_function(func_);
    }

    for var_ in &vars {
        builder = builder.whitelist_var(var_);
    }

    // Generate the bindings.
    let bindings = builder.generate().expect("Couldn't generate bindings");

    // Write the bindings.
    bindings
        .write_to_file(out_path)
        .expect("Couldn't write bindings!");
}
