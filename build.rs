use std::env;
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_path = Path::new(&out_dir).join("bindings.rs");
    let wrapper = "bindgen/wrapper.h";

    // Tell cargo to tell rustc to link libacl.so, only on Linux.
    #[cfg(target_os = "linux")]
    println!("cargo:rustc-link-lib=acl");

    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed={}", wrapper);

    if !cfg!(feature = "buildtime_bindgen") {
        // Use pre-built bindings when bindgen is not available (the default).
        prebuilt_bindings(&out_path);
    } else {
        #[cfg(feature = "buildtime_bindgen")]
        bindgen_bindings(wrapper, &out_path);
    }
}

#[cfg(feature = "buildtime_bindgen")]
fn bindgen_bindings(wrapper: &str, out_path: &Path) {
    // Build bindings for "wrapper.h". Tell cargo to invalidate the built
    // crate when any included header file changes.
    let mut builder = bindgen::Builder::default()
        .header(wrapper)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks));

    // Specify the types, functions, and constants we want to include.
    let types = ["acl_.*", "uid_t"];
    let funcs = [
        "acl_.*",
        "mbr_uid_to_uuid",
        "mbr_gid_to_uuid",
        "mbr_uuid_to_id",
        "open",
        "close",
    ];
    let vars = [
        "ACL_.*",
        "ENOENT",
        "ENOTSUP",
        "EINVAL",
        "ENOMEM",
        "O_SYMLINK",
        "ID_TYPE_UID",
        "ID_TYPE_GID",
    ];

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

fn prebuilt_bindings(out_path: &Path) {
    let target = env::var("CARGO_CFG_TARGET_OS").unwrap();

    // Untrusted input check.
    match target.as_str() {
        "macos" | "linux" => (),
        s => panic!("Unsupported target OS: {}", s),
    };

    let bindings_path = format!("bindgen/bindings_{}.rs", target);
    if let Err(err) = std::fs::copy(&bindings_path, out_path) {
        panic!("Can't copy {:?} to {:?}: {}", bindings_path, out_path, err);
    }

    println!("cargo:warning=Exacl is using built-in bindings, rather than running bindgen.");
}
