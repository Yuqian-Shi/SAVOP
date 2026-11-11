use std::{env, fs, path::PathBuf};

fn main() {
    let root = PathBuf::from(env::var("SAVOP_SOURCE_ROOT").expect("set SAVOP_SOURCE_ROOT"))
        .canonicalize()
        .expect("source root");
    let main_path = root.join("agent/src/main.rs");
    let source = fs::read_to_string(&main_path)
        .expect("production main.rs")
        .replace("\r\n", "\n");
    assert_eq!(source.matches("\nfn main() {").count(), 1);
    assert_eq!(source.matches("mod sav_apps;\n").count(), 1);
    // Instrumentation only: retain production types/functions verbatim. Never start its Agent.
    let mut source = source.replacen("\nfn main() {", "\nfn production_main_not_executed() {", 1);
    for (module, relative) in [
        ("sav_apps", "agent/src/sav_apps/mod.rs"),
        ("auto_dataplane", "agent/src/auto_dataplane.rs"),
        ("urpf_dataplane", "agent/src/urpf_dataplane.rs"),
    ] {
        let declaration = format!("mod {module};");
        if source.contains(&declaration) {
            source = source.replacen(
                &declaration,
                &format!("#[path = {:?}]\n{declaration}", root.join(relative)),
                1,
            );
        }
    }
    fs::write(
        PathBuf::from(env::var("OUT_DIR").unwrap()).join("production.rs"),
        source,
    )
    .unwrap();
    println!("cargo:rerun-if-env-changed=SAVOP_SOURCE_ROOT");
    println!("cargo:rerun-if-changed={}", main_path.display());
    println!(
        "cargo:rerun-if-changed={}",
        root.join("agent/src/sav_apps").display()
    );
}
