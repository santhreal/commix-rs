//! External contract tests: README, Cargo.toml metadata, and documented CLI argv wiring.
use commix_rs::CommixBuilder;
use std::path::PathBuf;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_workspace_file(name: &str) -> String {
    std::fs::read_to_string(manifest_dir().join(name))
        .unwrap_or_else(|e| panic!("failed to read {name}: {e}"))
}

fn cargo_toml_string_field(content: &str, key: &str) -> String {
    let needle = format!("{key} = \"");
    let start = content
        .find(&needle)
        .unwrap_or_else(|| panic!("Cargo.toml missing {key} string field"));
    let rest = &content[start + needle.len()..];
    let end = rest
        .find('"')
        .unwrap_or_else(|| panic!("Cargo.toml {key} string not terminated"));
    rest[..end].to_string()
}

fn cargo_toml_array_field(content: &str, key: &str) -> Vec<String> {
    let needle = format!("{key} = [");
    let start = content
        .find(&needle)
        .unwrap_or_else(|| panic!("Cargo.toml missing {key} array field"));
    let rest = &content[start + needle.len()..];
    let end = rest
        .find(']')
        .unwrap_or_else(|| panic!("Cargo.toml {key} array not terminated"));
    rest[..end]
        .split(',')
        .map(|item| item.trim().trim_matches('"').to_string())
        .filter(|item| !item.is_empty())
        .collect()
}

fn readme_version_pin(readme: &str) -> String {
    let marker = "commix-rs = \"";
    let start = readme
        .find(marker)
        .unwrap_or_else(|| panic!("README missing commix-rs version pin"));
    let rest = &readme[start + marker.len()..];
    let end = rest
        .find('"')
        .unwrap_or_else(|| panic!("README version pin not terminated"));
    rest[..end].to_string()
}

fn argv_flag_value(argv: &[String], flag: &str) -> Option<String> {
    argv.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].clone())
}

fn argv_contains(argv: &[String], token: &str) -> bool {
    argv.iter().any(|arg| arg == token)
}

// ---- Cargo.toml + README metadata ----

#[test]
fn contract_readme_version_pin_matches_cargo_package_version() {
    let cargo = read_workspace_file("Cargo.toml");
    let readme = read_workspace_file("README.md");
    let package_version = cargo_toml_string_field(&cargo, "version");
    let readme_pin = readme_version_pin(&readme);
    assert_eq!(
        readme_pin, package_version,
        "README install pin must match Cargo.toml version"
    );
    assert_eq!(package_version, "0.1.1", "expected release version 0.1.1");
}

#[test]
fn contract_repository_url_contains_santhreal_commix_rs() {
    let cargo = read_workspace_file("Cargo.toml");
    let repository = cargo_toml_string_field(&cargo, "repository");
    assert!(
        repository.contains("santhreal/commix-rs"),
        "repository must point at santhreal/commix-rs, got {repository}"
    );
}

#[test]
fn contract_license_is_mit() {
    let cargo = read_workspace_file("Cargo.toml");
    let license = cargo_toml_string_field(&cargo, "license");
    assert_eq!(license, "MIT");
    let license_file = read_workspace_file("LICENSE-MIT");
    assert!(
        license_file.contains("MIT License"),
        "LICENSE-MIT must document MIT terms"
    );
}

#[test]
fn contract_cargo_keywords_present() {
    let cargo = read_workspace_file("Cargo.toml");
    let keywords = cargo_toml_array_field(&cargo, "keywords");
    for required in [
        "commix",
        "security",
        "command-injection",
        "os-injection",
        "vulnerability",
    ] {
        assert!(
            keywords.iter().any(|k| k == required),
            "Cargo.toml keywords missing {required}: {keywords:?}"
        );
    }
}

#[test]
fn contract_cargo_categories_present() {
    let cargo = read_workspace_file("Cargo.toml");
    let categories = cargo_toml_array_field(&cargo, "categories");
    for required in ["api-bindings", "web-programming"] {
        assert!(
            categories.iter().any(|c| c == required),
            "Cargo.toml categories missing {required}: {categories:?}"
        );
    }
}

// ---- Documented builder flags → commix argv ----

#[test]
fn contract_documented_builder_flags_emit_expected_argv_tokens() {
    let argv = CommixBuilder::new()
        .url("http://example.com/page?id=1")
        .method("POST")
        .data("a=1&b=2")
        .cookie("session=abc")
        .ignore_waf(true)
        .delay_secs(5)
        .batch(true)
        .offline(true)
        .prefix(";")
        .suffix("#")
        .build()
        .command_argv();

    assert_eq!(
        argv_flag_value(&argv, "--url").as_deref(),
        Some("http://example.com/page?id=1")
    );
    assert_eq!(argv_flag_value(&argv, "--method").as_deref(), Some("POST"));
    assert_eq!(argv_flag_value(&argv, "--data").as_deref(), Some("a=1&b=2"));
    assert_eq!(
        argv_flag_value(&argv, "--cookie").as_deref(),
        Some("session=abc")
    );
    assert!(argv_contains(&argv, "--skip-waf"));
    assert_eq!(argv_flag_value(&argv, "--delay").as_deref(), Some("5"));
    assert!(argv_contains(&argv, "--batch"));
    assert!(argv_contains(&argv, "--offline"));
    assert_eq!(argv_flag_value(&argv, "--prefix").as_deref(), Some(";"));
    assert_eq!(argv_flag_value(&argv, "--suffix").as_deref(), Some("#"));
}

#[test]
fn contract_threads_builder_is_deprecated_no_op_not_on_argv() {
    #[allow(deprecated)]
    let argv = CommixBuilder::new()
        .url("http://example.com")
        .threads(8)
        .build()
        .command_argv();
    assert!(
        !argv_contains(&argv, "--threads"),
        "deprecated threads() must not emit --threads: {argv:?}"
    );
}

#[test]
fn contract_technique_ctef_emits_documented_argv_pair() {
    let argv = CommixBuilder::new()
        .url("http://example.com")
        .technique("ctef")
        .build()
        .command_argv();
    assert_eq!(
        argv_flag_value(&argv, "--technique").as_deref(),
        Some("ctef"),
        "builder rustdoc documents ctef letter codes for --technique"
    );
}
