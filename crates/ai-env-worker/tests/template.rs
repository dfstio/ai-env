//! WM-T33 (LD-WM16): `templates/worker/` builds against this tree, offline, in its own target directory,
//! and its commands and conformance test work; and it names nothing a public template may not. The copy's
//! lock starts as the tree's, so the template builds with the versions the tree pins.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The template's two ai-env dependencies, as it pins them.
const PINNED: &str = r#"git = "https://github.com/dfstio/ai-env", tag = "relay-v0.1.0""#;

fn tree() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().expect("the tree")
}

/// Every file of the template (no `target/`, no lock), as paths relative to it.
fn files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut dirs = vec![root.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).expect("a directory") {
            let path = entry.expect("an entry").path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_string();
            if path.is_dir() {
                if name != "target" {
                    dirs.push(path);
                }
            } else if name != "Cargo.lock" {
                out.push(path.strip_prefix(root).expect("under the root").to_path_buf());
            }
        }
    }
    out.sort();
    out
}

/// `cmd` must succeed within 30 minutes (the first build compiles the template's whole graph).
fn run_ok(cmd: &mut Command) -> String {
    let out = common::certs::output_within_for(cmd, std::time::Duration::from_secs(1800));
    assert!(out.status.success(), "{:?} failed:\n{}\n{}", cmd.get_args().collect::<Vec<_>>(), String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).expect("UTF-8")
}

/// The dotted quads of `text` that are not glued to a digit or a dot.
fn ipv4s(text: &str) -> Vec<String> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let glued = i > 0 && (b[i - 1].is_ascii_digit() || b[i - 1] == b'.');
        if !b[i].is_ascii_digit() || glued {
            i += 1;
            continue;
        }
        let mut j = i;
        while j < b.len() && (b[j].is_ascii_digit() || b[j] == b'.') {
            j += 1;
        }
        let run = &text[i..j];
        let parts: Vec<&str> = run.split('.').collect();
        if parts.len() == 4 && parts.iter().all(|p| !p.is_empty() && p.len() <= 3 && p.parse::<u16>().is_ok_and(|n| n <= 255)) {
            out.push(run.to_string());
        }
        i = j;
    }
    out
}

/// Each URL's host in `text`.
fn url_hosts(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find("://") {
        rest = &rest[at + 3..];
        let end = rest.find(|c: char| "/?#\"'`)>, \t\n".contains(c)).unwrap_or(rest.len());
        let authority = &rest[..end];
        let host = authority.rsplit('@').next().unwrap_or(authority);
        out.push(host.split(':').next().unwrap_or(host).to_string());
    }
    out
}

/// WM-T33.
#[test]
fn the_template_builds_against_this_tree() {
    let tree = tree();
    let template = tree.join("templates/worker");
    let names = files(&template);
    for want in [".gitignore", "Cargo.toml", "README.md", "ai-env-worker.service", "src/config.rs", "src/main.rs", "src/sources.rs", "tests/conformance.rs", "worker.toml.example"] {
        assert!(names.contains(&PathBuf::from(want)), "the template holds {want}");
    }
    assert!(!template.join("Cargo.lock").exists(), "the template ships no Cargo.lock");
    let ignore = std::fs::read_to_string(template.join(".gitignore")).expect("its .gitignore");
    assert_eq!(ignore.lines().collect::<Vec<_>>(), ["/target", "worker.toml", "*.key"]);

    // What a public template may name.
    for name in &names {
        let text = std::fs::read_to_string(template.join(name)).expect("text");
        assert!(!text.to_lowercase().contains("dangerous"), "{}: a dangerous API", name.display());
        assert!(!text.lines().any(|l| l.trim_start().starts_with("[patch")), "{}: an uncommented [patch section", name.display());
        for ip in ipv4s(&text) {
            assert!(ip == "127.0.0.1" || ip.starts_with("203.0.113."), "{}: the address {ip}", name.display());
        }
        for host in url_hosts(&text) {
            let allowed = host == "github.com" || host == "example.com" || host.ends_with(".example.com") || host == "127.0.0.1" || host.starts_with("203.0.113.");
            assert!(allowed, "{}: the host {host:?}", name.display());
        }
    }
    let manifest = std::fs::read_to_string(template.join("Cargo.toml")).expect("its manifest");
    assert_eq!(manifest.matches(PINNED).count(), 3, "both ai-env crates pinned by tag (and the testkit's)");
    assert!(!manifest.contains("branch =") && !manifest.contains("rev ="), "a tag, never a branch");

    // A copy, its ai-env dependencies pointed at this tree.
    let copy = tempfile::tempdir().expect("a temp dir");
    for name in &names {
        let to = copy.path().join(name);
        std::fs::create_dir_all(to.parent().expect("a parent")).expect("mkdir");
        std::fs::copy(template.join(name), &to).expect("copy");
    }
    let rewritten: String = manifest
        .lines()
        .map(|line| {
            for krate in ["ai-env-worker", "ai-env-source"] {
                if line.starts_with(&format!("{krate} = ")) {
                    let path = tree.join("crates").join(krate);
                    return format!("{}\n", line.replace(PINNED, &format!("path = {:?}", path.display().to_string())));
                }
            }
            format!("{line}\n")
        })
        .collect();
    assert!(!rewritten.contains("git = "), "{rewritten}");
    std::fs::write(copy.path().join("Cargo.toml"), rewritten).expect("the rewritten manifest");
    // The tree's own lock seeds the copy's: offline, the template resolves to the versions this tree builds
    // and tests (cargo then adds the few crates only the template uses, from the local cache).
    std::fs::copy(tree.join("Cargo.lock"), copy.path().join("Cargo.lock")).expect("the tree's lock");

    let target = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("template-check");
    // The cargo on PATH: under `cargo +<toolchain> test` (and `make test`), rustup's proxy keeps that
    // toolchain (`RUSTUP_TOOLCHAIN`), so the copy builds with the toolchain that runs this test.
    let cargo = |args: &[&str]| {
        let mut cmd = Command::new("cargo");
        cmd.args(args).current_dir(copy.path()).env("CARGO_TARGET_DIR", &target).env_remove("RUSTFLAGS");
        cmd
    };
    run_ok(&mut cargo(&["build", "--offline"]));
    let bin = target.join("debug/my-worker");

    let key = copy.path().join("k");
    let printed = run_ok(Command::new(&bin).arg("keygen").arg("--out").arg(&key));
    let lines: Vec<&str> = printed.lines().collect();
    assert_eq!(lines.len(), 1, "keygen prints one line: {printed:?}");
    assert!(lines[0].len() == 52 && lines[0].starts_with("ed25519:"), "{}", lines[0]);
    assert_eq!(std::fs::metadata(&key).expect("the key").permissions().mode() & 0o777, 0o600);
    assert_eq!(run_ok(Command::new(&bin).arg("pubkey").arg("--key").arg(&key)), printed);

    let ca = copy.path().join("relay-ca.pem");
    std::fs::write(&ca, &common::certs::pki().ca_a).expect("the CA");
    let example = std::fs::read_to_string(copy.path().join("worker.toml.example")).expect("the example");
    let config = example
        .replace("\"/etc/ai-env-worker/relay-ca.pem\"", &format!("{:?}", ca.display().to_string()))
        .replace("\"/etc/ai-env-worker/worker.key\"", &format!("{:?}", key.display().to_string()));
    assert_ne!(config, example);
    let config_path = copy.path().join("worker.toml");
    std::fs::write(&config_path, config).expect("a config");
    let fp = ai_env_worker::keys::read_key_file(&key).expect("the key").public_key().fingerprint();
    let checked = run_ok(Command::new(&bin).arg("check").arg("--config").arg(&config_path).arg("--offline"));
    assert_eq!(checked.trim(), format!("config ok: worker example-worker, 1 source(s), key fp {fp}"));

    let tested = run_ok(&mut cargo(&["test", "--offline"]));
    for test in ["the_example_sources_conform", "the_http_source_refuses_paths_outside_its_prefixes"] {
        assert!(tested.contains(&format!("{test} ... ok")), "{tested}");
    }
}
