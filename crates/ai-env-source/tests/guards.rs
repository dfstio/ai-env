//! P-T8: the Makefile still holds the S13 graph guards, lints and targets of P, W, M and R, word for word
//! where a loosened word would pass a bad graph (plans/s13-contracts.md §P-proto-sdk.10). V's lines (its
//! client's package, the shim pattern's `ai-env-relay`, its fifth `check-msrv` build) are pinned by V's own
//! test (X-5). The gate (G-1, G-5) runs the guards over the real graphs; this test catches a guard dropped or
//! loosened in the text.

/// The Makefile's logical lines: a line ending in `\` continues on the next.
fn logical_lines() -> Vec<String> {
    let makefile = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Makefile")).expect("the repository's Makefile");
    let mut out = Vec::new();
    let mut current = String::new();
    for line in makefile.lines() {
        match line.strip_suffix('\\') {
            Some(head) => {
                current.push_str(head);
                current.push(' ');
            }
            None => {
                current.push_str(line);
                out.push(std::mem::take(&mut current));
            }
        }
    }
    out
}

/// The recipe of `target`: the logical lines after its rule line that start with a tab.
fn recipe(target: &str) -> Vec<String> {
    let lines = logical_lines();
    let rule = format!("{target}:");
    let start = lines.iter().position(|l| l.starts_with(&rule)).unwrap_or_else(|| panic!("the Makefile has no {target} target"));
    lines[start + 1..].iter().take_while(|l| l.starts_with('\t')).map(|l| l.trim().to_string()).collect()
}

/// The one recipe line of `target` holding every needle.
fn line_with<'a>(lines: &'a [String], target: &str, needles: &[&str]) -> &'a str {
    let found: Vec<&String> = lines.iter().filter(|l| needles.iter().all(|n| l.contains(n))).collect();
    assert_eq!(found.len(), 1, "{target}: one line holding {needles:?}, found {found:#?}");
    found[0]
}

/// A variable's words: `NAME := a b c`.
fn words(name: &str) -> Vec<String> {
    let line = logical_lines()
        .into_iter()
        .find(|l| l.split_once(":=").is_some_and(|(n, _)| n.trim() == name))
        .unwrap_or_else(|| panic!("the Makefile defines no {name}"));
    line.split_once(":=").map(|(_, v)| v.split_whitespace().map(str::to_string).collect()).unwrap_or_default()
}

/// P-T8.
#[test]
fn the_makefile_guards_name_the_relay_crates() {
    assert_eq!(words("RELAY_LIBS"), ["ai-env-relay-proto", "ai-env-source", "ai-env-worker"]);
    assert_eq!(words("RELAY_CRATES"), ["$(RELAY_LIBS)", "ai-env-relay"]);
    assert_eq!(words("RELAY_PINNED").first().map(String::as_str), Some("ai-env-worker"), "the worker trusts the pinned relay CA alone");

    let features = recipe("check-features");
    let shim = line_with(&features, "check-features", &["--no-default-features --features shim --target $(TARGET) --prefix none | sort -u | grep -E"]);
    assert!(shim.contains("security-framework|tonic|prost|h2 |tokio-rustls"), "no gRPC or relay crate in the shim graph: {shim}");
    line_with(
        &features,
        "check-features",
        &["-p $(PKG) -e normal,features -i tonic", r#"'tonic feature "(tls-|_tls-any|transport|default|channel|server|router)'"#, "S13: tonic beyond codegen in ai-env-cli's graph"],
    );
    line_with(
        &features,
        "check-features",
        &[
            "-p ai-env-source -e normal --features testkit --prefix none | sort -u",
            "'^(tonic|prost|h2 |hyper|tower|axum|rustls|tokio-rustls|aws-|ring |webpki-roots|reqwest|async-trait)'",
            "S13: ai-env-source holds a gRPC, HTTP, TLS or AWS crate",
        ],
    );
    line_with(
        &features,
        "check-features",
        &[
            "-p ai-env-relay-proto -e normal --prefix none | sort -u",
            "'^(h2 |hyper|tower |axum|rustls|tokio-rustls|aws-|ring |webpki-roots|socket2)'",
            "S13: ai-env-relay-proto holds a transport crate (codegen only)",
        ],
    );
    line_with(
        &features,
        "check-features",
        &[
            "for p in $(RELAY_PINNED); do for t in \"\" \"--target $(TARGET)\"",
            "'^(ring |webpki-roots|rustls-native-certs|security-framework|openssl|aws-config|aws-sdk-|aws-smithy-)'",
            "must trust the pinned relay CA alone",
        ],
    );
    line_with(
        &features,
        "check-features",
        &[
            "for p in $(RELAY_CRATES); do out=$$($(CARGO) tree -p $$p -e normal,features -i tonic",
            r#"'tonic feature "(tls-|_tls-any|transport|default)'"#,
            "enables a tonic TLS, transport or default feature",
        ],
    );
    line_with(&features, "check-features", &["for p in ai-env-worker ai-env-relay;", "-e normal -d --depth 0", "'^(tonic|prost|h2|hyper|axum|rustls|tokio-rustls) '", "S13: duplicate crates in $$p"]);
    line_with(&features, "check-features", &["-p ai-env-relay -e normal $$t --prefix none", "'^ring '", "S13: ring in the relay's graph"]);
    line_with(&features, "check-features", &["-p ai-env-relay -e normal,features --target $(TARGET) -i rustls", r#"'rustls feature "tls12"'"#, "S13: rustls tls12 in the relay's graph"]);
    line_with(&features, "check-features", &["-p $(PKG) -e features -i ai-env-worker", r#"grep -q 'ai-env-worker feature "runtime"'"#, "ai-env-cli enables ai-env-worker/runtime"]);

    let deps = recipe("check-deps");
    line_with(&deps, "check-deps", &["cargo machete crates/$(PKG) $(addprefix crates/,$(RELAY_CRATES))"]);

    let msrv = recipe("check-msrv");
    for build in [
        "cargo +$(MSRV_OLD) build $(addprefix -p ,$(RELAY_LIBS))",
        "cargo +$(MSRV_OLD) build -p ai-env-worker --no-default-features",
        "cargo +$(MSRV_OLD) build -p ai-env-source --features testkit",
        "cargo +$(MSRV_OLD) build -p ai-env-relay",
    ] {
        assert!(msrv.iter().any(|l| l == build), "check-msrv runs {build}");
    }

    let clippy = recipe("clippy");
    let relay_lines: Vec<&String> = clippy.iter().filter(|l| l.contains("RELAY_CRATES") || l.contains("-p ai-env-")).filter(|l| !l.contains("-p ai-env-age")).collect();
    assert_eq!(relay_lines.first().map(|l| l.as_str()), Some("$(CARGO) clippy $(addprefix -p ,$(RELAY_CRATES)) --all-targets -- -D warnings"));
    for line in [
        "$(CARGO) clippy -p ai-env-worker --lib --no-default-features -- -D warnings",
        "$(CARGO) clippy -p ai-env-source --lib -- -D warnings",
        "$(CARGO) clippy -p ai-env-relay --lib --bins --target $(TARGET) -- -D warnings",
    ] {
        assert!(clippy.iter().any(|l| l == line), "clippy runs {line}");
    }
    line_with(&clippy, "clippy", &["command -v aarch64-linux-gnu-gcc"]);
    for line in logical_lines() {
        assert!(!(line.contains("$(RELAY_CRATES)") && line.contains("--all-features")), "never --all-features over the relay crates (A-H3): {line}");
    }

    let test = recipe("test");
    line_with(&test, "test", &["$(CARGO) test -p ai-env-worker --no-default-features --lib"]);

    let lint = recipe("lint");
    line_with(&lint, "lint", &["UnixListener::bind", "lint: a Unix listener lives only in src/bridge/relay/agent.rs"]);
    line_with(&lint, "lint", &["crates/ai-env-relay/src/registry.rs crates/ai-env-relay/src/calls.rs crates/ai-env-relay/src/limits.rs", "R-75"]);
    line_with(&lint, "lint", &["Peered::new(", "crates/ai-env-relay/src/tls.rs", "R-76"]);
    line_with(&lint, "lint", &["crates/ai-env-relay/tests/*.rs", "crates/ai-env-relay/Cargo.toml", "[[test]]"]);

    let negative = recipe("lint-negative");
    line_with(
        &negative,
        "lint-negative",
        &["$(CARGO) clippy -p ai-env-relay --example dashmap_lint_negative --features lint-negative -- -D warnings", "holding a disallowed type across an await point", "\"$$n\" -eq 9"],
    );

    let phony = logical_lines().into_iter().find(|l| l.starts_with(".PHONY:")).expect("a .PHONY line");
    let phony: Vec<&str> = phony.split_whitespace().collect();
    assert!(phony.contains(&"relay-proto") && phony.contains(&"relay-proto-check"), ".PHONY names both relay-proto targets");
    let generate = recipe("relay-proto");
    line_with(&generate, "relay-proto", &["command -v protoc"]);
    assert!(generate.iter().any(|l| l == "CARGO_TARGET_DIR=target/relay-protogen $(CARGO) run --locked --manifest-path tools/relay-protogen/Cargo.toml"));
    let check = recipe("relay-proto-check");
    line_with(&check, "relay-proto-check", &["command -v protoc"]);
    assert!(check.iter().any(|l| l == "CARGO_TARGET_DIR=target/relay-protogen $(CARGO) run --locked --manifest-path tools/relay-protogen/Cargo.toml -- target/relay-proto-check"));
    line_with(
        &check,
        "relay-proto-check",
        &[
            "cmp -s crates/ai-env-relay-proto/src/gen/descriptor.bin target/relay-proto-check/descriptor.bin",
            "cmp -s crates/ai-env-relay-proto/src/gen/ai_env.relay.v1.rs target/relay-proto-check/ai_env.relay.v1.rs",
        ],
    );
}
