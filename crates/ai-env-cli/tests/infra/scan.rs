//! tests/infra.rs area: scan — `ai-env infra scan` through the real binary
//! (S3 D7, §10, §12). Every planted value is built at runtime, never written
//! as a literal, and every run gets a temp HOME and bridge dir through
//! `common::ai_env`, so the developer's `[review]` lists never apply. The
//! image tree is a temp copy of the D5/D6 shape, not the repo's `image/`.
use super::common::*;
use std::path::Path;
use std::process::{Output, Stdio};

/// An Anthropic-shaped token, built at runtime.
fn planted_token() -> String {
    format!("{}oat01-{}", "sk-ant-", "Q".repeat(20))
}

/// An AWS access key id shape, built at runtime.
fn planted_key_id() -> String {
    format!("{}{}", "AKIA", "Z3".repeat(8))
}

fn write(root: &Path, rel: &str, text: &str) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// `ai-env infra scan <args>` with the temp environment of `tmp`.
fn scan(tmp: &Path, args: &[&str]) -> Output {
    let mut all = vec!["infra", "scan"];
    all.extend_from_slice(args);
    run(&mut ai_env(tmp, &all))
}

fn path_str(p: &Path) -> &str {
    p.to_str().unwrap()
}

/// The reviewed image config of D5/D6: settings with an empty allow list,
/// `claude.json` byte for byte as `image/claude/claude.json` (an empty
/// `projects` object), a prose `CLAUDE.md`, the managed settings.
fn image_tree(root: &Path) {
    write(root, "claude/settings.json", "{\n  \"permissions\": {\n    \"defaultMode\": \"default\",\n    \"allow\": []\n  }\n}\n");
    write(root, "claude/claude.json", "{\"hasCompletedOnboarding\":true,\"projects\":{}}\n");
    write(
        root,
        "claude/CLAUDE.md",
        "# Working in the VM\n\nThis machine is a disposable MicroVM that runs one session.\nThe workspace is mirrored back to the Mac after every turn.\nAsk before touching anything outside the workspace.\n",
    );
    write(
        root,
        "managed-settings.json",
        "{\n  \"permissions\": {\n    \"disableBypassPermissionsMode\": \"disable\",\n    \"disableAutoMode\": \"disable\"\n  },\n  \"env\": {\n    \"DISABLE_AUTOUPDATER\": \"1\",\n    \"DISABLE_UPDATES\": \"1\"\n  }\n}\n",
    );
}

const BYPASS_SETTINGS: &str = "{\n  \"permissions\": {\n    \"defaultMode\": \"bypassPermissions\",\n    \"allow\": []\n  }\n}\n";

#[test]
fn scan_is_clean_on_the_repo_image_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let tree = tmp.path().join("tree");
    image_tree(&tree);
    for args in [vec![path_str(&tree)], vec![path_str(&tree), "--profile", "image"]] {
        let o = scan(tmp.path(), &args);
        assert_eq!(o.status.code(), Some(0), "{args:?}: {}{}", stdout(&o), stderr(&o));
        assert_eq!(stdout(&o), "scan: clean (4 files)\n");
        assert_eq!(stderr(&o), "");
    }
}

#[test]
fn scan_refuses_a_planted_token_naming_file_and_line() {
    let tmp = tempfile::tempdir().unwrap();
    let tree = tmp.path().join("tree");
    image_tree(&tree);
    write(&tree, "claude/notes/todo.txt", &format!("one\ntwo\nkey={}\n", planted_token()));
    let o = scan(tmp.path(), &[path_str(&tree)]);
    assert_eq!(o.status.code(), Some(9), "{}", stderr(&o));
    assert_eq!(stdout(&o), "claude/notes/todo.txt:3: anthropic-key\nscan: 1 finding(s) (5 files)\n");
    assert!(stderr(&o).contains(&format!("ai-env: 1 finding(s) in {}", tree.display())), "{}", stderr(&o));
}

#[test]
fn scan_refuses_bypass_permissions_naming_the_key() {
    let tmp = tempfile::tempdir().unwrap();
    let tree = tmp.path().join("tree");
    image_tree(&tree);
    write(&tree, "claude/settings.json", BYPASS_SETTINGS);
    let o = scan(tmp.path(), &[path_str(&tree)]);
    assert_eq!(o.status.code(), Some(9), "{}", stderr(&o));
    assert_eq!(stdout(&o), "claude/settings.json:3: bypass-permissions\nclaude/settings.json:3: default-mode\nscan: 2 finding(s) (4 files)\n");
    assert!(stderr(&o).contains("2 finding(s) in"), "{}", stderr(&o));
}

/// D6: a managed-settings.json that drops or weakens a hardening value is a
/// finding (exit 9) at the key's line, or at line 0 when the key is gone.
#[test]
fn scan_refuses_weakened_managed_settings() {
    let tmp = tempfile::tempdir().unwrap();
    let tree = tmp.path().join("tree");
    image_tree(&tree);
    let hardened = std::fs::read_to_string(tree.join("managed-settings.json")).unwrap();
    write(&tree, "managed-settings.json", &hardened.replace("\"disableBypassPermissionsMode\": \"disable\"", "\"disableBypassPermissionsMode\": \"enable\""));
    let o = scan(tmp.path(), &[path_str(&tree)]);
    assert_eq!(o.status.code(), Some(9), "{}{}", stdout(&o), stderr(&o));
    assert_eq!(stdout(&o), "managed-settings.json:3: managed-hardening:permissions.disableBypassPermissionsMode\nscan: 1 finding(s) (4 files)\n");
    // `{}` is valid JSON claude accepts, and carries none of the four values.
    write(&tree, "managed-settings.json", "{}\n");
    let o = scan(tmp.path(), &[path_str(&tree), "--json"]);
    assert_eq!(o.status.code(), Some(9), "{}{}", stdout(&o), stderr(&o));
    let v: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    let rules: Vec<&str> = v["findings"].as_array().unwrap().iter().map(|f| f["rule"].as_str().unwrap()).collect();
    let mut want = ai_env_cli::bridge::scan::MANAGED_RULES.to_vec();
    want.sort_unstable();
    assert_eq!(rules, want, "one finding per missing D6 value (sorted by rule): {v}");
    assert!(v["findings"].as_array().unwrap().iter().all(|f| f["file"] == "managed-settings.json" && f["line"] == 0));
    // The repo profile has no settings rules.
    let o = scan(tmp.path(), &[path_str(&tree), "--profile", "repo"]);
    assert_eq!(o.status.code(), Some(0), "{}", stdout(&o));
}

/// D5: the baked `.claude.json` holds no project entry; a trusted project
/// with its own allow list and MCP server is refused at the entry's line.
#[test]
fn scan_refuses_a_project_entry_in_claude_json() {
    let tmp = tempfile::tempdir().unwrap();
    let tree = tmp.path().join("tree");
    image_tree(&tree);
    let project = format!(
        "{{\"hasCompletedOnboarding\":true,\n\"projects\":{{\n\"/Users/mike/work\":{{\"hasTrustDialogAccepted\":true,\"allowedTools\":[\"Bash(*)\"],\"mcpServers\":{{\"db\":{{\"command\":\"sh\",\"env\":{{\"DB_{}\":\"{}\"}}}}}}}}}}}}\n",
        "PASSWORD",
        "v".repeat(8)
    );
    write(&tree, "claude/claude.json", &project);
    let o = scan(tmp.path(), &[path_str(&tree)]);
    assert_eq!(o.status.code(), Some(9), "{}{}", stdout(&o), stderr(&o));
    assert_eq!(stdout(&o), "claude/claude.json:3: project-entry\nscan: 1 finding(s) (4 files)\n");
    assert!(!stdout(&o).contains("/Users/mike/work") && !stderr(&o).contains("/Users/mike/work"), "the entry's name is not printed");
}

#[test]
fn scan_refuses_a_symlink() {
    let tmp = tempfile::tempdir().unwrap();
    let tree = tmp.path().join("tree");
    image_tree(&tree);
    // Targets outside the tree carry a token: a followed link would report it.
    write(tmp.path(), "outside/secret.txt", &planted_token());
    std::os::unix::fs::symlink(tmp.path().join("outside/secret.txt"), tree.join("claude/link.txt")).unwrap();
    std::os::unix::fs::symlink(tmp.path().join("outside"), tree.join("dirlink")).unwrap();
    let o = scan(tmp.path(), &[path_str(&tree)]);
    assert_eq!(o.status.code(), Some(9), "{}", stderr(&o));
    assert_eq!(stdout(&o), "claude/link.txt:0: symlink\ndirlink:0: symlink\nscan: 2 finding(s) (4 files)\n");
}

#[test]
fn scan_refuses_a_special_file() {
    let tmp = tempfile::tempdir().unwrap();
    let tree = tmp.path().join("tree");
    image_tree(&tree);
    let _sock = std::os::unix::net::UnixListener::bind(tree.join("s.sock")).unwrap();
    let o = scan(tmp.path(), &[path_str(&tree)]);
    assert_eq!(o.status.code(), Some(9), "{}", stderr(&o));
    assert_eq!(stdout(&o), "s.sock:0: special-file\nscan: 1 finding(s) (4 files)\n");
}

#[test]
fn scan_never_prints_the_matched_text() {
    let tmp = tempfile::tempdir().unwrap();
    let tree = tmp.path().join("tree");
    image_tree(&tree);
    let sep = "://";
    let password = format!("pw{}", "Z".repeat(10));
    let jwt = format!("{}{}.{}", "eyJ", "k".repeat(24), "m".repeat(24));
    let env_value = format!("v{}", "9".repeat(12));
    write(&tree, "a.env", &format!("TOKEN={}\nID={}\n", planted_token(), planted_key_id()));
    write(&tree, "b/config.yml", &format!("url: postgres{sep}admin:{password}@db.internal/app\nbearer: {jwt}\n"));
    write(&tree, "claude/settings.json", &format!("{{\"permissions\": {{\"defaultMode\": \"bypassPermissions\"}},\n\"env\": {{\"API_TOKEN\": \"{env_value}\"}}}}"));
    // The shim-binary hint must not echo anything either.
    write(&tree, "ai-env", &format!("\u{7f}ELF{}", planted_key_id()));
    let never = [planted_token(), planted_key_id(), password.clone(), jwt.clone(), env_value.clone(), "bypassPermissions".to_string()];
    for json in [false, true] {
        let mut args = vec![path_str(&tree)];
        if json {
            args.push("--json");
        }
        let o = scan(tmp.path(), &args);
        assert_eq!(o.status.code(), Some(9), "{}", stderr(&o));
        let (out, err) = (stdout(&o), stderr(&o));
        for file in ["a.env", "ai-env", "b/config.yml", "claude/settings.json"] {
            assert!(out.contains(file), "json={json}: {file} not reported: {out}");
        }
        assert_eq!(o.status.code(), Some(9));
        let rules = ["anthropic-key", "aws-access-key-id", "url-credentials", "jwt", "bypass-permissions", "default-mode", "secret-env-name"];
        for rule in rules {
            assert!(out.contains(rule), "json={json}: {rule} not reported: {out}");
        }
        for (i, value) in never.iter().enumerate() {
            assert!(!out.contains(value.as_str()), "json={json}: planted value #{i} on stdout");
            assert!(!err.contains(value.as_str()), "json={json}: planted value #{i} on stderr");
        }
    }
}

/// `ai-env infra scan DIR | head -1`: the reader leaves before the report is
/// written, so printing it is a broken pipe (exit 0 by convention). The
/// verdict must not ride on that: findings stay exit 9, in both formats. The
/// report (20000 lines) outgrows any pipe buffer, so the write hits the
/// closed pipe whatever the timing.
#[test]
fn scan_exits_9_when_the_reader_closes_the_pipe_early() {
    let tmp = tempfile::tempdir().unwrap();
    let tree = tmp.path().join("tree");
    write(&tree, "many.txt", &format!("{}\n", planted_key_id()).repeat(20_000));
    for json in [false, true] {
        let mut args = vec!["infra", "scan", path_str(&tree)];
        if json {
            args.push("--json");
        }
        let mut child = ai_env(tmp.path(), &args).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("spawn ai-env");
        drop(child.stdout.take());
        let o = child.wait_with_output().unwrap();
        assert_eq!(o.status.code(), Some(9), "json={json}: {}", stderr(&o));
        assert!(stderr(&o).contains(&format!("ai-env: 20000 finding(s) in {}", tree.display())), "json={json}: {}", stderr(&o));
    }
}

/// The built-in patterns' text is compiled into this binary; it must not trip
/// them (plan D7: our own binary never trips the defaults), so a tree holding
/// a copy scans clean.
#[test]
fn scan_is_clean_on_a_copy_of_the_ai_env_binary() {
    let tmp = tempfile::tempdir().unwrap();
    let tree = tmp.path().join("tree");
    std::fs::create_dir_all(tree.join("bin")).unwrap();
    std::fs::copy(bin(), tree.join("bin/ai-env")).unwrap();
    let o = scan(tmp.path(), &[path_str(&tree), "--profile", "repo"]);
    assert_eq!(o.status.code(), Some(0), "{}{}", stdout(&o), stderr(&o));
    assert_eq!(stdout(&o), "scan: clean (1 files)\n");
}

#[test]
fn scan_json_reports_dir_clean_files_and_findings() {
    let tmp = tempfile::tempdir().unwrap();
    let tree = tmp.path().join("tree");
    image_tree(&tree);
    let o = scan(tmp.path(), &[path_str(&tree), "--json"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let v: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(v, serde_json::json!({"dir": path_str(&tree), "clean": true, "files": 4, "findings": []}));

    write(&tree, "x/y.txt", &format!("\n{}\n", planted_key_id()));
    write(&tree, "claude/settings.json", BYPASS_SETTINGS);
    let o = scan(tmp.path(), &[path_str(&tree), "--json"]);
    assert_eq!(o.status.code(), Some(9), "{}", stderr(&o));
    assert!(stdout(&o).starts_with("{\n  \"dir\": "), "dir comes first: {}", stdout(&o));
    let v: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(keys, ["clean", "dir", "files", "findings"]);
    assert_eq!(v["dir"], path_str(&tree));
    assert_eq!(v["clean"], false);
    assert_eq!(v["files"], 5);
    assert_eq!(
        v["findings"],
        serde_json::json!([
            {"file": "claude/settings.json", "line": 3, "rule": "bypass-permissions"},
            {"file": "claude/settings.json", "line": 3, "rule": "default-mode"},
            {"file": "x/y.txt", "line": 2, "rule": "aws-access-key-id"},
        ])
    );
    assert!(stderr(&o).contains("3 finding(s) in"), "{}", stderr(&o));
}

#[test]
fn scan_bad_dir_exits_1() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("missing");
    let o = scan(tmp.path(), &[path_str(&missing)]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert!(stderr(&o).contains("cannot scan"), "{}", stderr(&o));
    write(tmp.path(), "file.txt", "x");
    let o = scan(tmp.path(), &[path_str(&tmp.path().join("file.txt"))]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert!(stderr(&o).contains("not a directory"), "{}", stderr(&o));
    assert_eq!(stdout(&o), "");
}

#[test]
fn scan_bad_pattern_or_policy_file_exits_1_naming_file_and_line() {
    let tmp = tempfile::tempdir().unwrap();
    let tree = tmp.path().join("tree");
    image_tree(&tree);
    let tw = tmp.path().join("tw.txt");
    std::fs::write(&tw, "# ok\ncanaryword(x\n").unwrap();
    let o = scan(tmp.path(), &[path_str(&tree), "--tripwires", path_str(&tw)]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert!(stderr(&o).contains(&format!("{}:2: unsupported '('", tw.display())), "{}", stderr(&o));
    assert!(!stderr(&o).contains("canaryword"), "the pattern text is never echoed: {}", stderr(&o));
    assert_eq!(stdout(&o), "", "nothing is scanned with a bad rule set");

    let o = scan(tmp.path(), &[path_str(&tree), "--tripwires", path_str(&tmp.path().join("absent.txt"))]);
    assert_eq!(o.status.code(), Some(1), "an explicit list must exist: {}", stderr(&o));
    assert!(stderr(&o).contains("cannot read"), "{}", stderr(&o));

    let policy = tmp.path().join("policy.txt");
    std::fs::write(&policy, "allow Read(~/x)\ndeny canaryword\n").unwrap();
    let o = scan(tmp.path(), &[path_str(&tree), "--settings-policy", path_str(&policy)]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert!(stderr(&o).contains(&format!("{}:2: expected `allow <entry>`", policy.display())), "{}", stderr(&o));
    assert!(!stderr(&o).contains("canaryword"), "{}", stderr(&o));

    let o = scan(tmp.path(), &[path_str(&tree), "--settings-policy", path_str(&tmp.path().join("absent.txt"))]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
}

#[test]
fn scan_tripwires_file_adds_a_rule_and_the_built_ins_still_apply() {
    let tmp = tempfile::tempdir().unwrap();
    let tree = tmp.path().join("tree");
    write(&tree, "a.txt", "ticket INTERNAL-1234 here\n");
    write(&tree, "b.txt", &planted_token());
    let tw = tmp.path().join("tw.txt");
    std::fs::write(&tw, "# local tripwires\n\nINTERNAL-[0-9]{4}\n").unwrap();
    let o = scan(tmp.path(), &[path_str(&tree), "--tripwires", path_str(&tw)]);
    assert_eq!(o.status.code(), Some(9), "{}", stderr(&o));
    assert_eq!(stdout(&o), "a.txt:1: tripwire:3\nb.txt:1: anthropic-key\nscan: 2 finding(s) (2 files)\n");
    // Without the file only the built-in fires.
    let o = scan(tmp.path(), &[path_str(&tree)]);
    assert_eq!(stdout(&o), "b.txt:1: anthropic-key\nscan: 1 finding(s) (2 files)\n");
}

#[test]
fn scan_reads_the_review_lists_by_default_and_a_missing_default_is_silent() {
    let tmp = tempfile::tempdir().unwrap();
    let tree = tmp.path().join("tree");
    write(&tree, "a.txt", "ticket INTERNAL-1234 here\n");
    write(&tree, "claude/settings.json", "{\"permissions\": {\"allow\": [\n\"Read(~/docs)\"\n]}}");

    // No bridge dir at all: built-ins and an empty policy.
    let o = scan(tmp.path(), &[path_str(&tree)]);
    assert_eq!(stdout(&o), "claude/settings.json:2: allow-not-in-policy\nscan: 1 finding(s) (2 files)\n", "{}", stderr(&o));

    // The documented default files under the bridge root.
    write(tmp.path(), "bridge/tripwires.txt", "INTERNAL-[0-9]{4}\n");
    write(tmp.path(), "bridge/settings-policy.txt", "allow Read(~/docs)\n");
    let o = scan(tmp.path(), &[path_str(&tree)]);
    assert_eq!(stdout(&o), "a.txt:1: tripwire:1\nscan: 1 finding(s) (2 files)\n", "{}", stderr(&o));

    // [review] in bridge.toml moves both; a configured file that is missing is silent.
    write(tmp.path(), "lists/tw.txt", "# moved\nticket\n");
    let toml = format!("[review]\ntripwires = \"{}\"\nsettings_policy = \"{}\"\n", tmp.path().join("lists/tw.txt").display(), tmp.path().join("lists/absent.txt").display());
    write(tmp.path(), "bridge/bridge.toml", &toml);
    let o = scan(tmp.path(), &[path_str(&tree)]);
    assert_eq!(stdout(&o), "a.txt:1: tripwire:2\nclaude/settings.json:2: allow-not-in-policy\nscan: 2 finding(s) (2 files)\n", "{}", stderr(&o));

    // Flags win over the configuration.
    let tw = tmp.path().join("lists/none.txt");
    std::fs::write(&tw, "").unwrap();
    let policy = tmp.path().join("lists/policy.txt");
    std::fs::write(&policy, "allow Read(~/docs)\n").unwrap();
    let o = scan(tmp.path(), &[path_str(&tree), "--tripwires", path_str(&tw), "--settings-policy", path_str(&policy)]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert_eq!(stdout(&o), "scan: clean (2 files)\n");
}

#[test]
fn scan_settings_policy_admits_listed_entries_but_never_broad_ones() {
    let tmp = tempfile::tempdir().unwrap();
    let tree = tmp.path().join("tree");
    write(&tree, "claude/settings.local.json", "{\"permissions\": {\"allow\": [\n\"Bash(ls:*)\",\n\"Bash\"\n]}}");
    let o = scan(tmp.path(), &[path_str(&tree)]);
    assert_eq!(stdout(&o), "claude/settings.local.json:2: allow-not-in-policy\nclaude/settings.local.json:3: broad-allow\nscan: 2 finding(s) (1 files)\n");
    let policy = tmp.path().join("policy.txt");
    std::fs::write(&policy, "# reviewed\nallow Bash(ls:*)\nallow Bash\n").unwrap();
    let o = scan(tmp.path(), &[path_str(&tree), "--settings-policy", path_str(&policy)]);
    assert_eq!(o.status.code(), Some(9), "{}", stderr(&o));
    assert_eq!(stdout(&o), "claude/settings.local.json:3: broad-allow\nscan: 1 finding(s) (1 files)\n");
}

#[test]
fn scan_repo_profile_is_tripwires_only() {
    let tmp = tempfile::tempdir().unwrap();
    let tree = tmp.path().join("tree");
    write(&tree, ".claude/settings.json", BYPASS_SETTINGS);
    let o = scan(tmp.path(), &[path_str(&tree), "--profile", "repo"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert_eq!(stdout(&o), "scan: clean (1 files)\n");
    write(&tree, "src/main.rs", &format!("// {}\n", planted_key_id()));
    let o = scan(tmp.path(), &[path_str(&tree), "--profile", "repo"]);
    assert_eq!(o.status.code(), Some(9), "{}", stderr(&o));
    assert_eq!(stdout(&o), "src/main.rs:1: aws-access-key-id\nscan: 1 finding(s) (2 files)\n");
}

#[test]
fn scan_hints_when_the_staged_shim_binary_trips_a_rule() {
    let tmp = tempfile::tempdir().unwrap();
    let tree = tmp.path().join("tree");
    write(&tree, "usr/local/bin/ai-env", &format!("\u{7f}ELF\u{1}\u{1}{}", planted_key_id()));
    write(&tree, "other.bin", &planted_key_id());
    let o = scan(tmp.path(), &[path_str(&tree)]);
    assert_eq!(o.status.code(), Some(9), "{}", stderr(&o));
    let err = stderr(&o);
    assert!(err.contains("scan: hint: usr/local/bin/ai-env is the staged shim binary and trips aws-access-key-id"), "{err}");
    assert!(err.contains("DEFAULT_RULES"), "{err}");
    assert!(!err.contains("other.bin"), "the hint is for the shim binary only: {err}");

    let tw = tmp.path().join("tw.txt");
    std::fs::write(&tw, "ELF\n").unwrap();
    let o = scan(tmp.path(), &[path_str(&tree), "--tripwires", path_str(&tw)]);
    assert!(stderr(&o).contains("trips tripwire:1 by itself: narrow that line of the tripwires file"), "{}", stderr(&o));
}
