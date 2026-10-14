//! tests/workspace.rs area: the scans of a seed (plan §5, D8, L9): a
//! tripwire in a committed, an uncommitted or a staged blob, or in a commit
//! message, refuses the seed naming its place, the blob and the rule, never
//! the bytes; history the seed does not carry is not read, and the commits
//! an update carries are, a file named at the commit that brought it; each
//! of D8's keys in a repository's `.claude/settings*.json` is refused naming
//! the key unless the workspace trusts its repo settings; a plaintext dotenv
//! the WIP carries is refused; the clean-object cache is reused, and a
//! change of the rules starts it over.
use super::fixture::{api, caps, ensure_ctx, key_id, target, FakeVm, Repo, World};
use ai_env_cli::bridge::errors::BridgeError;
use ai_env_cli::bridge::workspace::{code, ensure_workspace, prepare, resolve, PreparedSeed, SeedLimits, SeedProgress, SeedWant};
use ai_env_cli::errors::CliError;

/// `prepare` of `repo` under `extra` config: the finding refusal's lines (exit 9), or the prepared seed.
fn seed_of(w: &World, repo: &Repo, extra: &str) -> Result<PreparedSeed, String> {
    let cfg = w.cfg(extra);
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    prepare(&w.paths(), &cfg, &ws, &SeedLimits::cli(&cfg, None)).map_err(|e| {
        assert!(matches!(&e, BridgeError::WorkspaceRefused { code: c, .. } if *c == code::FINDING), "{e:?}");
        let text = e.to_string();
        assert_eq!(CliError::from(e).exit_code(), 9);
        text.strip_prefix("workspace refused (finding): ").unwrap_or(&text).to_string()
    })
}

fn blob(repo: &Repo, spec: &str) -> String {
    repo.git(&["rev-parse", spec])[..12].to_string()
}

#[test]
fn a_tripwire_in_what_the_seed_carries_is_refused_naming_its_place() {
    let w = World::new();
    let repo = w.repo("app");
    let key = key_id();
    repo.write("cfg/prod.yaml", &format!("region: x\nkey: {key}\n"));
    repo.commit("config");
    let text = seed_of(&w, &repo, "").unwrap_err();
    assert_eq!(text, format!("HEAD:cfg/prod.yaml (blob {}) line 2: rule aws-access-key-id", blob(&repo, "HEAD:cfg/prod.yaml")));
    assert!(!text.contains(&key));
    // Removed from HEAD: the history it still holds never travels, so it is not read (D7).
    repo.write("cfg/prod.yaml", "region: x\n");
    repo.commit("drop the key");
    assert!(seed_of(&w, &repo, "").is_ok(), "an older commit's blob is no part of a shallow seed");
    // Uncommitted: in an untracked file, then only in the index (the worktree's copy clean).
    repo.write("notes/todo.txt", &format!("one\n{key}\n"));
    let text = seed_of(&w, &repo, "").unwrap_err();
    assert!(text.starts_with("wip:notes/todo.txt (blob ") && text.ends_with(" line 2: rule aws-access-key-id"), "{text}");
    repo.git(&["add", "notes/todo.txt"]);
    repo.write("notes/todo.txt", "one\n");
    let text = seed_of(&w, &repo, "").unwrap_err();
    assert!(text.starts_with("index:notes/todo.txt (blob ") && text.ends_with("rule aws-access-key-id"), "{text}");
}

#[test]
fn a_tripwire_in_a_commit_message_is_refused_naming_the_commit() {
    let w = World::new();
    let repo = w.repo("app");
    repo.git(&["commit", "-q", "--allow-empty", "-m", &format!("deploy with {}", key_id())]);
    let text = seed_of(&w, &repo, "").unwrap_err();
    assert_eq!(text, format!("commit {} line 6: rule aws-access-key-id", &repo.head()[..12]));
}

/// An update carries the commits since the VM's seed, and the scan reads
/// them all: a key file K1 brought, K2 kept and K3 removed (HEAD and the
/// first seed's plan, the dry run's, are clean) refuses the update before it
/// is sent, named at K1, the commit that brought it, never at K3 (whose tree
/// has no such file) or K2.
#[tokio::test]
async fn a_tripwire_an_update_carries_is_named_at_the_commit_that_brought_it() {
    let w = World::new();
    let repo = w.repo("app");
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let vm = FakeVm::new(&w.root.join("vm"), &w.root.join("vm-projects"));
    let (api, target, caps) = (api().await, target(), caps());
    let progress = |_: SeedProgress| {};
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    ensure_workspace(&ensure_ctx(&api, &vm, &paths, &cfg, &target, &caps, &ws, &progress), None, SeedWant::Auto).await.unwrap();
    repo.write("deploy.conf", &format!("region: x\nkey: {}\n", key_id()));
    let k1 = repo.commit("K1");
    repo.write("other.txt", "other\n");
    repo.commit("K2");
    std::fs::remove_file(repo.dir.join("deploy.conf")).unwrap();
    repo.commit("K3");
    assert!(seed_of(&w, &repo, "").is_ok(), "a first seed carries HEAD alone");
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    let e = ensure_workspace(&ensure_ctx(&api, &vm, &paths, &cfg, &target, &caps, &ws, &progress), None, SeedWant::Auto).await.unwrap_err();
    assert!(matches!(&e, BridgeError::WorkspaceRefused { code: c, .. } if *c == code::FINDING), "{e:?}");
    let text = e.to_string();
    assert_eq!(CliError::from(e).exit_code(), 9);
    let at = blob(&repo, &format!("{k1}:deploy.conf"));
    assert_eq!(text, format!("workspace refused (finding): commit {}:deploy.conf (blob {at}) line 2: rule aws-access-key-id", &k1[..12]));
    assert!(!vm.calls().iter().any(|c| c == "PUT /seed update"), "nothing sent: {:?}", vm.calls());
}

/// D8: each key a repository's settings may not set, named, never its value;
/// in the committed `settings.json` and in an untracked `settings.local.json`
/// alike; a symlink at either name is a finding of its own.
#[test]
fn each_d8_key_is_refused_naming_the_key() {
    let cases: [(&str, &str, &str); 12] = [
        ("{\n\"permissions\": {\"defaultMode\": \"acceptEdits\"}}", "default-mode", "permissions.defaultMode"),
        ("{\"permissions\": {\"allow\": [\"Read(./x)\",\n\"Bash(*)\"]}}", "broad-allow", "permissions.allow[1]"),
        ("{\"permissions\": {\"allow\": [\n\"WebFetch\"]}}", "broad-allow", "permissions.allow[0]"),
        ("{\"permissions\": {\"allow\": [\n\"mcp__github\"]}}", "broad-allow", "permissions.allow[0]"),
        ("{\n\"hooks\": {\"Stop\": [{\"command\": \"x\"}]}}", "repo-hooks", "hooks"),
        ("{\n\"apiKeyHelper\": \"./k.sh\"}", "repo-command", "apiKeyHelper"),
        ("{\n\"statusLine\": {\"type\": \"command\", \"command\": \"./s.sh\"}}", "repo-command", "statusLine"),
        ("{\n\"awsAuthRefresh\": \"aws sso login\"}", "repo-command", "awsAuthRefresh"),
        ("{\n\"otelHeadersHelper\": \"./h.sh\"}", "repo-command", "otelHeadersHelper"),
        ("{\n\"enableAllProjectMcpServers\": true}", "repo-mcp-autoapprove", "enableAllProjectMcpServers"),
        ("{\"permissions\": {\n\"additionalDirectories\": [\"/etc\"]}}", "additional-directories", "permissions.additionalDirectories"),
        ("{\"env\": {\"X\":\n\"bypassPermissions\"}}", "bypass-permissions", "env.X"),
    ];
    for (doc, rule, key) in cases {
        let w = World::new();
        let repo = w.repo("app");
        repo.write(".claude/settings.json", doc);
        repo.commit("settings");
        let text = seed_of(&w, &repo, "").unwrap_err();
        let at = blob(&repo, "HEAD:.claude/settings.json");
        assert_eq!(text, format!("HEAD:.claude/settings.json (blob {at}) line 2: rule {rule}, key {key}"), "{doc}");
    }
    let w = World::new();
    let repo = w.repo("app");
    repo.write("pkg/.claude/settings.local.json", "{\"permissions\": {\"allow\": [\"Edit\"]}}");
    let text = seed_of(&w, &repo, "").unwrap_err();
    assert!(text.starts_with("wip:pkg/.claude/settings.local.json (blob ") && text.ends_with("line 1: rule broad-allow, key permissions.allow[0]"), "{text}");
    std::fs::remove_file(repo.dir.join("pkg/.claude/settings.local.json")).unwrap();
    std::os::unix::fs::symlink("/etc/hosts", repo.dir.join("pkg/.claude/settings.local.json")).unwrap();
    let text = seed_of(&w, &repo, "").unwrap_err();
    assert!(text.starts_with("wip:pkg/.claude/settings.local.json (blob ") && text.ends_with(": rule settings-symlink"), "{text}");
}

/// D8 through a link: a `.claude` that is a symlink (here to `conf/`, whose
/// `settings.json` the VM's claude would read through it) is refused
/// whatever it points at, at any depth and in any case, as the Mac's disk
/// compares names.
#[test]
fn a_claude_directory_that_is_a_symlink_is_refused() {
    let w = World::new();
    let repo = w.repo("app");
    repo.write("conf/settings.json", "{\"permissions\": {\"defaultMode\": \"bypassPermissions\"}, \"hooks\": {\"Stop\": [{\"command\": \"x\"}]}}");
    std::os::unix::fs::symlink("conf", repo.dir.join(".claude")).unwrap();
    repo.commit("linked settings");
    let text = seed_of(&w, &repo, "").unwrap_err();
    assert_eq!(text, format!("HEAD:.claude (blob {}): rule settings-symlink", blob(&repo, "HEAD:.claude")));
    std::fs::remove_file(repo.dir.join(".claude")).unwrap();
    std::fs::create_dir_all(repo.dir.join("pkg")).unwrap();
    std::os::unix::fs::symlink("../conf", repo.dir.join("pkg/.Claude")).unwrap();
    repo.commit("nested");
    let text = seed_of(&w, &repo, "").unwrap_err();
    assert_eq!(text, format!("HEAD:pkg/.Claude (blob {}): rule settings-symlink", blob(&repo, "HEAD:pkg/.Claude")));
}

/// Every path name is scanned, not only the first path an object is listed
/// at: a tripwire-shaped file name whose bytes `0.txt` also holds, or a
/// directory name whose tree `0/` also is (`0` sorts first, so the listing
/// names the object there), is refused naming the tree that holds it, never
/// the name.
#[test]
fn a_name_at_an_objects_second_path_is_scanned() {
    let w = World::new();
    let repo = w.repo("app");
    let key = key_id();
    repo.write("0.txt", "same bytes\n");
    repo.write(&format!("{key}.txt"), "same bytes\n");
    repo.commit("one blob, two names");
    let text = seed_of(&w, &repo, "").unwrap_err();
    assert_eq!(text, format!("a path name (tree {}): rule aws-access-key-id", blob(&repo, "HEAD^{tree}")));
    std::fs::remove_file(repo.dir.join(format!("{key}.txt"))).unwrap();
    repo.write("0/x.txt", "x\n");
    repo.write(&format!("{key}/x.txt"), "x\n");
    repo.commit("one tree, two names");
    let text = seed_of(&w, &repo, "").unwrap_err();
    assert_eq!(text, format!("a path name (tree {}): rule aws-access-key-id", blob(&repo, "HEAD^{tree}")));
    assert!(!text.contains(&key));
}

/// A path that trips a custom tripwire is never shown, not even as the
/// place of a finding in the blob's bytes: neither match reaches the text.
#[test]
fn a_path_that_trips_a_custom_tripwire_is_never_shown() {
    let w = World::new();
    std::fs::write(w.paths().root.join("tripwires.txt"), "zq[0-9]{6}\n").unwrap();
    let repo = w.repo("app");
    repo.write("notes/zq123456.txt", "zq654321\n");
    repo.commit("notes");
    let text = seed_of(&w, &repo, "").unwrap_err();
    let at = blob(&repo, "HEAD:notes/zq123456.txt");
    assert_eq!(text, format!("a path name (blob {at}): rule tripwire:1\nHEAD:a path name (blob {at}) line 1: rule tripwire:1"));
    // Uncommitted, a dotenv the same: the WIP's place, never the path.
    repo.write("zq111111.env", "X=1\n");
    let text = seed_of(&w, &repo, "").unwrap_err();
    assert!(text.lines().any(|l| l.starts_with("wip:a path name (blob ") && l.ends_with(": rule env-file-plaintext")), "{text}");
    assert!(!text.contains("zq1") && !text.contains("zq6"), "{text}");
}

/// `trust_repo_settings` skips the repo mode for its workspace only; the
/// tripwires still apply there.
#[test]
fn trust_repo_settings_skips_the_repo_mode_only() {
    let w = World::new();
    let repo = w.repo("app");
    repo.write(".claude/settings.json", "{\"permissions\": {\"defaultMode\": \"bypassPermissions\"}, \"hooks\": {\"Stop\": [1]}}");
    repo.commit("settings");
    let trusted = format!("[[workspace]]\npath = {:?}\ntrust_repo_settings = true\n", repo.dir.display().to_string());
    assert!(seed_of(&w, &repo, "").is_err());
    let s = seed_of(&w, &repo, &trusted).unwrap().summary();
    assert!(s.trust_repo_settings && s.settings_files == 0, "{s:?}");
    repo.write("x.txt", &key_id());
    let text = seed_of(&w, &repo, &trusted).unwrap_err();
    assert!(text.contains("rule aws-access-key-id"), "{text}");
}

/// L9: a plaintext dotenv the WIP carries is refused; a template, an ai-env
/// container and an ignored one are not.
#[test]
fn a_plaintext_dotenv_the_wip_carries_is_refused() {
    let w = World::new();
    let repo = w.repo("app");
    repo.write(".env.example", "TOKEN=put-yours-here\n");
    repo.write("conf/app.env", "# ai-env container\nAI_ENV=1\nAI_ENV_DATA=x\n");
    assert!(seed_of(&w, &repo, "").is_ok(), "a template and a container pass");
    repo.write(".env.local", "DB_URL=postgres://u@h/db\n");
    let text = seed_of(&w, &repo, "").unwrap_err();
    assert!(text.starts_with("wip:.env.local (blob ") && text.ends_with(": rule env-file-plaintext"), "{text}");
    repo.write(".gitignore", ".env.local\n");
    assert!(seed_of(&w, &repo, "").is_ok(), "an ignored dotenv never leaves, so it is not read");
}

/// The clean-object cache: a second scan reads nothing it found clean
/// before; a change of the tripwires (a new rule set, a new digest) reads
/// everything again; a blob over `max_blob_mib` is a finding of its own,
/// which names that key.
#[test]
fn the_clean_cache_is_reused_and_a_rules_change_starts_it_over() {
    let w = World::new();
    let repo = w.repo("app");
    for i in 0..5 {
        repo.write(&format!("f{i}.txt"), &format!("file {i}\n"));
    }
    repo.commit("files");
    let first = seed_of(&w, &repo, "").unwrap().summary();
    assert_eq!(first.cached, 0);
    assert!(first.objects >= 7, "{first:?}");
    let second = seed_of(&w, &repo, "").unwrap().summary();
    assert_eq!(second.cached, 8, "six blobs, the root tree (its names) and the commit, from the cache: {second:?}");
    assert_eq!(second.scanned_bytes, 0);
    std::fs::write(w.paths().root.join("tripwires.txt"), "zzz[0-9]{6}\n").unwrap();
    let third = seed_of(&w, &repo, "").unwrap().summary();
    assert_eq!(third.cached, 0, "a new rule set reads everything again");
    let caches = std::fs::read_dir(w.paths().scan_cache()).unwrap().count();
    assert_eq!(caches, 2, "one cache per rule set");
    repo.write("big.bin", &"q".repeat(1024 * 1024 + 1));
    repo.commit("big");
    let text = seed_of(&w, &repo, "[seed]\nmax_blob_mib = 1\nmax_wip_mib = 1\nwrapper_inline_mib = 1\n").unwrap_err();
    assert!(text.starts_with("HEAD:big.bin (blob ") && text.ends_with(": rule blob-too-large (over [seed].max_blob_mib)"), "{text}");
}
