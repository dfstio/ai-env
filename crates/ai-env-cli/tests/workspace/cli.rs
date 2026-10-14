//! tests/workspace.rs area: `ai-env box seed --dry-run` through the real
//! binary, offline (no AWS call, no Touch ID: no credentials exist here):
//! the plan of a first seed, and the refusals a real seed would make, each
//! with its exit code, before anything could be sent.
use super::fixture::{key_id, World};
use crate::common::git_real;
use std::path::Path;
use std::process::{Command, Output};

/// `ai-env args` with only this world: its bridge root (bridge.toml naming
/// `work/` as the root), an empty keystore, HOME the tempdir, the real git
/// on PATH, nothing of the developer's environment that steers ai-env; run
/// to its end within [`LIMIT`] (killed and failed past it).
fn ai_env(w: &World, args: &[&str]) -> Output {
    std::fs::write(w.paths().config, w.config_text("")).unwrap();
    let git_dir = git_real().parent().unwrap().display().to_string();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-env"));
    cmd.args(args)
        .env_clear()
        .env("HOME", &w.root)
        .env("PATH", format!("{git_dir}:/usr/bin:/bin"))
        .env("AI_ENV_BRIDGE_DIR", w.paths().root)
        .env("AI_ENV_DIR", w.root.join("keys"))
        .env("AWS_CONFIG_FILE", "/dev/null")
        .env("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
        .env("LC_ALL", "C");
    crate::common::bounded::run_within(cmd, None, LIMIT, "ai-env")
}

/// How long one `ai-env` run may take here.
const LIMIT: std::time::Duration = std::time::Duration::from_secs(60);

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn dir(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn box_seed_dry_run_prints_the_plan_offline() {
    let w = World::new();
    let repo = w.repo("app");
    repo.write("src.txt", "committed\n");
    repo.commit("src");
    repo.write("src.txt", "changed\n");
    repo.write("new.txt", "untracked\n");
    let before = repo.state();
    let o = ai_env(&w, &["box", "seed", dir(&repo.dir), "--dry-run", "--json"]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("{e}: {}", text(&o.stdout)));
    assert_eq!(v["dry_run"], true);
    assert_eq!(v["root"], dir(&repo.dir));
    assert_eq!(v["seed"]["head"], repo.head());
    assert_eq!(v["seed"]["branch"], "main");
    assert_eq!(v["seed"]["wip"]["untracked"], 1);
    assert_eq!(v["seed"]["wip"]["changed"], 2);
    assert!(v["pack_bytes"].as_u64().is_some_and(|n| n > 0) && v["over_cap"] == false, "{v}");
    assert_eq!(repo.state(), before, "a dry run touches nothing");
    let o = ai_env(&w, &["box", "seed", dir(&repo.dir), "--dry-run"]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    let out = text(&o.stdout);
    assert!(out.contains(&format!("box seed --dry-run: {}", repo.dir.display())) && out.contains("1 untracked file(s)") && out.ends_with("nothing was sent: no AWS call, no Touch ID\n"), "{out}");
    // --no-wip leaves the changes on the Mac.
    let o = ai_env(&w, &["box", "seed", dir(&repo.dir), "--dry-run", "--json", "--no-wip"]);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert!(v["seed"].get("wip").is_none(), "{v}");
    assert!(!w.root.join("keys").exists(), "the keystore was never opened");
}

/// What a real seed refuses, the dry run refuses with the same exit code:
/// a workspace that is no repository (D6, exit 9, the plan's hint), one
/// outside the roots (9), a tripwire in what it carries (9, naming the
/// place and never the bytes), a seed over `--max-mib` (9), an unborn HEAD (1).
#[test]
fn box_seed_dry_run_refuses_what_a_seed_would() {
    let w = World::new();
    let plain = w.work().join("letters");
    std::fs::create_dir_all(&plain).unwrap();
    let o = ai_env(&w, &["box", "seed", dir(&plain), "--dry-run"]);
    assert_eq!(o.status.code(), Some(9));
    assert_eq!(text(&o.stderr), format!("ai-env: workspace refused (not_a_git_repo): {}: not a git repository: ai-env seeds git workspaces only; AI_ENV_BRIDGE_LOCAL=1 runs Cursor locally\n", plain.display()));
    let outside = w.root.join("elsewhere");
    std::fs::create_dir_all(&outside).unwrap();
    let o = ai_env(&w, &["box", "seed", dir(&outside), "--dry-run"]);
    assert_eq!(o.status.code(), Some(9));
    assert!(text(&o.stderr).contains("outside [workspaces].roots"), "{}", text(&o.stderr));
    let repo = w.repo("app");
    repo.write("leak.txt", &format!("{}\n", key_id()));
    let o = ai_env(&w, &["box", "seed", dir(&repo.dir), "--dry-run"]);
    assert_eq!(o.status.code(), Some(9));
    let err = text(&o.stderr);
    assert!(err.starts_with("ai-env: workspace refused (finding): wip:leak.txt (blob ") && err.contains("rule aws-access-key-id") && !err.contains(&key_id()), "{err}");
    std::fs::remove_file(repo.dir.join("leak.txt")).unwrap();
    // Bytes zlib cannot shrink (a xorshift stream), so the pack is as large as the file.
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let noise: Vec<u8> = (0..1536 * 1024)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect();
    repo.write_bytes("big.bin", &noise);
    repo.commit("big");
    let o = ai_env(&w, &["box", "seed", dir(&repo.dir), "--dry-run", "--max-mib", "1"]);
    assert_eq!(o.status.code(), Some(9), "{}", text(&o.stderr));
    assert!(text(&o.stderr).contains("the seed is over 1.0 MiB (box seed --max-mib, [seed].max_mib)") && text(&o.stdout).contains("pack: over the cap"), "{}{}", text(&o.stdout), text(&o.stderr));
    let unborn = w.work().join("unborn");
    std::fs::create_dir_all(&unborn).unwrap();
    super::fixture::git(&unborn, &["init", "-q", "-b", "main"]);
    let o = ai_env(&w, &["box", "seed", dir(&unborn), "--dry-run"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(text(&o.stderr).contains("workspace failed (unsupported_repo)") && text(&o.stderr).contains("no commit yet"), "{}", text(&o.stderr));
}
