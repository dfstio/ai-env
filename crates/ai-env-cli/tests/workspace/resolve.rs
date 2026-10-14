//! tests/workspace.rs area: `workspace::resolve` (plan §1, §5; D6): a git
//! repository under the roots, its NFC VM path, its HEAD; a workspace that
//! is no repository is refused with the plan's hint (exit 9), a repository a
//! seed cannot carry with `unsupported_repo` (exit 1), one outside the roots
//! with `outside_roots` (exit 9).
use super::fixture::{git, Repo, World};
use ai_env_cli::bridge::errors::BridgeError;
use ai_env_cli::bridge::workspace::{code, resolve, Head, WsKind};
use ai_env_cli::errors::CliError;
use ai_env_cli::wire::workspace::ObjectFormat;

fn exit(e: BridgeError) -> (i32, String) {
    let text = e.to_string();
    (CliError::from(e).exit_code(), text)
}

#[test]
fn a_repository_resolves_to_its_root_vm_path_slug_and_head() {
    let w = World::new();
    let repo = w.repo("app");
    std::fs::create_dir_all(repo.dir.join("src/deep")).unwrap();
    let ws = resolve(&w.cfg(""), &repo.dir.join("src/deep"), None).unwrap();
    assert_eq!((ws.root.clone(), ws.cwd.clone()), (repo.dir.clone(), repo.dir.join("src/deep")));
    assert_eq!((ws.vm_root.as_str(), ws.vm_cwd.as_str()), (repo.dir.to_str().unwrap(), repo.dir.join("src/deep").to_str().unwrap()));
    assert_eq!(ws.head, Head::Branch { name: "main".into(), sha: repo.head() });
    assert!(ws.slug.ends_with("-work-app-src-deep") && ws.slug.starts_with('-'), "{}", ws.slug);
    let WsKind::Git { git_dir, common_dir, object_format } = &ws.kind;
    assert_eq!((git_dir.clone(), common_dir.clone(), *object_format), (repo.dir.join(".git"), repo.dir.join(".git"), ObjectFormat::Sha1));
    assert_eq!(ws.seed_branch, None);
    // Detached, and `--branch` naming another branch (its committed state, no WIP).
    repo.git(&["branch", "feature"]);
    let ws = resolve(&w.cfg(""), &repo.dir, Some("feature")).unwrap();
    assert_eq!(ws.seed_branch.as_deref(), Some("feature"));
    assert_eq!(resolve(&w.cfg(""), &repo.dir, Some("main")).unwrap().seed_branch, None, "the checked-out branch is no --branch");
    let e = resolve(&w.cfg(""), &repo.dir, Some("nope")).unwrap_err();
    assert!(matches!(e, BridgeError::Config(_)) && e.to_string().contains("no such branch"), "{e}");
    assert!(resolve(&w.cfg(""), &repo.dir, Some("-x")).is_err(), "never an option-looking branch");
    let head = repo.head();
    repo.git(&["checkout", "-q", "--detach"]);
    assert_eq!(resolve(&w.cfg(""), &repo.dir, None).unwrap().head, Head::Detached { sha: head });
}

/// D6: a workspace that is no git repository is refused at once with the
/// plan's hint (exit 9), even when a repository holds the roots above it.
#[test]
fn a_workspace_that_is_no_repository_is_refused_with_the_hint() {
    let w = World::new();
    let plain = w.work().join("letters");
    std::fs::create_dir_all(&plain).unwrap();
    std::fs::write(plain.join("message.txt"), "hello\n").unwrap();
    let (code, text) = exit(resolve(&w.cfg(""), &plain, None).unwrap_err());
    assert_eq!(code, 9);
    assert_eq!(text, format!("workspace refused (not_a_git_repo): {}: not a git repository: ai-env seeds git workspaces only; AI_ENV_BRIDGE_LOCAL=1 runs Cursor locally", plain.display()));
    // A repository above every root is never the workspace's (git's ceiling is the outermost root's parent).
    let _outer = Repo::create(&w.root);
    let (code, text) = exit(resolve(&w.cfg(""), &plain, None).unwrap_err());
    assert!(code == 9 && text.contains("not_a_git_repo"), "{text}");
}

#[test]
fn outside_the_roots_is_refused() {
    let w = World::new();
    let elsewhere = Repo::create(&w.root.join("elsewhere"));
    let (code, text) = exit(resolve(&w.cfg(""), &elsewhere.dir, None).unwrap_err());
    assert_eq!(code, 9);
    assert!(text.starts_with("workspace refused (outside_roots)") && text.contains("elsewhere"), "{text}");
    // A root inside a repository: the repository's top level lies outside it.
    let big = Repo::create(&w.root.join("big"));
    std::fs::create_dir_all(big.dir.join("sub")).unwrap();
    let cfg = ai_env_cli::bridge::config::BridgeConfig::parse(&format!("[workspaces]\nroots = [{:?}]\n", big.dir.join("sub").display().to_string())).unwrap();
    let e = resolve(&cfg, &big.dir.join("sub"), None).unwrap_err();
    assert!(matches!(&e, BridgeError::WorkspaceRefused { code: c, .. } if *c == code::OUTSIDE_ROOTS || *c == code::NOT_A_GIT_REPO), "{e}");
}

/// Repositories a seed cannot carry: exit 1, one line naming why and the fix.
#[test]
fn unsupported_repositories_are_refused_with_exit_1() {
    let w = World::new();
    let check = |dir: &std::path::Path, why: &str| {
        let e = resolve(&w.cfg(""), dir, None).unwrap_err();
        assert!(matches!(&e, BridgeError::WorkspaceFailed { code: c, .. } if *c == code::UNSUPPORTED_REPO), "{why}: {e:?}");
        let (code, text) = exit(e);
        assert!(code == 1 && text.contains(why) && !text.contains('\n'), "{text}");
    };
    // Unborn HEAD.
    let unborn = w.work().join("unborn");
    std::fs::create_dir_all(&unborn).unwrap();
    git(&unborn, &["init", "-q", "-b", "main"]);
    check(&unborn, "no commit yet");
    // Shallow.
    let src = w.repo("src");
    src.write("a.txt", "a\n");
    src.commit("two");
    git(&w.work(), &["clone", "-q", "--depth", "1", &format!("file://{}", src.dir.display()), "shallow"]);
    check(&w.work().join("shallow"), "shallow clone");
    // Bare.
    git(&w.work(), &["init", "-q", "--bare", "bare.git"]);
    check(&w.work().join("bare.git"), "bare repository");
    // Sparse checkout.
    let sparse = w.repo("sparse");
    sparse.git(&["config", "core.sparseCheckout", "true"]);
    check(&sparse.dir, "sparse checkout");
    // Partial clone.
    let partial = w.repo("partial");
    partial.git(&["config", "extensions.partialClone", "origin"]);
    check(&partial.dir, "partial clone");
    let promisor = w.repo("promisor");
    promisor.git(&["config", "remote.origin.promisor", "true"]);
    check(&promisor.dir, "partial clone");
    // Inside the .git directory.
    check(&src.dir.join(".git"), "inside a .git directory");
}

/// T8.6's non-ASCII case (D6): a repository at a Cyrillic path written in
/// NFD on disk resolves to the NFC form for the VM, one slug.
#[test]
fn an_nfd_cyrillic_path_gives_its_nfc_vm_path() {
    let w = World::new();
    // Й as И + U+0306 (NFD), as macOS can hand it out; the NFC form is the precomposed Й.
    let nfd = "\u{0418}\u{0306}\u{043e}\u{0433}\u{0430}";
    let nfc = "\u{0419}\u{043e}\u{0433}\u{0430}";
    let repo = Repo::create(&w.work().join(nfd));
    let ws = resolve(&w.cfg(""), &repo.dir, None).unwrap();
    assert!(ws.vm_root.ends_with(&format!("/work/{nfc}")), "{}", ws.vm_root);
    assert!(!ws.vm_root.contains('\u{0306}'), "no combining mark: {:?}", ws.vm_root);
    assert_eq!(ws.vm_cwd, ws.vm_root);
    assert_eq!(ai_env_cli::wire::workspace::vm_path_check(&ws.vm_root), Ok(()));
    let again = resolve(&w.cfg(""), &w.work().join(nfc), None).unwrap();
    assert_eq!((again.vm_root, again.slug), (ws.vm_root.clone(), ws.slug.clone()), "either spelling: one VM path, one slug");
}
