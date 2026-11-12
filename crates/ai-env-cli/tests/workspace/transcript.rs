//! tests/workspace.rs area: the resume's transcript (S9, after the S3
//! cut-over, plans/s9-contracts.md §10; S8's upload of the Mac's mirror is
//! gone). A chat begun on the Mac goes up to the tests' S3 inline, then is
//! pulled into the VM's projects directory under the VM's slug; the Mac keeps
//! only its view, the original moved to `origin/`. A VM holding the committed
//! prefix keeps it (the VM went on: longer is fine); a VM without it (the
//! file gone, or other bytes at the committed length) has it pulled from S3
//! again. A file no transcript rel can name goes up with the chat but is
//! never written in the VM; a chat neither S3 nor this Mac holds restores
//! nothing. The fork gap: Cursor's fork of a remote chat, a copy of its view
//! under an id no record names, goes up as a chat begun here.
use super::fixture::{api, ensure_ctx, sha256_hex, target, FakeVm, Tokens, World};
use crate::common::fake_s3::FakeS3;
use ai_env_cli::bridge::s3::sync::SyncCtx;
use ai_env_cli::bridge::s3::{S3Endpoint, S3Target, TranscriptSync, LAB_BUCKET, LAB_OWNER};
use ai_env_cli::bridge::workspace::transcript::{restore, restore_subtree};
use ai_env_cli::bridge::workspace::{resolve, SeedProgress, TranscriptOutcome};
use ai_env_cli::wire::frame::{CAP_TRANSCRIPT_S3_V1, CAP_WORKSPACE_V1};
use ai_env_cli::wire::s3::S3Key;
use ai_env_cli::wire::view::{build_view, ViewLine, ViewMessage, ViewRole, ViewText, ViewTextKind, VIEW_ENTRYPOINT, VIEW_MARK_PREFIX, VIEW_USER_TYPE, VIEW_V};

const ID: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";

/// A chat's two entries, the reply chained to the prompt (a view can be built from them).
fn chat_lines() -> String {
    let (u, a) = ("0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a60", "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a61");
    format!(
        "{{\"type\":\"user\",\"uuid\":\"{u}\",\"parentUuid\":null,\"sessionId\":\"{ID}\",\"timestamp\":\"2026-10-18T10:00:00.000Z\",\"message\":{{\"role\":\"user\",\"content\":\"what does the seed carry?\"}}}}\n\
         {{\"type\":\"assistant\",\"uuid\":\"{a}\",\"parentUuid\":\"{u}\",\"sessionId\":\"{ID}\",\"timestamp\":\"2026-10-18T10:00:05.000Z\",\"message\":{{\"role\":\"assistant\",\"content\":[{{\"type\":\"text\",\"text\":\"The uncommitted work, as it is.\"}}]}}}}\n"
    )
}

#[tokio::test]
async fn the_transcript_is_restored_only_when_the_vm_lacks_it() {
    let w = World::new();
    let repo = w.repo("app");
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    let mac = w.root.join("mac-projects");
    let src = mac.join("-mac-slug");
    let main = chat_lines();
    let sub = "{\"type\":\"user\",\"message\":{\"content\":\"a subagent's prompt\"}}\n";
    for (rel, text) in [
        (format!("{ID}.jsonl"), main.as_str()),
        (format!("{ID}/subagents/agent-a1.jsonl"), sub),
        // Neither a .jsonl nor a .json, and one directly below the session: no transcript rel names them.
        (format!("{ID}/tool-results/out.txt"), "a tool's long output\n"),
        (format!("{ID}/stray.jsonl"), "{}\n"),
    ] {
        let p = src.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }
    let s3 = FakeS3::start();
    let target_s3 = S3Target { bucket: LAB_BUCKET.into(), owner: LAB_OWNER.into(), endpoint: S3Endpoint::Lab(s3.addr()) };
    let sync = TranscriptSync { target: target_s3, slug: "-vm-slug".into(), mac_cwd: ws.cwd.display().to_string(), mac_projects: mac.clone(), proxy: None, view_messages: 10 };
    let vm_projects = w.root.join("vm-projects");
    let vm = FakeVm::new(&w.root.join("vm"), &vm_projects);
    let (api, t, c) = (api().await, target(), vec![CAP_WORKSPACE_V1.to_string(), CAP_TRANSCRIPT_S3_V1.to_string()]);
    let progress = |_: SeedProgress| {};
    let ctx = ensure_ctx(&api, &vm, &paths, &cfg, &t, &c, &ws, &progress);
    let total = (main.len() + sub.len() + "a tool's long output\n".len() + "{}\n".len()) as u64;
    // A chat begun on this Mac: up to S3 inline, then into the VM; the Mac keeps its view.
    let up = restore(&ctx, &sync, Some(&mac), &["-mac-slug"], ID, &build_view).await.unwrap();
    assert_eq!(up, TranscriptOutcome::Staged { bytes: total });
    let vm_main = vm_projects.join("-vm-slug").join(format!("{ID}.jsonl"));
    assert_eq!(std::fs::read_to_string(&vm_main).unwrap(), main, "the VM's copy is the chat's bytes");
    let sub_in_vm = vm_projects.join("-vm-slug").join(ID).join("subagents/agent-a1.jsonl");
    assert!(!sub_in_vm.exists(), "the subtree follows after the spawn, out of P3's deadline");
    let rules = ai_env_cli::bridge::scan::Rules::defaults();
    let sctx = SyncCtx { api: &api, dp: &vm, tokens: &Tokens, paths: &paths, target: &t, sync: &sync, rules: &rules, deadline: None };
    let done = restore_subtree(&sctx, ID).await.unwrap();
    assert_eq!((done.pulled, done.unnamed), (1, 2), "{done:?}");
    assert_eq!(std::fs::read_to_string(&sub_in_vm).unwrap(), sub);
    for unnamed in ["tool-results/out.txt", "stray.jsonl"] {
        assert!(!vm_projects.join("-vm-slug").join(ID).join(unnamed).exists(), "{unnamed}: no transcript rel names it, never written in the VM");
    }
    let held = |text: &str| s3.get(&S3Key::Mac { session: ID.into(), sha256: sha256_hex(text.as_bytes()) }.render());
    assert_eq!(held(&main).as_deref(), Some(main.as_bytes()), "S3 holds the chat");
    assert_eq!(held("a tool's long output\n").as_deref(), Some(&b"a tool's long output\n"[..]), "and every file of it, as it went up");
    let view = std::fs::read_to_string(src.join(format!("{ID}.jsonl"))).unwrap();
    assert!(!view.is_empty() && view.lines().all(|l| l.starts_with(VIEW_MARK_PREFIX)), "the Mac keeps only the view: {view}");
    assert_eq!(std::fs::read_to_string(paths.transcript_origin(ID).join(format!("{ID}.jsonl"))).unwrap(), main, "the original moved to origin/");
    let pulls = |vm: &FakeVm| vm.calls().iter().filter(|c| c.starts_with("POST /transcript/pull")).count();
    assert_eq!(pulls(&vm), 2, "the transcript and its one named subagent file: {:?}", vm.calls());
    // The same VM holds the committed prefix: kept, nothing pulled; so is one that went on since.
    assert_eq!(restore(&ctx, &sync, Some(&mac), &["-mac-slug"], ID, &build_view).await.unwrap(), TranscriptOutcome::KeptOnVm);
    let mut longer = main.clone();
    longer.push_str("{\"type\":\"user\",\"message\":{\"content\":\"and then?\"}}\n");
    std::fs::write(&vm_main, &longer).unwrap();
    assert_eq!(restore(&ctx, &sync, Some(&mac), &["-mac-slug"], ID, &build_view).await.unwrap(), TranscriptOutcome::KeptOnVm);
    assert_eq!(pulls(&vm), 2, "nothing pulled for a VM that holds it");
    // Gone from the VM (a new VM), or other bytes at the committed length: pulled from S3 again.
    std::fs::remove_file(&vm_main).unwrap();
    assert_eq!(restore(&ctx, &sync, Some(&mac), &["-mac-slug"], ID, &build_view).await.unwrap(), TranscriptOutcome::Restored { parts: 1, bytes: main.len() as u64 });
    assert_eq!(std::fs::read_to_string(&vm_main).unwrap(), main);
    std::fs::write(&vm_main, "x".repeat(main.len())).unwrap();
    assert_eq!(restore(&ctx, &sync, Some(&mac), &["-mac-slug"], ID, &build_view).await.unwrap(), TranscriptOutcome::Restored { parts: 1, bytes: main.len() as u64 });
    assert_eq!(std::fs::read_to_string(&vm_main).unwrap(), main, "S3's bytes, not the VM's");
    // Neither S3 nor this Mac holds a chat: nothing to restore, nothing asked.
    let before = vm.calls().len();
    assert_eq!(restore(&ctx, &sync, Some(&mac), &["-mac-slug"], "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c", &build_view).await.unwrap(), TranscriptOutcome::NothingToRestore);
    assert_eq!(vm.calls().len(), before, "no request for nothing");
    assert!(!vm.calls().iter().any(|c| c.starts_with("PUT /transcript")), "S8's upload is gone: {:?}", vm.calls());
}

/// The fork gap: the fork Cursor made of a remote chat's view, under `fork`: a prompt and its reply as view lines
/// (each marked first, its own uuid, the fork's `sessionId`, as the extension re-keys them), then the fork's own
/// `custom-title` line.
fn fork_lines(fork: &str, cwd: &str) -> String {
    let (u, a) = ("0199a1b2-0000-7000-8000-0000000012b1", "0199a1b2-0000-7000-8000-0000000012b2");
    let line = |role: ViewRole, uuid: &str, parent: Option<&str>, text: &str| {
        let message = ViewMessage { role, content: vec![ViewText { kind: ViewTextKind::Text, text: text.into() }] };
        let l = ViewLine {
            ai_env_view: VIEW_V,
            parent_uuid: parent.map(str::to_string),
            is_sidechain: false,
            user_type: VIEW_USER_TYPE.into(),
            cwd: cwd.into(),
            session_id: fork.into(),
            version: "2.1.319".into(),
            git_branch: "main".into(),
            entrypoint: VIEW_ENTRYPOINT.into(),
            kind: role,
            message,
            uuid: uuid.into(),
            timestamp: "2026-11-09T10:00:00.000Z".into(),
        };
        format!("{}\n", serde_json::to_string(&l).unwrap())
    };
    format!(
        "{}{}{{\"type\":\"custom-title\",\"sessionId\":\"{fork}\",\"customTitle\":\"what the seed carries (fork)\"}}\n",
        line(ViewRole::User, u, None, "what does the seed carry?"),
        line(ViewRole::Assistant, a, Some(u), "The uncommitted work, as it is.")
    )
}

/// The fork gap: Cursor forks a remote chat on this Mac from its view, so the fork's copy is view-shaped (every
/// message line marked) under an id no row or manifest names. With no VM holding it and no g1 tail of it in S3
/// (asked first: a stat of the VM, a listing of S3), it goes up as a chat begun here: S3 holds its bytes (origin
/// `mac`), the VM gets them under its slug, the Mac keeps ai-env's view of it in its place (marked, the extension's
/// `(fork)` line carried byte for byte) and the copy under `origin/`, audited `transcript_stage`. The same shape
/// under an id an S8 row names is that chat's view, never its transcript: nothing to restore, nothing asked of the
/// VM, the file as it was.
#[tokio::test]
async fn a_fork_cursor_made_of_a_view_goes_up_when_nothing_claims_it() {
    use ai_env_cli::bridge::s3::manifest;
    const FORK: &str = "0199a1b2-0000-7000-8000-0000000012a4";
    const OTHER: &str = "0199a1b2-0000-7000-8000-0000000012a5";
    let w = World::new();
    let repo = w.repo("app");
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    let mac = w.root.join("mac-projects");
    let dir = mac.join("-mac-slug");
    std::fs::create_dir_all(&dir).unwrap();
    let fork = fork_lines(FORK, &ws.cwd.display().to_string());
    let carried = fork.lines().last().unwrap().to_string();
    assert!(fork.lines().filter(|l| *l != carried).all(|l| l.starts_with(VIEW_MARK_PREFIX)), "view-shaped: {fork}");
    std::fs::write(dir.join(format!("{FORK}.jsonl")), &fork).unwrap();
    let s3 = FakeS3::start();
    let target_s3 = S3Target { bucket: LAB_BUCKET.into(), owner: LAB_OWNER.into(), endpoint: S3Endpoint::Lab(s3.addr()) };
    let sync = TranscriptSync { target: target_s3, slug: "-vm-slug".into(), mac_cwd: ws.cwd.display().to_string(), mac_projects: mac.clone(), proxy: None, view_messages: 10 };
    let vm_projects = w.root.join("vm-projects");
    let vm = FakeVm::new(&w.root.join("vm"), &vm_projects);
    let (api, t, c) = (api().await, target(), vec![CAP_WORKSPACE_V1.to_string(), CAP_TRANSCRIPT_S3_V1.to_string()]);
    let progress = |_: SeedProgress| {};
    let ctx = ensure_ctx(&api, &vm, &paths, &cfg, &t, &c, &ws, &progress);
    let up = restore(&ctx, &sync, Some(&mac), &["-mac-slug"], FORK, &build_view).await.unwrap();
    assert_eq!(up, TranscriptOutcome::Staged { bytes: fork.len() as u64 });
    let calls = vm.calls();
    assert_eq!(calls.first().map(String::as_str), Some(format!("GET /transcript -vm-slug/{FORK}.jsonl from=-").as_str()), "the VM asked first: {calls:?}");
    let asked = s3.requests();
    assert!(asked.first().is_some_and(|q| q.method == "GET" && q.key.is_empty() && q.query_names.iter().any(|n| n == "list-type")), "S3 listed its tails before anything went up: {asked:?}");
    assert_eq!(std::fs::read_to_string(vm_projects.join("-vm-slug").join(format!("{FORK}.jsonl"))).unwrap(), fork, "the VM's copy is the fork's bytes");
    let key = S3Key::Mac { session: FORK.into(), sha256: sha256_hex(fork.as_bytes()) }.render();
    assert_eq!(s3.get(&key).as_deref(), Some(fork.as_bytes()), "S3 holds the fork");
    assert_eq!(manifest::read(&paths, FORK).unwrap().map(|m| m.origin), Some(manifest::ORIGIN_MAC.to_string()));
    let view = std::fs::read_to_string(dir.join(format!("{FORK}.jsonl"))).unwrap();
    let (marked, other): (Vec<&str>, Vec<&str>) = view.lines().partition(|l| l.starts_with(VIEW_MARK_PREFIX));
    assert!(marked.len() == 2 && other == [carried.as_str()] && view.ends_with(&format!("{carried}\n")), "ai-env's view, the fork's name carried: {view}");
    assert_eq!(std::fs::read_to_string(paths.transcript_origin(FORK).join(format!("{FORK}.jsonl"))).unwrap(), fork, "the copy moved to origin/");
    let audit = std::fs::read_to_string(paths.audit()).unwrap();
    let rows = |event: &str| -> Vec<(String, String)> {
        let row = |r: serde_json::Value| (r["detail"]["session"].as_str().unwrap_or_default().to_string(), r["detail"]["outcome"].as_str().unwrap_or_default().to_string());
        audit.lines().filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok()).filter(|r| r["event"] == event).map(row).collect()
    };
    let ours = (FORK.to_string(), "staged".to_string());
    assert_eq!(rows("transcript_stage"), [ours], "{audit}");
    assert_eq!(rows("transcript_view"), [(FORK.to_string(), "written".to_string())], "ai-env's view written in the copy's place: {audit}");
    // The same shape that an S8 row names: that chat's view, never a Mac copy.
    let row = ai_env_cli::bridge::registry::SessionRow { session_id: OTHER.into(), mode: "remote".into(), ..ai_env_cli::bridge::registry::SessionRow::default() };
    ai_env_cli::bridge::registry::write(&paths, &row).unwrap();
    let theirs = fork.replace(FORK, OTHER);
    let other = dir.join(format!("{OTHER}.jsonl"));
    std::fs::write(&other, &theirs).unwrap();
    let before = vm.calls();
    assert_eq!(restore(&ctx, &sync, Some(&mac), &["-mac-slug"], OTHER, &build_view).await.unwrap(), TranscriptOutcome::NothingToRestore);
    assert_eq!(vm.calls(), before, "nothing asked of the VM");
    assert_eq!(std::fs::read_to_string(&other).unwrap(), theirs, "the view as it was");
    assert!(manifest::read(&paths, OTHER).unwrap().is_none(), "nothing went up");
}
