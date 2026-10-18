//! tests/workspace.rs area: the resume's transcript (S9, after the S3
//! cut-over, plans/s9-contracts.md §10; S8's upload of the Mac's mirror is
//! gone). A chat begun on the Mac goes up to the tests' S3 inline, then is
//! pulled into the VM's projects directory under the VM's slug; the Mac keeps
//! only its view, the original moved to `origin/`. A VM holding the committed
//! prefix keeps it (the VM went on: longer is fine); a VM without it (the
//! file gone, or other bytes at the committed length) has it pulled from S3
//! again. A file no transcript rel can name goes up with the chat but is
//! never written in the VM; a chat neither S3 nor this Mac holds restores
//! nothing.
use super::fixture::{api, ensure_ctx, sha256_hex, target, FakeVm, Tokens, World};
use crate::common::fake_s3::FakeS3;
use ai_env_cli::bridge::s3::sync::SyncCtx;
use ai_env_cli::bridge::s3::{S3Endpoint, S3Target, TranscriptSync, LAB_BUCKET, LAB_OWNER};
use ai_env_cli::bridge::workspace::transcript::{restore, restore_subtree};
use ai_env_cli::bridge::workspace::{resolve, SeedProgress, TranscriptOutcome};
use ai_env_cli::wire::frame::{CAP_TRANSCRIPT_S3_V1, CAP_WORKSPACE_V1};
use ai_env_cli::wire::s3::S3Key;
use ai_env_cli::wire::view::{build_view, VIEW_MARK_PREFIX};

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
