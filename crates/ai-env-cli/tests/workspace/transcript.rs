//! tests/workspace.rs area: the resume's transcript upload (plan §8): the
//! Mac's mirror of a session (the S2 seeder's files) goes to the VM's
//! projects directory under the VM's slug when the VM's copy is absent,
//! shorter or different at equal length; the same copy is left alone; a
//! longer VM copy wins; a file no transcript rel can name is skipped.
use super::fixture::{api, caps, ensure_ctx, target, FakeVm, World};
use ai_env_cli::bridge::workspace::{ensure_transcript, resolve, SeedProgress, TranscriptOutcome};

const ID: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";

#[tokio::test]
async fn the_transcript_goes_up_only_when_the_vm_lacks_it() {
    let w = World::new();
    let repo = w.repo("app");
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    let mirror = w.root.join("mac-projects");
    let src = mirror.join("-mac-slug");
    std::fs::create_dir_all(src.join(ID).join("subagents")).unwrap();
    std::fs::write(src.join(format!("{ID}.jsonl")), "{\"type\":\"user\"}\n{\"type\":\"assistant\"}\n").unwrap();
    std::fs::write(src.join(ID).join("subagents/agent-a1.jsonl"), "{\"a\":1}\n").unwrap();
    std::fs::write(src.join(ID).join("subagents/agent-a1.meta.json"), "{\"agentType\":\"x\"}").unwrap();
    // One file directly below the session: the mirror writes none there, so no rel names it.
    std::fs::write(src.join(ID).join("stray.jsonl"), "{}\n").unwrap();
    let vm = FakeVm::new(&w.root.join("vm"), &w.root.join("vm-projects"));
    let (api, t, c) = (api().await, target(), caps());
    let progress = |_: SeedProgress| {};
    let ctx = ensure_ctx(&api, &vm, &paths, &cfg, &t, &c, &ws, &progress);
    let size = |p: std::path::PathBuf| std::fs::metadata(p).unwrap().len();
    let main_len = size(src.join(format!("{ID}.jsonl")));
    let all = main_len + size(src.join(ID).join("subagents/agent-a1.jsonl")) + size(src.join(ID).join("subagents/agent-a1.meta.json"));
    let up = ensure_transcript(&ctx, &mirror, &["-mac-slug"], ID, "-vm-slug").await.unwrap();
    assert_eq!(up, TranscriptOutcome::Uploaded { files: 3, bytes: all });
    let vm_main = w.root.join("vm-projects").join("-vm-slug").join(format!("{ID}.jsonl"));
    assert_eq!(std::fs::read(&vm_main).unwrap(), std::fs::read(src.join(format!("{ID}.jsonl"))).unwrap());
    assert!(w.root.join("vm-projects/-vm-slug").join(ID).join("subagents/agent-a1.meta.json").is_file());
    assert!(!w.root.join("vm-projects/-vm-slug").join(ID).join("stray.jsonl").exists(), "skipped, never sent");
    // The same copy: only stats.
    let puts = |vm: &FakeVm| vm.calls().iter().filter(|c| c.starts_with("PUT")).count();
    assert_eq!(ensure_transcript(&ctx, &mirror, &["-mac-slug"], ID, "-vm-slug").await.unwrap(), TranscriptOutcome::AlreadyThere);
    assert_eq!(puts(&vm), 3);
    // Different bytes at equal length: sent again.
    std::fs::write(src.join(ID).join("subagents/agent-a1.jsonl"), "{\"a\":2}\n").unwrap();
    assert_eq!(ensure_transcript(&ctx, &mirror, &["-mac-slug"], ID, "-vm-slug").await.unwrap(), TranscriptOutcome::Uploaded { files: 1, bytes: 8 });
    // The VM's copy longer (the session went on there): the VM's wins.
    std::fs::write(&vm_main, "{\"type\":\"user\"}\n{\"type\":\"assistant\"}\n{\"type\":\"user\"}\n").unwrap();
    let vm_len = size(vm_main.clone());
    assert_eq!(ensure_transcript(&ctx, &mirror, &["-mac-slug"], ID, "-vm-slug").await.unwrap(), TranscriptOutcome::VmLonger { vm: vm_len, mac: main_len });
    assert_eq!(size(vm_main.clone()), vm_len, "never shortened");
    // No Mac copy at all.
    assert_eq!(ensure_transcript(&ctx, &mirror, &["-mac-slug"], "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c", "-vm-slug").await.unwrap(), TranscriptOutcome::NoMacCopy);
}
