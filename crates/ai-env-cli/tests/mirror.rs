//! T2.2 — the transcript-mirror writer: byte equality and confinement through
//! the library (`bridge::mirror::Writer`), and through the wrapper that mirror
//! frames never reach the host and land where `AI_ENV_BRIDGE_MIRROR_ROOT`
//! says (or nowhere, for a local child without it), that a subagent's
//! `agent_metadata` entry becomes its `.meta.json` companion, and that the
//! stdout serializer's ` `/` ` escapes are written as the raw
//! characters the CLI's own file holds. T2.1 (`#[ignore]`,
//! `AI_ENV_CLAUDE_TESTS=1`) replays frames Mike captured from the real CLI
//! and demands byte equality with every real `.jsonl`; it reads files only
//! and never runs a binary.
mod common;

use ai_env_cli::bridge::mirror::{MirrorCfg, Writer};
use common::{is_init, note_has, uuid, Harness};
use serde_json::value::RawValue;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Upper bounds only (timing is `race.rs`'s): a loaded Mac can start a child seconds late.
const T: Duration = Duration::from_secs(30);
const EXIT: Duration = Duration::from_secs(30);

fn raw(text: &str) -> Box<RawValue> {
    RawValue::from_string(text.to_string()).unwrap_or_else(|e| panic!("not JSON ({e}): {text}"))
}

/// `entries` as the writer must lay them down: each raw text + `\n`.
fn joined(entries: &[&str]) -> String {
    entries.iter().map(|e| format!("{e}\n")).collect()
}

fn mode(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::symlink_metadata(p).unwrap_or_else(|e| panic!("{}: {e}", p.display())).permissions().mode() & 0o777
}

/// Every regular file under `dir`, recursively (empty when `dir` is absent).
fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else { return out };
    for e in rd.filter_map(Result::ok) {
        let p = e.path();
        match e.file_type() {
            Ok(t) if t.is_dir() => out.extend(files_under(&p)),
            Ok(t) if t.is_file() => out.push(p),
            _ => {}
        }
    }
    out.sort();
    out
}

#[test]
fn t2_2_writer_byte_equality_and_confinement() {
    let tmp = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    let child = root.join("child").join("projects");
    let dest = root.join("dest");
    let mut w = Writer::new(MirrorCfg { child_projects_root: child.clone(), dest_root: dest.clone(), enabled: true, reason: "test".into() });
    let slug = "-Users-mike-Documents-DeFi-ai-env";
    let sid = uuid(0x7702);
    let c = child.display().to_string();

    // Raw bytes the writer must not touch: key order, number format, escapes, inner spacing.
    let main1 = [r#"{"z":1,"type":"user","a":1e21,"s":"tab\t\"q\" é"}"#, r#"{"type":"assistant","n":2.50,"list":[1, 2]}"#];
    let main2 = [r#"{"type":"summary","leafUuid":"x"}"#];
    let sub = [r#"{"type":"user","isSidechain":true}"#, r#"{"type":"assistant","isSidechain":true,"v":-0.0}"#];
    let meta = [r#"{"type":"agent_metadata","agentType":"general-purpose"}"#];
    let append = |w: &mut Writer, path: &str, entries: &[&str]| {
        let boxed: Vec<Box<RawValue>> = entries.iter().map(|e| raw(e)).collect();
        let refs: Vec<&RawValue> = boxed.iter().map(AsRef::as_ref).collect();
        w.append(Some(path), &refs)
    };

    let main_path = format!("{c}/{slug}/{sid}.jsonl");
    let sub_path = format!("{c}/{slug}/{sid}/subagents/agent-a1.jsonl");
    let meta_path = format!("{c}/{slug}/{sid}/subagents/agent-a1.meta.json");
    assert!(append(&mut w, &main_path, &main1).is_ok(), "2-segment");
    assert!(append(&mut w, &sub_path, &sub).is_ok(), "4-segment subagent");
    assert!(append(&mut w, &meta_path, &meta).is_ok(), ".meta.json companion");
    assert!(append(&mut w, &main_path, &main2).is_ok(), "a second append to the same file");
    // Rejected: 3 segments, `..` out of the root, an absolute path elsewhere.
    let bad = [format!("{c}/{slug}/{sid}/x.jsonl"), format!("{c}/../escape/{slug}/{sid}.jsonl"), format!("{}/elsewhere/{slug}/{sid}.jsonl", root.display())];
    for b in &bad {
        assert!(append(&mut w, b, &main2).is_err(), "must be rejected: {b}");
    }
    w.sync_all().unwrap();
    println!("rejected={}", w.rejected);
    assert_eq!(w.rejected, 3);
    assert_eq!(w.appended_frames, 4);

    let d_main = dest.join(slug).join(format!("{sid}.jsonl"));
    let d_sub = dest.join(slug).join(&sid).join("subagents").join("agent-a1.jsonl");
    let d_meta = dest.join(slug).join(&sid).join("subagents").join("agent-a1.meta.json");
    let mut all: Vec<&str> = main1.to_vec();
    all.extend(main2);
    assert_eq!(std::fs::read_to_string(&d_main).unwrap(), joined(&all), "byte-equal, appends in order");
    assert_eq!(std::fs::read_to_string(&d_sub).unwrap(), joined(&sub));
    assert_eq!(std::fs::read_to_string(&d_meta).unwrap(), joined(&meta), "the companion keeps its own name");
    assert_eq!(files_under(&dest), {
        let mut v = vec![d_main.clone(), d_sub.clone(), d_meta.clone()];
        v.sort();
        v
    }, "nothing else was written (no rejected frame landed anywhere)");
    assert!(!root.join("escape").exists() && !root.join("elsewhere").exists());
    for f in [&d_main, &d_sub, &d_meta] {
        assert_eq!(mode(f), 0o600, "{}", f.display());
    }
    for d in [dest.join(slug), dest.join(slug).join(&sid), dest.join(slug).join(&sid).join("subagents")] {
        assert_eq!(mode(&d), 0o700, "{}", d.display());
    }
}

/// Two mirror frames (entries under the Mac's own projects root: the child's
/// root in local-child) and one noise line, as the fake's stdout file.
fn frames_file(p: &common::Prepared, sid: &str) -> (PathBuf, Vec<&'static str>, &'static str) {
    let entries: Vec<&'static str> = vec![r#"{"type":"user","uuid":"m1","a":1e21}"#, r#"{"type":"assistant","k":"v \"q\""}"#, r#"{"type":"summary","n":2.50}"#];
    let noise = r#"{"type":"stream_event","event":{"type":"ping"}}"#;
    let file_path = format!("{}/{}/{sid}.jsonl", p.mac_projects().display(), p.slug());
    let fp = serde_json::to_string(&file_path).unwrap();
    let text = format!(
        "{{\"type\":\"transcript_mirror\",\"filePath\":{fp},\"entries\":[{},{}]}}\n{noise}\n{{\"type\":\"transcript_mirror\",\"filePath\":{fp},\"entries\":[{}]}}\n",
        entries[0], entries[1], entries[2]
    );
    (p.write_file("mirror-frames.ndjson", &text), entries, noise)
}

#[test]
fn frames_are_never_forwarded() {
    let p = Harness::prepare();
    let sid = uuid(0x7703);
    let (file, entries, noise) = frames_file(&p, &sid);
    let mirror = p.root.join("mirror");
    let slug = p.slug();
    let mut h = p.spawn("local-child", &[], &[("FAKE_STDOUT_FILE", file.to_str().unwrap()), ("AI_ENV_BRIDGE_MIRROR_ROOT", mirror.to_str().unwrap())]);
    h.send_initialize();
    h.expect_out(|v| v["type"] == "stream_event", T);
    h.close_stdin();
    let (status, _) = h.wait(EXIT);
    let transcript = h.transcript();
    assert_eq!(status.code(), Some(0), "{transcript}");
    let out = h.out_lines();
    assert!(!out.iter().any(|l| l.contains("transcript_mirror")), "a mirror frame reached the host\n{transcript}");
    assert_eq!(out.iter().filter(|l| *l == noise).count(), 1, "the noise line is forwarded verbatim\n{transcript}");
    let at = out.iter().position(|l| serde_json::from_str::<serde_json::Value>(l).is_ok_and(|v| is_init(&v))).expect("init");
    assert_eq!(out.get(at + 1).map(String::as_str), Some(noise), "nothing but the noise follows the init\n{transcript}");
    let mirrored = mirror.join(&slug).join(format!("{sid}.jsonl"));
    assert_eq!(std::fs::read_to_string(&mirrored).unwrap_or_else(|e| panic!("{}: {e}\n{transcript}", mirrored.display())), joined(&entries));
    assert!(!h.prepared.mac_projects().exists(), "the wrapper wrote nothing under the Mac's projects root");
    let note = h.end_note();
    assert!(note_has(&note, "mirror:2/0"), "{note}");
    assert!(h.wrapper_log().contains("mirror writer enabled:"), "{}", h.wrapper_log());
}

#[test]
fn writer_disabled_without_mirror_root_in_local_child() {
    let p = Harness::prepare();
    let sid = uuid(0x7704);
    let (file, _, noise) = frames_file(&p, &sid);
    let mut h = p.spawn("local-child", &[], &[("FAKE_STDOUT_FILE", file.to_str().unwrap())]);
    h.send_initialize();
    h.expect_out(|v| v["type"] == "stream_event", T);
    h.close_stdin();
    let (status, _) = h.wait(EXIT);
    let transcript = h.transcript();
    assert_eq!(status.code(), Some(0), "{transcript}");
    let out = h.out_lines();
    assert!(!out.iter().any(|l| l.contains("transcript_mirror")), "a mirror frame reached the host\n{transcript}");
    assert_eq!(out.iter().filter(|l| *l == noise).count(), 1, "{transcript}");
    assert!(files_under(&h.prepared.mac_projects()).is_empty(), "the disabled writer wrote under the Mac's projects root: {:?}", files_under(&h.prepared.mac_projects()));
    let log = h.wrapper_log();
    assert!(log.contains("mirror writer disabled:"), "{log}");
}

/// Run one local-child session whose fake prints `frames` (NDJSON text) after
/// its init, with the writer pointed at `<tmp>/mirror`; the mirror root and
/// the finished harness.
fn run_frames(p: common::Prepared, frames: &str) -> (PathBuf, Harness) {
    let file = p.write_file("mirror-frames.ndjson", frames);
    let mirror = p.root.join("mirror");
    let mut h = p.spawn("local-child", &[], &[("FAKE_STDOUT_FILE", file.to_str().unwrap()), ("AI_ENV_BRIDGE_MIRROR_ROOT", mirror.to_str().unwrap())]);
    h.send_initialize();
    h.expect_out(|v| v["type"] == "stream_event", T);
    h.close_stdin();
    let (status, _) = h.wait(EXIT);
    assert_eq!(status.code(), Some(0), "{}", h.transcript());
    assert!(!h.out_lines().iter().any(|l| l.contains("transcript_mirror")), "a mirror frame reached the host\n{}", h.transcript());
    (mirror, h)
}

/// A subagent frame carrying one transcript entry and one `agent_metadata`
/// entry: the `.jsonl` gets only the transcript line, the `.meta.json`
/// companion the metadata without its `type` (0600).
#[test]
fn agent_metadata_frame_writes_the_meta_json() {
    let p = Harness::prepare();
    let sid = uuid(0x7705);
    let slug = p.slug();
    let entry = r#"{"type":"user","isSidechain":true,"agentId":"a1","message":{"role":"user","content":"sub"}}"#;
    let meta = r#"{"type":"agent_metadata","agentType":"general-purpose","description":"find the thing"}"#;
    let fp = serde_json::to_string(&format!("{}/{slug}/{sid}/subagents/agent-a1.jsonl", p.mac_projects().display())).unwrap();
    let frames = format!("{{\"type\":\"transcript_mirror\",\"filePath\":{fp},\"entries\":[{entry},{meta}]}}\n{{\"type\":\"stream_event\",\"event\":{{\"type\":\"ping\"}}}}\n");
    let (mirror, h) = run_frames(p, &frames);
    let dir = mirror.join(&slug).join(&sid).join("subagents");
    let jsonl = dir.join("agent-a1.jsonl");
    let meta_json = dir.join("agent-a1.meta.json");
    let transcript = h.transcript();
    assert_eq!(std::fs::read_to_string(&jsonl).unwrap_or_else(|e| panic!("{}: {e}\n{transcript}", jsonl.display())), format!("{entry}\n"), "only the transcript line");
    let got: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&meta_json).unwrap_or_else(|e| panic!("{}: {e}\n{transcript}", meta_json.display()))).expect("meta.json is JSON");
    let mut want: serde_json::Value = serde_json::from_str(meta).unwrap();
    want.as_object_mut().unwrap().remove("type");
    assert_eq!(got, want, "the metadata without its type");
    assert!(got.get("type").is_none());
    assert_eq!(mode(&meta_json), 0o600);
    assert_eq!(mode(&jsonl), 0o600);
    assert_eq!(files_under(&mirror), vec![jsonl.clone(), meta_json.clone()], "nothing else written");
    assert!(note_has(&h.end_note(), "mirror:1/0"), "{}", h.end_note());
}

/// The stdout serializer escapes U+2028/U+2029 (` `, ` `); the CLI's
/// file line holds the raw characters, and so must the mirror.
#[test]
fn line_separator_escapes_are_unescaped() {
    let p = Harness::prepare();
    let sid = uuid(0x7706);
    let slug = p.slug();
    let entry = r#"{"type":"user","message":{"role":"user","content":"a b c \\u2028 stays"}}"#;
    let fp = serde_json::to_string(&format!("{}/{slug}/{sid}.jsonl", p.mac_projects().display())).unwrap();
    let frames = format!("{{\"type\":\"transcript_mirror\",\"filePath\":{fp},\"entries\":[{entry}]}}\n{{\"type\":\"stream_event\",\"event\":{{\"type\":\"ping\"}}}}\n");
    let (mirror, h) = run_frames(p, &frames);
    let file = mirror.join(&slug).join(format!("{sid}.jsonl"));
    let text = std::fs::read_to_string(&file).unwrap_or_else(|e| panic!("{}: {e}\n{}", file.display(), h.transcript()));
    let want = "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"a\u{2028}b\u{2029}c \\\\u2028 stays\"}}\n";
    assert_eq!(text, want, "the raw separators, an escaped backslash left alone");
    assert!(text.contains('\u{2028}') && text.contains('\u{2029}'));
    let parsed: serde_json::Value = serde_json::from_str(text.trim_end_matches('\n')).unwrap();
    let original: serde_json::Value = serde_json::from_str(entry).unwrap();
    assert_eq!(parsed, original, "the same JSON value");
    assert!(note_has(&h.end_note(), "mirror:1/0"), "{}", h.end_note());
}

// ---- T2.1 (Mike; real CLI capture) ---------------------------------------------------------

/// One NDJSON line as its top-level members, raw.
fn members(line: &str) -> Option<BTreeMap<String, Box<RawValue>>> {
    serde_json::from_str(line).ok()
}

fn string_member(m: &BTreeMap<String, Box<RawValue>>, key: &str) -> Option<String> {
    m.get(key).and_then(|r| serde_json::from_str::<String>(r.get()).ok())
}

#[test]
#[ignore = "T2.1: needs a real CLI capture (AI_ENV_CLAUDE_TESTS=1, AI_ENV_T21_FRAMES, AI_ENV_T21_PROJECTS)"]
fn t2_1_captured_frames_match_real_file() {
    if std::env::var("AI_ENV_CLAUDE_TESTS").ok().as_deref() != Some("1") {
        println!("skipped: set AI_ENV_CLAUDE_TESTS=1");
        return;
    }
    let frames = std::env::var("AI_ENV_T21_FRAMES").expect("AI_ENV_T21_FRAMES: the captured stdout (ndjson) of the real CLI run with --session-mirror");
    let projects = PathBuf::from(std::env::var("AI_ENV_T21_PROJECTS").expect("AI_ENV_T21_PROJECTS: that run's CLAUDE_CONFIG_DIR/projects"));
    let text = std::fs::read_to_string(&frames).unwrap_or_else(|e| panic!("{frames}: {e}"));
    let dest = tempfile::tempdir().unwrap();
    let mut w = Writer::new(MirrorCfg { child_projects_root: projects.clone(), dest_root: dest.path().to_path_buf(), enabled: true, reason: "t2.1".into() });
    let mut ext: Option<String> = None;
    let mut mirror_frames = 0_u32;
    for line in text.lines() {
        let Some(m) = members(line) else { continue };
        match string_member(&m, "type").as_deref() {
            Some("system") if ext.is_none() && string_member(&m, "subtype").as_deref() == Some("init") => ext = string_member(&m, "claude_code_version"),
            Some("transcript_mirror") => {
                mirror_frames += 1;
                let path = string_member(&m, "filePath");
                let entries: Vec<Box<RawValue>> = m.get("entries").and_then(|r| serde_json::from_str(r.get()).ok()).unwrap_or_default();
                let refs: Vec<&RawValue> = entries.iter().map(AsRef::as_ref).collect();
                if let Err(e) = w.append(path.as_deref(), &refs) {
                    println!("frame not mirrored ({e:?}): {}", path.unwrap_or_default());
                }
            }
            _ => {}
        }
    }
    w.sync_all().unwrap();
    println!(
        "transcript_mirror frames: {mirror_frames}; appended {} / rejected {} / errors {} / meta files {}",
        w.appended_frames, w.rejected, w.errors, w.meta_files
    );
    let is_ext = |p: &Path, ext: &str| p.extension().is_some_and(|e| e == ext);
    let mut equal = mirror_frames > 0 && w.rejected == 0 && w.errors == 0;
    if w.rejected > 0 || w.errors > 0 {
        println!("FAIL: {} frame(s) rejected, {} append error(s)", w.rejected, w.errors);
    }
    // Every mirrored .jsonl equals the real file, byte for byte.
    let written: Vec<PathBuf> = files_under(dest.path()).into_iter().filter(|p| is_ext(p, "jsonl")).collect();
    equal &= !written.is_empty();
    for f in &written {
        let rel = f.strip_prefix(dest.path()).unwrap();
        let mirrored = std::fs::read(f).unwrap();
        let real = std::fs::read(projects.join(rel));
        let ok = real.as_ref().is_ok_and(|r| *r == mirrored);
        let real_len = real.as_ref().map_or_else(|e| format!("unreadable ({e})"), |r| format!("{} bytes", r.len()));
        println!("{}: mirrored {} bytes, real {real_len}, equal {ok}", rel.display(), mirrored.len());
        if !ok {
            if let Ok(r) = &real {
                let at = r.iter().zip(&mirrored).position(|(a, b)| a != b).unwrap_or_else(|| r.len().min(mirrored.len()));
                println!("  first difference at byte {at}");
            }
        }
        equal &= ok;
    }
    // Every real .jsonl has a mirrored counterpart.
    for real in files_under(&projects).into_iter().filter(|p| is_ext(p, "jsonl")) {
        let rel = real.strip_prefix(&projects).unwrap();
        if !dest.path().join(rel).is_file() {
            println!("FAIL: {} has no mirrored counterpart", rel.display());
            equal = false;
        }
    }
    // .meta.json companions: compared as parsed JSON, reported only.
    for real in files_under(&projects).into_iter().filter(|p| p.to_str().is_some_and(|s| s.ends_with(".meta.json"))) {
        let rel = real.strip_prefix(&projects).unwrap();
        let parse = |p: &Path| std::fs::read_to_string(p).ok().and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok());
        let verdict = match (parse(&real), parse(&dest.path().join(rel))) {
            (Some(a), Some(b)) if a == b => "same JSON".to_string(),
            (Some(a), Some(b)) => format!("differs: real {a} / mirrored {b}"),
            (None, _) => "real file unparseable".to_string(),
            (_, None) => "not mirrored (or unparseable)".to_string(),
        };
        println!("{} (meta, not a failure): {verdict}", rel.display());
    }
    println!("byte-equal: {equal}");
    if let Ok(probes) = std::env::var("AI_ENV_T21_PROBES") {
        let ts = ai_env_cli::wire::time::rfc3339_utc(ai_env_cli::wire::time::unix_now());
        let row = serde_json::json!({"probe": "mirror-schema", "stage": "S2", "ext": ext, "verdict": if equal { "byte-equal" } else { "differs" }, "ts": ts});
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&probes).unwrap_or_else(|e| panic!("{probes}: {e}"));
        writeln!(f, "{row}").unwrap();
        println!("probe row appended to {probes}: {row}");
    }
    assert!(equal, "the mirror does not reproduce the real .jsonl files byte for byte (see above)");
}
