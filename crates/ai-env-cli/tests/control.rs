//! S11 part B (wave 1, B2): `ai-env audit tail|grep`, `ai-env cost`,
//! `session list|show` and `vm list` through the real binary on the s11
//! fixtures (`tests/fixtures/s11/`, copied to a temporary bridge root), the
//! views' clock `AI_ENV_BRIDGE_LAB_NOW`. The snapshots are
//! `tests/fixtures/s11/expected/`; nothing here writes under `tests/fixtures`.
//! `vm list` runs against the file-backed fake (`AI_ENV_BRIDGE_LAB_FAKE_API`);
//! no test reaches AWS or runs claude.

mod common;

use ai_env_cli::bridge::api::{FakeState, IdleSpec, VmInfo, VmState, FAKE_IMAGE_ARN};
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/s11");
/// 2026-10-23T00:00:00Z: the end of the fixture's day.
const NOW: &str = "1792713600";
/// 2026-10-22T11:30:00Z: B suspended half an hour, its wall 6h50m away.
const NOON: &str = "1792668600";
/// 2026-10-22T00:00:00Z.
const DAY: i64 = 1_792_627_200;
const S1: &str = "11111111-1111-4111-8111-111111111111";
const S2: &str = "22222222-2222-4222-8222-222222222222";
const S3: &str = "33333333-3333-4333-8333-333333333333";
const A: &str = "microvm-0a5fc800-0000-4000-8000-00000000000a";
const B: &str = "microvm-0be03000-0000-4000-8000-00000000000b";

/// One copy of the fixture's bridge root (`bridge/`), with `keys/` and HOME beside it.
struct World {
    tmp: tempfile::TempDir,
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    std::fs::set_permissions(to, std::fs::Permissions::from_mode(0o700)).unwrap();
    for e in std::fs::read_dir(from).unwrap().flatten() {
        let (src, dst) = (e.path(), to.join(e.file_name()));
        if e.file_type().unwrap().is_dir() {
            copy_tree(&src, &dst);
        } else {
            std::fs::copy(&src, &dst).unwrap();
            std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
}

impl World {
    fn new() -> World {
        let tmp = tempfile::tempdir().unwrap();
        copy_tree(&Path::new(FIXTURE).join("bridge"), &tmp.path().join("bridge"));
        std::fs::create_dir_all(tmp.path().join("keys")).unwrap();
        World { tmp }
    }

    /// The world with the fake control plane: bridge.toml names its image; A TERMINATED and B SUSPENDED in it.
    /// The fixture's cut last line is closed first (a junk line): the next row written would be glued to it.
    fn with_fake() -> World {
        let w = World::new();
        std::fs::OpenOptions::new().append(true).open(w.audit_path()).unwrap().write_all(b"\n").unwrap();
        std::fs::write(w.bridge().join("bridge.toml"), format!("[aws]\nimage_arn = \"{FAKE_IMAGE_ARN}\"\n")).unwrap();
        w.fake(|s| {
            s.vms.insert(A.into(), vm(A, VmState::Terminated, DAY + 8 * 3600, Some(DAY + 10 * 3600 + 21 * 60 + 10)));
            s.vms.insert(B.into(), vm(B, VmState::Suspended, DAY + 10 * 3600 + 20 * 60 + 30, None));
        });
        w
    }

    fn bridge(&self) -> PathBuf {
        self.tmp.path().join("bridge")
    }

    fn audit_path(&self) -> PathBuf {
        self.bridge().join("audit.jsonl")
    }

    fn fake_path(&self) -> PathBuf {
        self.tmp.path().join("fake.json")
    }

    fn fake(&self, f: impl FnOnce(&mut FakeState)) {
        let mut s = std::fs::read_to_string(self.fake_path()).ok().map_or_else(FakeState::new, |t| serde_json::from_str(&t).unwrap());
        s.auto_advance = true;
        f(&mut s);
        std::fs::write(self.fake_path(), serde_json::to_string_pretty(&s).unwrap()).unwrap();
    }

    /// `ai-env <args>` in this world at `now`, the audit strict, every developer knob dropped.
    fn cmd(&self, now: &str, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_ai-env"));
        c.args(args).stdin(Stdio::null());
        for (k, _) in std::env::vars_os() {
            let k = k.to_string_lossy().to_string();
            if k.starts_with("AI_ENV") || k.starts_with("AWS_") || k.starts_with("PULUMI_") || k.starts_with("CLAUDE_CODE_") || k.starts_with("FAKE_") || k == "RUST_LOG" {
                c.env_remove(&k);
            }
        }
        for k in common::REMOVED_ENV {
            c.env_remove(k);
        }
        c.env("HOME", self.tmp.path())
            .env("AI_ENV_BRIDGE_DIR", self.bridge())
            .env("AI_ENV_DIR", self.tmp.path().join("keys"))
            .env("AI_ENV_BRIDGE_LAB_NOW", now)
            .env("AI_ENV_AUDIT_STRICT", "1");
        if self.fake_path().exists() {
            c.env("AI_ENV_BRIDGE_LAB_FAKE_API", self.fake_path()).env("AI_ENV_BRIDGE_LAB_BACKOFF_MS", "1");
        }
        c
    }

    fn run(&self, now: &str, args: &[&str]) -> Output {
        self.cmd(now, args).output().expect("spawn ai-env")
    }

    fn audit(&self) -> String {
        std::fs::read_to_string(self.audit_path()).unwrap()
    }
}

fn vm(id: &str, state: VmState, started: i64, terminated: Option<i64>) -> VmInfo {
    VmInfo {
        id: id.into(),
        state,
        endpoint: format!("{}.lambda-microvm.eu-central-1.on.aws", &id[8..]),
        image_arn: FAKE_IMAGE_ARN.into(),
        image_version: "1.0".into(),
        started_at_unix: Some(started),
        max_duration_s: 28_800,
        state_reason: None,
        execution_role_arn: None,
        idle: Some(IdleSpec { max_idle_s: 300, suspended_s: 3600, auto_resume: true }),
        ingress: vec![],
        egress: vec![],
        terminated_at_unix: terminated,
    }
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

/// The command's stdout, which must have exited 0.
fn ok(o: &Output) -> String {
    assert_eq!(code(o), 0, "stdout: {}\nstderr: {}", stdout(o), stderr(o));
    stdout(o)
}

fn expected(name: &str) -> String {
    std::fs::read_to_string(Path::new(FIXTURE).join("expected").join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn json(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|e| panic!("not JSON ({e}): {text}"))
}

/// The fixture's audit lines, as stored.
fn fixture_lines() -> Vec<String> {
    std::fs::read_to_string(Path::new(FIXTURE).join("bridge/audit.jsonl")).unwrap().lines().map(str::to_string).collect()
}

/// The events of `vm_observed` rows written after the fixture's (`(id, state, was, via)`).
fn observed(w: &World) -> Vec<(String, String, String, String)> {
    w.audit()
        .lines()
        .skip(fixture_lines().len())
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|r| r["event"] == "vm_observed")
        .map(|r| {
            let d = &r["detail"];
            assert_eq!((r["v"].as_u64(), d["actor"].as_str()), (Some(2), Some("cli")), "{r}");
            let s = |k: &str| d[k].as_str().unwrap().to_string();
            (s("id"), s("state"), s("was"), s("via"))
        })
        .collect()
}

/// `audit tail`: the last N matching rows, oldest first; `--json` prints them as stored; `--session` brings in
/// its VMs' rows inside each generation's span; a raw row (an unknown event) shows as its line; bad flags exit 2.
#[test]
fn audit_tail_filters_json_session_expansion() {
    let w = World::new();
    let lines = fixture_lines();
    let tail = ok(&w.run(NOW, &["audit", "tail", "-n", "3"]));
    let got: Vec<&str> = tail.lines().collect();
    assert_eq!(got.len(), 3, "{tail}");
    assert_eq!(got[0], lines[16], "an unknown event: its stored line");
    assert_eq!(got[1], format!("2026-10-22T13:00:00Z cli vm_observed - {B} state=TERMINATED via=survey was=SUSPENDED"));
    assert_eq!(got[2], "2026-10-22T19:00:00Z cli proxy_stop - - instance=i-0fixture vpc_vms=0", "the cut last line is skipped");
    let session = ok(&w.run(NOW, &["audit", "tail", "--session", S1, "-n", "100", "--json"]));
    let want: Vec<&str> = [5, 6, 7, 8, 9, 11, 12, 13, 15, 17].iter().map(|i| lines[*i].as_str()).collect();
    assert_eq!(session.lines().collect::<Vec<_>>(), want, "its own rows and its VMs' inside each generation's span, as stored");
    let last2 = ok(&w.run(NOW, &["audit", "tail", "--session", S1, "-n", "2", "--json"]));
    assert_eq!(last2.lines().collect::<Vec<_>>(), want[8..]);
    let events = ok(&w.run(NOW, &["audit", "tail", "--event", "vm_run,vm_terminate", "--vm", A, "--json"]));
    assert_eq!(events.lines().collect::<Vec<_>>(), [lines[1].as_str(), lines[14].as_str()]);
    let v1 = ok(&w.run(NOW, &["audit", "tail", "--event", "session_remote_end", "--where", &format!("vm={A}"), "--since", "2026-10-22T08:00:00Z"]));
    assert_eq!(
        v1.lines().collect::<Vec<_>>(),
        [
            format!("2026-10-22T08:30:00Z - session_remote_end 22222222 {A} close_ms=20 end=close exit=0 gen=1 last_acked_seq=7 spawn=spawn-s1"),
            format!("2026-10-22T10:21:08Z wrapper session_remote_end 11111111 {A} close_ms=30 end=moved exit=0 gen=1 last_acked_seq=40 spawn=spawn-s3"),
        ],
        "a v1 row has no actor (`-`)"
    );
    assert_eq!(ok(&w.run(NOW, &["audit", "tail", "--actor", "panel"])), "", "no panel row: nothing, exit 0");
    assert_eq!(ok(&w.run(NOW, &["audit", "tail", "--since", "2h"])), "", "nothing in the last two hours of the day");
    assert_eq!(ok(&w.run(NOW, &["audit", "tail", "--since", "12h", "--json"])).lines().count(), 3, "since noon: the raw row, the observation, the proxy's stop");
    for bad in [&["--session", "nope"][..], &["--vm", "a/b"], &["--where", "novalue"], &["--since", "yesterday"]] {
        let o = w.run(NOW, &[&["audit", "tail"][..], bad].concat());
        assert_eq!(code(&o), 2, "{bad:?}: {}", stderr(&o));
    }
    assert_eq!(w.audit(), std::fs::read_to_string(Path::new(FIXTURE).join("bridge/audit.jsonl")).unwrap(), "reading writes nothing");
}

/// A long-running child killed and reaped when the test ends early (a panic): `Child` does neither on drop.
struct KillOnDrop(Option<std::process::Child>);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if let Some(c) = self.0.as_mut() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// `audit tail -f`: the rows appended after its start as they come (a partial line waits for its newline), the
/// file again from its start once truncated; a stop (Ctrl-C's SIGINT, SIGTERM) ends it with exit 0.
#[test]
fn audit_follow_appends_and_truncation() {
    let w = World::new();
    // The fixture's cut last line, closed first: a junk line, skipped (an append would be glued to it).
    std::fs::OpenOptions::new().append(true).open(w.audit_path()).unwrap().write_all(b"\n").unwrap();
    let mut guard = KillOnDrop(Some(w.cmd(NOW, &["audit", "tail", "-f", "-n", "1", "--json", "--event", "vm_resume,proxy_stop"]).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap()));
    let (tx, rx) = mpsc::channel();
    let out = guard.0.as_mut().unwrap().stdout.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    // Generous bounds: a loaded machine (a gate beside this one) may hold a fresh debug binary for seconds.
    let next = |what: &str| rx.recv_timeout(Duration::from_secs(60)).unwrap_or_else(|e| panic!("{what}: {e}"));
    let row = |n: u32| format!(r#"{{"v":2,"ts":"2026-10-22T20:00:0{n}Z","event":"vm_resume","session_id":null,"pid":{n},"detail":{{"actor":"cli","id":"{B}"}}}}"#);
    let append = |text: &str| std::fs::OpenOptions::new().append(true).open(w.audit_path()).unwrap().write_all(text.as_bytes()).unwrap();
    assert_eq!(next("the last match"), fixture_lines()[18]);
    append(&format!("{}\n", row(1)));
    assert_eq!(next("an appended row"), row(1));
    let two = row(2);
    append(&two[..30]);
    std::thread::sleep(Duration::from_millis(700));
    assert!(rx.try_recv().is_err(), "a partial line is held");
    append(&format!("{}\n{}\n", &two[30..], r#"{"v":2,"ts":"2026-10-22T20:00:03Z","event":"vm_suspend","session_id":null,"pid":3,"detail":{"actor":"cli","id":"x"}}"#));
    assert_eq!(next("the completed row"), two, "the filter still holds: vm_suspend is not shown");
    std::fs::write(w.audit_path(), format!("{}\n", row(4))).unwrap();
    assert_eq!(next("after the truncation"), row(4));
    // SIGTERM, not SIGINT: a background job of a non-interactive shell (a gate run with `&`) ignores SIGINT,
    // and the follow keeps an ignored signal ignored. Both reach the same handler.
    let child = guard.0.take().unwrap();
    // SAFETY: kill(2) of our own child.
    assert_eq!(unsafe { libc::kill(libc::pid_t::try_from(child.id()).unwrap(), libc::SIGTERM) }, 0);
    let out = common::bounded::finish_within(child, Duration::from_secs(60), "audit tail -f");
    assert_eq!(out.status.code(), Some(0), "a stop ends the follow with exit 0: {}", String::from_utf8_lossy(&out.stderr));
}

/// `audit grep`: a fixed string in the rows' one-line form (`-i`: ASCII case), with the filters; exit 1 and
/// nothing printed when none matches.
#[test]
fn audit_grep_exit_1_on_no_match() {
    let w = World::new();
    let none = w.run(NOW, &["audit", "grep", "no-such-thing"]);
    assert_eq!((code(&none), stdout(&none), stderr(&none)), (1, String::new(), String::new()));
    let filtered = w.run(NOW, &["audit", "grep", "suspended", "--actor", "panel"]);
    assert_eq!((code(&filtered), stdout(&filtered)), (1, String::new()), "the filters hold first");
    let hits = ok(&w.run(NOW, &["audit", "grep", "-i", "SUSPENDED"]));
    let events: Vec<&str> = hits.lines().map(|l| l.split(' ').nth(2).unwrap()).collect();
    assert_eq!(events, ["session_unpark", "vm_run", "session_park", "vm_observed"], "vm_run by its suspended_s: {hits}");
    let exact = w.run(NOW, &["audit", "grep", "SUSPENDED"]);
    assert_eq!(ok(&exact).lines().count(), 1, "case matters without -i");
    let raw = ok(&w.run(NOW, &["audit", "grep", "spawn-s4", "--json"]));
    assert_eq!(raw.lines().collect::<Vec<_>>(), [fixture_lines()[12].as_str(), fixture_lines()[15].as_str()], "--json: the matching rows as stored");
    assert_eq!(ok(&w.run(NOW, &["audit", "grep", "frobnicate"])).trim_end(), fixture_lines()[16], "a raw row matches on its line");
}

/// `cost --json` of the fixture's day equals the snapshot; the text names the window, both VMs, the lines and
/// the hint; `--compare` judges a Cost Explorer file; bad windows and files exit 2.
#[test]
fn cost_json_snapshot() {
    let w = World::new();
    let doc = json(&ok(&w.run(NOW, &["cost", "--since", "2026-10-22", "--until", "2026-10-23", "--json"])));
    assert_eq!(doc, json(&expected("cost-2026-10-22.json")));
    assert_eq!(json(&ok(&w.run(NOW, &["cost", "--json"]))), doc, "the default window: the 24 hours to now");
    let text = ok(&w.run(NOW, &["cost", "--since", "2026-10-22", "--until", "2026-10-23"]));
    assert!(text.starts_with("window 2026-10-22T00:00:00Z .. 2026-10-23T00:00:00Z (UTC day; Cost Explorer lags 24–48 h)\n"), "{text}");
    assert!(text.contains("estimate $0.530 (range $0.504–0.557); not counted: S3, CloudWatch, data transfer\n"), "{text}");
    assert!(text.contains(&format!("{A:<46}   1h21m   1h00m      1       2        2    $0.248  2 idle suspends inferred; 1 auto-resume inferred; terminated (migrate)")), "{text}");
    assert!(text.contains("--time-period Start=2026-10-22,End=2026-10-23 "), "{text}");
    assert!(text.ends_with("then: ai-env cost --compare ce.json\n"), "{text}");
    let by_day = json(&ok(&w.run(NOW, &["cost", "--since", "2026-10-21T12:00:00Z", "--until", "2026-10-23", "--by", "day", "--json"])));
    assert_eq!(by_day["days"].as_array().unwrap().iter().map(|d| d["day"].as_str().unwrap()).collect::<Vec<_>>(), ["2026-10-21", "2026-10-22"]);
    assert_eq!(by_day["days"][1]["usd"], doc["usd"], "the second day is the day's estimate");
    let ce = |amount: &str| {
        let path = w.tmp.path().join("ce.json");
        let body = serde_json::json!({
            "GroupDefinitions": [{ "Type": "DIMENSION", "Key": "USAGE_TYPE" }],
            "ResultsByTime": [{ "TimePeriod": { "Start": "2026-10-22", "End": "2026-10-23" }, "Total": {}, "Estimated": false,
                "Groups": [{ "Keys": ["EUC1-Lambda-MicroVM-vCPU-Second-ARM"], "Metrics": { "UnblendedCost": { "Amount": amount, "Unit": "USD" } } }] }]
        });
        std::fs::write(&path, body.to_string()).unwrap();
        path.display().to_string()
    };
    let within = w.run(NOW, &["cost", "--compare", &ce("0.36")]);
    assert!(ok(&within).contains("MicroVM total: estimate $0.388, Cost Explorer $0.360: 7.7 % off: within ±30 %"), "{}", stdout(&within));
    let outside = w.run(NOW, &["cost", "--compare", &ce("0.10"), "--json"]);
    assert_eq!(code(&outside), 1, "outside the band: exit 1");
    let doc = json(&stdout(&outside));
    assert_eq!((doc["compare"]["microvm"]["pass"].as_bool(), doc["since"].as_str()), (Some(false), Some("2026-10-22T00:00:00Z")), "the file's window");
    std::fs::write(w.tmp.path().join("bad.json"), r#"{"GroupDefinitions":[{"Key":"SERVICE"}],"ResultsByTime":[]}"#).unwrap();
    let bad = w.run(NOW, &["cost", "--compare", &w.tmp.path().join("bad.json").display().to_string()]);
    assert_eq!(code(&bad), 2, "{}", stderr(&bad));
    assert!(stderr(&bad).contains("aws ce get-cost-and-usage --region us-east-1"), "{}", stderr(&bad));
    // A FIFO is refused, never waited on; so is a directory.
    let fifo = w.tmp.path().join("ce.fifo");
    let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    // SAFETY: mkfifo(3) of a fresh path in our own temporary directory.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    let (fifo, dir) = (fifo.display().to_string(), w.tmp.path().display().to_string());
    for args in [&["cost", "--since", "2026-10-23", "--until", "2026-10-22"][..], &["cost", "--since", "soon"], &["cost", "--until", "2026-02-30"], &["cost", "--compare", "/nonexistent/ce.json"], &["cost", "--compare", &fifo], &["cost", "--compare", &dir]] {
        let o = w.run(NOW, args);
        assert_eq!(code(&o), 2, "{args:?}: {}", stderr(&o));
    }
}

/// A window that reaches past now ends now: the time after it has not happened (`--until` tomorrow, the natural
/// "today so far"), and the text says so; a window that starts after now is exit 2.
#[test]
fn cost_window_ends_now() {
    let w = World::new();
    let capped = json(&ok(&w.run(NOON, &["cost", "--since", "2026-10-22", "--until", "2026-10-23", "--json"])));
    assert_eq!(capped["until"].as_str(), Some("2026-10-22T11:30:00Z"));
    assert_eq!(capped, json(&ok(&w.run(NOON, &["cost", "--since", "2026-10-22", "--until", "2026-10-22T11:30:00Z", "--json"]))));
    let b = capped["vms"].as_array().unwrap().iter().find(|v| v["id"] == B).unwrap();
    assert_eq!((b["running_s"].as_u64(), b["suspended_s"].as_u64(), b["note"].as_str()), (Some(2370), Some(1800), Some("-")), "B's suspended_s end lies after now: {b}");
    let hours = capped["lines"].as_array().unwrap().iter().find(|l| l["usage_type"] == "EUC1-BoxUsage:t4g.nano").unwrap()["quantity"].as_f64();
    assert_eq!(hours, Some(4.5), "the proxy from 07:00 to now");
    let text = ok(&w.run(NOON, &["cost", "--since", "2026-10-22", "--until", "2026-10-23"]));
    assert!(text.starts_with("window 2026-10-22T00:00:00Z .. 2026-10-22T11:30:00Z (until capped at now)\n"), "{text}");
    let future = w.run(NOON, &["cost", "--since", "2026-10-22T12:00:00Z", "--until", "2026-10-23"]);
    assert_eq!(code(&future), 2, "a window that starts after now: {}", stderr(&future));
    assert!(stderr(&future).contains("is not before now (2026-10-22T11:30:00Z)"), "{}", stderr(&future));
}

/// `session show` of the two-generation remote chat equals its snapshots (text and `--json`); a chat on this
/// Mac has no cost; an unknown session exits 1, a non-uuid 2.
#[test]
fn session_show_snapshot() {
    let w = World::new();
    assert_eq!(ok(&w.run(NOW, &["session", "show", S1])), expected(&format!("session-show-{S1}.txt")));
    let doc = json(&ok(&w.run(NOW, &["session", "show", S1, "--json"])));
    assert_eq!(doc, json(&expected(&format!("session-show-{S1}.json"))));
    assert_eq!((doc["session_id"].as_str(), doc["status"].as_str(), doc["vms"].as_array().map(Vec::len)), (Some(S1), Some("parked"), Some(2)), "the row's own keys first");
    let mac = ok(&w.run(NOW, &["session", "show", S3]));
    assert!(mac.contains("cost       - (a chat on this Mac)\n") && mac.contains("timeline (0)\n"), "{mac}");
    assert_eq!(json(&ok(&w.run(NOW, &["session", "show", S3, "--json"])))["cost"], Value::Null);
    let closed = json(&ok(&w.run(NOW, &["session", "show", S2, "--json"])));
    assert_eq!((closed["cost"]["running_s"].as_u64(), closed["moves"].as_array().map(Vec::len)), (Some(1795), Some(0)));
    assert_eq!(code(&w.run(NOW, &["session", "show", "44444444-4444-4444-8444-444444444444"])), 1);
    assert_eq!(code(&w.run(NOW, &["session", "show", "nope"])), 2);
}

/// `session list` gains each chat's VM, moves and cost at the end of its line; `--json` stays the rows alone.
#[test]
fn session_list_gains_vm_moves_cost() {
    let w = World::new();
    let text = ok(&w.run(NOW, &["session", "list"]));
    assert_eq!(
        text.lines().collect::<Vec<_>>(),
        [
            format!("{S3}  closed  local-child    2026-10-22T15:00:00Z  -tmp-elsewhere  -  0  -"),
            format!("{S1}  parked  remote         2026-10-22T11:00:00Z  -w-project  {B}  1  $0.254"),
            format!("{S2}  closed  remote         2026-10-22T08:30:00Z  -w-project  {A}  0  $0.079"),
        ]
    );
    let rows = json(&ok(&w.run(NOW, &["session", "list", "--json"])));
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 3);
    assert!(rows.iter().all(|r| r.get("session_id").is_some() && r.get("cost").is_none() && r.get("moves").is_none()), "the plain rows");
    // An audit that cannot be read (a symlink, refused): the rows still print, without cost cells, and say why.
    std::fs::rename(w.audit_path(), w.tmp.path().join("elsewhere.jsonl")).unwrap();
    std::os::unix::fs::symlink(w.tmp.path().join("elsewhere.jsonl"), w.audit_path()).unwrap();
    let o = w.run(NOW, &["session", "list"]);
    assert_eq!(
        ok(&o).lines().collect::<Vec<_>>(),
        [
            format!("{S3}  closed  local-child    2026-10-22T15:00:00Z  -tmp-elsewhere  -  0  -"),
            format!("{S1}  parked  remote         2026-10-22T11:00:00Z  -w-project  {B}  1  -"),
            format!("{S2}  closed  remote         2026-10-22T08:30:00Z  -w-project  {A}  0  -"),
        ]
    );
    assert!(stderr(&o).contains("session list: no cost cells: ") && stderr(&o).contains("symlink"), "{}", stderr(&o));
}

/// `vm list` on the fake: RUN and COST after WALL-LEFT (B over its life to 11:30), `--json` items with `cost`.
#[test]
fn vm_list_cost_and_wall_columns() {
    let w = World::with_fake();
    let text = ok(&w.run(NOON, &["vm", "list"]));
    assert_eq!(text, expected("vm-list.txt"));
    let cells: Vec<&str> = text.lines().nth(1).unwrap().split_whitespace().collect();
    assert_eq!((cells[1], cells[3], cells[4], cells[5]), ("SUSPENDED", "6h50m", "39m30s", "$0.119"), "WALL-LEFT stays cells[3]");
    let doc = json(&ok(&w.run(NOON, &["vm", "list", "--json"])));
    let b = doc["vms"].as_array().unwrap().iter().find(|v| v["id"] == B).unwrap();
    assert_eq!(b["cost"], serde_json::json!({ "usd": 0.118955, "running_s": 2370, "suspended_s": 1800, "inferred": false }));
    let all = json(&ok(&w.run(NOON, &["vm", "list", "--all", "--json"])));
    let a = all["vms"].as_array().unwrap().iter().find(|v| v["id"] == A).unwrap();
    assert_eq!((a["state"].as_str(), a["cost"]["running_s"].as_u64(), a["cost"]["inferred"].as_bool()), (Some("TERMINATED"), Some(4870), Some(true)));
    assert!(observed(&w).is_empty(), "no recorded state changed: no vm_observed");
    // `vm gc`'s dry run prices the expired VMs still running (B RUNNING, its wall long passed): B §B3.8.
    w.fake(|s| s.vms.get_mut(B).unwrap().state = VmState::Running);
    let gc = ok(&w.run(NOON, &["vm", "gc"]));
    assert!(gc.contains("\n1 expired VM(s) still run: $0.159 an hour now\n"), "{gc}");
    let doc = json(&ok(&w.run(NOON, &["vm", "gc", "--json"])));
    assert_eq!((doc["expired_running"].as_u64(), doc["expired_usd_per_hour"].as_f64()), (Some(1), Some(0.159_343)));
}

/// A refresh that changes a row's recorded state writes one `vm_observed` (the survey's; `vm status`'s), never
/// for an unchanged state, and the reconcile after the survey adds none for the same change.
#[test]
fn vm_observed_is_written_once_per_change() {
    let w = World::with_fake();
    w.fake(|s| s.vms.get_mut(B).unwrap().state = VmState::Running);
    ok(&w.run(NOON, &["vm", "list"]));
    let first = (B.to_string(), "RUNNING".to_string(), "SUSPENDED".to_string(), "survey".to_string());
    assert_eq!(observed(&w), std::slice::from_ref(&first));
    ok(&w.run(NOON, &["vm", "list", "--json"]));
    assert_eq!(observed(&w), std::slice::from_ref(&first), "unchanged: no second row");
    w.fake(|s| s.vms.get_mut(B).unwrap().state = VmState::Suspended);
    ok(&w.run(NOON, &["vm", "status", B]));
    let second = (B.to_string(), "SUSPENDED".to_string(), "RUNNING".to_string(), "status".to_string());
    assert_eq!(observed(&w), [first.clone(), second.clone()]);
    w.fake(|s| {
        let b = s.vms.get_mut(B).unwrap();
        b.state = VmState::Terminated;
        b.terminated_at_unix = Some(DAY + 12 * 3600);
    });
    let o = w.run(NOON, &["vm", "list", "--all"]);
    ok(&o);
    let third = (B.to_string(), "TERMINATED".to_string(), "SUSPENDED".to_string(), "survey".to_string());
    assert_eq!(observed(&w), [first.clone(), second.clone(), third.clone()], "the survey's row; the reconcile's mark adds none");
    let row = std::fs::read_to_string(w.bridge().join("state/vms").join(format!("{B}.toml"))).unwrap();
    assert!(row.contains("status = \"terminated\"") && row.contains("state_seen = \"TERMINATED\""), "the reconcile marked it: {row}");
    ok(&w.run(NOON, &["vm", "list", "--all"]));
    ok(&w.run(NOON, &["vm", "status", B]));
    assert_eq!(observed(&w), [first, second, third], "a terminated row stays as it is");
}
