//! S11 (A.7, A3): doctor's and `wrapper status`' claude rows: one per
//! version the installed bundle or a live window runs, then the image's
//! fallback note, and the newest remote chat's `claude_src`. Never `[NO ]`:
//! a version VMs cannot run yet leaves chats on what they hold, and no row
//! offers turning Cursor's auto-update off (VMs follow it with no deploy).
use super::{failed_why, version_key, Phase, Record};
use crate::bridge::census::RunningExtension;
use crate::commands::{DoctorLine, Tag};

/// One row per version the installed bundle or a live window runs (newest first), then the image's fallback note.
/// Never `[NO ]`. None when neither a bundle nor a window names a version (LD-36). A version that is the image's
/// own claude, while no other staged version is named before the image's (P4 names those; a VM that holds one runs
/// it), runs everywhere already: `[ok ]` unless its admission failed. The seen row promises automatic admission
/// ([`rows_claude_auto`] with `auto` false never does).
#[must_use]
pub fn rows_claude(records: &[Record], image: Option<&str>, bundle: Option<&str>, running: &[RunningExtension]) -> Vec<DoctorLine> {
    rows_claude_auto(records, image, bundle, running, true)
}

/// [`rows_claude`], the seen row's `(automatic while Docker answers: [claude].auto_admit)` only with `auto`: the
/// caller knows `[claude].auto_admit` is on and the effective mode is remote (automatic admission starts only at a
/// remote wrapper's `auth status --json` and a remote session's P0); without it the row names `ai-env claude admit
/// <v>` alone.
#[must_use]
pub fn rows_claude_auto(records: &[Record], image: Option<&str>, bundle: Option<&str>, running: &[RunningExtension], auto: bool) -> Vec<DoctorLine> {
    let mut versions: Vec<&str> = bundle.into_iter().chain(running.iter().map(|w| w.ext.as_str())).filter(|v| crate::wire::pin::is_version(v)).collect();
    if versions.is_empty() {
        return Vec::new();
    }
    versions.sort_by_key(|v| std::cmp::Reverse(version_key(v)));
    versions.dedup();
    let mut lines: Vec<DoctorLine> = versions.iter().map(|v| row_of(v, records, image, bundle, running, auto)).collect();
    lines.push(DoctorLine::row(Tag::Skip, format!("the image's claude {} runs where no staged version can", image.unwrap_or("unknown"))));
    lines
}

/// The hint of an admitted version not staged yet: `ai-env claude stage <v>`, or what stages it unasked: `vm warm`
/// stages the installed bundle's version (`bundle`) and the prewarm a window's (remote mode only).
#[must_use]
pub fn stage_hint(v: &str, bundle: Option<&str>) -> String {
    if bundle == Some(v) {
        format!("ai-env claude stage {v} (one Touch ID), or the next vm warm or prewarm stages it")
    } else {
        format!("ai-env claude stage {v} (one Touch ID), or the next prewarm of a window on it (remote mode) stages it")
    }
}

/// The row of version `v` (§8's table).
fn row_of(v: &str, records: &[Record], image: Option<&str>, bundle: Option<&str>, running: &[RunningExtension], auto: bool) -> DoctorLine {
    let mut who: Vec<String> = Vec::new();
    if bundle == Some(v) {
        who.push("the Cursor bundle".into());
    }
    who.extend(running.iter().filter(|w| w.ext == v).map(|w| format!("a Cursor window (host pid {})", w.host)));
    let what = who.join(", ");
    let record = records.iter().find(|r| r.version == v);
    let phase = record.map_or(Phase::Seen, Record::phase);
    // The newest other nameable version, else the image's.
    let mut others: Vec<&Record> = records.iter().filter(|r| r.version != v && r.nameable()).collect();
    others.sort_by_key(|r| std::cmp::Reverse(version_key(&r.version)));
    let fallback = others.first().map_or_else(|| format!("the image's {}", image.unwrap_or("claude")), |r| r.version.clone());
    let head = format!("claude {v} ({what})");
    match phase {
        Phase::Staged => DoctorLine::row(Tag::Ok, format!("{head}: admitted and staged; VMs fetch it after a chat's first output")),
        Phase::Failed(step) => {
            let why = record.and_then(failed_why).unwrap_or_else(|| step.clone());
            DoctorLine::row(Tag::Warn, format!("{head}: admission failed at {step} ({why}); chats run {fallback}  <- fix it, then ai-env claude admit {v} --redo"))
        }
        // V not nameable: P4 names the other staged versions, and a VM that holds one runs it before the image's.
        _ if image == Some(v) && others.is_empty() => DoctorLine::row(Tag::Ok, format!("{head}: the image's own claude; chats run it with nothing to fetch")),
        Phase::Admitted => DoctorLine::row(Tag::Warn, format!("{head}: admitted, not staged; chats run {fallback}  <- {}", stage_hint(v, bundle))),
        Phase::Stale => DoctorLine::row(Tag::Warn, format!("{head}: a VM refused its S3 object, which was deleted; chats run {fallback}  <- ai-env claude stage {v}")),
        Phase::Signed => DoctorLine::row(Tag::Warn, format!("{head}: signed, its Docker tests not run; chats run {fallback}  <- ai-env claude admit {v}")),
        Phase::Seen if auto => DoctorLine::row(Tag::Warn, format!("{head}: not admitted yet; chats run {fallback}  <- ai-env claude admit {v} (automatic while Docker answers: [claude].auto_admit)")),
        Phase::Seen => DoctorLine::row(Tag::Warn, format!("{head}: not admitted yet; chats run {fallback}  <- ai-env claude admit {v}")),
    }
}

/// The newest remote end row's `claude`, `claude_src` and `argv_dropped` (`wrapper status`): `[ok ]` for `cached` or
/// `image`; `[!! ]` for `older(…)` or `image(…)` (with `ai-env claude status` as the hint) and for a chat that
/// dropped a flag; `[-  ]` while no remote chat has ended with a `claude_src` part.
#[must_use]
pub fn row_last_claude(rows: &[serde_json::Value]) -> DoctorLine {
    let part = |row: &serde_json::Value, name: &str| -> Option<String> {
        let prefix = format!("{name}:");
        row.get("note")?.as_str()?.split("; ").find_map(|p| p.strip_prefix(&prefix)).map(str::to_string)
    };
    let src = crate::bridge::remote::census_part::CLAUDE_SRC;
    let newest = rows
        .iter()
        .filter(|r| r.get("route").and_then(serde_json::Value::as_str) == Some("remote") && r.get("end").is_some_and(|e| !e.is_null()) && part(r, src).is_some())
        .max_by_key(|r| (r.get("end").and_then(serde_json::Value::as_u64), r.get("start").and_then(serde_json::Value::as_u64)));
    let Some(row) = newest else {
        return DoctorLine::row(Tag::Skip, "no remote chat has ended with a claude_src part yet");
    };
    let claude_src = part(row, src).unwrap_or_default();
    let claude = part(row, crate::bridge::remote::census_part::CLAUDE).unwrap_or_else(|| "unknown".into());
    let dropped = part(row, crate::bridge::remote::census_part::ARGV_DROPPED);
    let mut text = format!("the newest remote chat ran claude {claude} ({claude_src})");
    if let Some(flags) = &dropped {
        text.push_str(&format!("; it dropped {flags}"));
    }
    let fell_back = claude_src != "cached" && claude_src != "image";
    if fell_back {
        text.push_str("  <- ai-env claude status");
    }
    DoctorLine::row(if fell_back || dropped.is_some() { Tag::Warn } else { Tag::Ok }, text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::claude::tests::put;
    use crate::bridge::config::Paths;

    fn text(l: &DoctorLine) -> (Tag, String) {
        match l {
            DoctorLine::Row { tag, text } => (*tag, text.clone()),
            other => panic!("not a row: {other:?}"),
        }
    }

    fn window(host: u32, ext: &str) -> RunningExtension {
        RunningExtension { host, ext: ext.into(), started: 1_700_000_000, seen: 1_700_000_060_000 }
    }

    /// §8's table: one row per version the bundle or a window runs, newest first, each phase's tag and text, the
    /// fallback (the newest other nameable version, else the image's), then the image's note; never `[NO ]`; none
    /// without a bundle or a window.
    #[test]
    fn rows_claude_say_seen_failed_admitted_staged_never_no() {
        let dir = tempfile::tempdir().unwrap();
        let p = Paths::from_root_and_env(dir.path().join("bridge"), None);
        for (v, c, phase) in [("2.1.307", 'b', "signed"), ("2.1.308", 'c', "admitted"), ("2.1.309", 'd', "failed"), ("2.1.310", 'e', "staged"), ("2.1.311", 'f', "stale")] {
            put(&p, v, c, phase);
        }
        let records = crate::bridge::claude::load_all(&p);
        let running = [window(4101, "2.1.311"), window(4102, "2.1.309"), window(4103, "2.1.308"), window(4104, "2.1.307"), window(4105, "unrecognised"), window(4106, "2.1.311")];
        let lines: Vec<(Tag, String)> = rows_claude(&records, Some("2.1.305"), Some("2.1.312"), &running).iter().map(text).collect();
        let want: Vec<(Tag, String)> = vec![
            (Tag::Warn, "claude 2.1.312 (the Cursor bundle): not admitted yet; chats run 2.1.310  <- ai-env claude admit 2.1.312 (automatic while Docker answers: [claude].auto_admit)".into()),
            (Tag::Warn, "claude 2.1.311 (a Cursor window (host pid 4101), a Cursor window (host pid 4106)): a VM refused its S3 object, which was deleted; chats run 2.1.310  <- ai-env claude stage 2.1.311".into()),
            (Tag::Warn, "claude 2.1.309 (a Cursor window (host pid 4102)): admission failed at markers (missing:auto_mode); chats run 2.1.310  <- fix it, then ai-env claude admit 2.1.309 --redo".into()),
            (Tag::Warn, "claude 2.1.308 (a Cursor window (host pid 4103)): admitted, not staged; chats run 2.1.310  <- ai-env claude stage 2.1.308 (one Touch ID), or the next prewarm of a window on it (remote mode) stages it".into()),
            (Tag::Warn, "claude 2.1.307 (a Cursor window (host pid 4104)): signed, its Docker tests not run; chats run 2.1.310  <- ai-env claude admit 2.1.307".into()),
            (Tag::Skip, "the image's claude 2.1.305 runs where no staged version can".into()),
        ];
        assert_eq!(lines, want);
        // The staged one, run by the bundle and a window; no other nameable version: the image's is the fallback.
        let lines: Vec<(Tag, String)> = rows_claude(&records, None, Some("2.1.310"), &[window(4107, "2.1.310"), window(4108, "2.1.308")]).iter().map(text).collect();
        assert_eq!(lines[0], (Tag::Ok, "claude 2.1.310 (the Cursor bundle, a Cursor window (host pid 4107)): admitted and staged; VMs fetch it after a chat's first output".into()));
        assert!(lines[1].1.ends_with("chats run 2.1.310  <- ai-env claude stage 2.1.308 (one Touch ID), or the next prewarm of a window on it (remote mode) stages it"), "{lines:?}");
        // `vm warm` stages the bundle's version only (T4).
        let bundled: Vec<(Tag, String)> = rows_claude(&records, None, Some("2.1.308"), &[]).iter().map(text).collect();
        assert_eq!(bundled[0], (Tag::Warn, "claude 2.1.308 (the Cursor bundle): admitted, not staged; chats run 2.1.310  <- ai-env claude stage 2.1.308 (one Touch ID), or the next vm warm or prewarm stages it".into()));
        assert_eq!(lines[2], (Tag::Skip, "the image's claude unknown runs where no staged version can".into()));
        let only: Vec<(Tag, String)> = rows_claude(&[], Some("2.1.305"), Some("2.1.306"), &[]).iter().map(text).collect();
        assert!(only[0].1.contains("not admitted yet; chats run the image's 2.1.305  <- "), "{only:?}");
        // The image's own claude: nothing to fetch, unless its admission failed, or another staged version is
        // named before the image's (T2: a VM that holds 2.1.310 runs it, so the phase's row stands).
        let unstaged: Vec<Record> = records.iter().filter(|r| !r.nameable()).cloned().collect();
        let none: &[Record] = &[];
        for phase_records in [&unstaged[..], none] {
            let own: Vec<(Tag, String)> = rows_claude(phase_records, Some("2.1.308"), Some("2.1.308"), &[]).iter().map(text).collect();
            assert_eq!(own[0], (Tag::Ok, "claude 2.1.308 (the Cursor bundle): the image's own claude; chats run it with nothing to fetch".into()));
        }
        let own: Vec<(Tag, String)> = rows_claude(&records, Some("2.1.308"), Some("2.1.308"), &[]).iter().map(text).collect();
        assert_eq!(own[0], (Tag::Warn, "claude 2.1.308 (the Cursor bundle): admitted, not staged; chats run 2.1.310  <- ai-env claude stage 2.1.308 (one Touch ID), or the next vm warm or prewarm stages it".into()));
        let seen: Vec<(Tag, String)> = rows_claude(&records, Some("2.1.306"), Some("2.1.306"), &[]).iter().map(text).collect();
        assert_eq!(seen[0], (Tag::Warn, "claude 2.1.306 (the Cursor bundle): not admitted yet; chats run 2.1.310  <- ai-env claude admit 2.1.306 (automatic while Docker answers: [claude].auto_admit)".into()));
        assert_eq!(text(&rows_claude(&records, Some("2.1.309"), Some("2.1.309"), &[])[0]).0, Tag::Warn);
        assert_eq!(text(&rows_claude(&unstaged, Some("2.1.309"), Some("2.1.309"), &[])[0]).0, Tag::Warn, "failed, whatever else is staged");
        // No automatic admission (off, or not remote): the seen row names the command alone (T6).
        let manual: Vec<(Tag, String)> = rows_claude_auto(&records, Some("2.1.305"), Some("2.1.312"), &running, false).iter().map(text).collect();
        assert_eq!(manual[0], (Tag::Warn, "claude 2.1.312 (the Cursor bundle): not admitted yet; chats run 2.1.310  <- ai-env claude admit 2.1.312".into()));
        assert_eq!(manual[1..], want[1..], "only the seen row differs");
        // Never `[NO ]`; nothing without a version.
        for l in rows_claude(&records, Some("2.1.305"), Some("2.1.312"), &running) {
            assert!(!l.is_no(), "{:?}", text(&l));
        }
        assert!(rows_claude(&records, Some("2.1.305"), None, &[]).is_empty());
        assert!(rows_claude(&records, Some("2.1.305"), None, &[window(1, "unrecognised")]).is_empty());
    }

    /// No row offers turning Cursor's auto-update off: VMs follow its claude with no deploy.
    #[test]
    fn no_text_offers_auto_update() {
        let dir = tempfile::tempdir().unwrap();
        let p = Paths::from_root_and_env(dir.path().join("bridge"), None);
        for (v, c, phase) in [("2.1.306", 'a', "seen"), ("2.1.307", 'b', "signed"), ("2.1.308", 'c', "admitted"), ("2.1.309", 'd', "failed"), ("2.1.310", 'e', "staged"), ("2.1.311", 'f', "stale")] {
            put(&p, v, c, phase);
        }
        let records = crate::bridge::claude::load_all(&p);
        let running: Vec<RunningExtension> = ["2.1.306", "2.1.307", "2.1.308", "2.1.309", "2.1.310", "2.1.311"].iter().zip(1..).map(|(v, h)| window(h, v)).collect();
        let mut texts: Vec<String> = rows_claude(&records, Some("2.1.305"), Some("2.1.312"), &running).iter().map(|l| text(l).1).collect();
        let census = |src: &str| serde_json::json!({"route": "remote", "start": 1, "end": 2, "note": format!("end:exit; claude:2.1.305; claude_src:{src}; argv_dropped:--x")});
        for src in ["cached", "image", "older(not_cached)", "image(no_cap)"] {
            texts.push(text(&row_last_claude(&[census(src)])).1);
        }
        let lower = texts.join("\n").to_lowercase();
        for banned in ["auto update", "auto-update", "autoupdate", "make claude-update", "disable"] {
            assert!(!lower.contains(banned), "{banned}: {texts:?}");
        }
    }

    /// `wrapper status`' row: the newest remote end row with a `claude_src` part, its `claude` and dropped flags.
    #[test]
    fn row_last_claude_names_the_newest_end_rows_claude() {
        let row = |start: u64, end: Option<u64>, route: &str, note: &str| serde_json::json!({"route": route, "start": start, "end": end, "note": note});
        assert_eq!(text(&row_last_claude(&[])), (Tag::Skip, "no remote chat has ended with a claude_src part yet".into()));
        let s10 = row(1, Some(2), "remote", "end:exit; vm:microvm-1; claude:2.1.305");
        let start_row = row(9, None, "remote", "mode:remote; claude_src:cached");
        assert_eq!(text(&row_last_claude(&[s10.clone(), start_row.clone()])).0, Tag::Skip, "an S10 end row and a start row name none");
        let cached = row(3, Some(4), "remote", "end:exit; vm:microvm-1; claude:2.1.310; claude_src:cached; legs:select=1");
        let older = row(5, Some(6), "remote", "end:exit; claude:2.1.309; claude_src:older(not_cached); argv_dropped:--x,--y");
        let local = row(7, Some(8), "local", "end:exit; claude:2.1.300; claude_src:image(no_ext)");
        assert_eq!(text(&row_last_claude(&[cached.clone(), s10.clone(), local.clone()])), (Tag::Ok, "the newest remote chat ran claude 2.1.310 (cached)".into()));
        assert_eq!(text(&row_last_claude(&[older.clone(), cached.clone(), start_row])), (Tag::Warn, "the newest remote chat ran claude 2.1.309 (older(not_cached)); it dropped --x,--y  <- ai-env claude status".into()));
        let image = row(11, Some(12), "remote", "end:exit; claude:2.1.305; claude_src:image(seen)");
        assert_eq!(text(&row_last_claude(&[older, image])), (Tag::Warn, "the newest remote chat ran claude 2.1.305 (image(seen))  <- ai-env claude status".into()));
        let dropped = row(13, Some(14), "remote", "end:exit; claude:2.1.310; claude_src:image; argv_dropped:--x");
        assert_eq!(text(&row_last_claude(&[dropped])), (Tag::Warn, "the newest remote chat ran claude 2.1.310 (image); it dropped --x".into()));
        let unknown = row(15, Some(16), "remote", "end:spawn_failed; claude_src:image(no_ext)");
        assert_eq!(text(&row_last_claude(&[unknown])).1, "the newest remote chat ran claude unknown (image(no_ext))  <- ai-env claude status");
    }
}
