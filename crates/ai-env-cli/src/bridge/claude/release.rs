//! S11 (A.1, A2): the release's trust: a version's `manifest.json` and its
//! signature fetched from the release bucket (curl with a cleared
//! environment), verified by gpgv against the vendored key
//! (`certs/claude-code-release.gpg`, its primary fingerprint
//! `wire::pin::RELEASE_KEY_FPR`), and the linux-arm64 pin read from it.
//! Fail-closed everywhere: an unknown status keyword, a missing exit line, a
//! signature by any other key or a manifest of another version verifies
//! nothing. Under the fake API (every test rig) the real curl and gpgv are
//! never the fallback: their lab knobs must be set.
use crate::bridge::config::Paths;
use crate::bridge::lab::VmKnobs;
use crate::wire::pin::{RELEASE_KEY_FPR, PLATFORM};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// The vendored release key (`gpg --dearmor` of `claude-code-release.asc`): the only keyring gpgv is given.
pub const RELEASE_KEYRING: &[u8] = include_bytes!("../../../certs/claude-code-release.gpg");
/// How long the manifest's and the signature's curl may each take.
pub const FETCH_MAX_TIME_S: u32 = 60;
/// The most the manifest's and the signature's curl may each write (`--max-filesize`): both are read whole before
/// gpgv judges them (a release's are a few KiB).
pub const MANIFEST_MAX_BYTES: u64 = 1 << 20;
/// How long gpgv may take (LD-16).
pub const GPGV_BOUND: Duration = Duration::from_secs(30);
/// The bound of one release curl beyond its own `--max-time` (a curl that never ends).
const CURL_GRACE: Duration = Duration::from_secs(10);
/// The darwin platform whose checksum is recorded only.
const DARWIN: &str = "darwin-arm64";

/// What a verified release manifest gives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// `manifest.json`'s and `manifest.json.sig`'s bytes.
    pub json: Vec<u8>,
    pub sig: Vec<u8>,
    pub manifest_sha256: String,
    /// VALIDSIG's last field: `RELEASE_KEY_FPR`.
    pub signer: String,
    /// The linux-arm64 pin (`imagepin::pin_from_manifest(json, PLATFORM)`).
    pub linux: crate::wire::pin::ClaudePin,
    /// The darwin-arm64 checksum, recorded only.
    pub darwin_sha256: Option<String>,
}

/// Why a manifest is not verified, each with its word: `Signature`, `Manifest` and `Version` are recorded (the
/// record's `signature.why`); `Fetch` and `Gpgv` may pass again and record nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseError {
    /// curl failed for the manifest or the signature (`fetch`).
    Fetch(String),
    /// gpgv is missing, or did not answer within 30 s (`gpgv`).
    Gpgv(String),
    /// `status_ok`'s word.
    Signature(&'static str),
    /// The JSON or its linux-arm64 entry (`manifest`).
    Manifest(String),
    /// The manifest is another version's (`version`).
    Version(String),
}

impl ReleaseError {
    /// The word a record or an audit row carries: `fetch`, `gpgv`, the signature's word, `manifest`, `version`.
    #[must_use]
    pub fn word(&self) -> &'static str {
        match self {
            ReleaseError::Fetch(_) => "fetch",
            ReleaseError::Gpgv(_) => "gpgv",
            ReleaseError::Signature(w) => w,
            ReleaseError::Manifest(_) => "manifest",
            ReleaseError::Version(_) => "version",
        }
    }

    /// `Fetch` and `Gpgv`: may pass again, nothing recorded (exit 1); the others are refusals (exit 9).
    #[must_use]
    pub fn may_pass_again(&self) -> bool {
        matches!(self, ReleaseError::Fetch(_) | ReleaseError::Gpgv(_))
    }
}

impl std::fmt::Display for ReleaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReleaseError::Fetch(m) | ReleaseError::Gpgv(m) | ReleaseError::Manifest(m) | ReleaseError::Version(m) => write!(f, "{m}"),
            ReleaseError::Signature(w) => write!(f, "the release manifest's signature is not the release key's ({w})"),
        }
    }
}

/// The status keywords that refuse a signature, in the order of their words (rule 3).
const DISQUALIFYING: [&str; 12] = ["BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "NO_PUBKEY", "NODATA", "UNEXPECTED", "BADARMOR", "FAILURE", "KEYEXPIRED", "KEYREVOKED"];
/// The informational keywords, ignored (`TRUST_*` by its prefix).
const INFORMATIONAL: [&str; 4] = ["NEWSIG", "KEY_CONSIDERED", "SIG_ID", "VERIFICATION_COMPLIANCE_MODE"];

/// The word of a disqualifying keyword (rule 3; `NO_PUBKEY` is rule 2's).
fn disqualifying_word(keyword: &str) -> &'static str {
    match keyword {
        "BADSIG" => "bad",
        "ERRSIG" => "errsig",
        "EXPSIG" | "EXPKEYSIG" | "KEYEXPIRED" => "expired",
        "REVKEYSIG" | "KEYREVOKED" => "revoked",
        "NODATA" | "UNEXPECTED" | "BADARMOR" => "nodata",
        "NO_PUBKEY" => "no_pubkey",
        _ => "failure",
    }
}

/// gpgv's status lines judged (pure): `Ok(the primary fingerprint)` only when one NEWSIG block holds a GOODSIG and a
/// VALIDSIG whose last field (uppercased) is `RELEASE_KEY_FPR`, no line anywhere is a disqualifying keyword or an
/// unknown one, and gpgv exited 0 (its caller appends that to gpgv's stdout as a last line `exit=<n>`); else
/// `Err(word)`, the first rule that applies: (1) a line that is neither `[GNUPG:] <KEYWORD> …` nor the last
/// `exit=<n>`, no `exit=` line, or an unknown keyword: `failure`; (2) `NO_PUBKEY` anywhere: `no_pubkey`; (3) the
/// first other disqualifying line: `bad`, `errsig`, `expired`, `revoked`, `nodata`, `failure`; (4) an exit other
/// than 0: `gpgv_exit`; (5) no block with a GOODSIG and a VALIDSIG: `no_goodsig`; (6) none whose VALIDSIG names the
/// pinned primary last: `wrong_key`. Empty lines are skipped.
pub fn status_ok(lines: &str) -> Result<String, &'static str> {
    let lines: Vec<&str> = lines.lines().map(|l| l.trim_end_matches('\r')).filter(|l| !l.trim().is_empty()).collect();
    // (1) The shape: status lines, then the caller's one `exit=<n>` line, last.
    let Some((last, status)) = lines.split_last() else {
        return Err("failure");
    };
    let Some(code) = last.strip_prefix("exit=").filter(|c| !c.is_empty() && c.bytes().all(|b| b.is_ascii_digit())).and_then(|c| c.parse::<u32>().ok()) else {
        return Err("failure");
    };
    let mut parsed: Vec<(&str, Vec<&str>)> = Vec::with_capacity(status.len());
    for line in status {
        let Some(rest) = line.strip_prefix("[GNUPG:] ") else {
            return Err("failure");
        };
        let mut words = rest.split(' ').filter(|w| !w.is_empty());
        let Some(keyword) = words.next() else {
            return Err("failure");
        };
        let known = DISQUALIFYING.contains(&keyword) || INFORMATIONAL.contains(&keyword) || keyword.starts_with("TRUST_") || keyword == "GOODSIG" || keyword == "VALIDSIG";
        if !known || !keyword.bytes().all(|b| b.is_ascii_uppercase() || b == b'_') {
            return Err("failure");
        }
        parsed.push((keyword, words.collect()));
    }
    // (2) NO_PUBKEY anywhere.
    if parsed.iter().any(|(k, _)| *k == "NO_PUBKEY") {
        return Err("no_pubkey");
    }
    // (3) The first other disqualifying line, in gpgv's order.
    if let Some((k, _)) = parsed.iter().find(|(k, _)| DISQUALIFYING.contains(k)) {
        return Err(disqualifying_word(k));
    }
    // (4) gpgv's own verdict.
    if code != 0 {
        return Err("gpgv_exit");
    }
    // (5) and (6): per NEWSIG block (the lines before the first NEWSIG are a block of their own).
    let mut blocks: Vec<Vec<&(&str, Vec<&str>)>> = vec![Vec::new()];
    for entry in &parsed {
        if entry.0 == "NEWSIG" {
            blocks.push(Vec::new());
        } else if let Some(b) = blocks.last_mut() {
            b.push(entry);
        }
    }
    let mut good = false;
    for block in &blocks {
        let goodsig = block.iter().any(|(k, _)| *k == "GOODSIG");
        let validsigs: Vec<&Vec<&str>> = block.iter().filter(|(k, _)| *k == "VALIDSIG").map(|(_, w)| w).collect();
        if !goodsig || validsigs.is_empty() {
            continue;
        }
        good = true;
        if let Some(primary) = validsigs.iter().filter_map(|w| w.last()).map(|f| f.to_ascii_uppercase()).find(|f| f == RELEASE_KEY_FPR) {
            return Ok(primary);
        }
    }
    Err(if good { "wrong_key" } else { "no_goodsig" })
}

/// gpgv: the lab knob's program, else `/opt/homebrew/bin/gpgv`, else `/usr/local/bin/gpgv`; never PATH.
#[must_use]
pub fn gpgv_path(knobs: &VmKnobs) -> Option<PathBuf> {
    if let Ok(Some(knob)) = knobs.gpgv() {
        return Some(knob);
    }
    ["/opt/homebrew/bin/gpgv", "/usr/local/bin/gpgv"].into_iter().map(PathBuf::from).find(|p| p.is_file())
}

/// The release curl: the lab knob's program, else `/usr/bin/curl`.
#[must_use]
pub fn release_curl(knobs: &VmKnobs) -> PathBuf {
    knobs.release_curl().ok().flatten().unwrap_or_else(|| PathBuf::from("/usr/bin/curl"))
}

/// The programs a release step runs, by their lab knobs' names (`VM_KNOBS`' S11 three).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabProgram {
    Curl,
    Gpgv,
    Make,
}

impl LabProgram {
    fn knob(self) -> &'static str {
        match self {
            LabProgram::Curl => crate::bridge::lab::VM_KNOBS[8],
            LabProgram::Gpgv => crate::bridge::lab::VM_KNOBS[9],
            LabProgram::Make => crate::bridge::lab::VM_KNOBS[10],
        }
    }

    fn of(self, knobs: &VmKnobs) -> Result<Option<PathBuf>, String> {
        match self {
            LabProgram::Curl => knobs.release_curl(),
            LabProgram::Gpgv => knobs.gpgv(),
            LabProgram::Make => knobs.admit_make(),
        }
    }
}

/// The lab rule (§6.3): every knob of `needs` valid when set, and, under the fake API, set: the real programs are
/// never the fallback in a test rig. `Err` names the knob (exit 1, nothing run or recorded).
pub fn lab_programs(knobs: &VmKnobs, needs: &[LabProgram]) -> Result<(), String> {
    for p in needs {
        match p.of(knobs)? {
            Some(_) => {}
            None if knobs.fake_api.is_some() => {
                return Err(format!("under {} the real program is never run: set {} (an absolute path to an executable)", crate::bridge::lab::VM_KNOBS[0], p.knob()));
            }
            None => {}
        }
    }
    Ok(())
}

/// The release curl, strictly: the lab rule first ([`lab_programs`]).
fn curl_program(knobs: &VmKnobs) -> Result<PathBuf, ReleaseError> {
    lab_programs(knobs, &[LabProgram::Curl]).map_err(ReleaseError::Fetch)?;
    Ok(release_curl(knobs))
}

/// gpgv, strictly: the lab rule first, then [`gpgv_path`].
fn gpgv_program(knobs: &VmKnobs) -> Result<PathBuf, ReleaseError> {
    lab_programs(knobs, &[LabProgram::Gpgv]).map_err(ReleaseError::Gpgv)?;
    gpgv_path(knobs).ok_or_else(|| ReleaseError::Gpgv("no gpgv at /opt/homebrew/bin/gpgv or /usr/local/bin/gpgv (never PATH's): brew install gnupg".into()))
}

/// A command with a cleared environment but `PATH=/usr/bin:/bin` and `LC_ALL=C`: no `.curlrc` path, no proxy
/// variable, no `GNUPGHOME`.
fn bare(program: &Path) -> Command {
    let mut cmd = Command::new(program);
    cmd.env_clear().env("PATH", "/usr/bin:/bin").env("LC_ALL", "C");
    cmd
}

/// The release curl's argv for `url` into `out`: `-q` first (no `.curlrc`), https only, TLS 1.2 or later, failing
/// on an HTTP error, `--max-time`; `max_filesize` adds `--max-filesize` (the binary's signed size; the manifest's
/// and the signature's [`MANIFEST_MAX_BYTES`]).
#[must_use]
pub fn curl_args(url: &str, out: &Path, max_time_s: u32, max_filesize: Option<u64>) -> Vec<String> {
    let mut args: Vec<String> = ["-q", "--proto", "=https", "--tlsv1.2", "-fsSL", "--max-time"].map(str::to_string).to_vec();
    args.push(max_time_s.to_string());
    if let Some(size) = max_filesize {
        args.push("--max-filesize".into());
        args.push(size.to_string());
    }
    args.push("-o".into());
    args.push(out.display().to_string());
    args.push(url.to_string());
    args
}

/// One release curl (§3.2): `url` into `out`, within `max_time_s` (and a grace). `Err` names the URL (public), the
/// exit and curl's first error line.
pub fn fetch(knobs: &VmKnobs, url: &str, out: &Path, max_time_s: u32, max_filesize: Option<u64>) -> Result<(), ReleaseError> {
    let curl = curl_program(knobs)?;
    let mut cmd = bare(&curl);
    cmd.args(curl_args(url, out, max_time_s, max_filesize));
    let bound = Duration::from_secs(u64::from(max_time_s)) + CURL_GRACE;
    let got = crate::bridge::doctor::capture(cmd, None, bound).map_err(|e| ReleaseError::Fetch(format!("{url}: {e}")))?;
    if got.success {
        return Ok(());
    }
    let line = got.stderr.lines().map(str::trim).find(|l| !l.is_empty()).map(|l| crate::wire::redact::scrub(l).into_owned()).unwrap_or_default();
    let code = got.code.map_or_else(|| "a signal".to_string(), |c| c.to_string());
    Err(ReleaseError::Fetch(format!("{url}: curl exit {code}{}", if line.is_empty() { String::new() } else { format!(": {line}") })))
}

/// gpgv on `sig` over `data` against the vendored key alone (LD-16): a temp `--homedir` (0700) and an absolute
/// 0600 copy of the keyring in it, the environment cleared but `PATH` and `LC_ALL`, [`GPGV_BOUND`]. Its stdout
/// with `exit=<n>` appended, judged by [`status_ok`].
fn gpgv(knobs: &VmKnobs, work: &Path, sig: &Path, data: &Path) -> Result<String, ReleaseError> {
    use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
    let program = gpgv_program(knobs)?;
    let home = work.join("gnupg");
    std::fs::DirBuilder::new().mode(0o700).create(&home).map_err(|e| ReleaseError::Gpgv(format!("cannot make gpgv's home {}: {e}", home.display())))?;
    let keyring = home.join("release.gpg");
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&keyring).map_err(|e| ReleaseError::Gpgv(format!("cannot write {}: {e}", keyring.display())))?;
    std::io::Write::write_all(&mut f, RELEASE_KEYRING).map_err(|e| ReleaseError::Gpgv(format!("cannot write {}: {e}", keyring.display())))?;
    drop(f);
    let mut cmd = bare(&program);
    cmd.arg("--status-fd").arg("1").arg("--homedir").arg(&home).arg("--keyring").arg(&keyring).arg(sig).arg(data);
    let got = crate::bridge::doctor::capture(cmd, None, GPGV_BOUND).map_err(|e| ReleaseError::Gpgv(format!("gpgv ({}): {e}", program.display())))?;
    let Some(code) = got.code else {
        return Err(ReleaseError::Gpgv(format!("gpgv ({}) ended on a signal", program.display())));
    };
    let mut lines = got.stdout;
    if !lines.is_empty() && !lines.ends_with('\n') {
        lines.push('\n');
    }
    lines.push_str(&format!("exit={code}\n"));
    status_ok(&lines).map_err(ReleaseError::Signature)
}

/// The darwin-arm64 checksum the manifest names, when it names one.
fn darwin_checksum(json: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let sum = v.get("platforms")?.get(DARWIN)?.get("checksum")?.as_str()?;
    (sum.len() == 64 && sum.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))).then(|| sum.to_string())
}

/// `version`'s manifest and signature fetched, gpgv on them, `status_ok`, the pin read and its version `version`.
pub fn verified_manifest(paths: &Paths, knobs: &VmKnobs, version: &str) -> Result<Verified, ReleaseError> {
    use sha2::Digest as _;
    let _ = paths;
    if !crate::wire::pin::is_version(version) {
        return Err(ReleaseError::Version(format!("not a claude version (N.N.N): {version:?}")));
    }
    // Both programs are settled before anything is fetched: a missing gpgv fetches nothing.
    curl_program(knobs)?;
    gpgv_program(knobs)?;
    let work = tempfile::Builder::new().prefix("ai-env-claude-release-").tempdir().map_err(|e| ReleaseError::Fetch(format!("cannot make a temp dir: {e}")))?;
    let (json_path, sig_path) = (work.path().join("manifest.json"), work.path().join("manifest.json.sig"));
    fetch(knobs, &crate::wire::pin::manifest_url(version), &json_path, FETCH_MAX_TIME_S, Some(MANIFEST_MAX_BYTES))?;
    fetch(knobs, &crate::wire::pin::sig_url(version), &sig_path, FETCH_MAX_TIME_S, Some(MANIFEST_MAX_BYTES))?;
    // Read only within the cap (a curl that wrote past it is a fetch that may pass again, never a refusal).
    let read = |p: &Path| {
        let len = std::fs::metadata(p).map_err(|e| ReleaseError::Fetch(format!("cannot read the fetched {}: {e}", p.display())))?.len();
        if len > MANIFEST_MAX_BYTES {
            return Err(ReleaseError::Fetch(format!("the fetched {} is {len} bytes, over {MANIFEST_MAX_BYTES}", p.display())));
        }
        std::fs::read(p).map_err(|e| ReleaseError::Fetch(format!("cannot read the fetched {}: {e}", p.display())))
    };
    let (json, sig) = (read(&json_path)?, read(&sig_path)?);
    let signer = gpgv(knobs, work.path(), &sig_path, &json_path)?;
    // The callers name the version (`claude <v>: …`): these texts do not.
    let text = std::str::from_utf8(&json).map_err(|_| ReleaseError::Manifest("the manifest is not UTF-8".into()))?;
    let linux = crate::bridge::imagepin::pin_from_manifest(text, PLATFORM).map_err(|e| ReleaseError::Manifest(e.to_string()))?;
    if linux.version != version {
        return Err(ReleaseError::Version(format!("the signed manifest is for version {}, not {version}", linux.version)));
    }
    let manifest_sha256 = hex::encode(sha2::Sha256::digest(&json));
    Ok(Verified { darwin_sha256: darwin_checksum(text), json, sig, manifest_sha256, signer, linux })
}

/// `ai-env claude manifest <v> --out DIR` (hidden; `make claude-pin`): `DIR/manifest.json` and
/// `DIR/manifest.json.sig` (0644, each written atomically) only once verified; nothing is written otherwise. Exit
/// 1 for a fetch, no gpgv or a lab run without its knobs; 9 for a refused signature or manifest.
pub fn cmd_manifest(version: &str, out: &Path) -> crate::errors::Result<()> {
    use crate::errors::CliError;
    if !crate::wire::pin::is_version(version) {
        return Err(CliError::Usage(format!("not a claude version (N.N.N): {version:?}")));
    }
    let paths = Paths::resolve()?;
    let knobs = crate::bridge::lab::vm_knobs();
    lab_programs(&knobs, &[LabProgram::Curl, LabProgram::Gpgv]).map_err(|e| CliError::Msg(format!("claude manifest {version}: {e}")))?;
    let verified = match verified_manifest(&paths, &knobs, version) {
        Ok(v) => v,
        Err(e) if e.may_pass_again() => return Err(CliError::Msg(format!("claude manifest {version}: {e}: nothing written"))),
        Err(e) => return Err(CliError::Policy(format!("claude {version}: {e}: nothing written"))),
    };
    std::fs::create_dir_all(out).map_err(|e| CliError::Msg(format!("cannot make {}: {e}", out.display())))?;
    crate::bridge::infra::write_atomic_mode(&out.join("manifest.json"), &verified.json, 0o644)?;
    crate::bridge::infra::write_atomic_mode(&out.join("manifest.json.sig"), &verified.sig, 0o644)?;
    crate::outln!("claude {version}: the release manifest's signature is the release key's ({}); linux-arm64 {} bytes, sha256 {}", verified.signer, verified.linux.size, verified.linux.sha256);
    crate::outln!("wrote {} and manifest.json.sig", out.join("manifest.json").display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const OTHER: &str = "0123456789ABCDEF0123456789ABCDEF01234567";
    const SUBKEY: &str = "1111222233334444555566667777888899990000";

    fn validsig(first: &str, last: &str) -> String {
        format!("[GNUPG:] VALIDSIG {first} 2026-10-22 1792627200 0 4 0 1 10 00 {last}")
    }

    /// The lines gpgv printed for 2.1.308's and 2.1.305's signatures (certs/README.md, the part A log of 23 Oct),
    /// with the informational lines a gpgv 2.4 prints around them.
    fn real(date: &str) -> String {
        [
            "[GNUPG:] NEWSIG".to_string(),
            format!("[GNUPG:] KEY_CONSIDERED {RELEASE_KEY_FPR} 0"),
            format!("[GNUPG:] SIG_ID abcdefghijklmnopqrstuvwxyz0 {date} 1792627200"),
            "[GNUPG:] GOODSIG BAA929FF1A7ECACE Anthropic Claude Code Release Signing".to_string(),
            format!("[GNUPG:] VALIDSIG {RELEASE_KEY_FPR} {date} 1792627200 0 4 0 1 10 00 {RELEASE_KEY_FPR}"),
            "[GNUPG:] VERIFICATION_COMPLIANCE_MODE 23".to_string(),
            "[GNUPG:] TRUST_UNDEFINED 0 pgp".to_string(),
            "exit=0".to_string(),
        ]
        .join("\n")
    }

    #[test]
    fn gpgv_status_needs_goodsig_and_the_pinned_primary() {
        // The real releases' lines pass (rule 1 never refuses them), and so does a subkey's VALIDSIG (primary last).
        assert_eq!(status_ok(&real("2026-10-22")), Ok(RELEASE_KEY_FPR.to_string()));
        assert_eq!(status_ok(&real("2026-10-20")), Ok(RELEASE_KEY_FPR.to_string()));
        let lower = format!("[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG K x\n{}\nexit=0\n", validsig(SUBKEY, &RELEASE_KEY_FPR.to_ascii_lowercase()));
        assert_eq!(status_ok(&lower), Ok(RELEASE_KEY_FPR.to_string()), "uppercased");
        let goodsig = "[GNUPG:] GOODSIG 7777888899990000 Fake Release Signing";
        let ok_block = |first: &str, last: &str| format!("[GNUPG:] NEWSIG\n{goodsig}\n{}", validsig(first, last));
        let cases: Vec<(&str, String, Result<String, &str>)> = vec![
            ("a subkey-first VALIDSIG", format!("{}\nexit=0", ok_block(SUBKEY, RELEASE_KEY_FPR)), Ok(RELEASE_KEY_FPR.to_string())),
            // gpg.sh's mixed cases: the release key's revoked signature beside another key's good one, either order.
            (
                "mixed",
                format!("[GNUPG:] NEWSIG\n[GNUPG:] REVKEYSIG K Fake\n{}\n[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG 0000111122223333 Else\n{}\nexit=0", validsig(SUBKEY, RELEASE_KEY_FPR), validsig(OTHER, OTHER)),
                Err("revoked"),
            ),
            (
                "mixed-other-first",
                format!("[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG 0000111122223333 Else\n{}\n[GNUPG:] NEWSIG\n[GNUPG:] REVKEYSIG K Fake\n{}\nexit=0", validsig(OTHER, OTHER), validsig(SUBKEY, RELEASE_KEY_FPR)),
                Err("revoked"),
            ),
            ("expired", format!("[GNUPG:] NEWSIG\n[GNUPG:] KEYEXPIRED 1790000000\n[GNUPG:] EXPKEYSIG K Fake\n{}\nexit=0", validsig(RELEASE_KEY_FPR, RELEASE_KEY_FPR)), Err("expired")),
            ("an expired signature", format!("[GNUPG:] NEWSIG\n[GNUPG:] EXPSIG K Fake\n{}\nexit=0", validsig(RELEASE_KEY_FPR, RELEASE_KEY_FPR)), Err("expired")),
            ("revoked", format!("[GNUPG:] NEWSIG\n[GNUPG:] REVKEYSIG K Fake\n{}\nexit=0", validsig(RELEASE_KEY_FPR, RELEASE_KEY_FPR)), Err("revoked")),
            ("a revoked key", format!("{}\n[GNUPG:] KEYREVOKED\nexit=0", ok_block(RELEASE_KEY_FPR, RELEASE_KEY_FPR)), Err("revoked")),
            ("no_pubkey", "[GNUPG:] NEWSIG\n[GNUPG:] ERRSIG K 22 10 00 1792627200 9 -\n[GNUPG:] NO_PUBKEY K\nexit=2".into(), Err("no_pubkey")),
            ("errsig", "[GNUPG:] NEWSIG\n[GNUPG:] ERRSIG K 22 10 00 1792627200 4 -\nexit=2".into(), Err("errsig")),
            ("a bad signature", "[GNUPG:] NEWSIG\n[GNUPG:] BADSIG K Fake\nexit=1".into(), Err("bad")),
            ("a bad one beside a good one", format!("{}\n[GNUPG:] NEWSIG\n[GNUPG:] BADSIG K Fake\nexit=1", ok_block(RELEASE_KEY_FPR, RELEASE_KEY_FPR)), Err("bad")),
            ("nodata", "[GNUPG:] NODATA 4\nexit=2".into(), Err("nodata")),
            ("unexpected", "[GNUPG:] UNEXPECTED 0\nexit=2".into(), Err("nodata")),
            ("badarmor", "[GNUPG:] BADARMOR 1\nexit=2".into(), Err("nodata")),
            ("failure", format!("{}\n[GNUPG:] FAILURE gpgv 33554433\nexit=0", ok_block(RELEASE_KEY_FPR, RELEASE_KEY_FPR)), Err("failure")),
            ("a wrong key", format!("{}\nexit=0", ok_block(OTHER, OTHER)), Err("wrong_key")),
            ("the pin first, another primary last", format!("{}\nexit=0", ok_block(RELEASE_KEY_FPR, OTHER)), Err("wrong_key")),
            ("a non-zero exit", format!("{}\nexit=1", ok_block(RELEASE_KEY_FPR, RELEASE_KEY_FPR)), Err("gpgv_exit")),
            ("no GOODSIG", format!("[GNUPG:] NEWSIG\n{}\nexit=0", validsig(RELEASE_KEY_FPR, RELEASE_KEY_FPR)), Err("no_goodsig")),
            ("no VALIDSIG", format!("[GNUPG:] NEWSIG\n{goodsig}\nexit=0"), Err("no_goodsig")),
            // The GOODSIG must not carry over a NEWSIG to another block's VALIDSIG.
            ("split blocks", format!("[GNUPG:] NEWSIG\n{goodsig}\n[GNUPG:] NEWSIG\n{}\nexit=0", validsig(RELEASE_KEY_FPR, RELEASE_KEY_FPR)), Err("no_goodsig")),
            ("nothing", "exit=0".into(), Err("no_goodsig")),
            // Rule 1: the shape.
            ("no exit line", ok_block(RELEASE_KEY_FPR, RELEASE_KEY_FPR), Err("failure")),
            ("an exit line not last", format!("exit=0\n{}", ok_block(RELEASE_KEY_FPR, RELEASE_KEY_FPR)), Err("failure")),
            ("a bad exit line", format!("{}\nexit=x", ok_block(RELEASE_KEY_FPR, RELEASE_KEY_FPR)), Err("failure")),
            ("a stray line", format!("{}\ngpgv: Good signature\nexit=0", ok_block(RELEASE_KEY_FPR, RELEASE_KEY_FPR)), Err("failure")),
            ("an unknown keyword", format!("{}\n[GNUPG:] NOTATION_DATA x\nexit=0", ok_block(RELEASE_KEY_FPR, RELEASE_KEY_FPR)), Err("failure")),
            ("a lowercase keyword", format!("{}\n[GNUPG:] goodsig x\nexit=0", ok_block(RELEASE_KEY_FPR, RELEASE_KEY_FPR)), Err("failure")),
            ("empty", String::new(), Err("failure")),
        ];
        for (what, lines, want) in cases {
            assert_eq!(status_ok(&lines), want, "{what}: {lines}");
        }
    }

    /// The vendored keyring, `RELEASE_KEY_FPR`, the Makefile's `CLAUDE_GPG_FPR` and certs/README.md name one key,
    /// without running gpg: the README's fpr line and the keyring's sha256 there.
    #[test]
    fn the_vendored_key_names_its_fingerprint() {
        use sha2::Digest as _;
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let readme = std::fs::read_to_string(dir.join("certs/README.md")).unwrap();
        assert!(readme.contains(&format!("fpr:::::::::{RELEASE_KEY_FPR}:")), "the README's gpg --show-keys line names the pinned primary");
        assert!(readme.contains(&format!("| Primary fingerprint | `{RELEASE_KEY_FPR}` |")), "the README's table");
        let gpg = hex::encode(sha2::Sha256::digest(RELEASE_KEYRING));
        assert!(readme.contains(&format!("`claude-code-release.gpg` | `gpg --dearmor` of it: the binary keyring `gpgv --keyring` takes | `{gpg}` |")), "the embedded keyring is the README's: {gpg}");
        let asc = hex::encode(sha2::Sha256::digest(std::fs::read(dir.join("certs/claude-code-release.asc")).unwrap()));
        assert!(readme.contains(&format!("| `{asc}` |")), "the armored key is the README's: {asc}");
        // An OpenPGP v4 key packet (old or new format) opens the keyring, and its fingerprint's long key id is the README's.
        assert!(matches!(RELEASE_KEYRING.first(), Some(0x99 | 0xC6)), "a public-key packet first");
        assert_eq!(&RELEASE_KEY_FPR[24..], "BAA929FF1A7ECACE", "the long key id is the fingerprint's last 16");
        let makefile = std::fs::read_to_string(dir.join("../../Makefile")).unwrap();
        let line = makefile.lines().find(|l| l.starts_with("CLAUDE_GPG_FPR")).expect("CLAUDE_GPG_FPR in the Makefile");
        assert_eq!(line.split_whitespace().last(), Some(RELEASE_KEY_FPR));
    }

    #[test]
    fn the_release_curl_argv_is_q_first_https_only() {
        let args = curl_args("https://downloads.claude.ai/claude-code-releases/2.1.308/manifest.json", Path::new("/t/m.json"), 60, Some(MANIFEST_MAX_BYTES));
        assert_eq!(args, ["-q", "--proto", "=https", "--tlsv1.2", "-fsSL", "--max-time", "60", "--max-filesize", "1048576", "-o", "/t/m.json", "https://downloads.claude.ai/claude-code-releases/2.1.308/manifest.json"]);
        let bin = curl_args("https://x/claude", Path::new("/t/.partial"), 900, Some(290));
        assert_eq!(&bin[5..9], ["--max-time", "900", "--max-filesize", "290"]);
    }

    #[test]
    fn under_the_fake_api_the_real_programs_are_never_the_fallback() {
        let fake = VmKnobs { fake_api: Some("/t/fake.json".into()), ..VmKnobs::default() };
        let e = lab_programs(&fake, &[LabProgram::Curl, LabProgram::Gpgv]).unwrap_err();
        assert!(e.contains("AI_ENV_BRIDGE_LAB_RELEASE_CURL"), "{e}");
        let e = lab_programs(&VmKnobs { release_curl: Some("/bin/sh".into()), ..fake.clone() }, &[LabProgram::Curl, LabProgram::Gpgv, LabProgram::Make]).unwrap_err();
        assert!(e.contains("AI_ENV_BRIDGE_LAB_GPGV"), "{e}");
        assert!(lab_programs(&VmKnobs::default(), &[LabProgram::Curl, LabProgram::Gpgv, LabProgram::Make]).is_ok(), "no fake API: the real programs");
        let e = lab_programs(&VmKnobs { release_curl: Some("/bin/sh".into()), ..VmKnobs::default() }, &[LabProgram::Curl]).unwrap_err();
        assert!(e.contains("needs AI_ENV_BRIDGE_LAB_FAKE_API"), "a knob alone: {e}");
        assert!(matches!(verified_manifest(&Paths::from_root_and_env("/nonexistent".into(), None), &fake, "2.1.308"), Err(ReleaseError::Fetch(_))));
    }
}
