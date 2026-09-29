//! `ai-env infra pin` (S3 step 9, plan D2): `image/claude.lock` from a
//! release `manifest.json`, and the lock-versus-bundle check.
//!
//! The image bakes the Linux build of the same Claude Code version the Mac's
//! Cursor extension bundles, so a session behaves the same on both sides. The
//! lock is the one place that version lives: `make claude-pin` downloads the
//! 2 KB manifest (and checks its signature when gpg can) and hands it to
//! `--manifest`, which extracts the `linux-arm64` entry, validates every
//! value through `wire::pin` (the shim's `/validate` parses the same file)
//! and rewrites the lock atomically. `--check-bundle` is the part B
//! preflight: the lock must name the version of the highest installed
//! `anthropic.claude-code-<v>-darwin-arm64` bundle, else the deploy would
//! ship a claude the Mac does not run. Nothing here downloads anything.
use crate::bridge::doctor::pick_bundle;
use crate::bridge::infra::write_atomic_mode;
use crate::errors::{CliError, Result};
use crate::outln;
use crate::wire::pin::{parse_lock, render_lock, ClaudePin, PLATFORM};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The lock is a committed file: world-readable, like the rest of `image/`.
const LOCK_MODE: u32 = 0o644;

/// The part of a release manifest the pin needs; every other key
/// (`commit`, `sdkCompat`, `manifestSignatureEnforcement`, …) is ignored.
#[derive(Debug, Deserialize)]
struct Manifest {
    version: String,
    #[serde(rename = "buildDate")]
    build_date: String,
    platforms: BTreeMap<String, PlatformEntry>,
}

#[derive(Debug, Deserialize)]
struct PlatformEntry {
    binary: String,
    checksum: String,
    size: u64,
}

/// The pin for `platform` from a release manifest
/// (`{"version", "buildDate", "platforms": {"<platform>": {"binary", "checksum", "size"}}}`).
/// The binary must be named `claude` (the download URL is built from that
/// name) and the result must pass [`ClaudePin::validate`], so a value a
/// shell could expand, an uppercase or short checksum, a zero size or a
/// non-UTC build date never reaches the lock; a `platform` other than
/// [`PLATFORM`] is refused by the same check.
pub fn pin_from_manifest(json: &str, platform: &str) -> std::result::Result<ClaudePin, String> {
    let m: Manifest = serde_json::from_str(json).map_err(|e| format!("manifest: {e}"))?;
    let Some(entry) = m.platforms.get(platform) else {
        let known: Vec<&str> = m.platforms.keys().map(String::as_str).collect();
        return Err(format!("manifest has no platform {platform} (it lists: {})", known.join(", ")));
    };
    if entry.binary != "claude" {
        return Err(format!("manifest platforms.{platform}.binary is {:?}, expected \"claude\"", entry.binary));
    }
    let pin = ClaudePin { version: m.version, platform: platform.to_string(), sha256: entry.checksum.clone(), size: entry.size, build_date: m.build_date };
    pin.validate().map_err(|e| format!("manifest: {e}"))?;
    Ok(pin)
}

/// `$HOME/.cursor/extensions`, where Cursor unpacks the Claude extension.
fn extensions_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or_else(|| CliError::Msg("HOME is not set".into()))?;
    Ok(PathBuf::from(home).join(".cursor").join("extensions"))
}

/// The lock at `lock`, parsed; exit 1 when it is missing or invalid.
fn read_lock(lock: &Path) -> Result<ClaudePin> {
    let text = std::fs::read_to_string(lock).map_err(|e| CliError::Msg(format!("cannot read {}: {e}  <- make claude-pin CLAUDE_VERSION=<version>", lock.display())))?;
    parse_lock(&text).map_err(|e| CliError::Msg(format!("{}: {e}", lock.display())))
}

fn print_pin(pin: &ClaudePin) -> Result<()> {
    outln!("claude {} ({})", pin.version, pin.platform);
    outln!("  size    {}", pin.size);
    outln!("  sha256  {}", pin.sha256);
    outln!("  built   {}", pin.build_date);
    outln!("  url     {}", pin.download_url());
    Ok(())
}

/// `ai-env infra pin [--manifest FILE | --check-bundle] [--lock FILE]`:
/// write the lock from a manifest, compare it with the installed Cursor
/// bundle, or (neither flag) print it. clap keeps the two flags exclusive.
pub fn cmd_pin(manifest: Option<&Path>, lock: &Path, check_bundle: bool, expect_version: Option<&str>) -> Result<()> {
    if let Some(path) = manifest {
        let json = std::fs::read_to_string(path).map_err(|e| CliError::Msg(format!("cannot read {}: {e}", path.display())))?;
        let pin = pin_from_manifest(&json, PLATFORM).map_err(|e| CliError::Msg(format!("{}: {e}", path.display())))?;
        // `make claude-pin` downloads <base>/<v>/manifest.json: a manifest of
        // another version (a validly signed older one, say) is not this pin.
        if let Some(want) = expect_version {
            if pin.version != want {
                return Err(CliError::Msg(format!("{}: the manifest is for version {}, not {want}; lock not written", path.display(), pin.version)));
            }
        }
        let text = render_lock(&pin).map_err(CliError::Msg)?;
        let previous = std::fs::read_to_string(lock).ok().and_then(|t| parse_lock(&t).ok());
        write_atomic_mode(lock, text.as_bytes(), LOCK_MODE)?;
        print_pin(&pin)?;
        match previous {
            Some(p) if p == pin => outln!("unchanged: {} already pinned {}", lock.display(), p.version),
            Some(p) => outln!("previous: {}", p.version),
            None => {}
        }
        outln!("wrote {}", lock.display());
        return Ok(());
    }
    let pin = read_lock(lock)?;
    if !check_bundle {
        return print_pin(&pin);
    }
    let dir = extensions_dir()?;
    let names: Vec<String> = std::fs::read_dir(&dir).map(|rd| rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect()).unwrap_or_default();
    let Some((bundle, _)) = pick_bundle(&names) else {
        return Err(CliError::Msg(format!("pin: no anthropic.claude-code-<version>-darwin-arm64 bundle under {} (is the Cursor Claude extension installed?)", dir.display())));
    };
    if bundle == pin.version {
        outln!("pin: lock {} equals the Cursor bundle", pin.version);
        return Ok(());
    }
    Err(CliError::Msg(format!("pin: lock {} ({}) differs from the Cursor bundle {bundle}  <- make claude-pin CLAUDE_VERSION={bundle}", pin.version, lock.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A manifest shaped like the real one (extra keys, several platforms);
    /// the checksums are built at runtime.
    fn manifest(version: &str, checksum: &str, size: u64, date: &str) -> String {
        serde_json::json!({
            "version": version,
            "manifestSignatureEnforcement": "warn",
            "commit": "0".repeat(8),
            "buildDate": date,
            "platforms": {
                "darwin-arm64": {"binary": "claude", "checksum": "cd".repeat(32), "size": 7},
                "linux-arm64": {"binary": "claude", "checksum": checksum, "size": size},
                "win32-x64": {"binary": "claude.exe", "checksum": "ef".repeat(32), "size": 9}
            },
            "sdkCompat": {"testedWrapperVersions": [], "harnessSchema": 1}
        })
        .to_string()
    }

    #[test]
    fn the_linux_arm64_entry_becomes_the_pin() {
        let sum = "ab".repeat(32);
        let pin = pin_from_manifest(&manifest("2.1.283", &sum, 240_902_136, "2026-09-25T01:39:37Z"), PLATFORM).unwrap();
        assert_eq!(pin, ClaudePin { version: "2.1.283".into(), platform: PLATFORM.into(), sha256: sum, size: 240_902_136, build_date: "2026-09-25T01:39:37Z".into() });
        assert_eq!(parse_lock(&render_lock(&pin).unwrap()).unwrap(), pin);
    }

    #[test]
    fn unsafe_or_malformed_values_are_refused() {
        let sum = "ab".repeat(32);
        let date = "2026-09-25T01:39:37Z";
        let cases = [
            (manifest("2.1.283;id", &sum, 1, date), "CLAUDE_VERSION"),
            (manifest("$(id)", &sum, 1, date), "CLAUDE_VERSION"),
            (manifest("2.1.283", &"AB".repeat(32), 1, date), "CLAUDE_SHA256"),
            (manifest("2.1.283", &format!("{}`id`", "ab".repeat(29)), 1, date), "CLAUDE_SHA256"),
            (manifest("2.1.283", &sum, 0, date), "CLAUDE_SIZE"),
            (manifest("2.1.283", &sum, 1, "2026-09-25 01:39:37"), "CLAUDE_BUILD_DATE"),
        ];
        for (json, key) in cases {
            let e = pin_from_manifest(&json, PLATFORM).unwrap_err();
            assert!(e.contains(key), "{key}: {e}");
        }
        let e = pin_from_manifest(&manifest("2.1.283", &sum, 1, date), "linux-x64").unwrap_err();
        assert!(e.contains("no platform linux-x64") && e.contains("linux-arm64"), "{e}");
        let e = pin_from_manifest(&manifest("2.1.283", &sum, 1, date), "win32-x64").unwrap_err();
        assert!(e.contains("binary is \"claude.exe\""), "{e}");
        assert!(pin_from_manifest("{}", PLATFORM).unwrap_err().starts_with("manifest: "));
        assert!(pin_from_manifest("not json", PLATFORM).is_err());
        let negative = manifest("2.1.283", &sum, 1, date).replace("\"size\":1", "\"size\":-1");
        assert!(pin_from_manifest(&negative, PLATFORM).is_err(), "a negative size is not a byte count");
    }
}
