//! S11 (A.6, A2): which staged versions' objects go (`ai-env claude gc`) and
//! a version forgotten (`ai-env claude forget`). gc keeps the 3 newest
//! staged versions, the installed bundle's and every live window's in S3,
//! and the 2 newest admitted binaries on this Mac; without `--yes` it reads
//! the records only (no Touch ID). Each object deleted leaves a delete
//! marker (old versions expire under the bucket's 30-day noncurrent rule),
//! is audited `claude_stage` `deleted` and marks its record `absent`.
use super::admit::{self, VersionLock};
use super::{version_key, Record, CLAUDE_GC_KEEP_STAGED};
use crate::bridge::api::MicrovmApi;
use crate::bridge::config::Paths;
use crate::bridge::errors::BridgeError;
use crate::bridge::s3::client::S3Client;
use crate::bridge::s3::{S3Sign, S3Target};
use crate::errors::CliError;
use crate::store::Keystore;
use crate::wire::s3::{S3Key, CLAUDE_PREFIX};
use std::time::Instant;

/// The versions whose objects go (pure): every staged version but the 3 newest (`CLAUDE_GC_KEEP_STAGED`), the
/// installed bundle's and every live window's; oldest first, each once.
#[must_use]
pub fn gc_plan(staged: &[String], bundle: Option<&str>, windows: &[String]) -> Vec<String> {
    let mut versions: Vec<&String> = staged.iter().collect();
    versions.sort_by_key(|v| std::cmp::Reverse((version_key(v), (*v).clone())));
    versions.dedup();
    let newest: Vec<&String> = versions.iter().take(CLAUDE_GC_KEEP_STAGED).copied().collect();
    let mut out: Vec<String> = versions.into_iter().filter(|v| !newest.contains(v) && bundle != Some(v.as_str()) && !windows.contains(v)).cloned().collect();
    out.reverse();
    out
}

/// The live windows' versions (`doctor::running_windows`), each once.
fn window_versions() -> Vec<crate::bridge::census::RunningExtension> {
    crate::bridge::doctor::running_windows()
}

/// The versions the records say are staged.
fn staged_by_records(paths: &Paths) -> Vec<String> {
    super::load_all(paths).into_iter().filter(|r| r.staging.as_ref().is_some_and(|s| s.state == "staged")).map(|r| r.version).collect()
}

/// The local binaries gc would remove (`admit::local_doomed`: past the 2 newest admitted, decided, not in flight; a
/// dry look: nothing removed, each lock let go at once).
fn local_plan(paths: &Paths) -> Vec<String> {
    admit::local_doomed(paths, None).into_iter().map(|(v, _)| v).filter(|v| paths.claude_bin(v).exists()).collect()
}

/// gc's JSON document: `outcome` first (§7.1; a struct keeps its fields' order).
#[derive(Debug, serde::Serialize)]
struct GcDoc<'a> {
    outcome: &'static str,
    versions: &'a [String],
    objects: &'a [String],
    local: &'a [String],
    bundle: Option<&'a str>,
    windows: &'a [String],
}

/// V's record marked `absent` (its object deleted), when it has one.
fn mark_absent(paths: &Paths, version: &str) {
    if matches!(Record::load(paths, version), Ok(Some(_))) {
        if let Err(e) = Record::update(paths, version, |r| {
            if let Some(s) = r.staging.as_mut() {
                s.state = "absent".into();
                s.at = crate::bridge::registry::now_rfc3339();
            }
        }) {
            crate::bridge::voice::warn(&format!("claude {version}: its record was not marked absent: {e}"));
        }
    }
}

/// Every object under `prefix` deleted, each audited `claude_stage` `deleted` with `why`: the keys deleted.
async fn delete_under<A: MicrovmApi + S3Sign>(paths: &Paths, client: &S3Client<'_, A>, listed: &[(String, String, String)], why: &str) -> Result<Vec<String>, BridgeError> {
    let mut gone = Vec::new();
    for (key, version, sha256) in listed {
        let t0 = Instant::now();
        client.delete(key).await?;
        super::stage::audit(paths, version, sha256, "deleted", t0, &[("why", why.to_string())]);
        gone.push(key.clone());
    }
    Ok(gone)
}

/// The claude objects under `prefix` (a listing): `(key, version, sha256)`, the ones `S3Key::Claude` parses.
async fn list_claude<A: MicrovmApi + S3Sign>(client: &S3Client<'_, A>, prefix: &str) -> Result<Vec<(String, String, String)>, BridgeError> {
    Ok(client
        .list(prefix)
        .await?
        .into_iter()
        .filter_map(|o| match S3Key::parse(&o.key) {
            Some(S3Key::Claude { version, sha256 }) => Some((o.key, version, sha256)),
            _ => None,
        })
        .collect())
}

/// The backend's control plane (the one Touch ID), `f` run with it on the command's runtime.
fn with_s3<T>(ctx: &crate::bridge::vm::cmd::Ctx, store: &Keystore, f: impl AsyncS3<T>) -> crate::errors::Result<T> {
    let rt = crate::bridge::vm::cmd::runtime()?;
    let target = S3Target::resolve(&ctx.paths, &ctx.knobs)?;
    let out = rt.block_on(async {
        let b = crate::bridge::vm::cmd::backend(store, ctx).await?;
        let ran = match &b {
            crate::bridge::vm::cmd::Backend::Sdk(api, _) => f.run(&S3Client::new(&**api, &target)?).await,
            crate::bridge::vm::cmd::Backend::Fake(fake) => f.run(&S3Client::new(fake, &target)?).await,
        };
        ran.map_err(CliError::from)
    });
    rt.shutdown_background();
    out
}

/// What [`with_s3`] runs: generic over the backend's signer.
trait AsyncS3<T> {
    async fn run<A: MicrovmApi + S3Sign>(&self, client: &S3Client<'_, A>) -> Result<T, BridgeError>;
}

/// gc's S3 half: the listing, the plan over the records' and the listing's versions, the deletes.
struct GcS3<'a> {
    paths: &'a Paths,
    staged: &'a [String],
    bundle: Option<&'a str>,
    windows: &'a [String],
}

impl AsyncS3<(Vec<String>, Vec<String>)> for GcS3<'_> {
    async fn run<A: MicrovmApi + S3Sign>(&self, client: &S3Client<'_, A>) -> Result<(Vec<String>, Vec<String>), BridgeError> {
        let listed = list_claude(client, CLAUDE_PREFIX).await?;
        let mut versions: Vec<String> = self.staged.to_vec();
        versions.extend(listed.iter().map(|(_, v, _)| v.clone()));
        let plan = gc_plan(&versions, self.bundle, self.windows);
        let doomed: Vec<(String, String, String)> = listed.into_iter().filter(|(_, v, _)| plan.contains(v)).collect();
        let gone = delete_under(self.paths, client, &doomed, "gc").await?;
        for v in &plan {
            mark_absent(self.paths, v);
        }
        Ok((plan, gone))
    }
}

/// forget's S3 half: every object of one version.
struct ForgetS3<'a> {
    paths: &'a Paths,
    version: &'a str,
}

impl AsyncS3<Vec<String>> for ForgetS3<'_> {
    async fn run<A: MicrovmApi + S3Sign>(&self, client: &S3Client<'_, A>) -> Result<Vec<String>, BridgeError> {
        let listed = list_claude(client, &format!("{CLAUDE_PREFIX}{}/", self.version)).await?;
        delete_under(self.paths, client, &listed, "forget").await
    }
}

fn json_out(v: &impl serde::Serialize) -> crate::errors::Result<()> {
    crate::outln!("{}", serde_json::to_string_pretty(v).map_err(|e| CliError::Msg(format!("cannot render JSON: {e}")))?);
    Ok(())
}

/// `ai-env claude gc [--yes] [--json]`: without `--yes`, what would go, from the records (no Touch ID); with it, one
/// Touch ID, a listing of `v1/_claude/mac/`, the plan applied to the listing's versions too, and the local binaries
/// past the 2 newest admitted removed. Exit 0; 7 AWS.
pub fn cmd_gc(store: &Keystore, yes: bool, json: bool) -> crate::errors::Result<()> {
    let paths = Paths::resolve()?;
    let staged = staged_by_records(&paths);
    let bundle = admit::installed_bundle();
    let windows: Vec<String> = window_versions().into_iter().map(|w| w.ext).filter(|v| crate::wire::pin::is_version(v)).collect();
    if !yes {
        let plan = gc_plan(&staged, bundle.as_deref(), &windows);
        let local = local_plan(&paths);
        if json {
            return json_out(&GcDoc { outcome: "dry_run", versions: &plan, objects: &[], local: &local, bundle: bundle.as_deref(), windows: &windows });
        }
        let keep = |what: &[String]| if what.is_empty() { "nothing".to_string() } else { what.join(", ") };
        crate::outln!("claude gc: the records say these staged versions' S3 objects would go: {}", keep(&plan));
        crate::outln!("claude gc: these local binaries would go: {}", keep(&local));
        crate::outln!("claude gc: kept: the {CLAUDE_GC_KEEP_STAGED} newest staged, the bundle's ({}) and every live window's ({}); ai-env claude gc --yes lists S3 too and deletes (one Touch ID)", bundle.as_deref().unwrap_or("none"), keep(&windows));
        return Ok(());
    }
    let ctx = crate::bridge::vm::cmd::Ctx::load()?;
    let (plan, gone) = with_s3(&ctx, store, GcS3 { paths: &paths, staged: &staged, bundle: bundle.as_deref(), windows: &windows })?;
    let local = admit::prune_local(&paths, None);
    if json {
        let outcome = if gone.is_empty() && local.is_empty() { "nothing" } else { "deleted" };
        return json_out(&GcDoc { outcome, versions: &plan, objects: &gone, local: &local, bundle: bundle.as_deref(), windows: &windows });
    }
    for key in &gone {
        crate::outln!("deleted {key}");
    }
    for v in &local {
        crate::outln!("removed claude {v}'s local binary");
    }
    crate::outln!("claude gc: {} S3 object(s) of {} version(s) deleted, {} local binary(ies) removed", gone.len(), plan.len(), local.len());
    Ok(())
}

/// `ai-env claude forget <v> [--local] [--force]`: its objects (one Touch ID; none with `--local`), its local
/// directory and its record removed; a version a live window runs refused without `--force` (exit 9); nothing to
/// forget, exit 1.
pub fn cmd_forget(store: &Keystore, version: &str, local: bool, force: bool) -> crate::errors::Result<()> {
    if !crate::wire::pin::is_version(version) {
        return Err(CliError::Usage(format!("not a claude version (N.N.N): {version:?}")));
    }
    let paths = Paths::resolve()?;
    if let Some(w) = window_versions().into_iter().find(|w| w.ext == version) {
        if !force {
            return Err(CliError::Policy(format!(
                "claude {version} runs in a live Cursor window ({}): not forgotten (ai-env claude forget {version} --force forgets it anyway)",
                crate::bridge::doctor::running_window_text(&w)
            )));
        }
    }
    let _lock = VersionLock::take_or_busy(&paths, version)?;
    let gone = if local {
        Vec::new()
    } else {
        let ctx = crate::bridge::vm::cmd::Ctx::load()?;
        with_s3(&ctx, store, ForgetS3 { paths: &paths, version })?
    };
    let dir = paths.claude_bin_dir(version);
    let had_dir = dir.is_dir();
    if had_dir {
        std::fs::remove_dir_all(&dir).map_err(|e| CliError::Msg(format!("cannot remove {}: {e}", dir.display())))?;
    }
    // A3's review: under `state/claude/records.lock`, so a late verdict never writes the forgotten version back; its
    // prewarm mark goes with it, so a V admitted again rides one prewarm again.
    let had_record = super::Record::remove(&paths, version).map_err(|e| CliError::Msg(e.to_string()))?;
    let _ = std::fs::remove_file(crate::bridge::remote::prewarm::staging_marker(&paths, version));
    if gone.is_empty() && !had_dir && !had_record {
        return Err(CliError::Msg(format!("claude {version}: nothing to forget (no record, no local binary{})", if local { "" } else { ", no S3 object" })));
    }
    for key in &gone {
        crate::outln!("deleted {key}");
    }
    crate::outln!("claude {version}: forgotten ({} S3 object(s){}{})", gone.len(), if had_dir { ", its local binary" } else { "" }, if had_record { ", its record" } else { "" });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn gc_plan_keeps_three_the_bundle_and_the_windows() {
        let staged = v(&["2.1.300", "2.1.306", "2.1.301", "2.1.302", "2.1.10", "2.1.305", "2.1.303", "2.1.304", "2.1.306"]);
        assert_eq!(gc_plan(&staged, Some("2.1.300"), &v(&["2.1.302"])), v(&["2.1.10", "2.1.301", "2.1.303"]), "oldest first, each once");
        assert_eq!(gc_plan(&staged, None, &[]), v(&["2.1.10", "2.1.300", "2.1.301", "2.1.302", "2.1.303"]));
        assert_eq!(gc_plan(&v(&["2.1.1", "2.1.2", "2.1.3"]), None, &[]), Vec::<String>::new(), "three staged: nothing goes");
        assert_eq!(gc_plan(&[], Some("2.1.1"), &v(&["2.1.2"])), Vec::<String>::new());
    }
}
