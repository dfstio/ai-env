//! The transcript store in S3 (S9 plan §5, M2 to M4): a remote chat's
//! transcript is kept in the stack's `ai-env-transcripts-<acct>` bucket,
//! never on this Mac. The Mac presigns every request ([`S3Sign`], with the
//! runtime key; `x-amz-expected-bucket-owner` signed in each), the VM moves
//! the bytes (`shim::s3xfer`, curl as `ai-env-net`), and the Mac keeps a
//! manifest of what S3 holds ([`manifest`]: it signed every write, so it
//! never reads an object) and the chat's last messages as its view
//! (`bridge::view`). A chat begun on this Mac goes up as a multipart upload
//! ([`stage`], `ai-env session stage`). A presigned URL exists only as
//! `wire::s3::PresignedUrl`.
//!
//! Frozen in S9 phase 0: [`S3Sign`] and its request ([`PresignReq`],
//! [`S3Target`]), the lab's identity, what the per-turn sync holds
//! ([`TranscriptSync`]); G4 built the rest, and the lead's cut-over
//! (plans/s9-contracts.md §10) replaced S8's transcript path with it (the
//! Mac's mirror and `PUT /transcript` are gone).
pub mod client;
pub mod commands;
pub mod manifest;
pub mod presign;
pub mod stage;
pub mod sync;

use crate::bridge::config::Paths;
use crate::bridge::errors::BridgeError;
use crate::bridge::lab::VmKnobs;
use crate::store::Keystore;
use std::future::Future;

/// Presigning with this API object's credentials: the runtime key (`SdkMicrovmApi`), the lab key (the two fakes).
/// Signing is `aws-sigv4` with the signature in the query (`SignatureLocation::QueryParams`), service `s3`, region
/// `eu-central-1`, S3's own settings (the path encoded once and never normalised) and an unsigned payload.
pub trait S3Sign: Send + Sync {
    /// A query-string SigV4 URL for `req`, signed now, expiring `req.expires` later.
    fn presign(&self, req: &PresignReq) -> impl Future<Output = Result<crate::wire::s3::PresignedUrl, BridgeError>> + Send;
}

/// One request to presign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresignReq {
    pub method: S3Method,
    pub target: S3Target,
    /// `None`: the bucket itself (ListObjectsV2; S12, P: DeleteObjects, `POST /?delete`).
    pub key: Option<String>,
    /// Signed query parameters besides the X-Amz ones, in this order when present: versionId, uploadId,
    /// partNumber, uploads (empty value), list-type, prefix, continuation-token, max-keys, delete (empty; a
    /// multi-object delete's, alone).
    pub query: Vec<(String, String)>,
    /// Signed headers besides host, lowercase: content-length, content-encoding, x-amz-checksum-sha256,
    /// x-amz-checksum-algorithm, x-amz-sdk-checksum-algorithm (a multi-object delete's only, `SHA256`),
    /// if-none-match, x-amz-expected-bucket-owner. The last is in every request, the Mac's own included, its value
    /// `target.owner`: `presign` refuses (`Config`, exit 1) a request without it or with another value.
    pub headers: Vec<(String, String)>,
    /// At most 3600 s: `PRESIGN_EXPIRY`; `TAIL_EXPIRY` for a tail; a pull's parts as `PULL_EXPIRY_MAX` says.
    pub expires: std::time::Duration,
}

/// The method a presigned URL is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S3Method {
    Get,
    Put,
    Post,
    Delete,
}

/// The bucket a request goes to, its owner, and how it is reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3Target {
    pub bucket: String,
    pub owner: String,
    pub endpoint: S3Endpoint,
}

/// Where a bucket is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S3Endpoint {
    /// `https://<bucket>.s3.eu-central-1.amazonaws.com/<key>` (virtual-hosted).
    Aws,
    /// Debug builds: `http://<addr>/<bucket>/<key>` (path-style), the fake S3 (tests/common/fake_s3.rs).
    Lab(std::net::SocketAddr),
}

impl S3Target {
    /// Under `AI_ENV_BRIDGE_LAB_S3_ADDR` (debug builds, with the fake API) the lab bucket at that address;
    /// else state/infra.toml's `transcripts_bucket` and `account_id` (`Config` naming `make infra-status WRITE=1`).
    /// `owner` is always that `account_id` (`LAB_OWNER` in the lab), never parsed from the bucket's name.
    /// A bucket that is not `ai-env-transcripts-<account_id>` is refused as well (exit 1).
    pub fn resolve(paths: &Paths, knobs: &VmKnobs) -> Result<S3Target, BridgeError> {
        if let Some(addr) = knobs.s3_addr().map_err(BridgeError::Config)? {
            if cfg!(debug_assertions) {
                return Ok(S3Target { bucket: LAB_BUCKET.to_string(), owner: LAB_OWNER.to_string(), endpoint: S3Endpoint::Lab(addr) });
            }
        }
        const FIX: &str = "make infra-status WRITE=1 (after the S9 deploy, which creates the transcripts bucket)";
        let state = crate::bridge::infra::read_infra_state(paths)?.ok_or_else(|| BridgeError::Config(format!("{} not found: {FIX}", paths.infra_state().display())))?;
        let bucket = state.transcripts_bucket.map(|b| b.trim().to_string()).filter(|b| !b.is_empty()).ok_or_else(|| BridgeError::Config(format!("{} records no transcripts_bucket: {FIX}", paths.infra_state().display())))?;
        let owner = state.account_id.map(|a| a.trim().to_string()).filter(|a| crate::wire::s3::is_account_id(a)).ok_or_else(|| BridgeError::Config(format!("{} records no account_id (12 digits): {FIX}", paths.infra_state().display())))?;
        if crate::wire::s3::bucket_name(&owner).as_deref() != Some(bucket.as_str()) {
            return Err(BridgeError::Config(format!("{} records the transcripts bucket {bucket:?}, not the stack account's {}{owner}: {FIX}", paths.infra_state().display(), crate::wire::s3::BUCKET_PREFIX)));
        }
        Ok(S3Target { bucket, owner, endpoint: S3Endpoint::Aws })
    }
}

/// The lab S3's bucket, owner and key (not credential-shaped): the fakes sign with them, the fake S3 checks them.
pub const LAB_BUCKET: &str = "ai-env-transcripts-123456789012";
pub const LAB_OWNER: &str = "123456789012";
pub const LAB_KEY_ID: &str = "ai-env-fake-s3";
pub const LAB_SECRET: &str = "fake-s3-secret";

/// What the code-out trigger's transcript step needs, held for the session (`CodeoutCtx.transcript`).
#[derive(Debug, Clone)]
pub struct TranscriptSync {
    pub target: S3Target,
    /// The session's project slug (the Mac's and the VM's: one path, Design A).
    pub slug: String,
    /// The view lines' `cwd`: the workspace's Mac path.
    pub mac_cwd: String,
    /// Where the view is written: `<CLAUDE_CONFIG_DIR, else ~/.claude>/projects`.
    pub mac_projects: std::path::PathBuf,
    /// squid for curl in the VM (`egress::proxy_url(PROXY_IP or the configured one, PROXY_PORT)`); `None` in the lab.
    pub proxy: Option<String>,
    /// `[transcript] view_messages`.
    pub view_messages: u32,
}

impl TranscriptSync {
    /// What a session in `ws` syncs with: `[transcript] view_messages`
    /// (validated here, where the view is built: exit 1 naming the key), the
    /// transcripts bucket ([`S3Target::resolve`]), the VM's slug of the
    /// workspace's VM path (the Mac's and the VM's: one path, Design A), the
    /// workspace's Mac path as the view's `cwd`, the Mac's projects directory,
    /// and squid for curl in the VM (`egress::proxy_url` of the address the
    /// VMs are told; none for the lab's loopback S3).
    pub fn for_workspace(paths: &Paths, cfg: &crate::bridge::config::BridgeConfig, knobs: &VmKnobs, ws: &crate::bridge::workspace::WorkspaceRef, mac_projects: &std::path::Path) -> Result<TranscriptSync, BridgeError> {
        cfg.transcript.validate()?;
        let target = S3Target::resolve(paths, knobs)?;
        let proxy = match target.endpoint {
            S3Endpoint::Lab(_) => None,
            S3Endpoint::Aws => {
                let state = crate::bridge::infra::read_infra_state(paths).ok().flatten();
                let (ip, _) = crate::bridge::egress::effective_proxy_ip(cfg.aws.proxy_private_ip.as_deref(), state.as_ref());
                Some(crate::bridge::egress::proxy_url(ip, crate::bridge::egress::PROXY_PORT))
            }
        };
        Ok(TranscriptSync {
            target,
            slug: crate::wire::slug::slug_of(&ws.vm_cwd),
            mac_cwd: ws.cwd.display().to_string(),
            mac_projects: mac_projects.to_path_buf(),
            proxy,
            view_messages: cfg.transcript.view_messages,
        })
    }
}

/// `ai-env session sync UUID [--json]`: the per-turn step on demand (stat, push, commit, view) ([`commands::cmd_sync`]).
pub fn cmd_sync(store: &Keystore, uuid: &str, json: bool) -> crate::errors::Result<()> {
    commands::cmd_sync(store, uuid, json)
}

/// `ai-env session gc --remote [--older-than DAYS] [--yes] [--json]` ([`commands::cmd_gc`]).
pub fn cmd_gc(store: &Keystore, older_than: u32, yes: bool, json: bool) -> crate::errors::Result<()> {
    commands::cmd_gc(store, older_than, yes, json)
}

/// `ai-env session migrate-s9 [--yes] [--json]` ([`commands::cmd_migrate_s9`]).
pub fn cmd_migrate_s9(store: &Keystore, yes: bool, json: bool) -> crate::errors::Result<()> {
    commands::cmd_migrate_s9(store, yes, json)
}

/// `session forget UUID --purge`'s S3 half, run only after
/// `registry::forget_check` passed: the session's objects, its manifest,
/// `state/transcripts/<sid>/` (its `origin/` included) and the view; whether
/// it removed anything ([`commands::forget_purge`]).
pub fn forget_purge(store: &Keystore, paths: &Paths, sid: &str) -> Result<bool, BridgeError> {
    commands::forget_purge(store, paths, sid)
}

/// S10 (F1): [`forget_purge`] of several sessions at once, for `session
/// forget UUID... --purge` once `registry::forget_check` passed for each:
/// whether each removed anything, in their order ([`commands::forget_purge_many`]).
pub fn forget_purge_many(store: &Keystore, paths: &Paths, sids: &[String]) -> Result<Vec<bool>, BridgeError> {
    commands::forget_purge_many(store, paths, sids)
}

/// S10 (R1): the most tail links a chat's chain is followed through, from
/// its `committed` offset, when the Mac hands the VM the next tail URL or
/// restores the chat (plans/s10-contracts.md §1.4).
pub const TAIL_CHAIN_MAX: usize = 32;
